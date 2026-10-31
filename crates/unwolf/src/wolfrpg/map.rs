//! Map files (`*.mps`, `WolfRPG/Map.hpp`). Only the event commands are
//! kept: they hold the WolfX keys.

use super::command::{self, Command, skip_route};
use super::{PRO_V33_HEADER_SIZE, Reader, decrypt_v3_1, lz4_unpack};
use crate::crypto::datadecrypt::{SeedIndices, decrypt_v3_3, pro_generation};
use crate::error::{Error, Result};

/// 20-byte magic number; byte 16 is 0x55 in UTF-8 games.
pub const MAP_MAGIC: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x4F, 0x4C, 0x46, 0x4D, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
const MAP_UTF8_INDEX: usize = 16;
/// Magic, version and one unknown byte precede the (possibly packed) content.
const PACKED_START: usize = 25;
/// Maps from this version on store their content LZ4-packed.
const PACKED_VERSION: u8 = 0x65;
/// Maps from this version on have a layer count and Wolf RPG 3.5 commands.
const V35_VERSION: u32 = 0x67;
/// The original constructs map readers without seeds: three zero indices.
const MAP_SEEDS: SeedIndices = [0, 0, 0];

#[derive(Debug, Clone)]
pub struct MapFile {
    /// The buffer the command fields point into.
    pub data: Vec<u8>,
    pub utf8: bool,
    /// Commands of every page of every event, in file order.
    pub commands: Vec<Command>,
}

impl MapFile {
    /// `Map::Map` with the decryption of `FileCoder::load`.
    pub fn load(file: &[u8]) -> Result<Self> {
        let (data, start, utf8) = match pro_generation(file) {
            Some(g) if g < 0x55 => {
                let (data, pos) = decrypt_v3_1(file, MAP_SEEDS)?;
                (data, pos, true)
            }
            Some(g) if g < 0x57 => {
                let mut data = file.to_vec();
                decrypt_v3_3(&mut data, MAP_SEEDS)?;
                if data.len() < PRO_V33_HEADER_SIZE {
                    return Err(Error::format("WolfRPG: Pro v3.3 map too short"));
                }
                (data, PRO_V33_HEADER_SIZE, true)
            }
            // `PRO_MAGIC` has no entry for maps: the original fails too.
            Some(_) => {
                return Err(Error::Unsupported(
                    "map protected by Wolf RPG Pro 3.5".into(),
                ));
            }
            None => {
                let magic = file
                    .get(..MAP_MAGIC.len())
                    .ok_or_else(|| Error::format("WolfRPG: map too short"))?;
                let ok = magic
                    .iter()
                    .zip(MAP_MAGIC)
                    .enumerate()
                    .all(|(i, (&f, m))| f == m || (i == MAP_UTF8_INDEX && f == 0x55));
                if !ok {
                    return Err(Error::format("WolfRPG: invalid map magic number"));
                }
                let utf8 = magic[MAP_UTF8_INDEX] == 0x55;
                let data = match file.get(MAP_MAGIC.len()) {
                    Some(&v) if v >= PACKED_VERSION && file.len() >= PACKED_START => {
                        let mut d = file[..PACKED_START].to_vec();
                        d.extend_from_slice(&lz4_unpack(&file[PACKED_START..])?.0);
                        d
                    }
                    _ => file.to_vec(),
                };
                (data, MAP_MAGIC.len(), utf8)
            }
        };
        let commands = parse_content(&data, start, utf8)?;
        Ok(Self {
            data,
            utf8,
            commands,
        })
    }
}

/// `Map::load` from the version field.
fn parse_content(data: &[u8], start: usize, utf8: bool) -> Result<Vec<Command>> {
    const EVENT_INDICATOR: u8 = 0x6F;
    const TERMINATOR: u8 = 0x66;
    let mut r = Reader::at(data, start);
    let version = r.u32()?;
    r.u8()?;
    r.string()?;
    let _tileset = r.u32()?;
    let width = r.u32()?;
    let height = r.u32()?;
    let event_count = r.u32()?;
    let mut layers = 3u32;
    let v35 = version >= V35_VERSION;
    if v35 {
        r.u32()?;
        layers = r.u32()?;
    }
    // UTF-8 maps may replace the tiles with -1.
    let mut read_tiles = true;
    if utf8 {
        if r.u32()? == u32::MAX {
            read_tiles = false;
        } else {
            r = Reader::at(data, r.pos() - 4);
        }
    }
    if read_tiles {
        let size = u64::from(width) * u64::from(height) * u64::from(layers) * 4;
        r.skip(usize::try_from(size).map_err(|_| Error::format("WolfRPG: map too large"))?)?;
    }

    let mut commands = Vec::new();
    let mut events = 0u32;
    let mut indicator = r.u8()?;
    while indicator == EVENT_INDICATOR {
        parse_event(&mut r, v35, &mut commands)?;
        events += 1;
        indicator = r.u8()?;
    }
    if events != event_count {
        return Err(Error::format(format!(
            "WolfRPG: map declares {event_count} events, found {events}"
        )));
    }
    if indicator != TERMINATOR {
        return Err(Error::format(format!(
            "WolfRPG: map event indicator {indicator:#04x}, expected 0x66"
        )));
    }
    if !r.is_eof() {
        return Err(Error::format("WolfRPG: map has trailing data"));
    }
    Ok(commands)
}

/// `Event::Init`.
fn parse_event(r: &mut Reader<'_>, v35: bool, commands: &mut Vec<Command>) -> Result<()> {
    const PAGE_INDICATOR: u8 = 0x79;
    if r.bytes(4)? != [0x39, 0x30, 0x00, 0x00] {
        return Err(Error::format("WolfRPG: bad map event magic"));
    }
    r.u32()?;
    r.string()?;
    r.skip(8)?;
    let page_count = r.u32()?;
    if r.bytes(4)? != [0; 4] {
        return Err(Error::format("WolfRPG: bad map event magic"));
    }
    let mut pages = 0u32;
    let mut indicator = r.u8()?;
    while indicator == PAGE_INDICATOR {
        parse_page(r, v35, commands)?;
        pages += 1;
        indicator = r.u8()?;
    }
    if pages != page_count {
        return Err(Error::format(format!(
            "WolfRPG: event declares {page_count} pages, found {pages}"
        )));
    }
    if indicator != 0x70 {
        return Err(Error::format(format!(
            "WolfRPG: event indicator {indicator:#04x}, expected 0x70"
        )));
    }
    Ok(())
}

/// `Page::Init`.
fn parse_page(r: &mut Reader<'_>, v35: bool, commands: &mut Vec<Command>) -> Result<()> {
    // Graphic direction, frame, opacity and render mode.
    const GRAPHIC_LEN: usize = 4;
    const CONDITIONS_LEN: usize = 1 + 4 + 4 * 4 + 4 * 4;
    const MOVEMENT_LEN: usize = 4;
    r.u32()?;
    r.string()?;
    r.skip(GRAPHIC_LEN + CONDITIONS_LEN + MOVEMENT_LEN + 2)?;
    skip_route(r)?;
    commands.extend(command::read_list(r, v35)?);
    let features = r.u32()?;
    r.skip(3)?;
    if features > 3 {
        r.u8()?;
    }
    r.expect_u8(0x7A, "map page terminator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wolfrpg::command::tests::encode;
    use crate::wolfrpg::lz4_pack;

    fn put_str(v: &mut Vec<u8>, s: &[u8]) {
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
        v.extend_from_slice(s);
    }

    fn put_u32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Content of a map after the version and unknown byte.
    fn content(version: u32, utf8: bool, commands: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        put_str(&mut v, b"\0");
        for x in [1, 2, 1, 1] {
            put_u32(&mut v, x); // tileset, width, height, events
        }
        let layers = if version >= V35_VERSION {
            put_u32(&mut v, 0);
            put_u32(&mut v, 2);
            2
        } else {
            3
        };
        if utf8 {
            put_u32(&mut v, u32::MAX);
        } else {
            v.extend_from_slice(&vec![0xEE; 2 * layers * 4]);
        }
        v.push(0x6F);
        v.extend_from_slice(&[0x39, 0x30, 0, 0]);
        put_u32(&mut v, 0);
        put_str(&mut v, b"ev\0");
        put_u32(&mut v, 3);
        put_u32(&mut v, 4);
        put_u32(&mut v, 1);
        v.extend_from_slice(&[0; 4]);
        v.push(0x79);
        put_u32(&mut v, 0);
        put_str(&mut v, b"gfx\0");
        v.extend_from_slice(&[0; 4 + 37 + 4 + 2]);
        put_u32(&mut v, 1);
        v.extend_from_slice(&[5, 1, 9, 0, 0, 0, 1, 0]);
        put_u32(&mut v, commands.len() as u32);
        for c in commands {
            v.extend_from_slice(c);
        }
        put_u32(&mut v, 4);
        v.extend_from_slice(&[0, 0, 0, 1, 0x7A]);
        v.push(0x70);
        v.push(0x66);
        v
    }

    fn file(version: u32, utf8: bool, commands: &[Vec<u8>]) -> Vec<u8> {
        let mut f = MAP_MAGIC.to_vec();
        if utf8 {
            f[MAP_UTF8_INDEX] = 0x55;
        }
        put_u32(&mut f, version);
        f.push(0);
        let c = content(version, utf8, commands);
        if version >= u32::from(PACKED_VERSION) {
            f.extend_from_slice(&lz4_pack(&c));
        } else {
            f.extend_from_slice(&c);
        }
        f
    }

    #[test]
    fn reads_plain_packed_and_v35_maps() {
        for (version, utf8) in [(0x64, false), (0x65, true), (0x67, true)] {
            let v35 = version >= V35_VERSION;
            let cmds = vec![
                encode(122, &[3_000_007], &[b"key\0"], v35),
                encode(121, &[2_000_001, 42], &[], v35),
            ];
            let m = MapFile::load(&file(version, utf8, &cmds)).unwrap();
            assert_eq!(m.utf8, utf8);
            assert_eq!(m.commands.len(), 2, "version {version:#x}");
            assert_eq!(m.commands[1].args, [2_000_001, 42]);
        }
    }

    #[test]
    fn rejects_bad_maps() {
        let mut f = file(0x64, false, &[]);
        f.push(0);
        assert!(MapFile::load(&f).is_err());
        let mut f = file(0x64, false, &[]);
        f[10] = 0;
        assert!(MapFile::load(&f).is_err());
        let mut p = vec![0u8; 200];
        p[1] = 0x50;
        p[5] = 0x57;
        assert!(matches!(MapFile::load(&p), Err(Error::Unsupported(_))));
    }
}
