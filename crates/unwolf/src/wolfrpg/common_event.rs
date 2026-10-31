//! `CommonEvent.dat` (`WolfRPG/CommonEvents.hpp`).

use super::command::{self, Command};
use super::{
    COMMON_EVENT_MAGIC, HEADER_LEN, PRO_V33_HEADER_SIZE, Reader, StringField, UTF8_FLAG_INDEX,
    check_magic, decrypt_v2_0_body, decrypt_v3_1, lz4_pack, lz4_unpack, splice_strings,
    strip_control_chars,
};
use crate::crypto::datadecrypt::{
    DEFAULT_SEEDS, ProFile, SeedIndices, decrypt_v3_3, decrypt_v3_5, pro_generation,
};
use crate::error::{Error, Result};

/// Versions written by Wolf RPG 3.5: LZ4-packed body and extra bytes after
/// each command.
const V35_VERSIONS: [u8; 2] = [0x93, 0xCC];

#[derive(Debug, Clone)]
pub struct CommonEvent {
    pub id: u32,
    pub name: StringField,
    pub commands: Vec<Command>,
    pub description: StringField,
}

/// A parsed plain `CommonEvent.dat`. Fields point into [`Self::body`].
#[derive(Debug, Clone)]
pub struct CommonEventFile {
    /// Indicator, magic and version bytes of the plain file.
    header: Vec<u8>,
    pub utf8: bool,
    pub version: u8,
    /// The event list: the rest of the file, or its LZ4-decoded content in
    /// Wolf RPG 3.5.
    pub body: Vec<u8>,
    pub events: Vec<CommonEvent>,
}

impl CommonEventFile {
    /// Parse a file whose indicator byte is 0 (not encrypted, or already
    /// decrypted).
    pub fn parse(file: &[u8]) -> Result<Self> {
        let mut r = Reader::new(file);
        r.expect_u8(0, "CommonEvent indicator")?;
        let utf8 = check_magic(r.bytes(COMMON_EVENT_MAGIC.len())?, &COMMON_EVENT_MAGIC)?;
        Self::from_content(utf8, &file[HEADER_LEN..])
    }

    /// Parse a file in any of the forms `FileCoder::load` accepts: plain,
    /// v2.0 encrypted, or protected by Wolf RPG Pro 3.1, 3.3 or 3.5.
    pub fn load(file: &[u8]) -> Result<Self> {
        const SEEDS: SeedIndices = DEFAULT_SEEDS;
        match pro_generation(file) {
            Some(g) if g < 0x55 => {
                let (data, pos) = decrypt_v3_1(file, SEEDS)?;
                Self::from_content(true, &data[pos..])
            }
            Some(g) if g < 0x57 => {
                let mut data = file.to_vec();
                decrypt_v3_3(&mut data, SEEDS)?;
                let content = data
                    .get(PRO_V33_HEADER_SIZE..)
                    .ok_or_else(|| Error::format("WolfRPG: Pro v3.3 file too short"))?;
                Self::from_content(true, content)
            }
            Some(_) => {
                let mut data = file.to_vec();
                decrypt_v3_5(&mut data, ProFile::CommonEvent)?;
                Self::parse(&data)
            }
            None if file.first().is_some_and(|&b| b != 0) => {
                // The original keeps the text encoding of the previous file
                // here; CommonEvent.dat is read first, so it is Shift-JIS.
                Self::from_content(false, &decrypt_v2_0_body(file, SEEDS)?)
            }
            None => Self::parse(file),
        }
    }

    /// `content` starts at the version byte.
    fn from_content(utf8: bool, content: &[u8]) -> Result<Self> {
        let version = *content
            .first()
            .ok_or_else(|| Error::format("WolfRPG: CommonEvent.dat is empty"))?;
        let v35 = V35_VERSIONS.contains(&version);
        let rest = &content[1..];
        // Data after the LZ4 block is ignored, as in the original.
        let body = if v35 {
            lz4_unpack(rest)?.0
        } else {
            rest.to_vec()
        };
        let events = parse_body(&body, v35)?;
        let mut header = vec![0];
        header.extend_from_slice(&COMMON_EVENT_MAGIC);
        if utf8 {
            header[1 + UTF8_FLAG_INDEX] = 0x55;
        }
        header.push(version);
        Ok(Self {
            header,
            utf8,
            version,
            body,
            events,
        })
    }

    pub fn is_v35(&self) -> bool {
        V35_VERSIONS.contains(&self.version)
    }

    pub fn string(&self, f: &StringField) -> &[u8] {
        &self.body[f.content.clone()]
    }

    /// Serialise with the body `body`, packing it again when needed.
    fn to_file(&self, body: &[u8]) -> Vec<u8> {
        let mut out = self.header.clone();
        if self.is_v35() {
            out.extend_from_slice(&lz4_pack(body));
        } else {
            out.extend_from_slice(body);
        }
        out
    }

    /// `FixPro35EventDescriptions` followed by `Dump`: the file with the
    /// control characters removed from every event description.
    pub fn fix_pro35_descriptions(&self) -> Vec<u8> {
        let fields: Vec<StringField> = self.events.iter().map(|e| e.description.clone()).collect();
        let body = splice_strings(&self.body, &fields, |s| strip_control_chars(s, self.utf8));
        self.to_file(&body)
    }
}

/// The event list: count, events, then a terminator byte (at least 0x89)
/// that must end the data.
fn parse_body(body: &[u8], v35: bool) -> Result<Vec<CommonEvent>> {
    let mut r = Reader::new(body);
    let n = r.u32()?;
    let events = (0..n)
        .map(|_| parse_event(&mut r, v35))
        .collect::<Result<Vec<_>>>()?;
    let terminator = r.u8()?;
    if terminator < 0x89 {
        return Err(Error::format(format!(
            "WolfRPG: CommonEvent terminator {terminator:#04x} < 0x89"
        )));
    }
    if !r.is_eof() {
        return Err(Error::format("WolfRPG: CommonEvent has trailing data"));
    }
    Ok(events)
}

/// `CommonEvent::init`.
fn parse_event(r: &mut Reader<'_>, v35: bool) -> Result<CommonEvent> {
    const UNKNOWN7_LEN: usize = 0x1D;
    const UNKNOWN8_COUNT: usize = 100;

    r.expect_u8(0x8E, "CommonEvent header")?;
    let id = r.u32()?;
    r.skip(4 + 7)?;
    let name = r.string()?;
    let commands = command::read_list(r, v35)?;
    let _unknown11 = r.string()?;
    let description = r.string()?;
    r.expect_u8(0x8F, "CommonEvent data")?;
    r.string_array()?;
    r.skip_array(1)?;
    for _ in 0..r.u32()? {
        r.string_array()?;
    }
    for _ in 0..r.u32()? {
        r.skip_array(4)?;
    }
    r.skip(UNKNOWN7_LEN)?;
    for _ in 0..UNKNOWN8_COUNT {
        r.string()?;
    }
    r.expect_u8(0x91, "CommonEvent data")?;
    r.string()?;
    match r.u8()? {
        0x91 => {}
        0x92 => {
            r.string()?;
            r.u32()?;
            r.expect_u8(0x92, "CommonEvent data")?;
        }
        b => {
            return Err(Error::format(format!(
                "WolfRPG: CommonEvent indicator {b:#04x}, expected 0x91 or 0x92"
            )));
        }
    }
    Ok(CommonEvent {
        id,
        name,
        commands,
        description,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::wolfrpg::command::tests::encode;

    fn put_str(v: &mut Vec<u8>, s: &[u8]) {
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
        v.extend_from_slice(s);
    }

    /// One serialised event, with `commands` already encoded.
    pub(crate) fn encode_event(id: u32, commands: &[Vec<u8>], description: &[u8]) -> Vec<u8> {
        let mut v = vec![0x8E];
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&[0; 4 + 7]);
        put_str(&mut v, b"name\0");
        v.extend_from_slice(&(commands.len() as u32).to_le_bytes());
        for c in commands {
            v.extend_from_slice(c);
        }
        put_str(&mut v, b"\0");
        put_str(&mut v, description);
        v.push(0x8F);
        v.extend_from_slice(&1u32.to_le_bytes());
        put_str(&mut v, b"u3\0");
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&[1, 2]);
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        put_str(&mut v, b"u5\0");
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&42u32.to_le_bytes());
        v.extend_from_slice(&[0; 0x1D]);
        for _ in 0..100 {
            put_str(&mut v, b"\0");
        }
        v.push(0x91);
        put_str(&mut v, b"u9\0");
        v.push(0x92);
        put_str(&mut v, b"u10\0");
        v.extend_from_slice(&7u32.to_le_bytes());
        v.push(0x92);
        v
    }

    /// A whole plain file.
    pub(crate) fn encode_file(events: &[Vec<u8>], version: u8, utf8: bool) -> Vec<u8> {
        let mut body = (events.len() as u32).to_le_bytes().to_vec();
        for e in events {
            body.extend_from_slice(e);
        }
        body.push(0x8F);
        let mut f = vec![0];
        let mut magic = COMMON_EVENT_MAGIC;
        if utf8 {
            magic[5] = 0x55;
        }
        f.extend_from_slice(&magic);
        f.push(version);
        if V35_VERSIONS.contains(&version) {
            f.extend_from_slice(&lz4_pack(&body));
        } else {
            f.extend_from_slice(&body);
        }
        f
    }

    #[test]
    fn parses_and_fixes_descriptions() {
        for (version, v35) in [(0x90, false), (0x93, true), (0xCC, true)] {
            let cmds = vec![encode(122, &[3_000_001], &[b"abc\0"], v35)];
            let file = encode_file(
                &[
                    encode_event(0, &cmds, b"bad\x02desc\0"),
                    encode_event(1, &[], b"ok\n\0"),
                ],
                version,
                true,
            );
            let ce = CommonEventFile::parse(&file).unwrap();
            assert!(ce.utf8);
            assert_eq!(ce.events.len(), 2);
            assert_eq!(ce.events[0].commands[0].code, 122);
            assert_eq!(ce.string(&ce.events[0].description), b"bad\x02desc\0");

            let fixed = CommonEventFile::parse(&ce.fix_pro35_descriptions()).unwrap();
            assert_eq!(fixed.string(&fixed.events[0].description), b"baddesc\0");
            assert_eq!(fixed.string(&fixed.events[1].description), b"ok\n\0");
            assert_eq!(fixed.events[0].commands.len(), 1);
        }
    }

    #[test]
    fn loads_encrypted_files() {
        use crate::crypto::datadecrypt::{encrypt_v3_5, xor_v2_0};
        let cmds = vec![encode(122, &[3_000_001], &[b"abc\0"], false)];
        let plain = encode_file(&[encode_event(3, &cmds, b"d\0")], 0x90, false);
        let content = &plain[HEADER_LEN..];
        let check = |f: &CommonEventFile| {
            assert_eq!(f.events.len(), 1);
            assert_eq!(f.events[0].id, 3);
            assert_eq!(f.string(&f.events[0].commands[0].strings[0]), b"abc\0");
        };

        // v2.0: clear 10-byte header holding the seeds, then the content.
        let mut v20 = vec![0x11, 1, 2, 0x33, 4, 5, 6, 7, 8, 0x99];
        let mut body = content.to_vec();
        xor_v2_0(&mut body, [0x11, 0x33, 0x99]);
        v20.extend_from_slice(&body);
        let f = CommonEventFile::load(&v20).unwrap();
        assert!(!f.utf8);
        check(&f);

        // Pro 3.1: the decrypted part holds a key before the content.
        let mut p31 = vec![0x11, 0x50, 2, 0x33, 4, 0x54, 6, 7, 8, 0x99];
        let mut body = vec![0u8; 5];
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"KEY");
        body.extend_from_slice(content);
        xor_v2_0(&mut body, [0x11, 0x33, 0x99]);
        p31.extend_from_slice(&body);
        let f = CommonEventFile::load(&p31).unwrap();
        assert!(f.utf8);
        check(&f);

        // Pro 3.5.
        let f = CommonEventFile::load(&encrypt_v3_5(content, ProFile::CommonEvent)).unwrap();
        check(&f);
        // Plain.
        check(&CommonEventFile::load(&plain).unwrap());
    }

    #[test]
    fn rejects_trailing_data_and_bad_terminator() {
        let mut file = encode_file(&[encode_event(0, &[], b"d\0")], 0x90, false);
        file.push(0);
        assert!(CommonEventFile::parse(&file).is_err());
        file.pop();
        *file.last_mut().unwrap() = 0x10;
        assert!(CommonEventFile::parse(&file).is_err());
    }
}
