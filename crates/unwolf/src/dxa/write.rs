//! Writing DX archives (`-p`): one folder becomes one archive that the
//! readers of this crate open with the same mode.
//!
//! The layout and the storage rules follow the DX Library encoder as
//! called by UberWolf (`EncodeArchiveOneDirectory[Wolf]`): LZ compression
//! for files under 10 MiB unless it saves less than 10 %, Huffman on top in
//! DXA v8 (whole stream up to 24 KiB, otherwise only its first and last
//! 12 KiB), stored sizes rounded up to 4 bytes, tables LZ+Huffman packed in
//! v8, then the Wolf RPG whole-file layers for `newCrypt` versions. The LZ
//! and Huffman encoders are this crate's own: the archive decodes to the
//! same files but is not byte-identical to the original's.

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::keys::{self, Cipher, legacy_key};
use super::v8::{self, HEADER_LEN as V8_HEADER_LEN, MIN_NEW_CRYPT_SIZE, is_new_crypt};
use super::{DXA_MAGIC, DxaFormat, huffman, lz};
use crate::crypto::wolf::{self, PWD_LEN};
use crate::error::{Error, IoContext, Result};
use crate::modes::CryptMode;

const ATTR_DIRECTORY: u64 = 0x10;
/// `FILE_ATTRIBUTE_ARCHIVE`, what Windows reports for ordinary files.
const ATTR_ARCHIVE: u64 = 0x20;
/// Shift-JIS, the code page the original writes (`0x3A4`).
const CODE_PAGE: u64 = 932;
/// Huffman applies to the first and last `HUFFMAN_KB` KiB (`0xC`).
const HUFFMAN_KB: u8 = 0x0C;
const PRESS_LIMIT: u64 = 10 * 1024 * 1024;
const PRESS_MIN_GAIN: f64 = 0.90;
/// Chunk size of the in-place pass of the whole-file layers.
const LAYER_CHUNK: usize = 1 << 20;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PackStats {
    pub files: u64,
    pub dirs: u64,
    /// Total size of the input files.
    pub bytes: u64,
    /// Size of the archive.
    pub archive_size: u64,
}

/// Field widths and features of one DXA version.
#[derive(Clone, Copy)]
struct Spec {
    format: DxaFormat,
    version: u16,
    word: usize,
    header_len: usize,
    huffman: bool,
}

impl Spec {
    fn new(format: DxaFormat) -> Self {
        match format {
            DxaFormat::V5 => Self {
                format,
                version: 5,
                word: 4,
                header_len: 28,
                huffman: false,
            },
            DxaFormat::V6 => Self {
                format,
                version: 6,
                word: 8,
                header_len: 48,
                huffman: false,
            },
            DxaFormat::V8 => Self {
                format,
                version: 8,
                word: 8,
                header_len: V8_HEADER_LEN as usize,
                huffman: true,
            },
        }
    }

    fn none(&self) -> u64 {
        if self.word == 4 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        }
    }

    /// name, attributes, 3 times, data address, size, press size, [huff size]
    fn file_head_len(&self) -> usize {
        self.word * (5 + usize::from(self.huffman)) + 24
    }

    fn put(&self, buf: &mut Vec<u8>, v: u64) -> Result<()> {
        if self.word == 4 {
            let v = u32::try_from(v)
                .map_err(|_| Error::Unsupported("archive too large for DXA v5".into()))?;
            buf.extend_from_slice(&v.to_le_bytes());
        } else {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }
}

/// One file or folder to store.
struct Item {
    name: String,
    path: PathBuf,
    is_dir: bool,
    /// FILETIME values: creation, last access, last write.
    times: [u64; 3],
    size: u64,
}

/// Pack the contents of `dir` into the archive `out` with `mode`.
///
/// The archive is written to a temporary file next to `out`, then renamed.
pub fn pack_directory(dir: &Path, out: &Path, mode: &CryptMode) -> Result<PackStats> {
    let file_name = out
        .file_name()
        .ok_or_else(|| Error::Game(format!("bad output path {}", out.display())))?
        .to_string_lossy()
        .into_owned();
    let tmp = out.with_file_name(format!(".{file_name}.unwolf-tmp"));
    let result = write_archive(dir, &tmp, mode, SMALL_NEW_CRYPT);
    match result {
        Ok(stats) => {
            fs::rename(&tmp, out).at(out)?;
            Ok(stats)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// How a `newCrypt` archive smaller than `MIN_NEW_CRYPT_SIZE` is written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SmallNewCrypt {
    /// Zero padding after the tables up to the minimum size, then the
    /// whole-file layers and the header address cipher.
    Pad,
    /// No whole-file layers and a plain header, like the original encoder.
    /// The tables and data keep the `KeyConv` XOR.
    #[cfg_attr(not(test), allow(dead_code))]
    Plain,
}

const SMALL_NEW_CRYPT: SmallNewCrypt = SmallNewCrypt::Pad;

fn write_archive(
    dir: &Path,
    path: &Path,
    mode: &CryptMode,
    small: SmallNewCrypt,
) -> Result<PackStats> {
    let spec = Spec::new(mode.format);
    let cv = if spec.format == DxaFormat::V8 {
        mode.crypt_version
    } else {
        0
    };
    // The original builds its keys from a zeroed header: the password
    // stored in `reserve` is all zeros.
    let pwd = [0u8; PWD_LEN];
    let cipher = match spec.format {
        DxaFormat::V8 => v8::data_cipher(cv, &mode.key, &pwd)?,
        _ => Cipher::Legacy(legacy_key(Some(&mode.key))),
    };

    // Read access too: the whole-file layers are applied in place.
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .at(path)?;
    let mut w = Writer {
        spec,
        cipher,
        key_string: v8::key_string(&mode.key).to_vec(),
        out: BufWriter::new(file),
        path: path.to_path_buf(),
        data_size: 0,
        names: Vec::new(),
        files: Vec::new(),
        dirs: Vec::new(),
        stats: PackStats::default(),
    };
    w.out.write_all(&vec![0; spec.header_len]).at(path)?;
    w.encode_root(dir)?;

    // Tables: names, file entries, directories, as one block.
    let mut tables = std::mem::take(&mut w.names);
    let (names_len, files_len) = (tables.len() as u64, w.files.len() as u64);
    tables.extend_from_slice(&w.files);
    tables.extend_from_slice(&w.dirs);
    let head_size = u32::try_from(tables.len())
        .map_err(|_| Error::Unsupported("archive tables larger than 4 GiB".into()))?;
    let mut stored = if spec.format == DxaFormat::V8 {
        huffman::encode(&lz::encode(&tables))
    } else {
        tables
    };
    w.cipher.apply(None, 0, &mut stored);
    w.out.write_all(&stored).at(path)?;

    let names_at = spec.header_len as u64 + w.data_size;
    let mut header = Vec::with_capacity(spec.header_len);
    header.extend_from_slice(&DXA_MAGIC.to_le_bytes());
    header.extend_from_slice(&spec.version.to_le_bytes());
    header.extend_from_slice(&head_size.to_le_bytes());
    for v in [
        spec.header_len as u64,
        names_at,
        names_len,
        names_len + files_len,
    ] {
        spec.put(&mut header, v)?;
    }
    if spec.format == DxaFormat::V8 {
        header.extend_from_slice(&(CODE_PAGE as u32).to_le_bytes());
        header.extend_from_slice(&(u32::from(cv) << 16).to_le_bytes());
        header.push(HUFFMAN_KB);
        header.extend_from_slice(&pwd);
    } else {
        spec.put(&mut header, CODE_PAGE)?;
        w.cipher.apply(None, 0, &mut header);
    }
    debug_assert_eq!(header.len(), spec.header_len);

    let mut file = w
        .out
        .into_inner()
        .map_err(|e| Error::io(path, e.into_error()))?;
    let plain_small =
        small == SmallNewCrypt::Plain && file.metadata().at(path)?.len() < MIN_NEW_CRYPT_SIZE;
    if is_new_crypt(cv) && !plain_small {
        let key_cstr = super::cstr(&mode.key);
        apply_wolf_layers(&mut file, path, &pwd, cv, key_cstr, &mode.key, names_at)?;
        let mut h = [0u8; 64];
        h.copy_from_slice(&header);
        wolf::crypt_addresses(&mut h, &pwd, cv);
        header = h.to_vec();
    }
    file.seek(SeekFrom::Start(0)).at(path)?;
    file.write_all(&header).at(path)?;
    file.sync_all().at(path)?;
    w.stats.archive_size = file.metadata().at(path)?.len();
    Ok(w.stats)
}

/// The `newCrypt` whole-file layers, applied in place. Archives shorter
/// than the minimum get zero padding after their tables first
/// (`SmallNewCrypt::Pad`).
fn apply_wolf_layers(
    file: &mut File,
    path: &Path,
    pwd: &[u8; PWD_LEN],
    cv: u16,
    key_cstr: &[u8],
    mode_key: &[u8],
    tables_start: u64,
) -> Result<()> {
    let mut size = file.metadata().at(path)?.len();
    if size < MIN_NEW_CRYPT_SIZE {
        file.set_len(MIN_NEW_CRYPT_SIZE).at(path)?;
        size = MIN_NEW_CRYPT_SIZE;
    }
    let layers = v8::wolf_layers(
        size,
        pwd,
        cv,
        key_cstr,
        v8::pro_key(cv, mode_key),
        tables_start,
    )?;
    let mut buf = vec![0u8; LAYER_CHUNK];
    let mut pos = V8_HEADER_LEN;
    while pos < size {
        let n = LAYER_CHUNK.min((size - pos) as usize);
        file.seek(SeekFrom::Start(pos)).at(path)?;
        file.read_exact(&mut buf[..n]).at(path)?;
        layers.apply(pos, &mut buf[..n], size);
        file.seek(SeekFrom::Start(pos)).at(path)?;
        file.write_all(&buf[..n]).at(path)?;
        pos += n as u64;
    }
    Ok(())
}

struct Writer {
    spec: Spec,
    cipher: Cipher,
    /// v8 key string, start of the per-file key strings.
    key_string: Vec<u8>,
    out: BufWriter<File>,
    path: PathBuf,
    /// Bytes written to the data area so far.
    data_size: u64,
    names: Vec<u8>,
    files: Vec<u8>,
    dirs: Vec<u8>,
    stats: PackStats,
}

impl Writer {
    /// The root directory: an unnamed entry whose children are the
    /// contents of `dir`.
    fn encode_root(&mut self, dir: &Path) -> Result<()> {
        let children = list_dir(dir)?;
        self.names.extend_from_slice(&[0; 4]);
        let mut root = Vec::new();
        let s = self.spec;
        s.put(&mut root, 0)?; // name
        s.put(&mut root, ATTR_DIRECTORY)?;
        root.extend_from_slice(&[0; 24]);
        s.put(&mut root, 0)?; // directory table offset
        s.put(&mut root, 0)?; // size
        s.put(&mut root, s.none())?; // press size
        if s.huffman {
            s.put(&mut root, 0)?;
        }
        self.files.extend_from_slice(&root);

        let block = self.files.len() as u64;
        let mut d = Vec::new();
        for v in [0, s.none(), children.len() as u64, block] {
            s.put(&mut d, v)?;
        }
        self.dirs.extend_from_slice(&d);
        self.files
            .resize(self.files.len() + children.len() * s.file_head_len(), 0);
        self.encode_children(&children, 0, block, &mut Vec::new())
    }

    /// `DirectoryEncode`: fill the entries of a directory whose entry block
    /// starts at `block` in the file table. `chain` holds the upper-case
    /// names of this directory and its parents, innermost first.
    fn encode_children(
        &mut self,
        children: &[Item],
        dir_off: u64,
        block: u64,
        chain: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        let s = self.spec;
        for (i, item) in children.iter().enumerate() {
            let slot = block as usize + i * s.file_head_len();
            let (entry, upper) = name_entry(&item.name)?;
            let name_addr = self.names.len() as u64;
            self.names.extend_from_slice(&entry);

            let mut head = Vec::with_capacity(s.file_head_len());
            s.put(&mut head, name_addr)?;
            if item.is_dir {
                let grandchildren = list_dir(&item.path)?;
                let sub_off = self.dirs.len() as u64;
                s.put(&mut head, ATTR_DIRECTORY)?;
                put_times(&mut head, &item.times);
                s.put(&mut head, sub_off)?;
                s.put(&mut head, 0)?;
                s.put(&mut head, s.none())?;
                if s.huffman {
                    s.put(&mut head, s.none())?;
                }
                self.files[slot..slot + head.len()].copy_from_slice(&head);

                let sub_block = self.files.len() as u64;
                let mut d = Vec::new();
                for v in [slot as u64, dir_off, grandchildren.len() as u64, sub_block] {
                    s.put(&mut d, v)?;
                }
                self.dirs.extend_from_slice(&d);
                self.files.resize(
                    self.files.len() + grandchildren.len() * s.file_head_len(),
                    0,
                );
                self.stats.dirs += 1;
                chain.insert(0, upper);
                self.encode_children(&grandchildren, sub_off, sub_block, chain)?;
                chain.remove(0);
            } else {
                let data = fs::read(&item.path).at(&item.path)?;
                if data.len() as u64 != item.size {
                    return Err(Error::Game(format!(
                        "{} changed while packing",
                        item.path.display()
                    )));
                }
                let key = self.cipher.uses_file_keys().then(|| {
                    let mut parts: Vec<&[u8]> = vec![&upper];
                    parts.extend(chain.iter().map(Vec::as_slice));
                    keys::v8_file_key(&self.key_string, &parts)
                });
                let (mut stored, press, huff) = if data.is_empty() {
                    (Vec::new(), None, None)
                } else {
                    encode_data(&s, &item.name, &data)
                };
                self.cipher
                    .apply(key.as_ref(), data.len() as u64, &mut stored);

                s.put(&mut head, ATTR_ARCHIVE)?;
                put_times(&mut head, &item.times);
                s.put(&mut head, self.data_size)?;
                s.put(&mut head, data.len() as u64)?;
                s.put(&mut head, press.unwrap_or(s.none()))?;
                if s.huffman {
                    s.put(&mut head, huff.unwrap_or(s.none()))?;
                }
                self.files[slot..slot + head.len()].copy_from_slice(&head);

                self.out.write_all(&stored).at(&self.path)?;
                self.data_size += stored.len() as u64;
                self.stats.files += 1;
                self.stats.bytes += data.len() as u64;
            }
        }
        Ok(())
    }
}

/// Last `n` characters of `name`, compared without case.
fn ends_with_ci(name: &str, ext: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(ext)
}

/// Encode one file's data: optional LZ, then Huffman in v8. Returns the
/// stored bytes (padded to 4 bytes), the LZ size and the Huffman size.
fn encode_data(spec: &Spec, name: &str, data: &[u8]) -> (Vec<u8>, Option<u64>, Option<u64>) {
    // Formats that are already compressed are stored as is, unless they
    // must always be compressed (v8). The original only looks at names
    // longer than 4 characters.
    let long_name = name.chars().count() > 4;
    let has = |exts: &[&str]| long_name && exts.iter().any(|e| ends_with_ci(name, e));
    let (skip, always) = if spec.format == DxaFormat::V8 {
        (
            has(&[
                "wav", "jpg", "png", "mpg", "mp3", "mp4", "ogg", "ogv", "ops", "wmv", "jpeg",
            ]),
            has(&["wav", "tga", "bmp"]),
        )
    } else {
        (
            has(&["wav", "jpg", "png", "mpg", "mp3", "ogg", "wmv", "jpeg"]),
            false,
        )
    };

    let mut press = None;
    let mut payload: Vec<u8> = Vec::new();
    if (always || (data.len() as u64) < PRESS_LIMIT) && (always || !skip) {
        let lz = lz::encode(data);
        if always || (lz.len() as f64 / data.len() as f64) <= PRESS_MIN_GAIN {
            press = Some(lz.len() as u64);
            payload = lz;
        }
    }
    let payload: &[u8] = if press.is_some() { &payload } else { data };

    let (mut stored, huff) = if spec.huffman {
        let kb = usize::from(HUFFMAN_KB) * 1024;
        if payload.len() <= kb * 2 {
            let h = huffman::encode(payload);
            let n = h.len() as u64;
            (h, Some(n))
        } else {
            let mut ends = payload[..kb].to_vec();
            ends.extend_from_slice(&payload[payload.len() - kb..]);
            let mut h = huffman::encode(&ends);
            let n = h.len() as u64;
            h.extend_from_slice(&payload[kb..payload.len() - kb]);
            (h, Some(n))
        }
    } else {
        (payload.to_vec(), None)
    };
    stored.resize(stored.len().div_ceil(4) * 4, 0);
    (stored, press, huff)
}

fn put_times(buf: &mut Vec<u8>, times: &[u64; 3]) {
    for t in times {
        buf.extend_from_slice(&t.to_le_bytes());
    }
}

/// A name table entry (`AddFileNameData`): number of 4-byte packs, 16-bit
/// sum of the upper-case bytes, the upper-case name, then the name, both
/// NUL padded to the packs. Also returns the upper-case bytes, used by the
/// v8 per-file keys.
fn name_entry(name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let (sjis, _, unmappable) = encoding_rs::SHIFT_JIS.encode(name);
    if unmappable || sjis.is_empty() || sjis.contains(&0) {
        return Err(Error::Unsupported(format!(
            "file name {name:?} cannot be stored in Shift-JIS"
        )));
    }
    let mut upper = Vec::with_capacity(sjis.len());
    let mut i = 0;
    while i < sjis.len() {
        let b = sjis[i];
        // Shift-JIS lead bytes start a two-byte character, copied as is.
        if matches!(b, 0x81..=0x9F | 0xE0..=0xFC) && i + 1 < sjis.len() {
            upper.extend_from_slice(&sjis[i..i + 2]);
            i += 2;
        } else {
            upper.push(b.to_ascii_uppercase());
            i += 1;
        }
    }
    let packs = (sjis.len() + 1).div_ceil(4);
    let parity = upper.iter().fold(0u32, |a, &b| a + u32::from(b)) as u16;
    let mut e = Vec::with_capacity(4 + packs * 8);
    e.extend_from_slice(&(packs as u16).to_le_bytes());
    e.extend_from_slice(&parity.to_le_bytes());
    for s in [&upper[..], &sjis[..]] {
        let start = e.len();
        e.extend_from_slice(s);
        e.resize(start + packs * 4, 0);
    }
    Ok((e, upper))
}

/// Windows FILETIME of `t` (100 ns ticks since 1601), 0 when unknown.
fn filetime(t: std::io::Result<SystemTime>) -> u64 {
    const EPOCH_DIFF_TICKS: u64 = 116_444_736_000_000_000;
    t.ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| EPOCH_DIFF_TICKS + d.as_secs() * 10_000_000 + u64::from(d.subsec_nanos()) / 100)
        .unwrap_or(0)
}

/// Entries of `dir`, sorted by upper-case name (close to NTFS order).
/// Symbolic links are followed; other special files are skipped.
fn list_dir(dir: &Path) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for e in fs::read_dir(dir).at(dir)? {
        let e = e.at(dir)?;
        let path = e.path();
        let md = fs::metadata(&path).at(&path)?;
        if !md.is_dir() && !md.is_file() {
            continue;
        }
        let name = e
            .file_name()
            .into_string()
            .map_err(|n| Error::Unsupported(format!("file name {n:?} is not UTF-8")))?;
        let modified = filetime(md.modified());
        let created = match filetime(md.created()) {
            0 => modified,
            t => t,
        };
        items.push(Item {
            name,
            is_dir: md.is_dir(),
            times: [created, filetime(md.accessed()), modified],
            size: md.len(),
            path,
        });
    }
    items.sort_by(|a, b| (a.name.to_uppercase(), &a.name).cmp(&(b.name.to_uppercase(), &b.name)));
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dxa::{Archive, OpenParams, extract_to};
    use crate::modes::default_modes;

    #[test]
    fn name_entries() {
        let (e, upper) = name_entry("Map01.mps").unwrap();
        assert_eq!(upper, b"MAP01.MPS");
        // 9 bytes + NUL -> 3 packs.
        assert_eq!(&e[..2], &3u16.to_le_bytes());
        let parity = b"MAP01.MPS".iter().map(|&b| u32::from(b)).sum::<u32>() as u16;
        assert_eq!(&e[2..4], &parity.to_le_bytes());
        assert_eq!(&e[4..16], b"MAP01.MPS\0\0\0");
        assert_eq!(&e[16..28], b"Map01.mps\0\0\0");

        // The trail byte 0x61 ('a') of a double-byte character stays as is.
        let (_, upper) = name_entry("ア").unwrap();
        assert_eq!(upper, [0x83, 0x41]);
        let (_, upper) = name_entry("ぁa").unwrap();
        assert_eq!(upper, [0x82, 0x9F, b'A']);
        assert!(name_entry("emoji😀").is_err());
    }

    /// A folder with nested folders, empty and large files, compressible
    /// and incompressible data, Japanese names and extensions that change
    /// the storage rules.
    fn sample_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let noise = |n: usize, seed: u32| -> Vec<u8> {
            let mut x = seed.wrapping_mul(2_654_435_761) | 1;
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect()
        };
        let text = |n: usize| -> Vec<u8> {
            b"Wolf RPG text line, "
                .iter()
                .copied()
                .cycle()
                .take(n)
                .collect()
        };
        let files: Vec<(PathBuf, Vec<u8>)> = vec![
            ("Game.dat".into(), text(500)),
            ("empty.txt".into(), Vec::new()),
            ("abc".into(), b"xyz".to_vec()),
            ("BasicData/CommonEvent.dat".into(), text(100_000)),
            ("BasicData/noise.bin".into(), noise(40_000, 1)),
            // Compresses to about half: LZ output above 24 KiB, so Huffman
            // covers only its ends.
            ("BasicData/half.bin".into(), noise(100_000, 4).repeat(2)),
            ("MapData/マップ01.mps".into(), text(30_000)),
            ("MapData/Sub/deep/x.png".into(), noise(30_000, 2)),
            ("MapData/Sub/img.bmp".into(), noise(1000, 3)),
            ("Sound/se.ogg".into(), text(20_000)),
            ("Empty".into(), Vec::new()),
        ];
        for (p, data) in &files {
            let full = root.join(p);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            if p == Path::new("Empty") {
                fs::create_dir_all(&full).unwrap();
            } else {
                fs::write(&full, data).unwrap();
            }
        }
        files
            .into_iter()
            .filter(|(p, _)| p != Path::new("Empty"))
            .collect()
    }

    #[test]
    fn every_default_mode_round_trips() {
        let base = std::env::temp_dir().join(format!("unwolf-pack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        let files = sample_tree(&src);
        fs::create_dir_all(src.join("Empty")).unwrap();

        for (i, mode) in default_modes().iter().enumerate() {
            let archive = base.join(format!("m{i}.wolf"));
            let stats = pack_directory(&src, &archive, mode).unwrap();
            assert_eq!(stats.files, files.len() as u64, "{}", mode.name);
            assert_eq!(stats.dirs, 6, "{}", mode.name);

            let a = Archive::open(
                &archive,
                &OpenParams {
                    format: mode.format,
                    key: &mode.key,
                },
            )
            .unwrap_or_else(|e| panic!("{}: {e}", mode.name));
            if mode.format == DxaFormat::V8 {
                assert_eq!(a.crypt_version, mode.crypt_version, "{}", mode.name);
            }
            let out = base.join(format!("out{i}"));
            fs::create_dir_all(&out).unwrap();
            extract_to(&a, &out).unwrap();
            for (p, data) in &files {
                let got =
                    fs::read(out.join(p)).unwrap_or_else(|e| panic!("{}: {p:?}: {e}", mode.name));
                assert!(got == *data, "{}: {p:?} differs", mode.name);
            }
            assert!(out.join("Empty").is_dir());

            // Another mode's key must not open the archive silently, except
            // where the header's crypt version alone selects the keys
            // (v3.50 salts with "958", ChaCha v1 has a built-in key).
            let other = &default_modes()[(i + 1) % default_modes().len()];
            let key_free = matches!(mode.crypt_version, 0x15E | 0x64);
            if other.format == mode.format && other.key != mode.key && !key_free {
                let wrong = Archive::open(
                    &archive,
                    &OpenParams {
                        format: other.format,
                        key: &other.key,
                    },
                )
                .and_then(|a| extract_to(&a, &base.join(format!("wrong{i}"))));
                assert!(wrong.is_err(), "{} opened with {}", mode.name, other.name);
            }
        }
        fs::remove_dir_all(&base).unwrap();
    }

    /// Files of 10 MiB and more are not LZ compressed; Huffman covers
    /// their first and last 12 KiB.
    #[test]
    fn large_file_round_trips() {
        let base = std::env::temp_dir().join(format!("unwolf-pack-large-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("src")).unwrap();
        let data: Vec<u8> = (0..(PRESS_LIMIT as usize + 4097))
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(base.join("src/big.dat"), &data).unwrap();
        let mode = default_modes()
            .into_iter()
            .find(|m| m.name == "Wolf RPG v3.31")
            .unwrap();
        let archive = base.join("a.wolf");
        pack_directory(&base.join("src"), &archive, &mode).unwrap();
        let a = Archive::open(
            &archive,
            &OpenParams {
                format: mode.format,
                key: &mode.key,
            },
        )
        .unwrap();
        let f = a.entries[0].data.as_ref().unwrap();
        assert_eq!(f.press_size, None);
        assert!(f.huff_size.is_some());
        assert!(a.read_file(f).unwrap() == data);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn small_new_crypt_archive_is_padded() {
        let base = std::env::temp_dir().join(format!("unwolf-pack-small-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("src")).unwrap();
        fs::write(base.join("src/a.txt"), b"tiny").unwrap();
        let mode = default_modes()
            .into_iter()
            .find(|m| m.name == "Wolf RPG v3.50")
            .unwrap();
        let archive = base.join("a.wolf");
        let stats = pack_directory(&base.join("src"), &archive, &mode).unwrap();
        assert_eq!(stats.archive_size, MIN_NEW_CRYPT_SIZE);
        let a = Archive::open(
            &archive,
            &OpenParams {
                format: mode.format,
                key: &mode.key,
            },
        )
        .unwrap();
        let f = a.entries[0].data.as_ref().unwrap();
        assert_eq!(a.read_file(f).unwrap(), b"tiny");
        fs::remove_dir_all(&base).unwrap();
    }

    /// Archives under 1088 bytes laid out like the original encoder writes
    /// them: plain header, no AES and no whole-file XOR, `KeyConv` XOR on
    /// the tables and data. An empty folder gives an empty folder.
    #[test]
    fn small_new_crypt_archive_without_layers_is_read() {
        let base = std::env::temp_dir().join(format!("unwolf-pack-plain-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let empty = base.join("empty");
        let tiny = base.join("tiny");
        fs::create_dir_all(&empty).unwrap();
        fs::create_dir_all(&tiny).unwrap();
        fs::write(tiny.join("a.txt"), b"tiny").unwrap();

        let new_crypt: Vec<_> = default_modes()
            .into_iter()
            .filter(|m| m.format == DxaFormat::V8 && is_new_crypt(m.crypt_version))
            .collect();
        assert!(!new_crypt.is_empty());
        for mode in &new_crypt {
            for (src, files) in [(&empty, 0usize), (&tiny, 1)] {
                let archive = base.join("a.wolf");
                let stats = write_archive(src, &archive, mode, SmallNewCrypt::Plain).unwrap();
                assert!(stats.archive_size < MIN_NEW_CRYPT_SIZE, "{}", mode.name);

                // Plain header: data at 64, names right after the data.
                let raw = fs::read(&archive).unwrap();
                let at = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                assert_eq!(at(8), V8_HEADER_LEN, "{}", mode.name);
                assert!(at(16) >= V8_HEADER_LEN && at(16) < raw.len() as u64);

                let a = Archive::open(
                    &archive,
                    &OpenParams {
                        format: mode.format,
                        key: &mode.key,
                    },
                )
                .unwrap_or_else(|e| panic!("{}: {e}", mode.name));
                assert_eq!(a.crypt_version, mode.crypt_version);
                let out = base.join("out");
                let _ = fs::remove_dir_all(&out);
                fs::create_dir_all(&out).unwrap();
                extract_to(&a, &out).unwrap();
                let names: Vec<_> = fs::read_dir(&out).unwrap().map(|e| e.unwrap()).collect();
                assert_eq!(names.len(), files, "{}", mode.name);
                if files == 1 {
                    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"tiny");
                }
            }
        }
        fs::remove_dir_all(&base).unwrap();
    }
}
