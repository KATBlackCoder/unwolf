//! DX Library archives (DXA v5, v6 and v8) as used by Wolf RPG Editor.
//!
//! Layout common to all versions:
//! `header | file data | name table | file entries | directory entries`.
//! The three tables are read as one block. Offsets in the file and
//! directory tables are relative to the start of that block.

mod extract;
pub mod huffman;
pub mod keys;
mod legacy;
pub mod lz;
mod source;
mod v8;
mod write;

use std::path::{Path, PathBuf};

pub use extract::{ExtractStats, extract_to};
pub use keys::Cipher;
pub use source::Source;
pub use write::{PackStats, pack_directory};

use crate::error::{Error, Result};

/// Magic `"DX"` read as a little-endian u16.
pub const DXA_MAGIC: u16 = 0x5844;
const ATTR_DIRECTORY: u64 = 0x10;
const NONE64: u64 = u64::MAX;

/// Which DX Library reader a mode uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DxaFormat {
    V5,
    V6,
    V8,
}

/// Where a file's bytes live and how they are stored.
#[derive(Debug, Clone)]
pub struct FileData {
    /// Absolute offset in the archive.
    pub offset: u64,
    pub size: u64,
    pub press_size: Option<u64>,
    pub huff_size: Option<u64>,
    /// DXA v8 per-file key.
    pub key: Option<[u8; 7]>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Path relative to the extraction root.
    pub path: PathBuf,
    /// Lower-case file name, used by the anti-extraction check.
    pub name_lower: String,
    /// FILETIME values: creation, last access, last write.
    pub times: [u64; 3],
    /// `None` for a directory.
    pub data: Option<FileData>,
}

/// A parsed archive whose files can be read.
pub struct Archive {
    pub format: DxaFormat,
    /// Wolf RPG crypt version (`Flags >> 16`, v8 only).
    pub crypt_version: u16,
    pub entries: Vec<Entry>,
    source: Source,
    cipher: Cipher,
    huffman_kb: u8,
    /// v5 archives older than version 5 key the XOR by file offset.
    absolute_positions: bool,
}

/// What the archive is opened with: the DX reader and the mode key bytes.
pub struct OpenParams<'a> {
    pub format: DxaFormat,
    /// Raw key bytes of the mode, as stored in UberWolf (may contain NULs).
    pub key: &'a [u8],
}

impl Archive {
    pub fn open(path: &Path, params: &OpenParams<'_>) -> Result<Self> {
        let source = Source::open(path)?;
        Self::from_source(source, params)
    }

    pub fn from_source(source: Source, params: &OpenParams<'_>) -> Result<Self> {
        match params.format {
            DxaFormat::V8 => v8::parse(source, params.key),
            DxaFormat::V5 | DxaFormat::V6 => legacy::parse(source, params.format, params.key),
        }
    }

    /// Decode one file.
    pub fn read_file(&self, f: &FileData) -> Result<Vec<u8>> {
        if f.size == 0 {
            return Ok(Vec::new());
        }
        let key = f.key.as_ref();
        let pos = |logical: u64, absolute: u64| {
            if self.absolute_positions {
                absolute
            } else {
                logical
            }
        };
        let read = |off: u64, len: u64, logical: u64| -> Result<Vec<u8>> {
            let mut b = self.source.read(off, len)?;
            self.cipher.apply(key, pos(logical, off), &mut b);
            Ok(b)
        };
        let kb = u64::from(self.huffman_kb) * 1024;
        let partial = |len: u64| self.huffman_kb != 0xFF && len > kb * 2;

        // Huffman pass (v8 only), possibly over the first and last `kb` only.
        let huff_stage = |target: u64| -> Result<Vec<u8>> {
            let Some(h) = f.huff_size else {
                return read(f.offset, target, f.size);
            };
            let blob = read(f.offset, h, f.size)?;
            if partial(target) {
                let ends = huffman::decode(&blob, kb * 2)?;
                let middle = read(f.offset + h, target - kb * 2, f.size + h)?;
                let mut out = Vec::with_capacity(target as usize);
                out.extend_from_slice(&ends[..kb as usize]);
                out.extend_from_slice(&middle);
                out.extend_from_slice(&ends[kb as usize..]);
                Ok(out)
            } else {
                huffman::decode(&blob, target)
            }
        };

        match f.press_size {
            Some(p) => {
                let packed = huff_stage(p)?;
                lz::decode(&packed, f.size)
            }
            None => huff_stage(f.size),
        }
    }
}

/// Stored length of a file in the data area, for bounds checks.
fn stored_len(f: &FileData, huffman_kb: u8) -> Option<u64> {
    let kb = u64::from(huffman_kb) * 1024;
    let target = f.press_size.unwrap_or(f.size);
    match f.huff_size {
        None => Some(target),
        Some(h) => {
            if huffman_kb != 0xFF && target > kb * 2 {
                h.checked_add(target - kb * 2)
            } else {
                Some(h)
            }
        }
    }
}

/// Little-endian reader over the decoded header tables.
struct Tables<'a> {
    buf: &'a [u8],
}

impl<'a> Tables<'a> {
    fn u16(&self, off: u64) -> Result<u16> {
        let b = self.bytes(off, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, off: u64) -> Result<u32> {
        let b = self.bytes(off, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&self, off: u64) -> Result<u64> {
        let b = self.bytes(off, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn bytes(&self, off: u64, len: u64) -> Result<&'a [u8]> {
        let end = off
            .checked_add(len)
            .filter(|&e| e <= self.buf.len() as u64)
            .ok_or_else(|| Error::format("table offset out of range"))?;
        Ok(&self.buf[off as usize..end as usize])
    }

    /// Name entry at `off` in the name table: `(upper-case bytes, original bytes)`,
    /// both without their NUL terminator.
    fn name(&self, off: u64) -> Result<(&'a [u8], &'a [u8])> {
        let packs = u64::from(self.u16(off)?);
        let upper = self.bytes(off + 4, packs * 4)?;
        let orig = self.bytes(off + 4 + packs * 4, packs * 4)?;
        Ok((cstr(upper), cstr(orig)))
    }
}

/// Table start offsets, as stored in the header.
struct TableOffsets {
    /// Absolute offset of the name table (start of the table block).
    names: u64,
    /// File table, relative to the table block.
    files: u64,
    /// Directory table, relative to the table block.
    dirs: u64,
    /// Absolute offset of the data area.
    data_start: u64,
}

/// Field widths of one DXA version.
struct Layout<'a> {
    /// Width of address and size fields: 4 (v5) or 8 (v6, v8).
    word: u64,
    has_press: bool,
    has_huff: bool,
    tables: TableOffsets,
    code_page: u32,
    huffman_kb: u8,
    /// v8 key string when data uses per-file keys.
    file_keys: Option<&'a [u8]>,
}

impl Layout<'_> {
    fn file_entry_len(&self) -> u64 {
        // name, attributes, 3 x u64 times, data address, size, [press], [huff]
        self.word * (4 + u64::from(self.has_press) + u64::from(self.has_huff)) + 24
    }

    fn none(&self) -> u64 {
        if self.word == 4 {
            u64::from(u32::MAX)
        } else {
            NONE64
        }
    }
}

const MAX_DEPTH: usize = 256;

/// Walk the directory tree from the root directory entry.
fn walk(buf: &[u8], layout: &Layout<'_>, archive_len: u64) -> Result<Vec<Entry>> {
    let mut w = Walker {
        t: Tables { buf },
        l: layout,
        archive_len,
        entries: Vec::new(),
        visited: std::collections::HashSet::new(),
    };
    let root_parent = w.word(layout.tables.dirs + layout.word)?;
    if root_parent != layout.none() {
        return Err(Error::format("root directory has a parent"));
    }
    w.dir(0, Path::new(""), &mut Vec::new(), 0)?;
    Ok(w.entries)
}

struct Walker<'a> {
    t: Tables<'a>,
    l: &'a Layout<'a>,
    archive_len: u64,
    entries: Vec<Entry>,
    visited: std::collections::HashSet<u64>,
}

impl Walker<'_> {
    fn word(&self, off: u64) -> Result<u64> {
        if self.l.word == 4 {
            Ok(u64::from(self.t.u32(off)?))
        } else {
            self.t.u64(off)
        }
    }

    fn opt(&self, off: u64) -> Result<Option<u64>> {
        let v = self.word(off)?;
        Ok((v != self.l.none()).then_some(v))
    }

    /// `dir_off` is relative to the directory table; `chain` holds the
    /// upper-case names of the enclosing directories, innermost first.
    fn dir(
        &mut self,
        dir_off: u64,
        path: &Path,
        chain: &mut Vec<Vec<u8>>,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH || !self.visited.insert(dir_off) {
            return Err(Error::format("directory tree loops"));
        }
        let (w, tab) = (self.l.word, &self.l.tables);
        let base = tab
            .dirs
            .checked_add(dir_off)
            .ok_or_else(|| Error::format("bad directory"))?;
        let count = self.word(base + 2 * w)?;
        let first = self.word(base + 3 * w)?;
        let entry_len = self.l.file_entry_len();
        count
            .checked_mul(entry_len)
            .and_then(|s| s.checked_add(first))
            .and_then(|s| s.checked_add(tab.files))
            .filter(|&e| e <= tab.dirs)
            .ok_or_else(|| Error::format("file entries out of range"))?;

        for i in 0..count {
            let fe = tab.files + first + i * entry_len;
            let name_addr = self.word(fe)?;
            if name_addr >= tab.files {
                return Err(Error::format("name offset out of range"));
            }
            let attrs = self.word(fe + w)?;
            let t0 = fe + 2 * w;
            let times = [self.t.u64(t0)?, self.t.u64(t0 + 8)?, self.t.u64(t0 + 16)?];
            let data_addr = self.word(t0 + 24)?;
            let size = self.word(t0 + 24 + w)?;
            let mut next = t0 + 24 + 2 * w;
            let press_size = if self.l.has_press {
                let v = self.opt(next)?;
                next += w;
                v
            } else {
                None
            };
            let huff_size = if self.l.has_huff {
                self.opt(next)?
            } else {
                None
            };

            let (upper, orig) = self.t.name(name_addr)?;
            let name = decode_name(orig, self.l.code_page)?;
            let child = path.join(&name);
            let name_lower = name.to_lowercase();

            if attrs & ATTR_DIRECTORY != 0 {
                self.entries.push(Entry {
                    path: child.clone(),
                    name_lower,
                    times,
                    data: None,
                });
                chain.insert(0, upper.to_vec());
                self.dir(data_addr, &child, chain, depth + 1)?;
                chain.remove(0);
                continue;
            }

            let key = self.l.file_keys.map(|ks| {
                let mut parts: Vec<&[u8]> = vec![upper];
                parts.extend(chain.iter().map(Vec::as_slice));
                keys::v8_file_key(ks, &parts)
            });
            let data = FileData {
                offset: tab.data_start.saturating_add(data_addr),
                size,
                press_size,
                huff_size,
                key,
            };
            let end = stored_len(&data, self.l.huffman_kb)
                .and_then(|l| data.offset.checked_add(l))
                .ok_or_else(|| Error::format("file size overflow"))?;
            if size > 0 && (end > tab.names || end > self.archive_len) {
                return Err(Error::format("file data out of range"));
            }
            self.entries.push(Entry {
                path: child,
                name_lower,
                times,
                data: Some(data),
            });
        }
        Ok(())
    }
}

fn cstr(b: &[u8]) -> &[u8] {
    b.iter().position(|&c| c == 0).map_or(b, |n| &b[..n])
}

/// Decode an archive file name and check it is a single safe component.
fn decode_name(raw: &[u8], code_page: u32) -> Result<String> {
    let name = if code_page == 65001 {
        String::from_utf8_lossy(raw).into_owned()
    } else {
        let (s, _, had_errors) = encoding_rs::SHIFT_JIS.decode(raw);
        if had_errors {
            log::warn!("file name is not valid Shift-JIS: {raw:02X?}");
        }
        s.into_owned()
    };
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return Err(Error::UnsafePath(name));
    }
    Ok(name)
}
