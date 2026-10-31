//! DXA v5 and v6 readers (Wolf RPG 2.0x to 2.2x).
//!
//! Unlike v8, the header itself is XORed with the 12-byte key, so the magic
//! check doubles as a key check.
//!
//! v5 header (28 bytes): `u16 magic, u16 version, u32 table size,
//! u32 data start, u32 name table, u32 file table, u32 directory table,
//! u32 code page`. v6 (48 bytes) widens every field after the table size to
//! u64.

use super::keys::{Cipher, legacy_key};
use super::source::Source;
use super::{Archive, DXA_MAGIC, DxaFormat, Layout, TableOffsets, walk};
use crate::error::{Error, Result};

pub fn parse(source: Source, format: DxaFormat, mode_key: &[u8]) -> Result<Archive> {
    let (header_len, word) = match format {
        DxaFormat::V5 => (28u64, 4u64),
        _ => (48, 8),
    };
    if source.len() < header_len {
        return Err(Error::NotDxArchive);
    }

    let mut key = legacy_key(Some(mode_key));
    let mut h = source.read(0, header_len)?;
    Cipher::Legacy(key).apply(None, 0, &mut h);
    if u16::from_le_bytes([h[0], h[1]]) != DXA_MAGIC {
        if format != DxaFormat::V5 {
            return Err(Error::NotDxArchive);
        }
        // The v5 reader retries with an all-0xFF key (a plain bit inversion).
        key = [0xFF; 12];
        h = source.read(0, header_len)?;
        Cipher::Legacy(key).apply(None, 0, &mut h);
        if u16::from_le_bytes([h[0], h[1]]) != DXA_MAGIC {
            return Err(Error::NotDxArchive);
        }
    }

    let version = u16::from_le_bytes([h[2], h[3]]);
    match format {
        DxaFormat::V5 if version > 5 => {
            return Err(Error::Unsupported(format!(
                "DXA version {version} with the v5 reader"
            )));
        }
        DxaFormat::V6 if version != 6 => {
            return Err(Error::Unsupported(format!(
                "DXA version {version} with the v6 reader"
            )));
        }
        _ => {}
    }

    let field = |i: u64| -> u64 {
        let off = (8 + i * word) as usize;
        let mut v = 0u64;
        for k in (0..word as usize).rev() {
            v = (v << 8) | u64::from(h[off + k]);
        }
        v
    };
    let head_size = u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]]));
    let tables = TableOffsets {
        data_start: field(0),
        names: field(1),
        files: field(2),
        dirs: field(3),
    };
    let code_page = field(4) as u32;
    if head_size == 0 || tables.files > tables.dirs || tables.dirs > head_size {
        return Err(Error::format("inconsistent table offsets"));
    }
    if tables.names < header_len || tables.names > source.len() {
        return Err(Error::format("name table offset out of range"));
    }

    // Before version 5 the XOR position is the file offset.
    let absolute = format == DxaFormat::V5 && version < 5;
    let cipher = Cipher::Legacy(key);
    let mut buf = source.read(tables.names, head_size)?;
    cipher.apply(None, if absolute { tables.names } else { 0 }, &mut buf);

    let layout = Layout {
        word,
        has_press: !(format == DxaFormat::V5 && version < 2),
        has_huff: false,
        tables,
        code_page,
        huffman_kb: 0,
        file_keys: None,
    };
    let entries = walk(&buf, &layout, source.len())?;

    Ok(Archive {
        format,
        crypt_version: 0,
        entries,
        source,
        cipher,
        huffman_kb: 0,
        absolute_positions: absolute,
    })
}
