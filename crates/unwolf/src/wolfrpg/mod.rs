//! The subset of the Wolf RPG data formats needed by `-u` and `-x`
//! (`WolfRPG/` in UberWolfLib).
//!
//! The original parses every file into objects and writes them back,
//! re-encoding every string. Here parsing records the position of each
//! field instead: files are rewritten by splicing only the fields that
//! change, everything else is copied byte for byte.

pub mod command;
pub mod common_event;
pub mod database;
pub mod map;
mod reader;

pub use reader::{Reader, StringField};

use std::ops::Range;

use crate::crypto::datadecrypt::{self, SeedIndices};
use crate::error::{Error, Result};

/// Header of the plain data files: an indicator byte (0 when the file is
/// not encrypted) followed by a 9-byte magic number.
pub const HEADER_LEN: usize = 10;

/// Magic numbers (`MagicNumber`), without the leading indicator byte. The
/// byte at [`UTF8_FLAG_INDEX`] is 0x55 in UTF-8 games, 0x00 otherwise.
pub const COMMON_EVENT_MAGIC: [u8; 9] = [0x57, 0x00, 0x00, 0x4F, 0x4C, 0x00, 0x46, 0x43, 0x00];
pub const DATABASE_MAGIC: [u8; 9] = [0x57, 0x00, 0x00, 0x4F, 0x4C, 0x00, 0x46, 0x4D, 0x00];
pub const UTF8_FLAG_INDEX: usize = 5;

/// Check `magic` (9 bytes) and return whether the file is UTF-8.
pub fn check_magic(found: &[u8], magic: &[u8; 9]) -> Result<bool> {
    let ok = found.len() >= magic.len()
        && found
            .iter()
            .zip(magic)
            .enumerate()
            .all(|(i, (f, m))| f == m || (i == UTF8_FLAG_INDEX && *f == 0x55));
    if !ok {
        return Err(Error::format("WolfRPG: invalid magic number"));
    }
    Ok(found[UTF8_FLAG_INDEX] == 0x55)
}

/// Decode a stored string. UTF-8 strings drop one trailing NUL; Shift-JIS
/// strings stop at the first NUL, like `MultiByteToWideChar(932, ..., -1)`.
pub fn decode_string(raw: &[u8], utf8: bool) -> String {
    if utf8 {
        let s = raw.strip_suffix(&[0]).unwrap_or(raw);
        String::from_utf8_lossy(s).into_owned()
    } else {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        encoding_rs::SHIFT_JIS
            .decode_without_bom_handling(&raw[..end])
            .0
            .into_owned()
    }
}

/// `FixPro35Description`: drop control characters other than CR and LF.
/// Returns the new stored bytes (NUL terminated).
pub fn strip_control_chars(raw: &[u8], utf8: bool) -> Vec<u8> {
    let content = if utf8 {
        raw.strip_suffix(&[0]).unwrap_or(raw)
    } else {
        &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())]
    };
    // Bytes below 0x20 are ASCII in both UTF-8 and Shift-JIS (trail bytes
    // start at 0x40).
    let mut out: Vec<u8> = content
        .iter()
        .copied()
        .filter(|&b| b >= 0x20 || b == b'\n' || b == b'\r')
        .collect();
    out.push(0);
    out
}

/// Copy `data`, replacing each string field (length prefix included) by the
/// output of `f`. Fields must be sorted and must not overlap.
pub fn splice_strings(
    data: &[u8],
    fields: &[StringField],
    mut f: impl FnMut(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    for field in fields {
        let Range { start, end } = field.span();
        out.extend_from_slice(&data[pos..start]);
        let new = f(&data[field.content.clone()]);
        out.extend_from_slice(&(new.len() as u32).to_le_bytes());
        out.extend_from_slice(&new);
        pos = end;
    }
    out.extend_from_slice(&data[pos..]);
    out
}

/// Header of Pro v3.3 files, skipped after decryption (`decryptV3_3`).
pub const PRO_V33_HEADER_SIZE: usize = 143;

/// `FileCoder::decryptV2_0`: the 10-byte header stays clear and gives the
/// seeds; the rest is decrypted. Returns the decrypted rest.
pub fn decrypt_v2_0_body(file: &[u8], seed_idx: SeedIndices) -> Result<Vec<u8>> {
    if file.len() < HEADER_LEN {
        return Err(Error::format("WolfRPG: encrypted file too short"));
    }
    let mut data = file[HEADER_LEN..].to_vec();
    datadecrypt::xor_v2_0(&mut data, seed_idx.map(|i| file[i]));
    Ok(data)
}

/// `FileCoder::decryptV3_1` (Pro 3.1) for files other than `Game.dat` and
/// databases. Returns the data and the offset of the content after the
/// embedded key.
///
/// Mirrors the original: with an indicator byte of 0 nothing is decrypted
/// and offsets count from byte 1 of the file; otherwise from byte 10 of the
/// decrypted file.
pub fn decrypt_v3_1(file: &[u8], seed_idx: SeedIndices) -> Result<(Vec<u8>, usize)> {
    let (data, start) = match file.first() {
        Some(0) => (file.to_vec(), 1),
        Some(_) => (decrypt_v2_0_body(file, seed_idx)?, 0),
        None => return Err(Error::format("WolfRPG: empty file")),
    };
    let mut r = Reader::at(&data, start);
    r.skip(5)?;
    let key_size = r.u32()? as usize;
    // One byte of project key, then the rest of the key.
    let pos = r.pos() + key_size;
    if pos > data.len() {
        return Err(Error::format("WolfRPG: Pro v3.1 key past the end"));
    }
    Ok((data, pos))
}

/// Largest LZ4 expansion ratio, used to bound the declared size before
/// allocating.
const LZ4_MAX_RATIO: u64 = 255;

/// `FileCoder::Unpack`: `[decoded size][encoded size][LZ4 block]` at the
/// start of `src`. Returns the decoded data and the bytes consumed.
pub fn lz4_unpack(src: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut r = Reader::new(src);
    let dec_size = r.u32()? as usize;
    let enc_size = r.u32()? as usize;
    let block = r.bytes(enc_size)?;
    if dec_size as u64 > (enc_size as u64 + 16) * LZ4_MAX_RATIO {
        return Err(Error::format("WolfRPG: implausible LZ4 size"));
    }
    let out = lz4_flex::block::decompress(block, dec_size)
        .map_err(|e| Error::format(format!("WolfRPG: LZ4: {e}")))?;
    if out.len() != dec_size {
        return Err(Error::format("WolfRPG: LZ4 size mismatch"));
    }
    Ok((out, r.pos()))
}

/// `FileCoder::Pack`.
pub fn lz4_pack(data: &[u8]) -> Vec<u8> {
    let block = lz4_flex::block::compress(data);
    let mut out = Vec::with_capacity(block.len() + 8);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(block.len() as u32).to_le_bytes());
    out.extend_from_slice(&block);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_accepts_utf8_flag_only() {
        assert!(!check_magic(&COMMON_EVENT_MAGIC, &COMMON_EVENT_MAGIC).unwrap());
        let mut m = COMMON_EVENT_MAGIC;
        m[UTF8_FLAG_INDEX] = 0x55;
        assert!(check_magic(&m, &COMMON_EVENT_MAGIC).unwrap());
        m[0] = 0;
        assert!(check_magic(&m, &COMMON_EVENT_MAGIC).is_err());
        assert!(check_magic(&DATABASE_MAGIC, &COMMON_EVENT_MAGIC).is_err());
    }

    #[test]
    fn strings() {
        assert_eq!(decode_string(b"abc\0", true), "abc");
        assert_eq!(decode_string(b"a\0b\0", false), "a");
        assert_eq!(decode_string(&[0x82, 0xA0, 0], false), "あ");
        assert_eq!(strip_control_chars(b"a\x01\nb\r\x1f\0", true), b"a\nb\r\0");
        assert_eq!(strip_control_chars(b"x", true), b"x\0");
    }

    #[test]
    fn lz4_round_trip() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 97) as u8).collect();
        let packed = lz4_pack(&data);
        let (out, used) = lz4_unpack(&packed).unwrap();
        assert_eq!(out, data);
        assert_eq!(used, packed.len());
        let mut bad = packed.clone();
        bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(lz4_unpack(&bad).is_err());
    }

    #[test]
    fn splice_replaces_only_listed_fields() {
        let mut data = vec![9u8];
        for s in [&b"one\0"[..], b"two\0", b"three\0"] {
            data.extend_from_slice(&(s.len() as u32).to_le_bytes());
            data.extend_from_slice(s);
        }
        data.push(7);
        let mut r = Reader::new(&data);
        r.u8().unwrap();
        let a = r.string().unwrap();
        let _ = r.string().unwrap();
        let c = r.string().unwrap();
        let out = splice_strings(&data, &[a, c], |s| [s, b"!"].concat());
        let mut r = Reader::new(&out);
        r.u8().unwrap();
        let got: Vec<_> = (0..3).map(|_| r.string().unwrap().content).collect();
        assert_eq!(&out[got[0].clone()], b"one\0!");
        assert_eq!(&out[got[1].clone()], b"two\0");
        assert_eq!(&out[got[2].clone()], b"three\0!");
        assert_eq!(r.u8().unwrap(), 7);
        assert!(r.is_eof());
    }
}
