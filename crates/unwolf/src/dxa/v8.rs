//! DXA v8 reader, with the Wolf RPG cipher layers.
//!
//! Header (64 bytes, plaintext except the Wolf-encrypted address fields):
//! `u16 magic, u16 version, u32 table size, u64 data start, u64 name table,
//! u64 file table, u64 directory table, u32 code page, u32 flags,
//! u8 Huffman KB, u8 reserve[15]`. The top 16 bits of `flags` carry the Wolf
//! RPG crypt version; `reserve` holds the Wolf password.

use super::keys::{self, Cipher, V8_KEY_STRING_MAX};
use super::source::{Source, WolfLayers};
use super::{Archive, DXA_MAGIC, DxaFormat, Layout, TableOffsets, cstr, huffman, lz, walk};
use crate::crypto::chacha20::ChaCha20;
use crate::crypto::wolf::{self, KeyKind, PWD_LEN};
use crate::error::{Error, Result};
use crate::rng::Xorshift32;

pub(super) const HEADER_LEN: u64 = 64;
/// `newCrypt` archives shorter than this have no whole-file layers: the
/// original encoder returns before the AES layer, the whole-file XOR and the
/// header address cipher (`DXArchive.cpp`, `EncodeArchive`). Their tables and
/// data still carry the `KeyConv` XOR. The original decoder returns success
/// on them without extracting anything; this reader reads them as written.
pub(super) const MIN_NEW_CRYPT_SIZE: u64 = HEADER_LEN + 0x400;
pub(super) const FLAG_NO_KEY: u32 = 0x1;
pub(super) const FLAG_NO_HEAD_PRESS: u32 = 0x2;

/// Compiled-in key and nonce of the "ChaCha2 v1" mode (crypt version 0x64).
pub(super) const CHACHA_V1_KEY: [u8; 32] = [
    0xC9, 0x82, 0xF8, 0xB4, 0x2C, 0x93, 0x9E, 0x83, 0x0E, 0xBC, 0xBC, 0x92, 0x68, 0x8D, 0x59, 0xA1,
    0x4A, 0x9E, 0x7F, 0xB0, 0xAC, 0xAF, 0x1D, 0x8F, 0x8E, 0xB8, 0x3B, 0x9E, 0xE8, 0x89, 0xD9, 0xAD,
];
pub(super) const CHACHA_V1_NONCE: [u8; 12] = [
    0xFF, 0xBC, 0x2D, 0xAB, 0x9D, 0x8B, 0x0F, 0xB4, 0xBB, 0x9A, 0x69, 0x85,
];

/// `newCrypt` in UberWolf: Wolf RPG 3.31 to 3.x and Pro 1010+.
pub fn is_new_crypt(cv: u16) -> bool {
    (331..1000).contains(&cv) || cv >= 1010
}

pub fn is_chacha(cv: u16) -> bool {
    cv == 0x64 || cv == 0xC8
}

/// The mode key up to its first NUL, capped like `KeyString` in the DX
/// Library.
pub(super) fn key_string(mode_key: &[u8]) -> &[u8] {
    let k = cstr(mode_key);
    &k[..k.len().min(V8_KEY_STRING_MAX)]
}

/// Pro games (1010+) keep extra key bytes after the key string's NUL.
pub(super) fn pro_key(cv: u16, mode_key: &[u8]) -> Option<&[u8]> {
    (cv >= 1010)
        .then(|| mode_key.get(key_string(mode_key).len() + 1..))
        .flatten()
}

/// The XOR applied to tables and file data (`KeyConv`), before
/// `DXA_FLAG_NO_KEY` is taken into account.
pub(super) fn data_cipher(cv: u16, mode_key: &[u8], pwd: &[u8; PWD_LEN]) -> Result<Cipher> {
    if is_new_crypt(cv) {
        let read_key = wolf::init_wolf_crypt(
            cv,
            pwd,
            KeyKind::Read {
                key2: pro_key(cv, mode_key),
            },
        )
        .map_err(|_| Error::format("empty Wolf key string"))?;
        Ok(Cipher::Wolf(read_key))
    } else if is_chacha(cv) {
        let c = if cv == 0x64 {
            ChaCha20::new(&CHACHA_V1_KEY, &CHACHA_V1_NONCE)
        } else {
            let (Some(k), Some(n)) = (mode_key.get(..32), mode_key.get(34..46)) else {
                return Err(Error::format("ChaCha20 mode key is too short"));
            };
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 12];
            key.copy_from_slice(k);
            nonce.copy_from_slice(n);
            ChaCha20::new(&key, &nonce)
        };
        Ok(Cipher::ChaCha(c))
    } else {
        Ok(Cipher::PerFile(keys::v8_key(key_string(mode_key))))
    }
}

struct Header {
    head_size: u64,
    data_start: u64,
    names: u64,
    files: u64,
    dirs: u64,
    code_page: u32,
    flags: u32,
    huffman_kb: u8,
}

fn le(b: &[u8], off: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in (0..n).rev() {
        v = (v << 8) | u64::from(b[off + i]);
    }
    v
}

pub fn parse(mut source: Source, mode_key: &[u8]) -> Result<Archive> {
    if source.len() < HEADER_LEN {
        return Err(Error::NotDxArchive);
    }
    let mut h = [0u8; 64];
    h.copy_from_slice(&source.raw()[..64]);
    if le(&h, 0, 2) as u16 != DXA_MAGIC {
        return Err(Error::NotDxArchive);
    }
    if le(&h, 2, 2) != 8 {
        return Err(Error::Unsupported(format!(
            "DXA version {} with the v8 reader",
            le(&h, 2, 2)
        )));
    }
    let flags = le(&h, 44, 4) as u32;
    let cv = (flags >> 16) as u16;

    let key_cstr = cstr(mode_key);
    let key_string = key_string(mode_key);

    let mut pwd = [0u8; PWD_LEN];
    pwd.copy_from_slice(&h[49..64]);

    let mut cipher = data_cipher(cv, mode_key, &pwd)?;
    if is_new_crypt(cv) && source.len() >= MIN_NEW_CRYPT_SIZE {
        wolf::crypt_addresses(&mut h, &pwd, cv);
        let names = le(&h, 16, 8);
        let layers = wolf_layers(
            source.len(),
            &pwd,
            cv,
            key_cstr,
            pro_key(cv, mode_key),
            names,
        )?;
        source.set_layers(layers);
    }
    if flags & FLAG_NO_KEY != 0 {
        cipher = Cipher::None;
    }

    let hd = Header {
        head_size: le(&h, 4, 4),
        data_start: le(&h, 8, 8),
        names: le(&h, 16, 8),
        files: le(&h, 24, 8),
        dirs: le(&h, 32, 8),
        code_page: le(&h, 40, 4) as u32,
        flags,
        huffman_kb: h[48],
    };
    let tables = read_tables(&source, &cipher, &hd)?;
    let layout = Layout {
        word: 8,
        has_press: true,
        has_huff: true,
        tables: TableOffsets {
            names: hd.names,
            files: hd.files,
            dirs: hd.dirs,
            data_start: hd.data_start,
        },
        code_page: hd.code_page,
        huffman_kb: hd.huffman_kb,
        file_keys: cipher.uses_file_keys().then_some(key_string),
    };
    let entries = walk(&tables, &layout, source.len())?;

    Ok(Archive {
        format: DxaFormat::V8,
        crypt_version: cv,
        entries,
        source,
        cipher,
        huffman_kb: hd.huffman_kb,
        absolute_positions: false,
    })
}

/// The whole-file layers of a `newCrypt` archive of `size` bytes.
pub(super) fn wolf_layers(
    size: u64,
    pwd: &[u8; PWD_LEN],
    cv: u16,
    key_string: &[u8],
    pro_key: Option<&[u8]>,
    tables_start: u64,
) -> Result<WolfLayers> {
    if size < MIN_NEW_CRYPT_SIZE {
        // Callers skip the layers below this size; see `MIN_NEW_CRYPT_SIZE`.
        return Err(Error::format(
            "no whole-file layers on a Wolf-encrypted archive smaller than 1088 bytes",
        ));
    }
    if tables_start < HEADER_LEN || tables_start > size {
        return Err(Error::format("name table offset out of range"));
    }
    let whole = wolf::init_wolf_crypt(cv, pwd, KeyKind::Whole { key_string })
        .map_err(|_| Error::format("empty Wolf key string"))?;
    let aes = wolf::init_aes128(pwd, pro_key, cv);

    let mut body = 0x400u64;
    if wolf::is_v35(cv) {
        let p = |i: usize| u32::from(pwd[i]);
        let mut seed = if cv >= 1020 {
            let k = pro_key.unwrap_or(&[]);
            let k0 = u32::from(k.first().copied().unwrap_or(0));
            let k1 = u32::from(k.get(1).copied().unwrap_or(0));
            k0 * k1 + p(2) * p(4) + p(11)
        } else {
            p(2) * p(4) + p(12)
        };
        if seed == 0 {
            seed = 1;
        }
        let mut x = Xorshift32::new(seed);
        x.next_u32();
        if size >= u64::from(x.next_u32() % 500 + 800) {
            x.next_u32();
        }
        body = size - HEADER_LEN;
        if body >= u64::from(x.next_u32() % 500 + 800) {
            body = u64::from(x.next_u32() % 500 + 800);
        }
    }

    Ok(WolfLayers {
        whole,
        whole_end: size.saturating_sub(HEADER_LEN),
        aes,
        body_end: HEADER_LEN + body,
        tables_start,
    })
}

fn read_tables(source: &Source, cipher: &Cipher, h: &Header) -> Result<Vec<u8>> {
    if h.names < HEADER_LEN || h.names > source.len() {
        return Err(Error::format("name table offset out of range"));
    }
    if h.head_size == 0 || h.files > h.dirs || h.dirs > h.head_size {
        return Err(Error::format("inconsistent table offsets"));
    }
    if h.flags & FLAG_NO_HEAD_PRESS != 0 {
        // UberWolf reads these from offset 64 without seeking; the DX
        // Library reader and encoder put them at the name table offset.
        let mut t = source.read(h.names, h.head_size)?;
        cipher.apply(None, 0, &mut t);
        return Ok(t);
    }
    let mut packed = source.read(h.names, source.len() - h.names)?;
    cipher.apply(None, 0, &mut packed);
    let lz_len = huffman::decoded_len(&packed)?;
    let lz_data = huffman::decode(&packed, lz_len)?;
    if (lz::decoded_len(&lz_data)? as u64) != h.head_size {
        return Err(Error::format("table size does not match the header"));
    }
    lz::decode(&lz_data, h.head_size)
}
