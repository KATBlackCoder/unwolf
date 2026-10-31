//! DXA key derivation and the XOR applied by every version.

use crate::crypto::chacha20::ChaCha20;
use crate::crypto::wolf::WolfKey;

/// Key string used when the archive key is shorter than 4 bytes.
const DEFAULT_KEY_STRING: &[u8] = b"DXBDXARC";
/// DXA v8 keeps at most 63 bytes of the key string.
pub const V8_KEY_STRING_MAX: usize = 63;
/// The per-file key string buffer is 2048 bytes, minus 8 reserved bytes.
const V8_FILE_KEY_STRING_MAX: usize = 2048 - 8;

pub fn crc32(data: impl Iterator<Item = u8>) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// DXA v8 key: CRC32 of the even-index bytes, then of the odd-index bytes.
pub fn v8_key(source: &[u8]) -> [u8; 7] {
    let mut src = source.to_vec();
    if src.len() < 4 {
        src.extend_from_slice(DEFAULT_KEY_STRING);
    }
    let c0 = crc32(src.iter().step_by(2).copied()).to_le_bytes();
    let c1 = crc32(src.iter().skip(1).step_by(2).copied()).to_le_bytes();
    [c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2]]
}

/// DXA v8 per-file key string: archive key string, then the upper-case name
/// of the file, then the upper-case names of its parent directories up to,
/// but excluding, the root.
pub fn v8_file_key(key_string: &[u8], upper_names: &[&[u8]]) -> [u8; 7] {
    let mut s = key_string.to_vec();
    for n in upper_names {
        s.extend_from_slice(n);
    }
    s.truncate(V8_FILE_KEY_STRING_MAX);
    v8_key(&s)
}

/// DXA v5/v6 key: the key string repeated to 12 bytes, then scrambled.
/// `None` stands for a NULL key string.
pub fn legacy_key(source: Option<&[u8]>) -> [u8; 12] {
    let mut k = [0xAAu8; 12];
    if let Some(s) = source.filter(|s| !s.is_empty()) {
        for (i, v) in k.iter_mut().enumerate() {
            *v = s[i % s.len()];
        }
    }
    k[0] = !k[0];
    k[1] = k[1].rotate_left(4);
    k[2] ^= 0x8A;
    k[3] = !k[3].rotate_left(4);
    k[4] = !k[4];
    k[5] ^= 0xAC;
    k[6] = !k[6];
    k[7] = !k[7].rotate_right(3);
    k[8] = k[8].rotate_right(5);
    k[9] ^= 0x7F;
    k[10] = k[10].rotate_left(4) ^ 0xD6;
    k[11] ^= 0xCC;
    k
}

/// The XOR layer applied when reading header tables and file data
/// (`KeyConv`). Positions are logical DXA positions, not file offsets.
#[derive(Clone)]
pub enum Cipher {
    /// `DXA_FLAG_NO_KEY`.
    None,
    /// v5/v6 12-byte key.
    Legacy([u8; 12]),
    /// v8: archive key for the tables, per-file keys for data.
    PerFile([u8; 7]),
    /// Wolf RPG 3.31+ (`newCrypt`): one table for everything.
    Wolf(WolfKey),
    /// Wolf RPG ChaCha20 modes.
    ChaCha(ChaCha20),
}

impl Cipher {
    /// `file_key` is the per-file key; `None` selects the archive key.
    pub fn apply(&self, file_key: Option<&[u8; 7]>, position: u64, data: &mut [u8]) {
        match self {
            Cipher::None => {}
            Cipher::Legacy(k) => xor_cycle(k, position, data),
            Cipher::PerFile(k) => xor_cycle(file_key.unwrap_or(k), position, data),
            Cipher::Wolf(k) => k.xor_at(position, data),
            Cipher::ChaCha(c) => c.xor_at(position, data),
        }
    }

    pub fn uses_file_keys(&self) -> bool {
        matches!(self, Cipher::PerFile(_))
    }
}

fn xor_cycle(key: &[u8], position: u64, data: &mut [u8]) {
    let n = key.len() as u64;
    let mut j = (position % n) as usize;
    for d in data.iter_mut() {
        *d ^= key[j];
        j += 1;
        if j == key.len() {
            j = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789".iter().copied()), 0xCBF4_3926);
    }

    #[test]
    fn legacy_key_of_wolf_220() {
        let k = legacy_key(Some(&[
            0x38, 0x50, 0x40, 0x28, 0x72, 0x4f, 0x21, 0x70, 0x3b, 0x73, 0x35, 0x38,
        ]));
        // Verified against the encrypted header of a Wolf 2.2x archive.
        assert_eq!(&k[..4], &[0xC7, 0x05, 0xCA, 0x7D]);
    }
}
