//! The Wolf RPG archive cipher layers (`WolfCrypt.hpp` and `initAES128`).

use super::aes::{Aes128, AesCtr, KeySchedule};
use crate::rng::MsvcRand;

/// Size of the password stored in the DXA v8 header `Reserve` field.
pub const PWD_LEN: usize = 15;

/// Wolf RPG 3.5 and later variants of the cipher (`isV35`).
pub fn is_v35(crypt_version: u16) -> bool {
    (0x15E..0x3E8).contains(&crypt_version) || crypt_version >= 0x3FC
}

/// The 768-byte XOR table produced by `initWolfCrypt`.
#[derive(Clone)]
pub struct WolfKey {
    table: Box<[u8; 768]>,
    v35: bool,
}

impl WolfKey {
    /// XOR `data`, located at absolute position `position` (`wolfCrypt`).
    ///
    /// Every byte depends only on its own position, so any range can be
    /// processed independently.
    pub fn xor_at(&self, position: u64, data: &mut [u8]) {
        let t = &self.table;
        if self.v35 {
            for (i, d) in data.iter_mut().enumerate() {
                let p = position + i as u64;
                let a = (p % 256) as usize;
                let b = ((p / 256) % 256) as usize + 256;
                // moddedKey[i] = key[i % 256] ^ (7 * i)
                *d ^= (t[a % 256] ^ (7 * a) as u8) ^ (t[b % 256] ^ (7 * b) as u8);
            }
        } else {
            for (i, d) in data.iter_mut().enumerate() {
                let p = position + i as u64;
                *d ^= t[(p % 256) as usize]
                    ^ t[256 + ((p / 256) % 256) as usize]
                    ^ t[512 + ((p / 65536) % 256) as usize];
            }
        }
    }
}

/// Which table `initWolfCrypt` builds.
pub enum KeyKind<'a> {
    /// The per-read table used in place of the DXA key (`other == false`).
    Read { key2: Option<&'a [u8]> },
    /// The whole-file table (`other == true`), salted from the mode key.
    Whole { key_string: &'a [u8] },
}

/// Error raised when the salt string is empty (the original divides by zero).
#[derive(Debug)]
pub struct EmptySalt;

/// `initWolfCrypt` without the data pass: build the 768-byte table.
pub fn init_wolf_crypt(
    crypt_version: u16,
    pwd: &[u8; PWD_LEN],
    kind: KeyKind<'_>,
) -> Result<WolfKey, EmptySalt> {
    let other = matches!(kind, KeyKind::Whole { .. });
    let v35 = is_v35(crypt_version);
    let (s0, s1, s2) = (pwd[2], pwd[5], pwd[12]);
    let mut s3: u8 = 0;
    if !other {
        for i in 0..pwd[11] / 3 {
            s3 = i ^ (s3 ^ pwd[usize::from(i) % 15]).rotate_right(3);
        }
    } else {
        for i in 0..pwd[8] / 4 {
            s3 = i ^ (s3 ^ pwd[usize::from(i) % 15]).rotate_right(2);
        }
    }

    let seed = u32::from(s0) * u32::from(s1) + u32::from(s2) + u32::from(s3);
    let mut rand = MsvcRand::new(seed);
    let mut fac = [0u8; 3];
    fac[usize::from(s3 % 3)] = (rand.next_u32() % 256) as u8;
    if !other && v35 {
        fac[1] = (rand.next_u32() % 0xFB) as u8;
    }

    let mut key = Box::new([0u8; 768]);
    for i in 0..256 {
        let rn = rand.next_u32() & 0xFFFF;
        key[i] = fac[0] ^ (rand.next_u32() & 0xFF) as u8;
        key[i + 256] = fac[1] ^ (rn >> 8) as u8;
        key[i + 512] = fac[2] ^ rn as u8;
    }

    match kind {
        KeyKind::Read { key2: Some(k2) } if k2.len() >= 3 => {
            for j in 0..128 {
                let rn = rand.next_u32() & 0xFFFF;
                key[j] ^= s3 ^ k2[2] ^ (rn >> 8) as u8;
                key[j + 256] ^= s3 ^ k2[0] ^ rn as u8;
            }
        }
        KeyKind::Read { .. } => {}
        KeyKind::Whole { key_string } => {
            salt_table(crypt_version, v35, s3, key_string, &mut key)?;
        }
    }

    Ok(WolfKey { table: key, v35 })
}

fn calc_salt(s: &[u8]) -> Result<[u8; 128], EmptySalt> {
    if s.is_empty() {
        return Err(EmptySalt);
    }
    let len = s.len();
    Ok(std::array::from_fn(|i| {
        ((i / len) as u8).wrapping_add(s[i % len])
    }))
}

fn salt_table(
    cv: u16,
    v35: bool,
    s3: u8,
    key_string: &[u8],
    key: &mut [u8; 768],
) -> Result<(), EmptySalt> {
    let salt = if cv == 0x15E {
        calc_salt(b"958")?
    } else {
        calc_salt(key_string)?
    };
    let (s3, mod_factor) = if v35 {
        (s3.wrapping_add(0x22), 16u32)
    } else {
        (s3, 7u32)
    };
    let late_rounds = !(cv < 0x154 || (cv > 0x3E8 && cv < 0x3FC));

    for i in 0..3usize {
        let mut t = i32::from(s3);
        for j in 0..256usize {
            let cur_s = salt[j & 0x7F];
            let cur_s2 = salt[(j + i) % 0x80];
            let cur_k = key[i * 256 + j];
            let sxk = cur_s ^ cur_k;
            let round = ((u32::from(cur_s2) | (u32::from(cur_s) << 8)) % mod_factor) as usize;
            let mut new_k = sxk;
            let mut skip = false;
            match round {
                1 if cur_s2 % 0xB == 0 => new_k = cur_k,
                2 if cur_s % 0x1D == 0 => new_k = !sxk,
                3 if (round + j) % 0x25 == 0 => new_k = cur_s2 ^ sxk,
                4 if (u32::from(cur_s) + u32::from(cur_s2)) % 97 == 0 => {
                    new_k = cur_s.wrapping_add(sxk)
                }
                5 if (j * round) % 0x7B == 0 => new_k = sxk ^ t as u8,
                6 if cur_s == 0xFF && cur_s2 == 0 => {
                    new_k = 0;
                    skip = true;
                }
                7 if late_rounds && (((round + j) % 0x33 == 0) || cv >= 0x3FC) => new_k ^= cur_s,
                8 if late_rounds && ((cur_s % 0x1D == 0) || cv >= 0x3FC) => new_k ^= cur_s,
                _ => {}
            }
            if (j + i) % (usize::from(cur_s % 5) + 1) == 0 {
                new_k ^= t as u8;
            } else if skip {
                new_k = !sxk;
            }
            key[i * 256 + j] = new_k;
            t += i as i32;
        }
    }
    Ok(())
}

/// `cryptAddresses`: XOR the address fields (bytes 8..40) of a DXA v8 header.
pub fn crypt_addresses(header: &mut [u8; 64], pwd: &[u8; PWD_LEN], crypt_version: u16) {
    let word = |h: &mut [u8; 64], idx: usize, v: u32| {
        let o = idx * 2;
        let w = u16::from_le_bytes([h[o], h[o + 1]]) ^ (v & 0xFFFF) as u16;
        h[o..o + 2].copy_from_slice(&w.to_le_bytes());
    };

    if is_v35(crypt_version) {
        let seed = 0xC + u32::from(pwd[9]) * u32::from(pwd[10]) + u32::from(pwd[3]);
        let mut rand = MsvcRand::new(seed);
        // Two groups of four 16-bit words at bytes 8..24, each in reverse.
        for group in 0..2 {
            for j in (0..4).rev() {
                word(header, 4 + group * 4 + j, rand.next_u32());
            }
        }
        // One 64-bit value at bytes 24..32.
        let r0 = u64::from(rand.next_u32()) << 17;
        let r1 = u64::from(rand.next_u32()) << 31;
        let v0 = (r0 as u32) | (r1 as u32) | rand.next_u32();
        let v1 = ((r0 >> 32) | (r1 >> 32)) as u32;
        let lo = u32::from_le_bytes([header[24], header[25], header[26], header[27]]) ^ v0;
        let hi = u32::from_le_bytes([header[28], header[29], header[30], header[31]]) ^ v1;
        header[24..28].copy_from_slice(&lo.to_le_bytes());
        header[28..32].copy_from_slice(&hi.to_le_bytes());
        // Four 16-bit words at bytes 32..40, in reverse.
        for j in (0..4).rev() {
            word(header, 16 + j, rand.next_u32());
        }
    } else {
        let seed = u32::from(pwd[0]) + u32::from(pwd[7]) * u32::from(pwd[12]);
        let mut rand = MsvcRand::new(seed);
        for group in 0..4 {
            for j in (0..4).rev() {
                word(header, 4 + group * 4 + j, rand.next_u32());
            }
        }
    }
}

/// `initAES128`: derive the archive AES-CTR key and IV from the header
/// password and, for Pro games, four extra key bytes.
pub fn init_aes128(pwd: &[u8; PWD_LEN], pro_key: Option<&[u8]>, crypt_version: u16) -> AesCtr {
    let mut pro = [0u8; 4];
    if let Some(k) = pro_key {
        for (p, v) in pro.iter_mut().zip(k) {
            *p = *v;
        }
    }
    let pw = |i: usize| u32::from(pwd[i]);
    let pk = |i: usize| u32::from(pro[i]);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];

    if is_v35(crypt_version) {
        for i in 0..PWD_LEN {
            let iu = i as u32;
            let elem = pk(i % 4);
            let idx_key = (((iu * (elem % 5 + 7)) ^ (3 * pw(i))) % 15) as usize;
            let idx_iv =
                (((iu * ((pk((i + 1) % 4) % 7) + 0xB)) ^ (5 * pw((i + 3) % 15))) % 15) as usize;
            key[i] ^= (((iu ^ elem).wrapping_add(pw(idx_key) << (i % 3))) % 0xFB) as u8;
            iv[i] ^=
                (((pw(idx_iv) >> (i % 2)).wrapping_add((iu * iu) ^ pk((i + 2) % 4))) % 0xF6) as u8;
            key[15] ^= ((7 * (pw(i) + ((iu + 1) ^ elem))) % 0xFD) as u8;
            let diff = pw(i).wrapping_sub((iu * 2) ^ pk((i + 2) % 4)) as u16;
            iv[15] ^= ((11 * u32::from(diff)) % 0x100) as u8;
        }
    } else if crypt_version == 0x3F2 {
        for i in 0..PWD_LEN {
            let iu = i as u32;
            key[i] ^= (pw((i * 7) % 15) + pk(i & 3))
                .wrapping_mul(iu)
                .wrapping_mul(iu) as u8;
            iv[i] ^= (pw((i * 11) % 15) + pk((i + 2) % 4)).wrapping_sub(iu * iu) as u8;
            key[15] ^= (iu * 3 + pw(i) + pk(i & 3)) as u8;
            iv[15] ^= (iu * 5 + pw(i) + pk((i + 2) % 4)) as u8;
        }
    } else {
        for i in 0..PWD_LEN {
            let iu = i as u32;
            key[i] ^= (pw((i * 7) % 15) + iu * iu) as u8;
            iv[i] ^= pw((i * 11) % 15).wrapping_sub(iu * iu) as u8;
            key[15] ^= (pw(i) + iu * 3) as u8;
            iv[15] ^= (pw(i) + iu * 5) as u8;
        }
    }

    key[0] ^= pro[0];
    iv[10] ^= pro[0];
    key[4] ^= pro[1];
    iv[1] ^= pro[1];
    key[8] ^= pro[2];
    iv[4] ^= pro[2];
    key[12] ^= pro[3];
    iv[7] ^= pro[3];

    AesCtr::new(Aes128::new(&key, KeySchedule::Wolf), iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v35_range() {
        assert!(!is_v35(0x14B));
        assert!(is_v35(0x15E));
        assert!(!is_v35(1000));
        assert!(!is_v35(1010));
        assert!(is_v35(1020));
    }

    #[test]
    fn crypt_addresses_is_an_involution() {
        let pwd: [u8; PWD_LEN] = std::array::from_fn(|i| (i * 31 + 7) as u8);
        for cv in [0x14Bu16, 0x15E] {
            let orig: [u8; 64] = std::array::from_fn(|i| i as u8);
            let mut h = orig;
            crypt_addresses(&mut h, &pwd, cv);
            assert_eq!(h[..8], orig[..8]);
            assert_eq!(h[40..], orig[40..]);
            assert_ne!(h, orig);
            crypt_addresses(&mut h, &pwd, cv);
            assert_eq!(h, orig);
        }
    }

    #[test]
    fn empty_salt_is_an_error() {
        let pwd = [1u8; PWD_LEN];
        assert!(init_wolf_crypt(0x14B, &pwd, KeyKind::Whole { key_string: b"" }).is_err());
    }
}
