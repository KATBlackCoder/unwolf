//! Wolf RPG Pro: archive key derivation from the game's key file
//! (`WolfPro::GetDxArcKey` and `WolfCrypt/WolfDxArcKey.hpp`).

use std::path::{Path, PathBuf};

use crate::crypto::aes::{Aes128, AesCtr, KeySchedule};
use crate::error::{Error, Result};
use crate::fsutil::find_ci;
use crate::rng::MsvcRand;
use crate::rng::chain::{RngData, aes_key_gen};

/// Archive extensions recognised by UberWolf (`POSSIBLE_EXTENSIONS`).
pub const WOLF_EXTENSIONS: [&str; 8] = [
    "wolf", "data", "pak", "bin", "assets", "content", "res", "resource",
];

/// Base names of files that are not regular archives (`SPECIAL_FILES`).
/// In Pro games one of them holds the material for the archive key.
const SPECIAL_BASES: [&str; 5] = ["Game", "List", "Data2", "GameFile", "BasicData2"];

/// Whether `file_name` is one of the special files that are never unpacked.
pub fn is_special_file(file_name: &str) -> bool {
    SPECIAL_BASES.iter().any(|b| {
        WOLF_EXTENSIONS
            .iter()
            .any(|e| file_name.eq_ignore_ascii_case(&format!("{b}.{e}")))
    })
}

/// The first special file present in `data_folder`, in UberWolf's order.
pub fn find_key_file(data_folder: &Path) -> Option<PathBuf> {
    SPECIAL_BASES.iter().find_map(|b| {
        WOLF_EXTENSIONS
            .iter()
            .find_map(|e| find_ci(data_folder, &format!("{b}.{e}")))
    })
}

/// A derived archive key and the crypt version it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProKey {
    pub key: Vec<u8>,
    pub crypt_version: u16,
}

/// Derive the archive key from the contents of the Pro key file.
pub fn dx_arc_key(bytes: &[u8]) -> Result<ProKey> {
    match bytes.first() {
        None => Err(Error::Game("empty Pro key file".into())),
        Some(0xA0) => {
            let mut key = key_v1(bytes)?;
            if key.last() != Some(&0) {
                key.push(0);
            }
            Ok(ProKey {
                key,
                crypt_version: 1000,
            })
        }
        Some(0xF1) => Ok(ProKey {
            key: key_cc2(bytes.len() as u32).to_vec(),
            crypt_version: 0xC8,
        }),
        Some(_) => Ok(ProKey {
            key: key_v2(bytes)?,
            crypt_version: 1010,
        }),
    }
}

fn key_v1(bytes: &[u8]) -> Result<Vec<u8>> {
    const SEED_OFFSET: usize = 4;
    const KEY_LEN_OFFSET: usize = 19;
    const KEY_START: usize = 30;
    const STEP_DIVISOR: usize = 0x58B1;
    const MIN_SIZE: usize = 0x5CB8;
    const XOR_START: usize = 20;

    if bytes.len() < MIN_SIZE {
        return Err(Error::Game("Pro key file too small".into()));
    }
    let mut b = bytes.to_vec();
    let mut rand = MsvcRand::new(u32::from(b[SEED_OFFSET]));
    for v in &mut b[XOR_START..] {
        *v ^= (rand.next_u32() >> 12) as u8;
    }
    let len = usize::from(b[KEY_LEN_OFFSET]);
    if len == 0 {
        return Err(Error::Game("Pro key length is zero".into()));
    }
    let step = STEP_DIVISOR / len;
    (0..len)
        .map(|i| {
            b.get(KEY_START + i * step)
                .copied()
                .ok_or_else(|| Error::Game("Pro key offset out of range".into()))
        })
        .collect()
}

fn key_v2(bytes: &[u8]) -> Result<Vec<u8>> {
    const HEADER: usize = 31;
    const AES_START: usize = 30;
    if bytes.len() <= HEADER {
        return Err(Error::Game("Pro key file too small".into()));
    }
    let size = (bytes.len() - HEADER) as u32;
    let div = size / 3;
    let v1 = div + 71 + (div >> 31);
    let v2 = size ^ 0x70;
    let v3 = size % 1200 + 152;
    let v4 = size.wrapping_add(size.wrapping_mul(2)).wrapping_add(85);
    let key_bytes = [
        (v4 ^ v1) as u8,
        v3.wrapping_add(v2) as u8,
        v2.wrapping_sub(v4) as u8,
        v2.wrapping_mul(v4) as u8,
    ];
    let seed_bytes = [
        v1.wrapping_add(u32::from(bytes[3])) as u8,
        v3.wrapping_add(u32::from(bytes[7])) as u8,
        v2.wrapping_add(u32::from(bytes[5])) as u8,
        v4.wrapping_add(u32::from(bytes[6])) as u8,
    ];

    let mut rd = RngData::default();
    rd.run_chain(v1, v3);
    let (key, iv) = aes_key_gen(seed_bytes, &mut rd);
    let ctr = AesCtr::new(Aes128::new(&key, KeySchedule::Wolf), iv);
    let mut b = bytes.to_vec();
    let end = AES_START + size as usize;
    ctr.xor_region(ctr.counter_after(0), &mut b[AES_START..end]);

    let mut k = i32::from(b[4]) + i32::from((u16::from(b[3]) * u16::from(b[6])) & 0x3FF);
    // Find the first k >= start that is coprime with the data size.
    loop {
        let (mut a, mut c) = (size as i32, k);
        if k != 0 {
            loop {
                let r = a % c;
                a = c;
                c = r;
                if r == 0 {
                    break;
                }
            }
        }
        if a <= 1 {
            break;
        }
        k += 1;
    }

    let key_len = u32::from(b[19]);
    let mut out = Vec::with_capacity(key_len as usize + 5);
    for i in 0..key_len {
        let idx = (i.wrapping_mul(k as u32) % size) as usize + AES_START + usize::from(b[7]);
        out.push(
            *b.get(idx)
                .ok_or_else(|| Error::Game("Pro key offset out of range".into()))?,
        );
    }
    out.push(0);
    out.extend_from_slice(&key_bytes);
    Ok(out)
}

fn key_cc2(file_size: u32) -> [u8; 64] {
    const MOD1: [u8; 4] = [0x3F, 0xA7, 0xD2, 0x1C];
    const MOD2: [u8; 4] = [0xB4, 0xE1, 0x9D, 0x58];
    const MOD3: [u8; 4] = [0x6A, 0x2B, 0x4C, 0x8E];
    let size = file_size.wrapping_sub(31);
    let rem = size % 0x064B;
    let x = size ^ 0x70;
    let sum = rem + 152;
    let div4 = size / 4 + 1285;
    let div2 = size / 2 + 171;
    let data = [
        (div4 ^ div2) as u8,
        x.wrapping_add(sum) as u8,
        x.wrapping_sub(div4) as u8,
        div4.wrapping_mul(x) as u8,
    ];
    std::array::from_fn(|i| {
        let n = i % 4;
        let mut t = data[n].wrapping_add(MOD2[n]) ^ MOD1[n].wrapping_add((17 * i) as u8);
        t = if i % 2 == 0 {
            t.rotate_right(5)
        } else {
            t.rotate_right(2)
        };
        !(t ^ data[n] ^ MOD3[n])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_files() {
        assert!(is_special_file("Game.wolf"));
        assert!(is_special_file("basicdata2.WOLF"));
        assert!(!is_special_file("Data.wolf"));
        assert!(!is_special_file("BasicData.wolf"));
    }
}
