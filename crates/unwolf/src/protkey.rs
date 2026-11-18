//! Wolf RPG Pro protection key: the password the editor asks for before
//! opening a protected project (`WolfPro::findProtectionKey` and
//! `WolfCrypt/WolfProtKey.hpp`). It is read from `BasicData/Game.dat`.

use std::fmt;

use crate::crypto::datadecrypt::{self, GAME_DAT_SEEDS, pro_generation};
use crate::error::{Error, Result};
use crate::rng::MsvcRand;

/// Generation of the Pro protection, which also selects how `-u` works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProVersion {
    V1,
    V2,
    /// Wolf RPG 3.5: only a hash of the key is stored.
    V35,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtectionKey {
    Key {
        version: ProVersion,
        key: Vec<u8>,
    },
    /// Wolf RPG 3.5 stores only a hash: the key cannot be recovered.
    NotRecoverable,
}

impl ProtectionKey {
    pub fn version(&self) -> ProVersion {
        match self {
            Self::Key { version, .. } => *version,
            Self::NotRecoverable => ProVersion::V35,
        }
    }
}

impl fmt::Display for ProtectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Validated keys are ASCII alphanumeric.
            Self::Key { key, .. } => f.write_str(&String::from_utf8_lossy(key)),
            Self::NotRecoverable => f.write_str("NOT POSSIBLE FOR WolfRPG v3.5"),
        }
    }
}

/// Start of a `Game.dat` in plain form: written by the editor without
/// protection, or put back by `-u` (`DEC_START` with bytes 6 and 9 swapped).
const PLAIN_GAME_DAT_START: [u8; 6] = [0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C];

/// Whether `game_dat` is in plain form, that is not protected: the Pro
/// protection was never applied or has already been removed (`-u`).
///
/// A v1 protected file has no Pro header either, so [`detect_version`]
/// alone cannot tell the two apart.
pub fn is_unprotected(game_dat: &[u8]) -> bool {
    game_dat.starts_with(&PLAIN_GAME_DAT_START)
}

/// Generation of a protected `Game.dat`, as tested by `findProtectionKey`.
///
/// Any file without a Pro header counts as v1, including a plain one: check
/// [`is_unprotected`] first.
pub fn detect_version(game_dat: &[u8]) -> ProVersion {
    match pro_generation(game_dat) {
        Some(0x55) => ProVersion::V2,
        Some(g) if g >= 0x57 => ProVersion::V35,
        _ => ProVersion::V1,
    }
}

/// Recover the protection key from the bytes of `BasicData/Game.dat`.
///
/// Fails with [`Error::Game`] when the file is not protected
/// ([`is_unprotected`]).
pub fn protection_key(game_dat: &[u8]) -> Result<ProtectionKey> {
    if is_unprotected(game_dat) {
        return Err(Error::Game("Game.dat is not protected".into()));
    }
    let version = detect_version(game_dat);
    let key = match version {
        ProVersion::V35 => return Ok(ProtectionKey::NotRecoverable),
        ProVersion::V1 => key_v1(game_dat)?,
        ProVersion::V2 => key_v2(game_dat)?,
    };
    if !is_valid_key(&key) {
        return Err(Error::Game("invalid protection key".into()));
    }
    Ok(ProtectionKey::Key { version, key })
}

/// Header layout shared by v1 protected files (`ProtKey` in `WolfPro.cpp`).
pub(crate) const KEY_LEN_OFFSET: usize = 0xA + 5;
pub(crate) const KEY_OFFSET: usize = KEY_LEN_OFFSET + 4;

/// Decrypt a v1 protected file with the seeds read at `seed_idx` and return
/// the length of the key stored in its header.
pub(crate) fn decrypt_v1(bytes: &mut [u8], seed_idx: [usize; 3]) -> Result<usize> {
    if bytes.len() < KEY_OFFSET {
        return Err(Error::format("Pro v1 file too small"));
    }
    datadecrypt::xor_v2_0(bytes, seed_idx.map(|i| bytes[i]));
    let mut l = [0u8; 4];
    l.copy_from_slice(&bytes[KEY_LEN_OFFSET..KEY_OFFSET]);
    let key_len = u32::from_le_bytes(l) as usize;
    if key_len.saturating_add(KEY_OFFSET) >= bytes.len() {
        return Err(Error::format("invalid key length"));
    }
    Ok(key_len)
}

/// `findProtectionKeyV1`: the key follows the header, XORed with MSVC
/// `rand` seeded with a constant.
fn key_v1(game_dat: &[u8]) -> Result<Vec<u8>> {
    const KEY_SEED: u32 = 0x5D9_3EBF;
    let mut bytes = game_dat.to_vec();
    let key_len = decrypt_v1(&mut bytes, GAME_DAT_SEEDS)?;
    let mut rand = MsvcRand::new(KEY_SEED);
    Ok(bytes[KEY_OFFSET..KEY_OFFSET + key_len]
        .iter()
        .map(|b| b ^ rand.next_u32() as u8)
        .collect())
}

const ENCRYPTED_KEY_SIZE: usize = 128;

/// `protkey::v2::calcProtKey`: decrypt the v3.3 header, then a second AES
/// layer over the 128-byte key block at offset 15, keyed by header bytes.
fn key_v2(game_dat: &[u8]) -> Result<Vec<u8>> {
    const BLOCK_OFFSET: usize = 0xF;
    let mut bytes = game_dat.to_vec();
    if bytes.len() < BLOCK_OFFSET + ENCRYPTED_KEY_SIZE {
        return Err(Error::format("Pro v2 Game.dat too small"));
    }
    let st = datadecrypt::decrypt_v3_3(&mut bytes, GAME_DAT_SEEDS)?;

    let mut block = [0u8; ENCRYPTED_KEY_SIZE];
    block.copy_from_slice(&bytes[BLOCK_OFFSET..BLOCK_OFFSET + ENCRYPTED_KEY_SIZE]);
    datadecrypt::aes_key_gen_xor(st.key_bytes, &mut block);
    find_key(&block).ok_or_else(|| Error::Game("unable to calculate the protection key".into()))
}

/// The block holds the key repeated, each repetition offset by its index:
/// `block[i] = key[i % n] + i / n`. Return the shortest key that fits.
fn find_key(block: &[u8; ENCRYPTED_KEY_SIZE]) -> Option<Vec<u8>> {
    const MIN_KEY_LEN: usize = 4;
    (MIN_KEY_LEN..ENCRYPTED_KEY_SIZE).find_map(|n| {
        let key = &block[..n];
        block
            .iter()
            .enumerate()
            .all(|(i, &b)| b == key[i % n].wrapping_add((i / n) as u8))
            .then(|| key.to_vec())
    })
}

/// `validateProtectionKey`: keys are ASCII letters and digits.
fn is_valid_key(key: &[u8]) -> bool {
    !key.is_empty() && key.iter().all(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_key_recovers_repeated_key() {
        let key = b"Abc123";
        let block: [u8; 128] = std::array::from_fn(|i| key[i % 6].wrapping_add((i / 6) as u8));
        assert_eq!(find_key(&block).as_deref(), Some(&key[..]));
    }

    #[test]
    fn find_key_rejects_noise() {
        // Every candidate length n needs block[n] == block[0] + 1.
        let block = [0u8; 128];
        assert_eq!(find_key(&block), None);
    }

    #[test]
    fn validation_matches_original_ranges() {
        assert!(is_valid_key(b"aZ09"));
        for bad in [&b""[..], b"a-b", b"a b", b"[", b"`", b"@", b":"] {
            assert!(!is_valid_key(bad), "{bad:?}");
        }
    }

    #[test]
    fn version_detection() {
        let mut d = vec![0u8; 8];
        assert_eq!(detect_version(&d), ProVersion::V1);
        d[1] = 0x50;
        d[5] = 0x54;
        assert_eq!(detect_version(&d), ProVersion::V1);
        d[5] = 0x55;
        assert_eq!(detect_version(&d), ProVersion::V2);
        d[5] = 0x56;
        assert_eq!(detect_version(&d), ProVersion::V1);
        d[5] = 0x57;
        assert_eq!(detect_version(&d), ProVersion::V35);
        assert_eq!(
            protection_key(&d).unwrap().to_string(),
            "NOT POSSIBLE FOR WolfRPG v3.5"
        );
    }

    /// A plain `Game.dat` (as left by `-u` on a real Pro 3.7 game) is not
    /// protected, even though `detect_version` alone would call it v1.
    #[test]
    fn plain_game_dat_is_unprotected() {
        let plain = [
            0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C, 0x00, 0x46, 0x4D, 0x55, 0x2B, 0x00,
        ];
        assert!(is_unprotected(&plain));
        assert_eq!(detect_version(&plain), ProVersion::V1);
        assert!(matches!(protection_key(&plain), Err(Error::Game(_))));

        let mut v35 = plain;
        v35[0] = 0x57;
        v35[1] = 0x50;
        v35[5] = 0x57;
        assert!(!is_unprotected(&v35));
        assert!(!is_unprotected(&plain[..5]));
        assert!(!is_unprotected(&[]));
    }

    /// Build a v1 `Game.dat` holding `key` and read it back.
    #[test]
    fn v1_round_trip() {
        let key = b"Secret42";
        let mut plain = vec![0u8; 64];
        plain[0] = 0x11;
        plain[8] = 0x22;
        plain[6] = 0x33;
        plain[KEY_LEN_OFFSET..KEY_OFFSET].copy_from_slice(&(key.len() as u32).to_le_bytes());
        let mut rand = MsvcRand::new(0x5D9_3EBF);
        for (i, k) in key.iter().enumerate() {
            plain[KEY_OFFSET + i] = k ^ rand.next_u32() as u8;
        }
        // The cipher also changes the seed bytes; the reader takes its seeds
        // from the stored file, so store them unencrypted.
        let mut file = plain.clone();
        datadecrypt::xor_v2_0(&mut file, GAME_DAT_SEEDS.map(|i| plain[i]));
        for i in GAME_DAT_SEEDS {
            file[i] = plain[i];
        }
        assert!(!is_unprotected(&file));
        let got = key_v1(&file).unwrap();
        assert_eq!(got, key);
    }
}
