//! Encryption of the Wolf RPG Pro data files (`Game.dat`, `CommonEvent.dat`,
//! databases...), from `WolfCrypt/WolfDataDecrypt.hpp` in UberWolfLib.
//!
//! Three generations exist, told apart by the header bytes `[1] == 0x50`
//! and `[5]`: below 0x55 the MSVC `rand` XOR (v2.0, used by Pro 3.1), below
//! 0x57 MT19937 then AES (v3.3), from 0x57 xorshift then AES keyed by the
//! Wolf SHA-512 (v3.5).

use super::aes::{Aes128, AesCtr, KeySchedule};
use super::sha512;
use crate::error::{Error, Result};
use crate::rng::chain::{RngData, aes_key_gen};
use crate::rng::{MsvcRand, Mt19937, Xorshift32};

/// Header bytes indices used as seeds (`SeedIncides`).
pub type SeedIndices = [usize; 3];

/// Seeds of `Game.dat`.
pub const GAME_DAT_SEEDS: SeedIndices = [0, 8, 6];
/// Seeds of every other protected file.
pub const DEFAULT_SEEDS: SeedIndices = [0, 3, 9];

/// Start of the AES region in v3.3 and v3.5 files.
const AES_DATA_OFFSET: usize = 20;

/// Whether `data` starts with a Pro encryption header (`[1] == 0x50`), and
/// its generation byte.
pub fn pro_generation(data: &[u8]) -> Option<u8> {
    (data.len() > 5 && data[1] == 0x50).then(|| data[5])
}

/// `v2_0::decryptData`: three MSVC `rand` passes with strides 1, 2 and 5.
/// The cipher is a XOR, so this also encrypts.
pub fn xor_v2_0(data: &mut [u8], seeds: [u8; 3]) {
    const INTERVALS: [usize; 3] = [1, 2, 5];
    for (seed, step) in seeds.into_iter().zip(INTERVALS) {
        let mut rand = MsvcRand::new(u32::from(seed));
        for d in data.iter_mut().step_by(step) {
            *d ^= (rand.next_u32() >> 12) as u8;
        }
    }
}

/// `utils::genMTSeed`.
pub fn gen_mt_seed(seeds: [u8; 3]) -> u32 {
    let x = (u32::from(seeds[0]) << 16) | (u32::from(seeds[1]) << 8) | u32::from(seeds[2]);
    let y = (x << 13) ^ x;
    let z = (y >> 17) ^ y;
    z ^ (z << 5)
}

/// State derived from a v3.3 header (`CryptData` after `v3_3::initCrypt`).
#[derive(Debug, Clone)]
pub struct V33State {
    pub key_bytes: [u8; 4],
    pub seed_bytes: [u8; 4],
    /// Length of the AES region starting at offset 20.
    pub data_size: usize,
}

/// `v3_3::initCrypt`: undo the MT19937 layer from offset 10 and derive the
/// key material. Fails when the file is shorter than the header.
pub fn init_v3_3(data: &mut [u8], seed_idx: SeedIndices) -> Result<V33State> {
    const NUM_RNDS: usize = 128;
    if data.len() <= AES_DATA_OFFSET || seed_idx.iter().any(|&i| i >= data.len()) {
        return Err(Error::format("Pro v3.3 data too short"));
    }
    let data_size = (data.len() - AES_DATA_OFFSET).min(326);
    let mut mt = Mt19937::new(gen_mt_seed(seed_idx.map(|i| data[i])));
    let rnds: [u32; NUM_RNDS] = std::array::from_fn(|_| mt.next_u32());
    for (i, d) in data.iter_mut().enumerate().skip(0xA) {
        *d ^= rnds[i % NUM_RNDS] as u8;
    }

    let k = [data[0xB], data[0xC], data[0xD], data[0xE]];
    let d7 = data[7];
    let seed_bytes = [
        d7.wrapping_add(k[0].wrapping_mul(3)),
        k[1] ^ k[2],
        k[3] ^ d7,
        k[2].wrapping_add(d7).wrapping_sub(k[0]),
    ];
    Ok(V33State {
        key_bytes: k,
        seed_bytes,
        data_size,
    })
}

/// AES-CTR (Wolf key schedule) keyed by `aesKeyGen(seed_bytes)`, applied to
/// `data` as one `aesCtrXCrypt` call.
pub fn aes_key_gen_xor(seed_bytes: [u8; 4], data: &mut [u8]) {
    let mut rd = RngData::default();
    let (key, iv) = aes_key_gen(seed_bytes, &mut rd);
    let ctr = AesCtr::new(Aes128::new(&key, KeySchedule::Wolf), iv);
    ctr.xor_region(ctr.counter_after(0), data);
}

/// `v3_3::decryptData`: the MT19937 layer, then AES over `[20, 20+size)`.
/// The 143-byte header is left in place.
pub fn decrypt_v3_3(data: &mut [u8], seed_idx: SeedIndices) -> Result<V33State> {
    let st = init_v3_3(data, seed_idx)?;
    let end = AES_DATA_OFFSET + st.data_size;
    aes_key_gen_xor(st.seed_bytes, &mut data[AES_DATA_OFFSET..end]);
    Ok(st)
}

/// The file kinds handled by the v3.5 scheme, each with its own static salt
/// and replacement header (`PRO_MAGIC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProFile {
    GameDat,
    CommonEvent,
    DataBase,
    TileSetData,
}

impl ProFile {
    pub fn static_salt(self) -> &'static [u8] {
        match self {
            Self::GameDat => b"basicD1",
            Self::CommonEvent => b"Commo2",
            Self::DataBase => b"DBase4",
            Self::TileSetData => b"TilesetA",
        }
    }

    /// The plain header written in place of the 143-byte protected one.
    pub fn magic(self) -> [u8; 10] {
        match self {
            Self::GameDat => [0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C, 0x00, 0x46, 0x4D, 0x55],
            Self::CommonEvent => [0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C, 0x55, 0x46, 0x43, 0x00],
            Self::DataBase => [0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C, 0x55, 0x46, 0x4D, 0x00],
            Self::TileSetData => [0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C, 0x55, 0x46, 0x4D, 0x00],
        }
    }

    pub fn seed_indices(self) -> SeedIndices {
        match self {
            Self::GameDat => GAME_DAT_SEEDS,
            _ => DEFAULT_SEEDS,
        }
    }
}

/// 15-byte header plus 128-byte hash.
pub const PRO_V35_HEADER_SIZE: usize = 143;

/// `decryptProV3P1`: the xorshift layer from offset 10.
fn xor_v3_5_stream(data: &mut [u8], seed_idx: SeedIndices) {
    let seed = (0x0B << 24)
        | (u32::from(data[seed_idx[0]]) << 16)
        | (u32::from(data[seed_idx[1]]) << 8)
        | u32::from(data[seed_idx[2]]);
    // `xorshift32(seed)` stores the seed and steps once.
    let mut rn = Xorshift32::new(seed).next_u32() as i32;
    for d in data.iter_mut().skip(0xA) {
        // Signed arithmetic as in the original: `>>` is arithmetic and `%`
        // keeps the sign of the dividend; only the low byte is used.
        let v1 = (((rn << 15) ^ rn) >> 21) ^ (rn << 15) ^ rn;
        rn = (v1 << 9) ^ v1;
        *d ^= (rn % 0xF9) as u8;
    }
}

/// `sha512::calcDynSalt`.
fn dyn_salt(data: &[u8]) -> [u8; 4] {
    let (d0, d1, d2) = (data[7], data[11], data[13]);
    let r = [
        ((u32::from(d0) + 2 * u32::from(d1)) % 0xF6) as u8,
        d2 ^ data[14],
        d0 ^ data[12],
        d0.wrapping_add(d2).wrapping_sub(d1),
    ];
    // A zero would end the C string the salt is part of.
    r.map(|c| if c == 0 { 1 } else { c })
}

/// AES key and IV of a v3.5 file: slices of the hexadecimal Wolf SHA-512
/// digest of `<dynamic salt><static salt>`.
pub fn v3_5_key(data: &[u8], kind: ProFile) -> ([u8; 16], [u8; 16]) {
    const KEY_START: usize = 12;
    const IV_START: usize = 73;
    let mut pwd = dyn_salt(data).to_vec();
    pwd.extend_from_slice(kind.static_salt());
    let digest = sha512::hex_digest(&sha512::hash(&pwd, sha512::Variant::Wolf));
    let d = digest.as_bytes();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&d[KEY_START..KEY_START + 16]);
    iv.copy_from_slice(&d[IV_START..IV_START + 16]);
    (key, iv)
}

/// `v3_5::decryptData`: remove both layers and replace the 143-byte header
/// with the plain one. The buffer is left untouched on error.
pub fn decrypt_v3_5(buf: &mut Vec<u8>, kind: ProFile) -> Result<()> {
    if buf.len() < PRO_V35_HEADER_SIZE {
        return Err(Error::format("Pro v3.5 file too small"));
    }
    if pro_generation(buf).is_none_or(|g| g < 0x57) {
        return Err(Error::format("not a Pro v3.5 protected file"));
    }
    xor_v3_5_stream(buf, kind.seed_indices());

    let mut rand = MsvcRand::new(u32::from(buf[12]));
    let mut aes_size = buf.len() - AES_DATA_OFFSET;
    // The original draws twice: once for the test, once for the size.
    if aes_size >= (rand.next_u32() % 126 + 200) as usize {
        aes_size = aes_size.min((rand.next_u32() % 126 + 200) as usize);
    }

    let (key, iv) = v3_5_key(buf, kind);
    let ctr = AesCtr::new(Aes128::new(&key, KeySchedule::Wolf), iv);
    ctr.xor_region(
        ctr.counter_after(0),
        &mut buf[AES_DATA_OFFSET..AES_DATA_OFFSET + aes_size],
    );

    buf.splice(..PRO_V35_HEADER_SIZE, kind.magic());
    Ok(())
}

/// Test helper: protect `payload` with the v3.5 scheme, behind a
/// synthetic 143-byte header. Runs the layers in the encrypting direction:
/// the keys come from the plain header, then both XOR layers are applied.
#[cfg(test)]
pub(crate) fn encrypt_v3_5(payload: &[u8], kind: ProFile) -> Vec<u8> {
    let mut file = vec![0u8; PRO_V35_HEADER_SIZE];
    file[1] = 0x50;
    file[5] = 0x57;
    for (i, h) in file.iter_mut().enumerate().skip(6) {
        *h = (i * 13) as u8;
    }
    file.extend_from_slice(payload);
    let mut rand = MsvcRand::new(u32::from(file[12]));
    let mut aes_size = file.len() - AES_DATA_OFFSET;
    if aes_size >= (rand.next_u32() % 126 + 200) as usize {
        aes_size = aes_size.min((rand.next_u32() % 126 + 200) as usize);
    }
    let (key, iv) = v3_5_key(&file, kind);
    let ctr = AesCtr::new(Aes128::new(&key, KeySchedule::Wolf), iv);
    ctr.xor_region(
        ctr.counter_after(0),
        &mut file[AES_DATA_OFFSET..AES_DATA_OFFSET + aes_size],
    );
    // The seed bytes (< 10) are outside the xorshift layer.
    xor_v3_5_stream(&mut file, kind.seed_indices());
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_0_is_an_involution() {
        let orig: Vec<u8> = (0..200u8).collect();
        let mut d = orig.clone();
        xor_v2_0(&mut d, [1, 2, 3]);
        assert_ne!(d, orig);
        xor_v2_0(&mut d, [1, 2, 3]);
        assert_eq!(d, orig);
    }

    #[test]
    fn v2_0_strides() {
        let stream = |seed: u32, n: usize| -> Vec<u8> {
            let mut r = MsvcRand::new(seed);
            (0..n).map(|_| (r.next_u32() >> 12) as u8).collect()
        };
        let mut d = vec![0u8; 11];
        xor_v2_0(&mut d, [5, 6, 7]);
        let (s1, s2, s3) = (stream(5, 11), stream(6, 6), stream(7, 3));
        for (i, &v) in d.iter().enumerate() {
            let mut e = s1[i];
            if i % 2 == 0 {
                e ^= s2[i / 2];
            }
            if i % 5 == 0 {
                e ^= s3[i / 5];
            }
            assert_eq!(v, e, "index {i}");
        }
    }

    #[test]
    fn mt_seed_formula() {
        // x = 0x010203; y = x ^ x<<13; z = y ^ y>>17; z ^ z<<5
        let x: u32 = 0x0001_0203;
        let y = (x << 13) ^ x;
        let z = (y >> 17) ^ y;
        assert_eq!(gen_mt_seed([1, 2, 3]), z ^ (z << 5));
    }

    #[test]
    fn dyn_salt_never_zero() {
        let mut d = [0u8; 17];
        assert_eq!(dyn_salt(&d), [1, 1, 1, 1]);
        d[7] = 10;
        d[11] = 3;
        d[13] = 5;
        d[14] = 6;
        d[12] = 10;
        assert_eq!(dyn_salt(&d), [16, 3, 1, 12]);
    }

    #[test]
    fn v3_5_round_trip() {
        let kind = ProFile::CommonEvent;
        let payload: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut enc = encrypt_v3_5(&payload, kind);
        assert_ne!(enc[PRO_V35_HEADER_SIZE..], payload[..]);
        decrypt_v3_5(&mut enc, kind).unwrap();
        assert_eq!(enc[..10], kind.magic());
        assert_eq!(enc[10..], payload[..]);
    }

    #[test]
    fn v3_5_rejects_other_files() {
        let mut v = vec![0u8; 200];
        assert!(decrypt_v3_5(&mut v, ProFile::GameDat).is_err());
        v[1] = 0x50;
        v[5] = 0x55;
        assert!(decrypt_v3_5(&mut v, ProFile::GameDat).is_err());
        assert_eq!(v, {
            let mut w = vec![0u8; 200];
            w[1] = 0x50;
            w[5] = 0x55;
            w
        });
    }
}
