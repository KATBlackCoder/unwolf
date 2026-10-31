//! AES-128 in CTR mode with the Wolf RPG key schedule.
//!
//! The round function is standard AES. Only the key expansion differs: Wolf
//! RPG alters three of the four S-box results of the `RotWord`/`SubWord` step.
//! [`KeySchedule::Standard`] exists so the cipher core can be checked against
//! the FIPS-197 test vectors.

const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

const RCON: [u8; 11] = [
    0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];
const ROUNDS: usize = 10;
const BLOCK: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySchedule {
    /// Key expansion as used by Wolf RPG.
    Wolf,
    /// FIPS-197 key expansion (tests only).
    Standard,
}

/// An expanded AES-128 key.
#[derive(Clone)]
pub struct Aes128 {
    round_keys: [u8; 176],
}

impl Aes128 {
    pub fn new(key: &[u8; 16], schedule: KeySchedule) -> Self {
        let mut rk = [0u8; 176];
        rk[..16].copy_from_slice(key);
        for i in 4..44 {
            let k = (i - 1) * 4;
            let mut t = [rk[k], rk[k + 1], rk[k + 2], rk[k + 3]];
            if i % 4 == 0 {
                let rotated = [t[1], t[2], t[3], t[0]];
                t = match schedule {
                    KeySchedule::Standard => [
                        SBOX[rotated[0] as usize] ^ RCON[i / 4],
                        SBOX[rotated[1] as usize],
                        SBOX[rotated[2] as usize],
                        SBOX[rotated[3] as usize],
                    ],
                    KeySchedule::Wolf => [
                        SBOX[rotated[0] as usize] ^ RCON[i / 4],
                        SBOX[rotated[1] as usize] >> 4,
                        !SBOX[rotated[2] as usize],
                        SBOX[rotated[3] as usize].rotate_right(7),
                    ],
                };
            }
            let j = i * 4;
            let p = (i - 4) * 4;
            for n in 0..4 {
                rk[j + n] = rk[p + n] ^ t[n];
            }
        }
        Self { round_keys: rk }
    }

    pub fn encrypt_block(&self, state: &mut [u8; BLOCK]) {
        self.add_round_key(state, 0);
        for round in 1..ROUNDS {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            self.add_round_key(state, round);
        }
        sub_bytes(state);
        shift_rows(state);
        self.add_round_key(state, ROUNDS);
    }

    fn add_round_key(&self, state: &mut [u8; BLOCK], round: usize) {
        for (s, k) in state.iter_mut().zip(&self.round_keys[round * BLOCK..]) {
            *s ^= k;
        }
    }
}

fn sub_bytes(state: &mut [u8; BLOCK]) {
    for s in state.iter_mut() {
        *s = SBOX[*s as usize];
    }
}

fn shift_rows(s: &mut [u8; BLOCK]) {
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    s.swap(2, 10);
    s.swap(6, 14);
    let t = s[3];
    s[3] = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = t;
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1B)
}

fn mix_columns(state: &mut [u8; BLOCK]) {
    for c in state.chunks_exact_mut(4) {
        let t = c[0];
        let all = c[0] ^ c[1] ^ c[2] ^ c[3];
        let c01 = xtime(c[0] ^ c[1]);
        let c12 = xtime(c[1] ^ c[2]);
        let c23 = xtime(c[2] ^ c[3]);
        let c30 = xtime(c[3] ^ t);
        c[0] ^= all ^ c01;
        c[1] ^= all ^ c12;
        c[2] ^= all ^ c23;
        c[3] ^= all ^ c30;
    }
}

/// AES-CTR with a 128-bit big-endian counter.
///
/// Every call to the original `aesCtrXCrypt` starts on a fresh block while the
/// counter keeps running, so a region's counter is the IV plus the number of
/// blocks consumed by earlier regions. [`AesCtr::xor_at`] addresses a byte
/// directly by its offset from the region start.
#[derive(Clone)]
pub struct AesCtr {
    aes: Aes128,
    iv: u128,
}

impl AesCtr {
    pub fn new(aes: Aes128, iv: [u8; 16]) -> Self {
        Self {
            aes,
            iv: u128::from_be_bytes(iv),
        }
    }

    /// Counter of the first block of a region that starts after
    /// `prior_bytes` bytes of earlier regions.
    pub fn counter_after(&self, prior_bytes: u64) -> u128 {
        self.iv
            .wrapping_add(u128::from(prior_bytes.div_ceil(BLOCK as u64)))
    }

    /// XOR `data`, which sits at `offset` bytes from the start of a region
    /// whose first block uses `counter`.
    pub fn xor_at(&self, counter: u128, offset: u64, data: &mut [u8]) {
        let mut block_idx = offset / BLOCK as u64;
        let mut in_block = (offset % BLOCK as u64) as usize;
        let mut pos = 0;
        while pos < data.len() {
            let mut ks = counter.wrapping_add(u128::from(block_idx)).to_be_bytes();
            self.aes.encrypt_block(&mut ks);
            let n = (BLOCK - in_block).min(data.len() - pos);
            for (d, k) in data[pos..pos + n].iter_mut().zip(&ks[in_block..]) {
                *d ^= k;
            }
            pos += n;
            in_block = 0;
            block_idx += 1;
        }
    }

    /// One call of the original `aesCtrXCrypt` over a whole buffer.
    pub fn xor_region(&self, counter: u128, data: &mut [u8]) {
        self.xor_at(counter, 0, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn standard_schedule_matches_fips197() {
        // FIPS-197 appendix C.1
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let mut block: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        Aes128::new(&key, KeySchedule::Standard).encrypt_block(&mut block);
        assert_eq!(block.to_vec(), hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[test]
    fn standard_ctr_matches_sp800_38a() {
        // NIST SP 800-38A F.5.1, first two blocks
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let iv: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let mut data = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ctr = AesCtr::new(Aes128::new(&key, KeySchedule::Standard), iv);
        ctr.xor_region(ctr.counter_after(0), &mut data);
        assert_eq!(
            data,
            hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff")
        );
    }

    #[test]
    fn xor_at_matches_contiguous_xor() {
        let ctr = AesCtr::new(Aes128::new(&[7; 16], KeySchedule::Wolf), [0xFF; 16]);
        let mut whole = vec![0u8; 100];
        ctr.xor_region(ctr.counter_after(0), &mut whole);
        let mut part = vec![0u8; 37];
        ctr.xor_at(ctr.counter_after(0), 41, &mut part);
        assert_eq!(part, whole[41..78]);
    }
}
