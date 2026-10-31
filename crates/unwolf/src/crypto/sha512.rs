//! SHA-512 with the three Wolf RPG Pro modifications.
//!
//! Wolf RPG uses its own initial hash values, XORs the choice term with
//! `e >> 3` in every round and XORs each working variable with
//! `0x123456789ABCDEF0` before adding it back into the hash state.
//! [`Variant::Standard`] keeps plain SHA-512 so the code can be checked
//! against FIPS 180-4 vectors.

const WOLF_H0: [u64; 8] = [
    0x123456789ABCDEF0,
    0xFEDCBA9876543210,
    0x0F1E2D3C4B5A6978,
    0x89ABCDEF01234567,
    0x13579BDF02468ACE,
    0xF0E1D2C3B4A59687,
    0x5A6B7C8D9E0F1A2B,
    0x1A2B3C4D5E6F7890,
];

const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const WOLF_STATE_XOR: u64 = 0x1234_5678_9ABC_DEF0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Wolf,
    /// FIPS 180-4 SHA-512 (tests only).
    Standard,
}

/// Hash `msg` and return the eight state words.
pub fn hash(msg: &[u8], variant: Variant) -> [u64; 8] {
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&(u128::from(msg.len() as u64) * 8).to_be_bytes());

    let mut h = match variant {
        Variant::Wolf => WOLF_H0,
        Variant::Standard => H0,
    };
    for block in padded.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, word) in block.chunks_exact(8).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(word);
            w[i] = u64::from_be_bytes(b);
        }
        for j in 16..80 {
            w[j] = w[j - 16]
                .wrapping_add(small_sig0(w[j - 15]))
                .wrapping_add(w[j - 7])
                .wrapping_add(small_sig1(w[j - 2]));
        }

        let mut s = h;
        for j in 0..80 {
            let ch = (s[4] & s[5]) ^ (!s[4] & s[6]);
            let ch = match variant {
                Variant::Wolf => (s[4] >> 3) ^ ch,
                Variant::Standard => ch,
            };
            let t1 = s[7]
                .wrapping_add(big_sig1(s[4]))
                .wrapping_add(ch)
                .wrapping_add(K[j])
                .wrapping_add(w[j]);
            let maj = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
            let t2 = big_sig0(s[0]).wrapping_add(maj);
            s[7] = s[6];
            s[6] = s[5];
            s[5] = s[4];
            s[4] = s[3].wrapping_add(t1);
            s[3] = s[2];
            s[2] = s[1];
            s[1] = s[0];
            s[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            let v = match variant {
                Variant::Wolf => s[i] ^ WOLF_STATE_XOR,
                Variant::Standard => s[i],
            };
            h[i] = h[i].wrapping_add(v);
        }
    }
    h
}

/// The lowercase hexadecimal digest string, as built by UberWolf's `digest`.
pub fn hex_digest(state: &[u64; 8]) -> String {
    state.iter().map(|w| format!("{w:016x}")).collect()
}

fn big_sig0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn big_sig1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn small_sig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn small_sig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_variant_matches_fips180() {
        let abc = hex_digest(&hash(b"abc", Variant::Standard));
        assert_eq!(
            abc,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let empty = hex_digest(&hash(b"", Variant::Standard));
        assert!(empty.starts_with("cf83e1357eefb8bdf1542850d66d8007"));
    }

    #[test]
    fn wolf_variant_differs() {
        assert_ne!(hash(b"abc", Variant::Wolf), hash(b"abc", Variant::Standard));
    }
}
