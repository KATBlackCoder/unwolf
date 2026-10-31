//! ChaCha20 (RFC 8439 block function) addressed by byte position.
//!
//! Wolf RPG starts the block counter at `1 + position / 64` and lets it carry
//! into the first nonce word, as the original `blockNext` does.

#[derive(Clone)]
pub struct ChaCha20 {
    key: [u32; 8],
    nonce: [u32; 3],
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            key: std::array::from_fn(|i| le32(&key[i * 4..])),
            nonce: std::array::from_fn(|i| le32(&nonce[i * 4..])),
        }
    }

    fn block(&self, counter: u64) -> [u8; 64] {
        let mut init = [0u32; 16];
        init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]);
        init[4..12].copy_from_slice(&self.key);
        // 64-bit counter over words 12 and 13, like the original carry.
        let nonce0 = u64::from(self.nonce[0]) << 32;
        let wide = nonce0.wrapping_add(counter);
        init[12] = counter as u32;
        init[13] = (wide >> 32) as u32;
        init[14] = self.nonce[1];
        init[15] = self.nonce[2];

        let mut x = init;
        for _ in 0..10 {
            quarter(&mut x, 0, 4, 8, 12);
            quarter(&mut x, 1, 5, 9, 13);
            quarter(&mut x, 2, 6, 10, 14);
            quarter(&mut x, 3, 7, 11, 15);
            quarter(&mut x, 0, 5, 10, 15);
            quarter(&mut x, 1, 6, 11, 12);
            quarter(&mut x, 2, 7, 8, 13);
            quarter(&mut x, 3, 4, 9, 14);
        }
        let mut out = [0u8; 64];
        for i in 0..16 {
            out[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(init[i]).to_le_bytes());
        }
        out
    }

    /// XOR `data` with the key stream starting at byte `position`.
    ///
    /// The original truncates the position to 32 bits.
    pub fn xor_at(&self, position: u64, data: &mut [u8]) {
        let pos = u64::from(position as u32);
        let mut counter = 1 + pos / 64;
        let mut offset = (pos % 64) as usize;
        let mut done = 0;
        while done < data.len() {
            let ks = self.block(counter);
            let n = (64 - offset).min(data.len() - done);
            for (d, k) in data[done..done + n].iter_mut().zip(&ks[offset..]) {
                *d ^= k;
            }
            done += n;
            offset = 0;
            counter += 1;
        }
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc8439_encryption_vector() {
        // RFC 8439 section 2.4.2: counter 1, so position 0 here.
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        ChaCha20::new(&key, &nonce).xor_at(0, &mut data);
        assert_eq!(
            &data[..16],
            &[
                0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
                0x69, 0x81
            ]
        );
        assert_eq!(data[113], 0x4d);
    }

    #[test]
    fn position_addressing_is_contiguous() {
        let c = ChaCha20::new(&[3; 32], &[9; 12]);
        let mut whole = vec![0u8; 300];
        c.xor_at(0, &mut whole);
        let mut part = vec![0u8; 100];
        c.xor_at(77, &mut part);
        assert_eq!(part, whole[77..177]);
    }
}
