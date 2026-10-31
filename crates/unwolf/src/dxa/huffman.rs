//! DX Library Huffman compression (DXA v8).
//!
//! The header is an MSB-first bit stream: a 6-bit width then the original
//! size, a 6-bit width then the compressed size, then 256 symbol weights
//! stored as deltas (3-bit half width, sign bit, magnitude). Both sides build
//! the same tree from the weights: 256 leaves, then 255 merges of the two
//! lightest free nodes, scanning in index order with strict comparisons. The
//! body stores codes LSB-first, root to leaf, child 0 being the lighter node.

use crate::error::{Error, Result};

const LEAVES: usize = 256;
const ROOT: usize = LEAVES * 2 - 2;

struct BitReader<'a> {
    data: &'a [u8],
    byte: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte: 0,
            bit: 0,
        }
    }

    /// Read `n` bits, most significant first.
    fn read_msb(&mut self, n: u32) -> Result<u64> {
        let mut v = 0u64;
        for _ in 0..n {
            let b = *self
                .data
                .get(self.byte)
                .ok_or_else(|| Error::format("truncated Huffman header"))?;
            v = (v << 1) | u64::from((b >> (7 - self.bit)) & 1);
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.byte += 1;
            }
        }
        Ok(v)
    }

    fn consumed_bytes(&self) -> usize {
        self.byte + usize::from(self.bit != 0)
    }
}

struct Header {
    original: u64,
    weights: [u16; LEAVES],
    body_start: usize,
}

fn read_header(data: &[u8]) -> Result<Header> {
    let mut r = BitReader::new(data);
    let w = r.read_msb(6)? as u32 + 1;
    let original = r.read_msb(w)?;
    let w = r.read_msb(6)? as u32 + 1;
    let _compressed = r.read_msb(w)?;
    let mut weights = [0u16; LEAVES];
    for i in 0..LEAVES {
        let bits = (r.read_msb(3)? as u32 + 1) * 2;
        let minus = r.read_msb(1)? == 1;
        let delta = r.read_msb(bits)? as u16;
        weights[i] = if i == 0 {
            delta
        } else if minus {
            weights[i - 1].wrapping_sub(delta)
        } else {
            weights[i - 1].wrapping_add(delta)
        };
    }
    Ok(Header {
        original,
        weights,
        body_start: r.consumed_bytes(),
    })
}

/// Children of the internal nodes, indexed by `node - 256`.
fn build_tree(weights: &[u16; LEAVES]) -> Vec<[usize; 2]> {
    let mut weight: Vec<u64> = weights.iter().map(|&w| u64::from(w)).collect();
    let mut free: Vec<usize> = (0..LEAVES).collect();
    let mut children = Vec::with_capacity(LEAVES - 1);
    while free.len() > 1 {
        let mut min1: Option<usize> = None;
        let mut min2: Option<usize> = None;
        for &n in &free {
            match min1 {
                Some(m) if weight[m] <= weight[n] => {
                    if min2.is_none_or(|m2| weight[m2] > weight[n]) {
                        min2 = Some(n);
                    }
                }
                _ => {
                    min2 = min1;
                    min1 = Some(n);
                }
            }
        }
        let (a, b) = match (min1, min2) {
            (Some(a), Some(b)) => (a, b),
            _ => unreachable!("at least two free nodes"),
        };
        free.retain(|&n| n != a && n != b);
        let new = weight.len();
        weight.push(weight[a] + weight[b]);
        children.push([a, b]);
        free.push(new);
    }
    children
}

/// Size of the decoded data, read from the header only.
pub fn decoded_len(data: &[u8]) -> Result<u64> {
    Ok(read_header(data)?.original)
}

/// Decode a Huffman stream whose decoded size must be `expected`.
pub fn decode(data: &[u8], expected: u64) -> Result<Vec<u8>> {
    let h = read_header(data)?;
    if h.original != expected {
        return Err(Error::format("Huffman decoded size does not match"));
    }
    let body = data
        .get(h.body_start..)
        .ok_or_else(|| Error::format("truncated Huffman body"))?;
    // Every symbol costs at least one bit.
    if h.original > body.len() as u64 * 8 {
        return Err(Error::format("Huffman decoded size is implausible"));
    }
    let children = build_tree(&h.weights);

    let mut out = Vec::with_capacity(h.original as usize);
    let mut byte = 0usize;
    let mut bit = 0u8;
    for _ in 0..h.original {
        let mut node = ROOT;
        while node >= LEAVES {
            let b = *body
                .get(byte)
                .ok_or_else(|| Error::format("truncated Huffman body"))?;
            let dir = (b >> bit) & 1;
            bit += 1;
            if bit == 8 {
                bit = 0;
                byte += 1;
            }
            node = children[node - LEAVES][usize::from(dir)];
        }
        out.push(node as u8);
    }
    Ok(out)
}

/// MSB-first bit writer for the Huffman header.
struct BitWriter {
    out: Vec<u8>,
    bits: u32,
}

impl BitWriter {
    fn put(&mut self, v: u64, n: u32) {
        for i in (0..n).rev() {
            if self.bits % 8 == 0 {
                self.out.push(0);
            }
            if (v >> i) & 1 == 1 {
                let last = self.out.len() - 1;
                self.out[last] |= 1 << (7 - self.bits % 8);
            }
            self.bits += 1;
        }
    }
}

/// Bits needed to store `v`, at least 1 (`BitStream_GetBitNum`).
fn bit_num(v: u64) -> u32 {
    (64 - v.leading_zeros()).max(1)
}

/// Encode `src` in the DX Library Huffman format read by [`decode`].
///
/// Weights are the symbol counts scaled to 16 bits, as the DX Library
/// encoder stores them, so the tree is the one its decoder rebuilds.
pub fn encode(src: &[u8]) -> Vec<u8> {
    let mut counts = [0u64; LEAVES];
    for &b in src {
        counts[usize::from(b)] += 1;
    }
    let total = src.len().max(1) as u64;
    let weights: [u16; LEAVES] = std::array::from_fn(|i| (counts[i] * 0xFFFF / total) as u16);

    // Codes, root to leaf.
    let children = build_tree(&weights);
    let mut parent = vec![(usize::MAX, 0u8); ROOT + 1];
    for (k, c) in children.iter().enumerate() {
        parent[c[0]] = (k + LEAVES, 0);
        parent[c[1]] = (k + LEAVES, 1);
    }
    let codes: Vec<Vec<u8>> = (0..LEAVES)
        .map(|leaf| {
            let mut path = Vec::new();
            let mut n = leaf;
            while n != ROOT {
                let (p, d) = parent[n];
                path.push(d);
                n = p;
            }
            path.reverse();
            path
        })
        .collect();

    // Body: codes packed LSB-first; at least one byte, as the original.
    let mut body = vec![0u8];
    let mut bit = 0u32;
    for &s in src {
        for &d in &codes[usize::from(s)] {
            if bit == 8 {
                body.push(0);
                bit = 0;
            }
            let last = body.len() - 1;
            body[last] |= d << bit;
            bit += 1;
        }
    }

    let mut h = BitWriter {
        out: Vec::new(),
        bits: 0,
    };
    for v in [src.len() as u64, body.len() as u64] {
        let n = bit_num(v);
        h.put(u64::from(n - 1), 6);
        h.put(v, n);
    }
    let mut prev = 0i32;
    for (i, &w) in weights.iter().enumerate() {
        let delta = if i == 0 {
            i32::from(w)
        } else {
            i32::from(w) - prev
        };
        prev = i32::from(w);
        let mag = u64::from(delta.unsigned_abs());
        let half = bit_num(mag).div_ceil(2).saturating_sub(1);
        h.put(u64::from(half), 3);
        h.put(u64::from(delta < 0), 1);
        h.put(mag, (half + 1) * 2);
    }
    let mut out = h.out;
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data: Vec<u8> = (0..5000u32).map(|i| ((i * i) % 17) as u8).collect();
        let enc = encode(&data);
        assert_eq!(decode(&enc, data.len() as u64).unwrap(), data);
        assert!(decode(&enc, data.len() as u64 + 1).is_err());
    }

    #[test]
    fn edge_inputs() {
        for data in [
            vec![],
            vec![7u8],
            vec![0u8; 100],
            (0..=255u8).collect::<Vec<_>>(),
        ] {
            let enc = encode(&data);
            assert_eq!(decode(&enc, data.len() as u64).unwrap(), data);
        }
    }

    #[test]
    fn header_stores_the_body_size() {
        let data = b"abracadabra".repeat(50);
        let enc = encode(&data);
        let mut r = BitReader::new(&enc);
        let w = r.read_msb(6).unwrap() as u32 + 1;
        assert_eq!(r.read_msb(w).unwrap(), data.len() as u64);
        let w = r.read_msb(6).unwrap() as u32 + 1;
        let body = r.read_msb(w).unwrap() as usize;
        assert_eq!(enc.len() - read_header(&enc).unwrap().body_start, body);
    }

    #[test]
    fn garbage_does_not_panic() {
        for seed in 0..200u32 {
            let g: Vec<u8> = (0..300u32)
                .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed * 7)) as u8)
                .collect();
            let _ = decode(&g, 100);
        }
    }
}
