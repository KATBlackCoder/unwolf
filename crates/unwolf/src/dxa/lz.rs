//! DX Library LZ compression.
//!
//! Stream layout: `u32 decoded size`, `u32 stream size including this 9-byte
//! header`, `u8 marker`, then tokens. A byte other than the marker is a
//! literal. `marker marker` is a literal marker byte. Otherwise the byte after
//! the marker is a code `c` (decremented when above the marker):
//! length = `c >> 3` (plus `next << 5` when bit 2 is set) + 4, then a distance
//! of `(c & 3) + 1` little-endian bytes, minus one.

use crate::error::{Error, Result};

const HEADER: usize = 9;
const MIN_MATCH: usize = 4;
/// Upper bound of the expansion ratio, used to reject absurd sizes before
/// allocating: the longest match (8195 bytes) costs at least 4 input bytes.
const MAX_RATIO: u64 = 2100;

/// Read the decoded size from an LZ header without decoding.
pub fn decoded_len(src: &[u8]) -> Result<usize> {
    if src.len() < HEADER {
        return Err(Error::format("LZ stream shorter than its header"));
    }
    Ok(u32::from_le_bytes([src[0], src[1], src[2], src[3]]) as usize)
}

/// Decode a complete LZ stream. `expected` is the size the container
/// announces; a mismatch means a wrong key or a corrupt archive.
pub fn decode(src: &[u8], expected: u64) -> Result<Vec<u8>> {
    let dest_len = decoded_len(src)?;
    let stream_len = u32::from_le_bytes([src[4], src[5], src[6], src[7]]) as usize;
    if dest_len as u64 != expected {
        return Err(Error::format("LZ decoded size does not match the entry"));
    }
    if stream_len < HEADER || stream_len > src.len() {
        return Err(Error::format("LZ stream size out of range"));
    }
    if dest_len as u64 > (stream_len as u64) * MAX_RATIO + 64 {
        return Err(Error::format("LZ decoded size is implausible"));
    }

    let marker = src[8];
    let body = &src[HEADER..stream_len];
    let mut out = Vec::with_capacity(dest_len);
    let mut i = 0;
    let truncated = || Error::format("truncated LZ stream");

    while i < body.len() {
        let b = body[i];
        if b != marker {
            out.push(b);
            i += 1;
            continue;
        }
        let mut code = *body.get(i + 1).ok_or_else(truncated)?;
        i += 2;
        if code == marker {
            out.push(marker);
            continue;
        }
        if code > marker {
            code -= 1;
        }
        let mut len = usize::from(code >> 3);
        if code & 0x4 != 0 {
            len |= usize::from(*body.get(i).ok_or_else(truncated)?) << 5;
            i += 1;
        }
        len += MIN_MATCH;
        let width = usize::from(code & 0x3) + 1;
        if width == 4 {
            // Width code 3 is never produced by the encoder.
            return Err(Error::format("invalid LZ distance width"));
        }
        let bytes = body.get(i..i + width).ok_or_else(truncated)?;
        let mut dist = 0usize;
        for (k, v) in bytes.iter().enumerate() {
            dist |= usize::from(*v) << (8 * k);
        }
        dist += 1;
        i += width;

        if dist > out.len() {
            return Err(Error::format("LZ back-reference before start"));
        }
        if out.len() + len > dest_len {
            return Err(Error::format("LZ output exceeds its declared size"));
        }
        let start = out.len() - dist;
        for k in 0..len {
            let v = out[start + k];
            out.push(v);
        }
    }

    if out.len() != dest_len {
        return Err(Error::format("LZ output shorter than its declared size"));
    }
    Ok(out)
}

/// Longest match a token can describe: 5 + 8 bits of length beyond the
/// minimum.
const MAX_MATCH: usize = MIN_MATCH + (1 << 13) - 1;
/// Distances are stored on up to 3 bytes.
const MAX_DIST: usize = 1 << 24;
const HASH_BITS: u32 = 16;
/// Candidates examined per position: a speed/ratio trade-off.
const CHAIN_LIMIT: usize = 32;
/// After 32 searches in a row without a match, positions are searched one
/// byte in two, then one in three... up to one in `MAX_SKIP`; the skipped
/// bytes are literals. Incompressible data (PCM audio) is then scanned in
/// a fraction of the time. The count restarts at the next match.
const SKIP_SHIFT: u32 = 5;
const MAX_SKIP: usize = 256;
const NO_POS: u32 = u32::MAX;

fn hash4(b: &[u8]) -> usize {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// Bytes needed to store `dist - 1`.
fn dist_width(dist: usize) -> usize {
    match dist - 1 {
        d if d < 1 << 8 => 1,
        d if d < 1 << 16 => 2,
        _ => 3,
    }
}

/// Encode `src` in the DX Library LZ format read by [`decode`]: greedy
/// matching over hash chains, with the least frequent byte as marker.
/// The output differs from the DX Library encoder but decodes the same.
pub fn encode(src: &[u8]) -> Vec<u8> {
    let mut counts = [0usize; 256];
    for &b in src {
        counts[usize::from(b)] += 1;
    }
    let marker = (0..=255u8)
        .min_by_key(|&b| counts[usize::from(b)])
        .unwrap_or(0);

    let mut out = vec![0u8; HEADER];
    let mut head = vec![NO_POS; 1 << HASH_BITS];
    let mut prev = vec![NO_POS; src.len()];
    let insert = |pos: usize, head: &mut Vec<u32>, prev: &mut Vec<u32>| {
        if pos + MIN_MATCH <= src.len() {
            let h = hash4(&src[pos..]);
            prev[pos] = head[h];
            head[h] = pos as u32;
        }
    };

    let mut i = 0;
    let mut misses = 0usize;
    while i < src.len() {
        let (mut best_len, mut best_dist) = (0, 0);
        if i + MIN_MATCH <= src.len() {
            let max = MAX_MATCH.min(src.len() - i);
            let mut cand = head[hash4(&src[i..])];
            let mut chain = 0;
            while cand != NO_POS && chain < CHAIN_LIMIT {
                let c = cand as usize;
                let dist = i - c;
                if dist > MAX_DIST {
                    break;
                }
                let l = src[c..]
                    .iter()
                    .zip(&src[i..i + max])
                    .take_while(|(a, b)| a == b)
                    .count();
                if l > best_len {
                    best_len = l;
                    best_dist = dist;
                    if l == max {
                        break;
                    }
                }
                cand = prev[c];
                chain += 1;
            }
        }

        let token_len =
            |len: usize, dist: usize| 2 + usize::from(len - MIN_MATCH >= 32) + dist_width(dist);
        if best_len >= MIN_MATCH && token_len(best_len, best_dist) < best_len {
            let extra = best_len - MIN_MATCH;
            let width = dist_width(best_dist);
            let mut code = ((extra & 0x1F) << 3) as u8 | (width - 1) as u8;
            if extra >= 32 {
                code |= 0x4;
            }
            // The decoder treats `marker marker` as a literal and decrements
            // codes above the marker.
            if code >= marker {
                code += 1;
            }
            out.push(marker);
            out.push(code);
            if extra >= 32 {
                out.push((extra >> 5) as u8);
            }
            out.extend_from_slice(&((best_dist - 1) as u32).to_le_bytes()[..width]);
            for p in i..i + best_len {
                insert(p, &mut head, &mut prev);
            }
            i += best_len;
            misses = 0;
        } else {
            let step = (1 + (misses >> SKIP_SHIFT))
                .min(MAX_SKIP)
                .min(src.len() - i);
            insert(i, &mut head, &mut prev);
            for &b in &src[i..i + step] {
                out.push(b);
                if b == marker {
                    out.push(marker);
                }
            }
            i += step;
            misses += 1;
        }
    }

    let stream_len = out.len() as u32;
    out[0..4].copy_from_slice(&(src.len() as u32).to_le_bytes());
    out[4..8].copy_from_slice(&stream_len.to_le_bytes());
    out[8] = marker;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(dest: u32, marker: u8, body: &[u8]) -> Vec<u8> {
        let mut v = dest.to_le_bytes().to_vec();
        v.extend_from_slice(&((body.len() + HEADER) as u32).to_le_bytes());
        v.push(marker);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn literals_escape_and_overlapping_copy() {
        // "ab" then copy len 4 at distance 2 -> "ababab", then a literal marker.
        // code: len-4 = 0 -> bits 3.. = 0, width 1 -> code 0; 0 < marker so no shift.
        let s = stream(7, 0xFF, &[b'a', b'b', 0xFF, 0x00, 0x01, 0xFF, 0xFF]);
        assert_eq!(decode(&s, 7).unwrap(), b"ababab\xFF".to_vec());
    }

    fn round_trip(data: &[u8]) -> usize {
        let enc = encode(data);
        assert_eq!(decode(&enc, data.len() as u64).unwrap(), data);
        enc.len()
    }

    #[test]
    fn encoder_round_trips() {
        assert_eq!(round_trip(b""), HEADER);
        round_trip(b"a");
        round_trip(&(0..=255u8).collect::<Vec<_>>());
        // Every byte value present, so the marker occurs as a literal.
        let mut all: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        all.extend(std::iter::repeat_n(b'x', 20_000));
        round_trip(&all);
        // Long runs: matches longer than one token, distance 1.
        assert!(round_trip(&vec![0u8; 100_000]) < 200);
        // Far matches need 3-byte distances.
        let mut far: Vec<u8> = (0..70_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let head = far[..1000].to_vec();
        far.extend_from_slice(&head);
        round_trip(&far);
    }

    #[test]
    fn skips_incompressible_data_then_compresses_again() {
        // 1 MB without repeats: the step reaches its cap.
        let mut x = 0x1234_5678u32;
        let mut data: Vec<u8> = (0..1_000_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let noise = data.len();
        // Then a repetitive zone: the first match resets the step.
        data.extend(b"wolf archive ".iter().cycle().take(200_000));
        let n = round_trip(&data);
        assert!(n < noise + noise / 100 + 2_000, "{n}");
    }

    #[test]
    fn rejects_bad_sizes_and_references() {
        let s = stream(3, 0xFF, b"abc");
        assert!(decode(&s, 4).is_err());
        let s = stream(5, 0xFF, &[b'a', 0xFF, 0x00, 0x05]);
        assert!(decode(&s, 5).is_err());
        assert!(decode(&[1, 2, 3], 0).is_err());
    }
}
