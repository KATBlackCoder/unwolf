//! LZ encoder throughput, release build:
//!
//! ```text
//! cargo run --release -p unwolf --example lz_bench               # synthetic, 20 MB each
//! cargo run --release -p unwolf --example lz_bench -- a.wav ...  # given files
//! ```
//!
//! Prints MB/s, the time that rate gives for 1.1 GB, and the LZ ratio
//! (output / input). Every result is decoded again and compared with the
//! input.
use std::time::Instant;

use unwolf::dxa::lz;

const SIZE: usize = 20_000_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Uniform in `[-a, a]`.
    fn noise(&mut self, a: i32) -> i32 {
        if a == 0 {
            return 0;
        }
        (self.next() % (2 * a as u64 + 1)) as i32 - a
    }
}

/// 16-bit stereo PCM at 44.1 kHz: two tones at `amp` of full scale, plus
/// uniform noise of ±`noise` LSB.
fn pcm(seed: u64, amp: f64, noise: i32) -> Vec<u8> {
    let mut r = Rng(seed);
    let mut v = Vec::with_capacity(SIZE + 4);
    let mut n = 0u64;
    while v.len() < SIZE {
        let t = n as f64 / 44_100.0;
        let base = amp * 32767.0;
        for f in [440.0, 554.37] {
            let s = base * (2.0 * std::f64::consts::PI * f * t).sin();
            let x = (s.round() as i32 + r.noise(noise)).clamp(-32768, 32767) as i16;
            v.extend_from_slice(&x.to_le_bytes());
        }
        n += 1;
    }
    v.truncate(SIZE);
    v
}

/// 2 s of music-like PCM, then 1 s of dithered silence, repeated.
fn mixed(seed: u64) -> Vec<u8> {
    let music = pcm(seed, 0.3, 256);
    let quiet = pcm(seed + 1, 0.0, 1);
    let (m, q) = (2 * 176_400, 176_400);
    let mut v = Vec::with_capacity(SIZE + m + q);
    let mut k = 0;
    while v.len() < SIZE {
        v.extend_from_slice(&music[k * m % (SIZE - m)..][..m]);
        v.extend_from_slice(&quiet[k * q % (SIZE - q)..][..q]);
        k += 1;
    }
    v.truncate(SIZE);
    v
}

/// Random words from a small vocabulary, with punctuation and line breaks.
fn text(seed: u64) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "of",
        "and",
        "to",
        "in",
        "a",
        "is",
        "that",
        "for",
        "it",
        "as",
        "was",
        "with",
        "be",
        "by",
        "on",
        "not",
        "he",
        "this",
        "are",
        "or",
        "his",
        "from",
        "at",
        "which",
        "but",
        "have",
        "an",
        "had",
        "they",
        "you",
        "were",
        "their",
        "one",
        "all",
        "we",
        "can",
        "her",
        "has",
        "there",
        "been",
        "if",
        "more",
        "when",
        "will",
        "would",
        "who",
        "so",
        "no",
        "archive",
        "folder",
        "wolf",
        "event",
        "map",
        "variable",
        "string",
        "common",
        "database",
        "picture",
        "sound",
        "music",
        "player",
        "enemy",
        "skill",
        "item",
        "weapon",
        "armor",
        "state",
        "battle",
        "switch",
        "message",
        "choice",
        "地図",
        "変数",
        "文字列",
        "イベント",
        "画像",
        "効果音",
        "戦闘",
        "主人公",
    ];
    let mut r = Rng(seed);
    let mut v = Vec::with_capacity(SIZE + 32);
    let mut col = 0;
    while v.len() < SIZE {
        let w = WORDS[(r.next() % WORDS.len() as u64) as usize];
        v.extend_from_slice(w.as_bytes());
        col += w.len() + 1;
        match r.next() % 16 {
            0 => v.extend_from_slice(b". "),
            1 => v.extend_from_slice(b", "),
            _ => v.push(b' '),
        }
        if col > 70 {
            v.push(b'\n');
            col = 0;
        }
    }
    v.truncate(SIZE);
    v
}

fn synthetic() -> Vec<(String, Vec<u8>)> {
    vec![
        ("pcm sine (pure)".into(), pcm(1, 0.3, 0)),
        ("pcm sine + noise 8 LSB".into(), pcm(2, 0.3, 8)),
        ("pcm sine + noise 256 LSB".into(), pcm(3, 0.3, 256)),
        ("pcm silence (zeros)".into(), vec![0u8; SIZE]),
        ("pcm silence + dither 1 LSB".into(), pcm(4, 0.0, 1)),
        ("pcm silence + noise 8 LSB".into(), pcm(5, 0.0, 8)),
        ("pcm music 2s / silence 1s".into(), mixed(7)),
        ("text".into(), text(6)),
    ]
}

fn main() {
    let files: Vec<String> = std::env::args().skip(1).collect();
    println!(
        "{:<40} {:>10} {:>8} {:>9} {:>7}",
        "input", "bytes", "MB/s", "s/1.1GB", "ratio"
    );
    let measure = |name: &str, d: &[u8]| -> (usize, f64) {
        let t = Instant::now();
        let enc = lz::encode(d);
        let s = t.elapsed().as_secs_f64();
        let back = lz::decode(&enc, d.len() as u64).expect("decode");
        assert!(back == d, "round trip failed: {name}");
        let mbs = d.len() as f64 / 1e6 / s;
        println!(
            "{:<40} {:>10} {:>8.2} {:>9.0} {:>7.3}",
            name,
            d.len(),
            mbs,
            1.1e3 / mbs,
            enc.len() as f64 / d.len().max(1) as f64
        );
        (enc.len(), s)
    };
    if files.is_empty() {
        for (name, d) in synthetic() {
            measure(&name, &d);
        }
        return;
    }
    let (mut total_in, mut total_out, mut total_s) = (0usize, 0usize, 0f64);
    for f in &files {
        let d = std::fs::read(f).unwrap_or_else(|e| panic!("{f}: {e}"));
        let name = std::path::Path::new(f)
            .file_name()
            .map_or_else(|| f.clone(), |n| n.to_string_lossy().into_owned());
        let (out, s) = measure(&name, &d);
        total_in += d.len();
        total_out += out;
        total_s += s;
    }
    if files.len() > 1 {
        println!(
            "{:<40} {:>10} {:>8.2} {:>9.0} {:>7.3}",
            "TOTAL",
            total_in,
            total_in as f64 / 1e6 / total_s,
            1.1e3 / (total_in as f64 / 1e6 / total_s),
            total_out as f64 / total_in.max(1) as f64
        );
    }
}
