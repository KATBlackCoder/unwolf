//! `-x`: decrypt `.wolfx` files (`WolfX/` and `WolfXWrapper.cpp` in
//! UberWolfLib).
//!
//! A `.wolfx` file is XORed with a 256-byte stream derived from a key set
//! by the game (`SetWolfxKey`, a Pro command), then perturbed by the values
//! of one string variable and one integer variable whose indices are stored
//! in the file header. Nothing is brute-forced: the candidate keys and
//! values are read from the game's own commands, and five checksum bytes
//! stored in the file confirm a candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, IoContext, Result};
use crate::fsutil::has_extension_ci;
use crate::wolfrpg::command::{self, Command};
use crate::wolfrpg::common_event::CommonEventFile;
use crate::wolfrpg::decode_string;
use crate::wolfrpg::map::MapFile;

pub const WOLFX_MAGIC: &[u8; 5] = b"WOLFX";

/// [`WOLFX_MAGIC`] as numbers, for `scripts/check-constants.py`.
#[cfg(test)]
pub fn wolfx_magic_bytes() -> [u8; 5] {
    [0x57, 0x4F, 0x4C, 0x46, 0x58]
}
pub const WOLFX_EXTENSION: &str = "wolfx";

/// Bytes 10..15 hold the encrypted string and integer indices, 15..20 the
/// checksum; the data starts after a key-dependent offset.
const HEADER_LEN: usize = 15;
const STATIC_BLOB_LEN: usize = 64;
const BLOB_LEN: usize = 256;
/// Indices at or above these values mean "no string" / "no integer".
const STRING_INDEX_LIMIT: u32 = 10_000;
const INT_INDEX_LIMIT: u32 = 1_000_000;

type StaticBlob = [u8; STATIC_BLOB_LEN];
type Blob = [u8; BLOB_LEN];

/// Candidate keys and variable values (`WolfXDecryptCollection`).
#[derive(Debug, Clone, Default)]
pub struct Candidates {
    /// `SetWolfxKey` keys, in the original order (sorted by folder then key);
    /// the folder plays no part in decryption, so duplicates are dropped.
    pub keys: Vec<Vec<u8>>,
    pub strings: BTreeMap<u32, BTreeSet<Vec<u8>>>,
    pub ints: BTreeMap<u32, BTreeSet<u32>>,
}

/// Collects candidates from commands (`collectWolfXDecryptionInfo`).
#[derive(Debug, Default)]
pub struct Collector {
    /// (folder, key), UTF-8 encoded like the original's `ws2s`.
    keys: BTreeSet<(Vec<u8>, Vec<u8>)>,
    strings: BTreeMap<u32, BTreeSet<Vec<u8>>>,
    ints: BTreeMap<u32, BTreeSet<u32>>,
}

impl Collector {
    pub fn new() -> Self {
        let mut c = Self::default();
        // The default (empty) key is always tried.
        c.keys.insert((b"/".to_vec(), Vec::new()));
        c
    }

    /// Record `SetString`, `SetVariable` and `SetWolfxKey` commands.
    /// `data` is the buffer the string fields point into.
    pub fn add(&mut self, commands: &[Command], data: &[u8], utf8: bool) {
        // Strings are decoded, then stored as UTF-8 (`ToUTF8`, `ws2s`).
        let text = |c: &Command, i: usize| -> Vec<u8> {
            c.strings
                .get(i)
                .map(|f| decode_string(&data[f.content.clone()], utf8).into_bytes())
                .unwrap_or_default()
        };
        for c in commands {
            match c.code {
                command::SET_STRING => {
                    let id = match c.args.first() {
                        Some(&a) if (3_000_000..4_000_000).contains(&a) => a % 1_000_000,
                        Some(&a) => a,
                        None => 0,
                    };
                    self.strings.entry(id).or_default().insert(text(c, 0));
                }
                command::SET_VARIABLE => {
                    let id = match c.args.first() {
                        Some(&a) if (2_000_000..3_000_000).contains(&a) => a - 2_000_000,
                        Some(&a) => a,
                        None => 0,
                    };
                    // The original ignores the operation in args[2..].
                    let value = c.args.get(1).copied().unwrap_or(0);
                    self.ints.entry(id).or_default().insert(value);
                }
                command::PRO_FEATURE
                    if c.args.first() == Some(&command::PRO_FEATURE_SET_WOLFX_KEY) =>
                {
                    self.keys.insert((text(c, 0), text(c, 1)));
                }
                _ => {}
            }
        }
    }

    pub fn finish(self) -> Candidates {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for (_, k) in self.keys {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        Candidates {
            keys,
            strings: self.strings,
            ints: self.ints,
        }
    }
}

/// `generateWolfxStaticBlob`.
fn static_blob(key: &[u8]) -> StaticBlob {
    let mut d = [0xAAu8; STATIC_BLOB_LEN];
    let mut dynamic: u8 = 0xBE;
    for (i, &k) in key.iter().enumerate() {
        let x = &mut d[i % STATIC_BLOB_LEN];
        *x = (*x ^ k).wrapping_add(dynamic).rotate_left(3);
        dynamic = k ^ 0xB3u8.wrapping_mul(dynamic);
    }
    for _ in 0..5 {
        for j in 0..STATIC_BLOB_LEN {
            let prev = d[(j + 13) % STATIC_BLOB_LEN];
            let mix = d[j] ^ d[(j + 7) % STATIC_BLOB_LEN];
            d[j] = prev.wrapping_add(mix).rotate_right(7);
        }
    }
    d.map(|b| if b == 0 { 1 } else { b })
}

/// 32-bit FNV-1.
fn fnv1(data: &[u8]) -> u32 {
    data.iter().fold(0x811C_9DC5u32, |h, &b| {
        0x0100_0193u32.wrapping_mul(h ^ u32::from(b))
    })
}

/// `generateWolfxDecryptBlob`: a LCG stream seeded from the static blob.
fn decrypt_blob(mut seed: u32, sb: &StaticBlob) -> Blob {
    for &b in sb {
        seed ^= u32::from(b);
    }
    std::array::from_fn(|_| {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        seed as u8
    })
}

fn be(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |acc, &b| (acc << 8) | u32::from(b))
}

/// Everything derived from a file and a key, before the variable values.
struct KeyState {
    blob: Blob,
    data_offset: usize,
    /// Decrypted bytes 10..15: string index (2 bytes, big-endian) and the
    /// low 3 bytes of the integer index.
    header: [u8; 5],
}

impl KeyState {
    /// `tryDecryptP1` up to the variable lookup. `None` when the key gives
    /// a data offset past the end of the file.
    fn new(enc: &[u8], key: &[u8]) -> Option<Self> {
        let sb = static_blob(key);
        let data_offset = 512 + usize::from(sb[0]) + usize::from(sb[1]);
        if data_offset >= enc.len() {
            return None;
        }
        let seed = fnv1(&sb) ^ be(&enc[5..9]);
        let blob = decrypt_blob(seed, &sb);
        let header = std::array::from_fn(|i| enc[10 + i] ^ blob[i]);
        Some(Self {
            blob,
            data_offset,
            header,
        })
    }

    fn string_index(&self) -> u32 {
        be(&self.header[..2])
    }

    fn int_index(&self, string: &[u8]) -> u32 {
        let h = fnv1(string);
        ((h & 0xFFFF_0000) >> 8) ^ (h & 0xFFFF) ^ be(&self.header[2..5])
    }

    /// `tryDecryptP3`'s key transformation. `int` is `None` when the file
    /// uses no integer variable.
    fn final_blob(&self, string: &[u8], int: Option<u32>) -> Blob {
        let int_index = self.int_index(string).to_be_bytes();
        let mod_val = [int_index[1], int_index[2], int_index[3]];
        let int_mod = int
            .map(|v| ((v << 13) ^ 73_244_475u32.wrapping_mul(v)).to_be_bytes())
            .unwrap_or_default();
        let mut b = self.blob;
        for (i, x) in b.iter_mut().enumerate() {
            let magic = if string.is_empty() {
                0
            } else {
                string[i % string.len()]
            };
            *x ^= self.header[i % 2] ^ magic ^ int_mod[i & 3] ^ mod_val[i % 3];
        }
        b
    }
}

/// Byte `i` (>= 15) of the decrypted file (`xorBufferBlob`).
fn plain_at(enc: &[u8], blob: &Blob, i: usize) -> u8 {
    enc[i] ^ blob[(i - 10) % BLOB_LEN]
}

/// `validateChecksum`: five bytes spread over the data must equal bytes
/// 15..20. Only these ten bytes are decrypted.
fn checksum_ok(enc: &[u8], blob: &Blob, data_offset: usize) -> bool {
    let last = (enc.len() - data_offset - 1) as u64;
    (0..5u64).all(|i| {
        // `(size_t)(finalIdx * 0.25 * i)`: exact in double, so floor(x*i/4).
        let pos = data_offset + (last * i / 4) as usize;
        plain_at(enc, blob, pos) == plain_at(enc, blob, HEADER_LEN + i as usize)
    })
}

/// A key and variable values that decrypt a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Solution {
    pub key: Vec<u8>,
    pub string: Vec<u8>,
    pub int: Option<u32>,
}

/// Find the candidate that decrypts `enc`, in the original search order:
/// keys, then the string values of the stored index, then the integer
/// values. `hint` (the previous solution) is tried first.
pub fn solve(
    enc: &[u8],
    c: &Candidates,
    hint: Option<&Solution>,
) -> Option<(Solution, Blob, usize)> {
    if enc.len() < HEADER_LEN + 5 || &enc[..5] != WOLFX_MAGIC {
        return None;
    }
    if let Some(h) = hint {
        if let Some(ks) = KeyState::new(enc, &h.key) {
            let int = h.int.filter(|_| ks.int_index(&h.string) < INT_INDEX_LIMIT);
            let blob = ks.final_blob(&h.string, int);
            if checksum_ok(enc, &blob, ks.data_offset) {
                let s = Solution { int, ..h.clone() };
                return Some((s, blob, ks.data_offset));
            }
        }
    }

    const EMPTY: &[u8] = b"";
    for key in &c.keys {
        let Some(ks) = KeyState::new(enc, key) else {
            continue;
        };
        let si = ks.string_index();
        let strings: Vec<&[u8]> = if si < STRING_INDEX_LIMIT {
            match c.strings.get(&si) {
                Some(set) => set.iter().map(Vec::as_slice).collect(),
                None => continue,
            }
        } else {
            vec![EMPTY]
        };
        for s in strings {
            let ii = ks.int_index(s);
            let ints: Vec<Option<u32>> = if ii < INT_INDEX_LIMIT {
                match c.ints.get(&ii) {
                    Some(set) => set.iter().copied().map(Some).collect(),
                    None => continue,
                }
            } else {
                vec![None]
            };
            for int in ints {
                let blob = ks.final_blob(s, int);
                if checksum_ok(enc, &blob, ks.data_offset) {
                    let sol = Solution {
                        key: key.clone(),
                        string: s.to_vec(),
                        int,
                    };
                    return Some((sol, blob, ks.data_offset));
                }
            }
        }
    }
    None
}

/// Decrypt a whole file with a validated stream: the data after the offset.
pub fn decrypt_with(enc: &[u8], blob: &Blob, data_offset: usize) -> Vec<u8> {
    (data_offset..enc.len())
        .map(|i| plain_at(enc, blob, i))
        .collect()
}

/// Read the candidates from `CommonEvent.dat` and the maps under
/// `data_folder` (`collectWolfXDecryptionInfo`). Files that cannot be read
/// are reported and skipped.
pub fn collect(data_folder: &Path, common_event: Option<&Path>) -> (Candidates, Vec<Error>) {
    let mut col = Collector::new();
    let mut warnings = Vec::new();
    let read = |path: &Path| fs::read(path).at(path);
    let warn = |path: &Path, e: Error| Error::Game(format!("{}: {e}", path.display()));
    for map in files_with_extension(data_folder, "mps", &mut warnings) {
        match read(&map).and_then(|b| MapFile::load(&b)) {
            Ok(m) => col.add(&m.commands, &m.data, m.utf8),
            Err(e) => warnings.push(warn(&map, e)),
        }
    }
    if let Some(ce) = common_event {
        match read(ce).and_then(|b| CommonEventFile::load(&b)) {
            Ok(f) => {
                for e in &f.events {
                    col.add(&e.commands, &f.body, f.utf8);
                }
            }
            Err(e) => warnings.push(warn(ce, e)),
        }
    }
    (col.finish(), warnings)
}

/// Files under `root` (recursively) with extension `ext`, ignoring case,
/// sorted by path.
pub fn files_with_extension(root: &Path, ext: &str, errors: &mut Vec<Error>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                errors.push(Error::io(&dir, e));
                continue;
            }
        };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() && has_extension_ci(&p, ext) => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// Result for one `.wolfx` file.
#[derive(Debug)]
pub struct FileResult {
    pub path: PathBuf,
    pub outcome: Result<PathBuf>,
}

/// Decrypt every `.wolfx` file in `files` next to itself (the path without
/// `.wolfx`, overwritten if present). The original keeps the `.wolfx` too.
pub fn decrypt_files(files: &[PathBuf], c: &Candidates) -> Vec<FileResult> {
    let mut hint: Option<Solution> = None;
    files
        .iter()
        .map(|path| {
            let outcome = decrypt_file(path, c, &mut hint);
            FileResult {
                path: path.clone(),
                outcome,
            }
        })
        .collect()
}

fn decrypt_file(path: &Path, c: &Candidates, hint: &mut Option<Solution>) -> Result<PathBuf> {
    let enc = fs::read(path).at(path)?;
    if enc.len() < HEADER_LEN + 5 || &enc[..5] != WOLFX_MAGIC {
        return Err(Error::format("not a WOLFX file"));
    }
    let (sol, blob, offset) = solve(&enc, c, hint.as_ref())
        .ok_or_else(|| Error::Game("no candidate key decrypts this file".into()))?;
    *hint = Some(sol);
    let out = path.with_extension("");
    fs::write(&out, decrypt_with(&enc, &blob, offset)).at(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt `plain` the way the reader expects: the inverse of every
    /// step, built from the same primitives.
    fn encrypt(
        plain: &[u8],
        key: &[u8],
        string_index: u16,
        string: &[u8],
        int: Option<(u32, u32)>,
    ) -> Vec<u8> {
        let sb = static_blob(key);
        let data_offset = 512 + usize::from(sb[0]) + usize::from(sb[1]);
        let mut enc = vec![0u8; data_offset + plain.len()];
        enc[..5].copy_from_slice(WOLFX_MAGIC);
        enc[5..9].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        let seed = fnv1(&sb) ^ be(&enc[5..9]);
        let blob = decrypt_blob(seed, &sb);
        // Choose the integer index so that the stored 3 bytes give it.
        let h = fnv1(string);
        let wanted = int.map(|(idx, _)| idx).unwrap_or(0xFF_FFFF);
        let stored = (((h & 0xFFFF_0000) >> 8) ^ (h & 0xFFFF) ^ wanted) & 0xFF_FFFF;
        let header = [
            (string_index >> 8) as u8,
            string_index as u8,
            (stored >> 16) as u8,
            (stored >> 8) as u8,
            stored as u8,
        ];
        for i in 0..5 {
            enc[10 + i] = header[i] ^ blob[i];
        }
        let ks = KeyState {
            blob,
            data_offset,
            header,
        };
        let fb = ks.final_blob(string, int.map(|(_, v)| v));
        let mut full = vec![0u8; enc.len()];
        full[data_offset..].copy_from_slice(plain);
        let last = (plain.len() - 1) as u64;
        for i in 0..5u64 {
            full[HEADER_LEN + i as usize] = full[data_offset + (last * i / 4) as usize];
        }
        for i in HEADER_LEN..enc.len() {
            enc[i] = full[i] ^ fb[(i - 10) % BLOB_LEN];
        }
        enc
    }

    fn candidates() -> Candidates {
        let mut c = Collector::new();
        c.keys.insert((b"Data/".to_vec(), b"wrong".to_vec()));
        c.keys.insert((b"Data/".to_vec(), b"SecretKey".to_vec()));
        c.keys.insert((b"Other/".to_vec(), b"SecretKey".to_vec()));
        c.strings.entry(42).or_default().insert(b"nope".to_vec());
        c.strings.entry(42).or_default().insert(b"magic".to_vec());
        c.ints.entry(77).or_default().insert(5);
        c.ints.entry(77).or_default().insert(123_456);
        c.finish()
    }

    #[test]
    fn keys_are_sorted_and_unique() {
        let c = candidates();
        assert_eq!(
            c.keys,
            [b"".to_vec(), b"SecretKey".to_vec(), b"wrong".to_vec()]
        );
    }

    #[test]
    fn decrypts_with_string_and_int() {
        let plain: Vec<u8> = (0..3000u32).map(|i| (i * 31 % 251) as u8).collect();
        let enc = encrypt(&plain, b"SecretKey", 42, b"magic", Some((77, 123_456)));
        let c = candidates();
        let (sol, blob, off) = solve(&enc, &c, None).unwrap();
        assert_eq!(sol.key, b"SecretKey");
        assert_eq!(sol.string, b"magic");
        assert_eq!(sol.int, Some(123_456));
        assert_eq!(decrypt_with(&enc, &blob, off), plain);
        // The hint path finds it directly.
        assert_eq!(solve(&enc, &c, Some(&sol)).unwrap().0, sol);
    }

    #[test]
    fn decrypts_without_variables() {
        let plain = b"no variables here, only the default key".repeat(20);
        let enc = encrypt(&plain, b"", 0xFFFF, b"", None);
        let (sol, blob, off) = solve(&enc, &candidates(), None).unwrap();
        assert_eq!(sol.key, b"");
        assert_eq!(sol.int, None);
        assert_eq!(decrypt_with(&enc, &blob, off), plain);
    }

    #[test]
    fn unknown_key_fails() {
        let plain = vec![7u8; 100];
        let enc = encrypt(&plain, b"absent", 0xFFFF, b"", None);
        assert!(solve(&enc, &candidates(), None).is_none());
        assert!(solve(b"WOLF", &candidates(), None).is_none());
    }

    #[test]
    fn collects_from_commands() {
        use crate::wolfrpg::Reader;
        use crate::wolfrpg::command::tests::encode;
        let mut data = encode(122, &[3_000_005], &[b"str\0"], false);
        data.extend(encode(121, &[2_000_003, 9, 0, 0], &[], false));
        data.extend(encode(1000, &[7], &[b"Data/\0", b"Key1\0"], false));
        data.extend(encode(1000, &[3], &[b"x\0", b"NotAKey\0"], false));
        let mut r = Reader::new(&data);
        let cmds: Vec<Command> = (0..4)
            .map(|_| command::read(&mut r, false).unwrap())
            .collect();
        let mut col = Collector::new();
        col.add(&cmds, &data, true);
        let c = col.finish();
        assert_eq!(c.keys, [b"".to_vec(), b"Key1".to_vec()]);
        assert!(c.strings[&5].contains(b"str".as_slice()));
        assert!(c.ints[&3].contains(&9));
    }

    /// A game folder with a `.wolfx` file whose key and values are set by
    /// commands of `CommonEvent.dat`.
    #[test]
    fn session_end_to_end() {
        use crate::game::{Options, Session};
        use crate::wolfrpg::command::tests::encode;
        use crate::wolfrpg::common_event::tests::{encode_event, encode_file};

        let dir = std::env::temp_dir().join(format!("unwolf-wolfx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let basic = dir.join("Data/BasicData");
        fs::create_dir_all(&basic).unwrap();
        fs::create_dir_all(dir.join("Fonts")).unwrap();
        fs::write(dir.join("Game.exe"), b"").unwrap();

        let cmds = vec![
            encode(1000, &[7], &[b"Fonts/\0", b"GameKey\0"], true),
            encode(122, &[3_000_042], &[b"magic\0"], true),
            encode(121, &[2_000_077, 5], &[], true),
        ];
        let ce = encode_file(&[encode_event(0, &cmds, b"\0")], 0x93, true);
        fs::write(basic.join("CommonEvent.dat"), ce).unwrap();

        let plain = b"font data ".repeat(100);
        let enc = encrypt(&plain, b"GameKey", 42, b"magic", Some((77, 5)));
        fs::write(dir.join("Fonts/f.ttf.wolfx"), &enc).unwrap();
        fs::write(dir.join("Fonts/bad.wolfx"), b"WOLFX0123456789012345").unwrap();

        let opts = Options {
            config_path: dir.join("cfg.json"),
            ..Default::default()
        };
        let mut s = Session::new(opts, Box::new(|_| {}));
        s.init_game(&dir.join("Game.exe")).unwrap();
        let r = s.decrypt_wolfx().unwrap();
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.candidates, (2, 1, 1));
        assert_eq!(r.files.len(), 2);
        assert!(r.files.iter().any(|f| f.outcome.is_err()));
        assert_eq!(fs::read(dir.join("Fonts/f.ttf")).unwrap(), plain);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn magic_bytes_spell_wolfx() {
        assert_eq!(&wolfx_magic_bytes(), WOLFX_MAGIC);
    }

    #[test]
    fn static_blob_has_no_zero() {
        for key in [&b""[..], b"a", b"SecretKey", &[0u8; 100]] {
            assert!(static_blob(key).iter().all(|&b| b != 0));
        }
    }
}
