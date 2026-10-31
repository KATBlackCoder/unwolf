//! Integration test on real games, ignored by default: games are never
//! committed. Run it locally:
//!
//! ```text
//! UBERWOLF_GAMES_DIR=game-test UBERWOLF_REF_DIR=work/ref \
//!     cargo test --release -p unwolf --test real_games -- --ignored --nocapture
//! ```
//!
//! `cargo test` runs this test from `crates/unwolf`, so relative paths in
//! the variables below are resolved from the workspace root, not from the
//! current folder. Absolute paths are used as is.
//!
//! Variables:
//! - `UBERWOLF_GAMES_DIR` (required): one folder per game, each holding
//!   `Game.exe` or `GamePro.exe`. Games are copied before use, never
//!   modified in place.
//! - `UBERWOLF_REF_DIR` (optional): `<ref>/<game>` is the output of
//!   `scripts/reference-wine.sh <game> <ref>/<game>`. Every folder extracted
//!   by unwolf is compared with the one UberWolfCli extracted: same files,
//!   same contents, same modification times.
//! - `UBERWOLF_GAMES` (optional): comma-separated game folder names to run.
//! - `UBERWOLF_WORK_DIR` (optional): where the copies go; default
//!   `target/tmp/real-games`. Must be on the same file system as the games
//!   for `cp --reflink` to avoid real copies.
//! - `UBERWOLF_REPACK=1` (optional): also pack every extracted folder again
//!   with the mode that opened it, extract the new archive and compare.
//! - `UBERWOLF_SKIP_TIMES=1` (optional): do not compare modification times.
//! - `UBERWOLF_KEEP=1` (optional): keep the copies after the run.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

use unwolf::dxa::{Archive, OpenParams, extract_to, pack_directory};
use unwolf::game::{Options, Outcome, Session, output_dir};

/// At most this many differences are printed per folder.
const MAX_REPORTED: usize = 20;

/// The workspace root: two levels above this crate.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the workspace root")
}

/// A path variable; relative paths are taken from the workspace root.
fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(|v| workspace_root().join(v))
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|v| v == "1")
}

/// What a tree holds: relative path -> (is directory, size, mtime seconds).
type Listing = BTreeMap<PathBuf, (bool, u64, u64)>;

fn list_tree(root: &Path) -> Listing {
    let mut out = Listing::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let e = e.unwrap();
            let p = e.path();
            let md = fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().to_path_buf();
            // Left behind by an interrupted UberWolfCli run.
            if rel == Path::new("decrypt_temp") {
                continue;
            }
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            out.insert(rel, (md.is_dir(), md.len(), mtime));
            if md.is_dir() {
                stack.push(p);
            }
        }
    }
    out
}

fn same_contents(a: &Path, b: &Path) -> bool {
    let (mut fa, mut fb) = (fs::File::open(a).unwrap(), fs::File::open(b).unwrap());
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let na = read_full(&mut fa, &mut ba);
        let nb = read_full(&mut fb, &mut bb);
        if na != nb || ba[..na] != bb[..nb] {
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

fn read_full(f: &mut fs::File, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]).unwrap() {
            0 => break,
            k => n += k,
        }
    }
    n
}

/// Differences between two trees, described one per line.
fn compare_trees(expected: &Path, actual: &Path, times: bool) -> Vec<String> {
    let (le, la) = (list_tree(expected), list_tree(actual));
    let mut diffs = Vec::new();
    for (rel, &(dir_e, size_e, time_e)) in &le {
        let Some(&(dir_a, size_a, time_a)) = la.get(rel) else {
            diffs.push(format!("missing: {}", rel.display()));
            continue;
        };
        if dir_e != dir_a {
            diffs.push(format!("file/folder mismatch: {}", rel.display()));
        } else if !dir_e {
            if size_e != size_a {
                diffs.push(format!("size {size_a} != {size_e}: {}", rel.display()));
            } else if !same_contents(&expected.join(rel), &actual.join(rel)) {
                diffs.push(format!("contents differ: {}", rel.display()));
            } else if times && time_e != time_a {
                diffs.push(format!("mtime {time_a} != {time_e}: {}", rel.display()));
            }
        }
    }
    for rel in la.keys().filter(|r| !le.contains_key(*r)) {
        diffs.push(format!("unexpected: {}", rel.display()));
    }
    diffs
}

fn report(what: &str, diffs: &[String]) {
    println!("    {what}: {} difference(s)", diffs.len());
    for d in diffs.iter().take(MAX_REPORTED) {
        println!("      {d}");
    }
    if diffs.len() > MAX_REPORTED {
        println!("      ... {} more", diffs.len() - MAX_REPORTED);
    }
}

fn find_exe(game: &Path) -> Option<PathBuf> {
    ["Game.exe", "GamePro.exe"]
        .iter()
        .map(|n| game.join(n))
        .find(|p| p.is_file())
}

/// Copy `src` to `dst` (`cp -a --reflink=auto`).
fn copy_game(src: &Path, dst: &Path) {
    if dst.exists() {
        fs::remove_dir_all(dst).unwrap();
    }
    fs::create_dir_all(dst.parent().unwrap()).unwrap();
    let st = Command::new("cp")
        .args(["-a", "--reflink=auto"])
        .arg(src)
        .arg(dst)
        .status()
        .expect("cannot run cp");
    assert!(st.success(), "cp {} failed", src.display());
}

/// Pack `dir` with `mode`, extract the new archive, compare with `dir`.
fn repack_round_trip(dir: &Path, mode: &unwolf::modes::CryptMode, work: &Path) -> Vec<String> {
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let archive = work.join(format!("{name}.wolf"));
    let out = work.join(&name);
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).unwrap();
    let res = pack_directory(dir, &archive, mode).and_then(|_| {
        let a = Archive::open(
            &archive,
            &OpenParams {
                format: mode.format,
                key: &mode.key,
            },
        )?;
        extract_to(&a, &out)
    });
    let diffs = match res {
        Ok(_) => compare_trees(dir, &out, false),
        Err(e) => vec![format!("repack failed: {e}")],
    };
    let _ = fs::remove_file(&archive);
    let _ = fs::remove_dir_all(&out);
    diffs
}

#[test]
#[ignore = "needs real games: set UBERWOLF_GAMES_DIR (see the file header)"]
fn real_games() {
    let Some(games_dir) = env_path("UBERWOLF_GAMES_DIR") else {
        panic!("set UBERWOLF_GAMES_DIR to a folder holding one folder per game");
    };
    let ref_dir = env_path("UBERWOLF_REF_DIR");
    let work = env_path("UBERWOLF_WORK_DIR")
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("real-games"));
    let only: Option<Vec<String>> = env::var("UBERWOLF_GAMES")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());
    let (repack, times, keep) = (
        env_flag("UBERWOLF_REPACK"),
        !env_flag("UBERWOLF_SKIP_TIMES"),
        env_flag("UBERWOLF_KEEP"),
    );

    let mut games: Vec<PathBuf> = fs::read_dir(&games_dir)
        .unwrap_or_else(|e| panic!("{}: {e}", games_dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir() && find_exe(p).is_some())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy();
            only.as_ref().is_none_or(|o| o.iter().any(|x| *x == n))
        })
        .collect();
    games.sort();
    assert!(
        !games.is_empty(),
        "no game folder with Game.exe in {}",
        games_dir.display()
    );

    let mut failures: Vec<String> = Vec::new();
    for game in &games {
        let name = game.file_name().unwrap().to_string_lossy().into_owned();
        println!("== {name}");
        let copy = work.join("games").join(&name);
        copy_game(game, &copy);

        let opts = Options {
            overwrite: false,
            config_path: work.join(format!("{name}.UberWolfConfig.json")),
        };
        let mut session = Session::new(opts, Box::new(|_| {}));
        let exe = find_exe(&copy).unwrap();
        let data = match session.init_game(&exe) {
            Ok(g) => g.data_folder.clone(),
            Err(e) => {
                failures.push(format!("{name}: init: {e}"));
                continue;
            }
        };
        let rel_data = data.strip_prefix(&copy).unwrap().to_path_buf();
        let started = std::time::Instant::now();
        let results = match session.unpack_data() {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("{name}: unpack: {e}"));
                continue;
            }
        };
        println!("  extracted in {:.1} s", started.elapsed().as_secs_f64());

        for (archive, outcome) in &results {
            let arch = archive.file_name().unwrap().to_string_lossy().into_owned();
            let mode_name = match outcome {
                Outcome::Extracted { mode, stats } => {
                    println!("  {arch}: {} files, mode {mode}", stats.files);
                    mode.clone()
                }
                Outcome::Skipped | Outcome::AlreadyUnpacked => continue,
                Outcome::Failed(e) => {
                    println!("  {arch}: FAILED: {e}");
                    failures.push(format!("{name}/{arch}: {e}"));
                    continue;
                }
            };
            let out = output_dir(archive);

            if let Some(r) = &ref_dir {
                let expected = r.join(&name).join(&rel_data).join(out.file_name().unwrap());
                if expected.is_dir() {
                    let diffs = compare_trees(&expected, &out, times);
                    report("vs UberWolfCli", &diffs);
                    if !diffs.is_empty() {
                        failures.push(format!(
                            "{name}/{arch}: {} difference(s) with Wine",
                            diffs.len()
                        ));
                    }
                } else {
                    println!("    no reference at {}", expected.display());
                }
            }

            if repack {
                let mode = session
                    .modes()
                    .iter()
                    .find(|m| m.name == mode_name)
                    .cloned()
                    .expect("mode of an extracted archive");
                let diffs = repack_round_trip(&out, &mode, &work.join("repack"));
                report("repack round trip", &diffs);
                if !diffs.is_empty() {
                    failures.push(format!(
                        "{name}/{arch}: repack: {} difference(s)",
                        diffs.len()
                    ));
                }
            }
        }
        if !keep {
            let _ = fs::remove_dir_all(&copy);
        }
    }

    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}
