//! `-u`: remove the Wolf RPG Pro protection from the files of `BasicData`
//! (`WolfPro::RemoveProtection` and `WolfUnprotect.hpp`).
//!
//! - Pro v3.5: files are decrypted in place; originals go to
//!   `BasicData/backup/` (kept from the first run). Event and database
//!   descriptions also lose the control characters added as protection.
//! - Pro v1: decrypted copies are written to `<data>/unprotected/`.
//! - Pro v2: not supported, like the original.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::datadecrypt::{
    self, DEFAULT_SEEDS, GAME_DAT_SEEDS, ProFile, SeedIndices, pro_generation,
};
use crate::error::{Error, IoContext, Result};
use crate::fsutil::find_ci;
use crate::protkey::{self, KEY_OFFSET};
use crate::rng::MsvcRand;
use crate::wolfrpg::common_event::CommonEventFile;
use crate::wolfrpg::database::Project;

/// What happened to one file.
#[derive(Debug)]
pub enum FileStatus {
    Done,
    /// Already unprotected, or protected by another scheme.
    NotProtected,
    Failed(Error),
}

#[derive(Debug)]
pub struct FileReport {
    pub name: String,
    pub status: FileStatus,
}

const BACKUP_FOLDER: &str = "backup";

/// Files handled by the v3.5 scheme, in the original order.
const V35_FILES: [(&str, ProFile); 6] = [
    ("Game.dat", ProFile::GameDat),
    ("CommonEvent.dat", ProFile::CommonEvent),
    ("DataBase.dat", ProFile::DataBase),
    ("SysDatabase.dat", ProFile::DataBase),
    ("CDatabase.dat", ProFile::DataBase),
    ("TileSetData.dat", ProFile::TileSetData),
];

/// `unprotectProFiles`.
pub fn unprotect_v35(basic_data: &Path) -> Result<Vec<FileReport>> {
    let backup = basic_data.join(BACKUP_FOLDER);
    fs::create_dir_all(&backup).at(&backup)?;
    Ok(V35_FILES
        .iter()
        .map(|&(name, kind)| FileReport {
            name: name.to_string(),
            status: match unprotect_v35_file(basic_data, &backup, name, kind) {
                Ok(s) => s,
                Err(e) => FileStatus::Failed(e),
            },
        })
        .collect())
}

fn unprotect_v35_file(dir: &Path, backup: &Path, name: &str, kind: ProFile) -> Result<FileStatus> {
    let path = find_ci(dir, name)
        .ok_or_else(|| Error::io(dir.join(name), std::io::ErrorKind::NotFound.into()))?;
    backup_file(&path, backup)?;
    let mut buf = read_non_empty(&path)?;
    if pro_generation(&buf).is_none_or(|g| g < 0x57) {
        return Ok(FileStatus::NotProtected);
    }
    let old_size = buf.len();
    datadecrypt::decrypt_v3_5(&mut buf, kind)?;
    if kind == ProFile::GameDat {
        game_dat_update_size(&mut buf, old_size)?;
    }
    fs::write(&path, &buf).at(&path)?;

    match kind {
        ProFile::CommonEvent => {
            let ce = CommonEventFile::parse(&buf)?;
            fs::write(&path, ce.fix_pro35_descriptions()).at(&path)?;
        }
        ProFile::DataBase => {
            // There is no marker telling whether a project file is still
            // protected: it is processed together with its `.dat` file.
            let proj_name = with_extension(&path, "project");
            let proj = find_ci(dir, &proj_name).ok_or_else(|| {
                Error::io(dir.join(&proj_name), std::io::ErrorKind::NotFound.into())
            })?;
            backup_file(&proj, backup)?;
            let mut data = read_non_empty(&proj)?;
            // `srand(0)` in the original, which only works with the MSVC CRT.
            xor_msvc_rand(&mut data, 0);
            fs::write(&proj, &data).at(&proj)?;
            // The database files of a v3.5 game are UTF-8 (the header written
            // above says so).
            let fixed = Project::parse(data)?.fix_pro35_descriptions(true);
            fs::write(&proj, fixed).at(&proj)?;
        }
        ProFile::GameDat | ProFile::TileSetData => {}
    }
    Ok(FileStatus::Done)
}

/// v1 files of the general kind: each `.dat` with an optional `.project`.
const V1_GENERAL_FILES: [&str; 4] = ["TileSetData", "SysDatabase", "DataBase", "CDataBase"];

/// Pro v1: write decrypted copies of the `BasicData` files to `out_dir`.
pub fn unprotect_v1(basic_data: &Path, out_dir: &Path) -> Result<Vec<FileReport>> {
    fs::create_dir_all(out_dir).at(out_dir)?;
    let mut reports = Vec::new();
    for base in V1_GENERAL_FILES {
        let status = unprotect_v1_general(basic_data, out_dir, base);
        reports.push(report(format!("{base}.dat"), status));
    }
    for (name, kind) in [
        ("Game.dat", V1Kind::GameDat),
        ("CommonEvent.dat", V1Kind::CommonEvent),
    ] {
        let status = find_ci(basic_data, name)
            .ok_or_else(|| Error::io(basic_data.join(name), std::io::ErrorKind::NotFound.into()))
            .and_then(|p| {
                let (bytes, _) = unprotect_v1_dat(&p, kind)?;
                write_into(out_dir, &p, &bytes)
            });
        reports.push(report(name.to_string(), status));
    }
    Ok(reports)
}

fn report(name: String, status: Result<()>) -> FileReport {
    FileReport {
        name,
        status: match status {
            Ok(()) => FileStatus::Done,
            Err(e) => FileStatus::Failed(e),
        },
    }
}

fn unprotect_v1_general(dir: &Path, out_dir: &Path, base: &str) -> Result<()> {
    let dat_name = format!("{base}.dat");
    let dat = find_ci(dir, &dat_name)
        .ok_or_else(|| Error::io(dir.join(&dat_name), std::io::ErrorKind::NotFound.into()))?;
    let (bytes, project_seed) = unprotect_v1_dat(&dat, V1Kind::General)?;
    write_into(out_dir, &dat, &bytes)?;
    if let Some(proj) = find_ci(dir, &format!("{base}.project")) {
        let mut data = fs::read(&proj).at(&proj)?;
        xor_msvc_rand(&mut data, project_seed);
        write_into(out_dir, &proj, &data)?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum V1Kind {
    General,
    GameDat,
    CommonEvent,
}

/// `removeProtectionFromDat`: decrypt, drop the header and the key, put the
/// plain header back. Also returns the seed of the matching project file.
fn unprotect_v1_dat(path: &Path, kind: V1Kind) -> Result<(Vec<u8>, u32)> {
    /// Plain header written in place of the protected one (`DEC_START`).
    const DEC_START: [u8; 10] = [0x00, 0x57, 0x00, 0x00, 0x4F, 0x4C, 0x55, 0x46, 0x4D, 0x00];
    let seeds: SeedIndices = if kind == V1Kind::GameDat {
        GAME_DAT_SEEDS
    } else {
        DEFAULT_SEEDS
    };
    let mut bytes = read_non_empty(path)?;
    let old_size = bytes.len();
    let key_len = protkey::decrypt_v1(&mut bytes, seeds)?;
    // Sign-extended, as the original casts through `int8_t`.
    let project_seed = bytes[KEY_OFFSET] as i8 as i32 as u32;
    bytes.splice(..KEY_OFFSET + key_len, DEC_START);
    match kind {
        V1Kind::GameDat => {
            bytes.swap(6, 9);
            game_dat_update_size(&mut bytes, old_size)?;
        }
        V1Kind::CommonEvent => bytes[8] = 0x43,
        V1Kind::General => {}
    }
    Ok((bytes, project_seed))
}

/// `gameDatUpdateSize`: `Game.dat` stores the file size minus one in a
/// field after its header strings; update it to the new size.
fn game_dat_update_size(bytes: &mut [u8], old_size: usize) -> Result<()> {
    let read = |b: &[u8], off: usize| -> Result<usize> {
        b.get(off..off + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
            .ok_or_else(|| Error::format("Game.dat: size field not found"))
    };
    let mut off = 10;
    off += read(bytes, off)? + 4; // bytes
    off += 4; // DWORD
    for _ in 0..4 {
        // title, number, decrypt key, font
        off += read(bytes, off)? + 4;
    }
    let target = old_size.wrapping_sub(1);
    while read(bytes, off)? != target {
        off += read(bytes, off)? + 4;
    }
    let new = (bytes.len() as u32).wrapping_sub(1);
    bytes[off..off + 4].copy_from_slice(&new.to_le_bytes());
    Ok(())
}

/// XOR with the low byte of each MSVC `rand()` after `srand(seed)`.
fn xor_msvc_rand(data: &mut [u8], seed: u32) {
    let mut rand = MsvcRand::new(seed);
    for b in data {
        *b ^= rand.next_u32() as u8;
    }
}

fn read_non_empty(path: &Path) -> Result<Vec<u8>> {
    let v = fs::read(path).at(path)?;
    if v.is_empty() {
        return Err(Error::Game(format!("{} is empty", path.display())));
    }
    Ok(v)
}

/// `backupFile`: copy into the backup folder unless a copy already exists.
fn backup_file(path: &Path, backup: &Path) -> Result<()> {
    let dst = backup.join(path.file_name().unwrap_or_default());
    if !dst.exists() {
        fs::copy(path, &dst).at(&dst)?;
    }
    Ok(())
}

fn with_extension(path: &Path, ext: &str) -> String {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    format!("{stem}.{ext}")
}

fn write_into(out_dir: &Path, src: &Path, data: &[u8]) -> Result<()> {
    let dst: PathBuf = out_dir.join(src.file_name().unwrap_or_default());
    fs::write(&dst, data).at(&dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_str(v: &mut Vec<u8>, s: &[u8]) {
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
        v.extend_from_slice(s);
    }

    #[test]
    fn update_size_finds_the_field() {
        let mut b = vec![0u8; 10];
        put_str(&mut b, b"xx");
        b.extend_from_slice(&[0; 4]);
        for s in [&b"title"[..], b"0000-0000", b"key", b"font"] {
            put_str(&mut b, s);
        }
        put_str(&mut b, b"other");
        let size_off = b.len();
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0xAB; 7]);
        let old_size = 1000;
        b[size_off..size_off + 4].copy_from_slice(&((old_size - 1) as u32).to_le_bytes());
        game_dat_update_size(&mut b, old_size).unwrap();
        let v = u32::from_le_bytes(b[size_off..size_off + 4].try_into().unwrap());
        assert_eq!(v as usize, b.len() - 1);

        // No matching field: an error, not a panic.
        assert!(game_dat_update_size(&mut b, 5).is_err());
    }

    #[test]
    fn msvc_xor_is_an_involution() {
        let mut d = b"project".to_vec();
        xor_msvc_rand(&mut d, 0);
        assert_ne!(d, b"project");
        xor_msvc_rand(&mut d, 0);
        assert_eq!(d, b"project");
    }

    /// Protect synthetic files with the v3.5 scheme, run `-u` and read the
    /// results back.
    #[test]
    fn v35_end_to_end() {
        use crate::crypto::datadecrypt::encrypt_v3_5;
        use crate::wolfrpg::command::tests::encode;
        use crate::wolfrpg::common_event::tests::{encode_event, encode_file};

        let dir = std::env::temp_dir().join(format!("unwolf-unprot35-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // CommonEvent.dat: the protected payload is the plain file without
        // its 10-byte header.
        let cmds = vec![encode(122, &[3_000_001], &[b"abc\0"], true)];
        let plain_ce = encode_file(&[encode_event(0, &cmds, b"d\x01\x02e\0")], 0x93, true);
        let ce = encrypt_v3_5(&plain_ce[10..], ProFile::CommonEvent);
        fs::write(dir.join("CommonEvent.dat"), &ce).unwrap();

        // CDataBase.dat (other case than the list) and its project.
        fs::write(
            dir.join("CDataBase.dat"),
            encrypt_v3_5(&[0xC4, 1, 2, 3], ProFile::DataBase),
        )
        .unwrap();
        let mut proj = 1u32.to_le_bytes().to_vec();
        put_str(&mut proj, b"T\0");
        proj.extend_from_slice(&[0; 8]); // no fields, no data
        put_str(&mut proj, b"x\x05y\0");
        proj.extend_from_slice(&[0; 4 * 5]); // empty lists
        let mut stored = proj.clone();
        xor_msvc_rand(&mut stored, 0);
        fs::write(dir.join("CDataBase.project"), &stored).unwrap();

        let r = unprotect_v35(&dir).unwrap();
        let status = |n: &str| &r.iter().find(|f| f.name == n).unwrap().status;
        assert!(
            matches!(status("CommonEvent.dat"), FileStatus::Done),
            "{r:?}"
        );
        assert!(matches!(status("CDatabase.dat"), FileStatus::Done), "{r:?}");
        assert!(matches!(status("Game.dat"), FileStatus::Failed(_)));

        let out = CommonEventFile::parse(&fs::read(dir.join("CommonEvent.dat")).unwrap()).unwrap();
        assert_eq!(out.string(&out.events[0].description), b"de\0");
        assert_eq!(
            fs::read(dir.join("CDataBase.dat")).unwrap(),
            [&ProFile::DataBase.magic()[..], &[0xC4, 1, 2, 3]].concat()
        );
        let p = Project::parse(fs::read(dir.join("CDataBase.project")).unwrap()).unwrap();
        assert_eq!(p.string(&p.types[0].description), b"xy\0");
        assert_eq!(
            fs::read(dir.join("backup/CDataBase.project")).unwrap(),
            stored
        );

        // A second run finds nothing left to decrypt and keeps the backups.
        let r = unprotect_v35(&dir).unwrap();
        assert!(matches!(r[1].status, FileStatus::NotProtected));
        assert_eq!(fs::read(dir.join("backup/CommonEvent.dat")).unwrap(), ce);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn v35_reports_missing_files_and_plain_files() {
        let dir = std::env::temp_dir().join(format!("unwolf-unprot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Game.dat"), [0u8, 0x57, 0, 0]).unwrap();
        let r = unprotect_v35(&dir).unwrap();
        assert!(matches!(r[0].status, FileStatus::NotProtected));
        assert!(matches!(r[1].status, FileStatus::Failed(_)));
        assert!(dir.join("backup/Game.dat").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
