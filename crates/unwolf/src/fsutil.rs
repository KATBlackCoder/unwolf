//! File system helpers. The original runs on NTFS, where names are
//! case-insensitive (it looks for `data.wolf`, `BasicData`, `CDatabase.dat`
//! while games ship `Data.wolf`, `CDataBase.dat`...). Lookups here emulate
//! that on case-sensitive file systems.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{IoContext, Result};

/// Find `name` in `dir`, ignoring case. An exact match wins.
pub fn find_ci(dir: &Path, name: &str) -> Option<PathBuf> {
    let exact = dir.join(name);
    if exact.exists() {
        return Some(exact);
    }
    let wanted = name.to_lowercase();
    let mut matches: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().to_lowercase() == wanted)
        .map(|e| e.path())
        .collect();
    matches.sort();
    matches.into_iter().next()
}

/// Case-insensitive comparison of a path's extension with `ext` (no dot).
pub fn has_extension_ci(path: &Path, ext: &str) -> bool {
    path.extension()
        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case(ext))
}

/// Regular files directly inside `dir`, sorted by lower-case name to get a
/// stable order close to NTFS enumeration.
pub fn list_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .at(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect();
    v.sort_by_key(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()));
    Ok(v)
}

/// Move the contents of `from` into `to`, replacing files that exist in both.
pub fn merge_move(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).at(to)?;
    for e in fs::read_dir(from).at(from)? {
        let e = e.at(from)?;
        let src = e.path();
        let dst = to.join(e.file_name());
        if e.file_type().at(&src)?.is_dir() && dst.is_dir() {
            merge_move(&src, &dst)?;
        } else {
            if dst.is_dir() {
                fs::remove_dir_all(&dst).at(&dst)?;
            }
            fs::rename(&src, &dst).at(&dst)?;
        }
    }
    fs::remove_dir_all(from).at(from)
}
