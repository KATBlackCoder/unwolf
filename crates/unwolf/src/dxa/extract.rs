//! Writing an archive's contents to disk.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::{Archive, Entry};
use crate::error::{IoContext, Result};

/// Prefix some Wolf RPG games put in front of their data files to deter
/// extraction; UberWolf removes it after unpacking.
const ANTI_UNPACK: &[u8; 62] = b"Extracting data from encrypted files violates the guidelines.\0";
const ANTI_UNPACK_FILES: [&str; 4] = [
    "game.dat",
    "cdatabase.dat",
    "database.dat",
    "commonevent.dat",
];

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExtractStats {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
}

/// Decode every entry into `out`, which must exist.
///
/// Decoding errors abort the extraction; the caller removes the partial
/// output.
pub fn extract_to(archive: &Archive, out: &Path) -> Result<ExtractStats> {
    let mut stats = ExtractStats::default();
    for e in &archive.entries {
        let target = out.join(&e.path);
        match &e.data {
            None => {
                fs::create_dir_all(&target).at(&target)?;
                stats.dirs += 1;
            }
            Some(f) => {
                let mut bytes = archive.read_file(f)?;
                strip_anti_unpack(e, &mut bytes);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).at(parent)?;
                }
                fs::write(&target, &bytes).at(&target)?;
                set_times(&target, e);
                stats.files += 1;
                stats.bytes += bytes.len() as u64;
            }
        }
    }
    Ok(stats)
}

fn strip_anti_unpack(e: &Entry, bytes: &mut Vec<u8>) {
    // UberWolf matches with `ends_with` on the lower-case name.
    if ANTI_UNPACK_FILES.iter().any(|n| e.name_lower.ends_with(n)) && bytes.starts_with(ANTI_UNPACK)
    {
        bytes.drain(..ANTI_UNPACK.len());
    }
}

/// Convert a Windows FILETIME (100 ns ticks since 1601-01-01) to SystemTime.
fn filetime(ft: u64) -> Option<SystemTime> {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let secs = ft / 10_000_000;
    let nanos = (ft % 10_000_000) * 100;
    let unix = secs.checked_sub(EPOCH_DIFF_SECS)?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(unix, nanos as u32))
}

/// Restore access and modification times. Failures are only logged, as in
/// the original, which ignores the result of `SetFileTime`.
fn set_times(path: &Path, e: &Entry) {
    let mut t = fs::FileTimes::new();
    if let Some(a) = filetime(e.times[1]) {
        t = t.set_accessed(a);
    }
    if let Some(m) = filetime(e.times[2]) {
        t = t.set_modified(m);
    }
    let res = fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_times(t));
    if let Err(err) = res {
        log::debug!("cannot set times on {}: {err}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_conversion() {
        // 2000-01-01T00:00:00Z
        let t = filetime(125_911_584_000_000_000).unwrap();
        assert_eq!(
            t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            946_684_800
        );
        assert!(filetime(0).is_none());
    }
}
