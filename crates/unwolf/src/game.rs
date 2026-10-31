//! Orchestration: locate a game's data, pick the decryption mode of each
//! archive and extract it (`UberWolfLib` and `WolfDec` in the original).
//!
//! The original runs each mode attempt in a child process and treats a crash
//! as "wrong mode". Here every attempt is a bounds-checked decode into a
//! temporary directory that is renamed into place on success.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config;
use crate::dxa::{
    Archive, DXA_MAGIC, ExtractStats, OpenParams, PackStats, extract_to, pack_directory,
};
use crate::error::{Error, IoContext, Result};
use crate::fsutil::{find_ci, has_extension_ci, list_files, merge_move};
use crate::modes::{CryptMode, default_modes};
use crate::pro::{self, WOLF_EXTENSIONS};
use crate::protkey::{self, ProVersion, ProtectionKey};
use crate::unprotect::{self, FileReport};
use crate::wolfx;

/// Name UberWolf gives the data folder and data file (`data.wolf`, `Data/`).
const DATA_NAME: &str = "data";
const GAME_EXE_NAMES: [&str; 2] = ["Game.exe", "GamePro.exe"];
/// Left behind by an interrupted UberWolf run.
const DECRYPT_TEMP: &str = "decrypt_temp";
/// Folder (and archive) holding the protected `Game.dat` of Pro games.
const BASIC_DATA: &str = "BasicData";
const PROTECTED_GAME_DAT: &str = "Game.dat";
/// Output folder of the Pro v1 unprotection, inside the data folder.
const UNPROTECTED_FOLDER: &str = "unprotected";
const COMMON_EVENT_DAT: &str = "CommonEvent.dat";

#[derive(Debug, Clone)]
pub struct Options {
    /// Re-extract archives whose output folder already exists (`-o`).
    pub overwrite: bool,
    /// Where `UberWolfConfig.json` is read and written.
    pub config_path: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            overwrite: false,
            config_path: PathBuf::from(config::CONFIG_FILE_NAME),
        }
    }
}

/// Progress notifications, mirroring the original console messages.
#[derive(Debug)]
pub enum Event<'a> {
    Unpacking(&'a Path),
    AlreadyUnpacked(&'a Path),
    Done {
        path: &'a Path,
        mode: &'a str,
        stats: ExtractStats,
    },
    Failed {
        path: &'a Path,
        error: &'a Error,
    },
    SearchingGame(&'a Path),
    GameFound(&'a Path),
    ProDetected,
    ProKeyFound {
        config_name: &'a str,
    },
    Warning(&'a Error),
    Packing(&'a Path),
    Packed {
        path: &'a Path,
        result: std::result::Result<PackStats, &'a Error>,
    },
}

/// Result of one archive.
#[derive(Debug)]
pub enum Outcome {
    Extracted {
        mode: String,
        stats: ExtractStats,
    },
    AlreadyUnpacked,
    /// Special files (`Game.wolf`, `List.wolf`...) are never unpacked.
    Skipped,
    Failed(Error),
}

#[derive(Debug, Clone)]
pub struct GameInfo {
    pub exe: PathBuf,
    /// Folder holding the archives: the game folder itself when it contains
    /// `data.<ext>`, otherwise its `Data` folder.
    pub data_folder: PathBuf,
    pub data_as_file: bool,
    /// Pro key file, when present.
    pub pro_key_file: Option<PathBuf>,
}

pub struct Session {
    modes: Vec<CryptMode>,
    /// Mode of the previous successful archive (`m_mode`), reused for the
    /// next ones like the original does.
    current: Option<usize>,
    opts: Options,
    game: Option<GameInfo>,
    on_event: Box<dyn FnMut(&Event<'_>)>,
}

impl Session {
    pub fn new(opts: Options, on_event: Box<dyn FnMut(&Event<'_>)>) -> Self {
        let mut s = Self {
            modes: default_modes(),
            current: None,
            opts,
            game: None,
            on_event,
        };
        let (extra, err) = config::load(&s.opts.config_path);
        s.modes.extend(extra);
        if let Some(e) = err {
            (s.on_event)(&Event::Warning(&e));
        }
        s
    }

    pub fn game(&self) -> Option<&GameInfo> {
        self.game.as_ref()
    }

    pub fn modes(&self) -> &[CryptMode] {
        &self.modes
    }

    /// `InitGame`: find the data folder next to `Game.exe` / `GamePro.exe`.
    pub fn init_game(&mut self, exe: &Path) -> Result<&GameInfo> {
        if !exe.is_file() {
            return Err(Error::Game(format!(
                "invalid game executable path: {}",
                exe.display()
            )));
        }
        let exe = std::path::absolute(exe).at(exe)?;
        let folder = exe
            .parent()
            .ok_or_else(|| Error::Game("game executable has no parent folder".into()))?
            .to_path_buf();

        let data_file = WOLF_EXTENSIONS
            .iter()
            .find_map(|e| find_ci(&folder, &format!("{DATA_NAME}.{e}")));
        let (data_folder, data_as_file) = if data_file.is_some() {
            (folder.clone(), true)
        } else if let Some(d) = find_ci(&folder, DATA_NAME).filter(|d| d.is_dir()) {
            (d, false)
        } else {
            return Err(Error::Game("could not find the data folder".into()));
        };
        let pro_key_file = pro::find_key_file(&data_folder);
        Ok(self.game.insert(GameInfo {
            exe,
            data_folder,
            data_as_file,
            pro_key_file,
        }))
    }

    /// `UnpackData`: every archive of the game's data folder.
    pub fn unpack_data(&mut self) -> Result<Vec<(PathBuf, Outcome)>> {
        let folder = self
            .game
            .as_ref()
            .ok_or_else(|| Error::Game("no game initialised".into()))?
            .data_folder
            .clone();
        let files = list_files(&folder)?;
        Ok(self.unpack_files(&files))
    }

    /// `UnpackDataVec`: archives with a known extension; others are ignored.
    /// Failures do not stop the remaining archives.
    pub fn unpack_files(&mut self, paths: &[PathBuf]) -> Vec<(PathBuf, Outcome)> {
        paths
            .iter()
            .filter(|p| WOLF_EXTENSIONS.iter().any(|e| has_extension_ci(p, e)))
            .map(|p| (p.clone(), self.unpack_archive(p)))
            .collect()
    }

    pub fn unpack_archive(&mut self, path: &Path) -> Outcome {
        self.unpack_archive_inner(path, false)
    }

    fn unpack_archive_inner(&mut self, path: &Path, second_run: bool) -> Outcome {
        if !path.is_file() {
            return Outcome::Failed(Error::io(path, std::io::ErrorKind::NotFound.into()));
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if pro::is_special_file(&name) {
            return Outcome::Skipped;
        }
        if !self.opts.overwrite && is_already_unpacked(path) {
            (self.on_event)(&Event::AlreadyUnpacked(path));
            return Outcome::AlreadyUnpacked;
        }
        if !second_run {
            (self.on_event)(&Event::Unpacking(path));
        }

        match self.decrypt(path) {
            Ok((mode, stats)) => {
                (self.on_event)(&Event::Done {
                    path,
                    mode: &mode,
                    stats,
                });
                Outcome::Extracted { mode, stats }
            }
            Err(err) => {
                if !second_run {
                    if self.game.is_none() {
                        self.find_game_from_archive(path);
                    }
                    match self.find_pro_key() {
                        Ok(true) => return self.unpack_archive_inner(path, true),
                        Ok(false) => {}
                        Err(e) => (self.on_event)(&Event::Warning(&e)),
                    }
                }
                (self.on_event)(&Event::Failed { path, error: &err });
                Outcome::Failed(err)
            }
        }
    }

    /// `WolfDec::UnpackArchive`: choose the mode, then extract.
    fn decrypt(&mut self, path: &Path) -> Result<(String, ExtractStats)> {
        let idx = match self.current {
            Some(i) => i,
            None => {
                let cv = crypt_version(path)?;
                if cv == 0 {
                    return self.detect_mode(path);
                }
                if cv >= 1000 || cv == 0xC8 {
                    return Err(Error::Game(format!(
                        "Wolf RPG Pro archive (crypt version {cv}): the key comes from the game files"
                    )));
                }
                let i = self
                    .modes
                    .iter()
                    .position(|m| m.crypt_version == cv)
                    .ok_or_else(|| Error::Unsupported(format!("unknown crypt version {cv}")))?;
                self.current = Some(i);
                i
            }
        };
        let mode = self.modes[idx].clone();
        let stats = extract_with(path, &mode)?;
        Ok((mode.name, stats))
    }

    /// Try every mode in order; the first that decodes the whole archive wins.
    fn detect_mode(&mut self, path: &Path) -> Result<(String, ExtractStats)> {
        for i in 0..self.modes.len() {
            let mode = self.modes[i].clone();
            match extract_with(path, &mode) {
                Ok(stats) => {
                    self.current = Some(i);
                    return Ok((mode.name, stats));
                }
                Err(e) => log::debug!("mode {} rejected: {e}", mode.name),
            }
        }
        Err(Error::NoMatchingMode(path.to_path_buf()))
    }

    /// `findGameFromArchive`: look for the executable next to the archive or
    /// one level up when the archive sits in `Data/`.
    fn find_game_from_archive(&mut self, archive: &Path) {
        let Some(mut folder) = archive.parent().map(Path::to_path_buf) else {
            return;
        };
        if folder
            .file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(DATA_NAME))
        {
            if let Some(p) = folder.parent() {
                folder = p.to_path_buf();
            }
        }
        (self.on_event)(&Event::SearchingGame(&folder));
        for exe in GAME_EXE_NAMES {
            if let Some(p) = find_ci(&folder, exe) {
                (self.on_event)(&Event::GameFound(&p));
                if let Err(e) = self.init_game(&p) {
                    (self.on_event)(&Event::Warning(&e));
                }
                return;
            }
        }
    }

    /// `findDxArcKeyFile`: derive the archive key of a Pro game, register it
    /// as the current mode and store it in the config file.
    fn find_pro_key(&mut self) -> Result<bool> {
        let Some(key_file) = self.game.as_ref().and_then(|g| g.pro_key_file.clone()) else {
            return Ok(false);
        };
        (self.on_event)(&Event::ProDetected);
        let bytes = fs::read(&key_file).at(&key_file)?;
        let k = pro::dx_arc_key(&bytes)?;
        self.modes.push(CryptMode {
            name: "UNKNOWN_PRO".into(),
            crypt_version: k.crypt_version,
            format: crate::dxa::DxaFormat::V8,
            key: k.key.clone(),
        });
        self.current = Some(self.modes.len() - 1);
        // UberWolf appends a new UNKNOWN_<n> entry on every run; an identical
        // key already in the config is not written again here.
        let known = self
            .modes
            .iter()
            .find(|m| m.crypt_version == 0 && m.key == k.key);
        let name = match known {
            Some(m) => m.name.clone(),
            None => config::add_key(&self.opts.config_path, &k.key)?,
        };
        (self.on_event)(&Event::ProKeyFound { config_name: &name });
        Ok(true)
    }
}

/// Result of packing one folder.
#[derive(Debug)]
pub enum PackOutcome {
    Packed(PackStats),
    /// The archive exists and `overwrite` is off.
    Exists,
    Failed(Error),
}

/// Result of [`Session::unprotect`].
#[derive(Debug)]
pub struct Unprotected {
    /// Where the unprotected files are.
    pub location: PathBuf,
    pub files: Vec<FileReport>,
}

/// Result of [`Session::decrypt_wolfx`].
#[derive(Debug, Default)]
pub struct WolfxReport {
    /// Candidate keys, string values and integer values found.
    pub candidates: (usize, usize, usize),
    /// Data files that could not be read; their commands are missing.
    pub warnings: Vec<Error>,
    pub files: Vec<wolfx::FileResult>,
}

impl Session {
    /// Folder holding the extracted data: the data folder, or its `Data`
    /// subfolder when the archives sit next to the executable.
    fn extracted_data_folder(&self) -> Result<PathBuf> {
        let g = self
            .game
            .as_ref()
            .ok_or_else(|| Error::Game("no game initialised".into()))?;
        let folder = g.data_folder.clone();
        Ok(if g.data_as_file {
            find_ci(&folder, DATA_NAME).unwrap_or_else(|| folder.join(DATA_NAME))
        } else {
            folder
        })
    }

    /// `getBasicDataFolder`: `<data>/BasicData`, or `<game>/Data/BasicData`
    /// when the archives sit next to the executable.
    fn basic_data_folder(&self) -> Result<PathBuf> {
        let folder = self.extracted_data_folder()?;
        Ok(find_ci(&folder, BASIC_DATA).unwrap_or_else(|| folder.join(BASIC_DATA)))
    }

    /// `PackData` (`-p`): pack every folder of the data folder into
    /// `<folder>.wolf` next to it, with the mode at `mode_idx` in
    /// [`Self::modes`]. An existing archive is kept unless `overwrite` is on.
    pub fn pack_data(&mut self, mode_idx: usize) -> Result<Vec<(PathBuf, PackOutcome)>> {
        let mode = self
            .modes
            .get(mode_idx)
            .cloned()
            .ok_or_else(|| Error::Game(format!("invalid mode index {mode_idx}")))?;
        let data = self
            .game
            .as_ref()
            .ok_or_else(|| Error::Game("no game initialised".into()))?
            .data_folder
            .clone();
        let mut dirs: Vec<PathBuf> = fs::read_dir(&data)
            .at(&data)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect();
        dirs.sort();
        Ok(dirs
            .into_iter()
            .map(|dir| {
                let out = dir.with_extension("wolf");
                let outcome = if !self.opts.overwrite && out.exists() {
                    PackOutcome::Exists
                } else {
                    (self.on_event)(&Event::Packing(&dir));
                    let r = pack_directory(&dir, &out, &mode);
                    (self.on_event)(&Event::Packed {
                        path: &dir,
                        result: r.as_ref().map(|s| *s),
                    });
                    match r {
                        Ok(s) => PackOutcome::Packed(s),
                        Err(e) => PackOutcome::Failed(e),
                    }
                };
                (dir, outcome)
            })
            .collect())
    }

    /// `DecryptWolfXFiles` (`-x`): decrypt every `.wolfx` file of the game
    /// folder, with keys and values read from the extracted
    /// `CommonEvent.dat` and maps. Run it after extraction.
    pub fn decrypt_wolfx(&self) -> Result<WolfxReport> {
        let g = self
            .game
            .as_ref()
            .ok_or_else(|| Error::Game("no game initialised".into()))?;
        let mut warnings = Vec::new();
        let root = g.exe.parent().unwrap_or(&g.data_folder);
        let mut files = wolfx::files_with_extension(root, wolfx::WOLFX_EXTENSION, &mut warnings);
        if files.is_empty() {
            return Ok(WolfxReport {
                warnings,
                ..Default::default()
            });
        }
        // Small files first, as in the original; the solution of one file
        // is tried first on the next.
        files.sort_by_key(|p| (fs::metadata(p).map(|m| m.len()).unwrap_or(0), p.clone()));

        let data = self.extracted_data_folder()?;
        let ce = find_ci(&self.basic_data_folder()?, COMMON_EVENT_DAT);
        if ce.is_none() {
            warnings.push(Error::Game(format!(
                "{BASIC_DATA}/{COMMON_EVENT_DAT} not found in {}",
                data.display()
            )));
        }
        let (cands, w) = wolfx::collect(&data, ce.as_deref());
        warnings.extend(w);
        Ok(WolfxReport {
            candidates: (
                cands.keys.len(),
                cands.strings.values().map(|s| s.len()).sum(),
                cands.ints.values().map(|s| s.len()).sum(),
            ),
            files: wolfx::decrypt_files(&files, &cands),
            warnings,
        })
    }

    /// `FindProtectionKey`: the protection key of a Pro game, `None` for
    /// other games. Unpacks the `BasicData` archive first when its
    /// `Game.dat` is not there yet.
    pub fn protection_key(&mut self) -> Result<Option<ProtectionKey>> {
        let Some(g) = self.game.clone() else {
            return Err(Error::Game("no game initialised".into()));
        };
        if g.pro_key_file.is_none() {
            return Ok(None);
        }
        let mut game_dat = find_ci(&self.basic_data_folder()?, PROTECTED_GAME_DAT);
        if game_dat.is_none() {
            let archive = WOLF_EXTENSIONS
                .iter()
                .find_map(|e| find_ci(&g.data_folder, &format!("{BASIC_DATA}.{e}")))
                .ok_or_else(|| {
                    Error::Game(format!("could not find the protection file {BASIC_DATA}"))
                })?;
            if let Outcome::Failed(e) = self.unpack_archive(&archive) {
                return Err(e);
            }
            game_dat = find_ci(&self.basic_data_folder()?, PROTECTED_GAME_DAT);
        }
        let path = game_dat
            .ok_or_else(|| Error::Game(format!("{BASIC_DATA}/{PROTECTED_GAME_DAT} not found")))?;
        let bytes = fs::read(&path).at(&path)?;
        protkey::protection_key(&bytes).map(Some)
    }

    /// `RemoveProtection` (`-u`), for the version returned with the
    /// protection key.
    pub fn unprotect(&self, version: ProVersion) -> Result<Unprotected> {
        let basic = self.basic_data_folder()?;
        match version {
            ProVersion::V35 => Ok(Unprotected {
                files: unprotect::unprotect_v35(&basic)?,
                location: basic,
            }),
            ProVersion::V1 => {
                let out = self
                    .game
                    .as_ref()
                    .map(|g| g.data_folder.join(UNPROTECTED_FOLDER))
                    .unwrap_or_default();
                Ok(Unprotected {
                    files: unprotect::unprotect_v1(&basic, &out)?,
                    location: out,
                })
            }
            ProVersion::V2 => Err(Error::Unsupported(
                "removing the Pro v2 protection (not implemented in UberWolf either)".into(),
            )),
        }
    }
}

/// Crypt version of a DXA v8 header, 0 when the file has no plain header.
pub fn crypt_version(path: &Path) -> Result<u16> {
    let mut h = [0u8; 48];
    let mut f = fs::File::open(path).at(path)?;
    if std::io::Read::read_exact(&mut f, &mut h).is_err() {
        return Ok(0);
    }
    if u16::from_le_bytes([h[0], h[1]]) != DXA_MAGIC {
        return Ok(0);
    }
    Ok(u16::from_le_bytes([h[46], h[47]]))
}

/// Output folder: the archive path without its extension.
pub fn output_dir(archive: &Path) -> PathBuf {
    archive.with_extension("")
}

/// `IsAlreadyUnpacked`: the output folder exists and is not empty (a folder
/// holding only UberWolf's `decrypt_temp` counts as empty).
fn is_already_unpacked(archive: &Path) -> bool {
    let out = output_dir(archive);
    let Ok(rd) = fs::read_dir(&out) else {
        return false;
    };
    let names: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
    if names.is_empty() {
        return false;
    }
    if names.len() == 1 && names[0] == DECRYPT_TEMP {
        let _ = fs::remove_file(out.join(DECRYPT_TEMP));
        return false;
    }
    true
}

/// Extract `archive` with one mode into a temporary folder, then move it
/// into place. Nothing is left behind on failure.
fn extract_with(archive: &Path, mode: &CryptMode) -> Result<ExtractStats> {
    let out = output_dir(archive);
    let file_name = out
        .file_name()
        .ok_or_else(|| Error::Game(format!("bad archive path {}", archive.display())))?
        .to_string_lossy()
        .into_owned();
    let tmp = out.with_file_name(format!(".{file_name}.unwolf-tmp"));
    if tmp.exists() {
        fs::remove_dir_all(&tmp).at(&tmp)?;
    }
    fs::create_dir_all(&tmp).at(&tmp)?;

    let result = Archive::open(
        archive,
        &OpenParams {
            format: mode.format,
            key: &mode.key,
        },
    )
    .and_then(|a| extract_to(&a, &tmp));

    match result {
        Ok(stats) => {
            if out.exists() {
                merge_move(&tmp, &out)?;
            } else {
                fs::rename(&tmp, &out).at(&out)?;
            }
            Ok(stats)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}
