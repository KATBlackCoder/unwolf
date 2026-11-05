//! Orchestration: locate a game's data, pick the decryption mode of each
//! archive and extract it (`UberWolfLib` and `WolfDec` in the original).
//!
//! The original runs each mode attempt in a child process and treats a crash
//! as "wrong mode". Here every attempt is a bounds-checked decode into a
//! temporary directory that is renamed into place on success.

use std::fs;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::config;
use crate::dxa::{
    Archive, DXA_MAGIC, ExtractStats, OpenParams, PackStats, extract_with_progress, pack_directory,
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
/// Mode name of the archive key derived from a Pro game's key file.
const PRO_MODE_NAME: &str = "UNKNOWN_PRO";

/// Keys compare without their final NUL: keys loaded from the config file
/// always end with one, derived Pro v2 keys do not.
fn same_key(a: &[u8], b: &[u8]) -> bool {
    fn trim(k: &[u8]) -> &[u8] {
        k.strip_suffix(&[0]).unwrap_or(k)
    }
    trim(a) == trim(b)
}

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
    /// The archive key of a Pro game was derived and the extraction starts
    /// again with it.
    ProKeyFound {
        /// Name of the key in the config file. When the key cannot be saved
        /// there, a [`Event::Warning`] comes first and this is `UNKNOWN_PRO`:
        /// the key is kept for this session only.
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

/// One extracted file, passed to the callback of
/// [`Session::unpack_data_with_progress`] and
/// [`Session::unpack_files_with_progress`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FileProgress<'a> {
    /// The archive being extracted.
    pub archive: &'a Path,
    /// Path of the file inside the archive, relative to its output folder.
    pub path: &'a Path,
    /// Number of the file in the archive, from 1 to `total`.
    pub index: u64,
    /// Number of files in the archive, folders excluded.
    pub total: u64,
}

/// Callback of the `*_with_progress` methods.
type OnFile<'f> = dyn FnMut(&FileProgress<'_>) -> ControlFlow<()> + 'f;

fn no_progress(_: &FileProgress<'_>) -> ControlFlow<()> {
    ControlFlow::Continue(())
}

/// The outcome inside a [`ControlFlow`]: `Break` when the caller stopped.
fn outcome(flow: ControlFlow<Outcome, Outcome>) -> Outcome {
    match flow {
        ControlFlow::Continue(o) | ControlFlow::Break(o) => o,
    }
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

    /// [`Self::unpack_data`], calling `on_file` after each extracted file.
    /// See [`Self::unpack_files_with_progress`].
    ///
    /// ```no_run
    /// use std::ops::ControlFlow;
    /// use std::path::Path;
    /// use unwolf::game::{Event, Options, Session};
    ///
    /// # fn main() -> unwolf::Result<()> {
    /// let mut session = Session::new(Options::default(), Box::new(|_: &Event<'_>| {}));
    /// session.init_game(Path::new("/path/to/game/Game.exe"))?;
    /// let results = session.unpack_data_with_progress(|f| {
    ///     println!("{}: {}/{} {}", f.archive.display(), f.index, f.total, f.path.display());
    ///     ControlFlow::Continue(()) // ControlFlow::Break(()) stops
    /// })?;
    /// # let _ = results;
    /// # Ok(())
    /// # }
    /// ```
    pub fn unpack_data_with_progress<F>(&mut self, on_file: F) -> Result<Vec<(PathBuf, Outcome)>>
    where
        F: FnMut(&FileProgress<'_>) -> ControlFlow<()>,
    {
        let folder = self
            .game
            .as_ref()
            .ok_or_else(|| Error::Game("no game initialised".into()))?
            .data_folder
            .clone();
        let files = list_files(&folder)?;
        Ok(self.unpack_files_with_progress(&files, on_file))
    }

    /// `UnpackDataVec`: archives with a known extension; others are ignored.
    /// Failures do not stop the remaining archives.
    pub fn unpack_files(&mut self, paths: &[PathBuf]) -> Vec<(PathBuf, Outcome)> {
        self.unpack_files_with_progress(paths, no_progress)
    }

    /// [`Self::unpack_files`], calling `on_file` after each file is written
    /// in the temporary folder of its archive.
    ///
    /// The numbering starts again at 1 for each archive. It can also start
    /// again within one archive: when a decryption mode fails partway, the
    /// next mode extracts the archive from its first file. Archives skipped
    /// or already unpacked call nothing.
    ///
    /// When `on_file` returns [`ControlFlow::Break`], the extraction stops:
    /// - the current archive is [`Outcome::Failed`] with an [`Error::Io`]
    ///   of kind [`std::io::ErrorKind::Interrupted`] for its path, also sent
    ///   as [`Event::Failed`];
    /// - its temporary folder is removed: no partial output is left, and
    ///   with `overwrite` an existing output folder stays as it was;
    /// - the remaining archives are not opened and are missing from the
    ///   result, which ends with the stopped archive.
    ///
    /// A stop on the last file of an archive discards that archive too.
    pub fn unpack_files_with_progress<F>(
        &mut self,
        paths: &[PathBuf],
        mut on_file: F,
    ) -> Vec<(PathBuf, Outcome)>
    where
        F: FnMut(&FileProgress<'_>) -> ControlFlow<()>,
    {
        let mut results = Vec::new();
        for p in paths
            .iter()
            .filter(|p| WOLF_EXTENSIONS.iter().any(|e| has_extension_ci(p, e)))
        {
            let flow = self.unpack_archive_inner(p, false, &mut on_file);
            let stop = flow.is_break();
            results.push((p.clone(), outcome(flow)));
            if stop {
                break;
            }
        }
        results
    }

    pub fn unpack_archive(&mut self, path: &Path) -> Outcome {
        outcome(self.unpack_archive_inner(path, false, &mut no_progress))
    }

    /// `Break` when `on_file` stopped the extraction.
    fn unpack_archive_inner(
        &mut self,
        path: &Path,
        second_run: bool,
        on_file: &mut OnFile<'_>,
    ) -> ControlFlow<Outcome, Outcome> {
        use ControlFlow::{Break, Continue};
        if !path.is_file() {
            return Continue(Outcome::Failed(Error::io(
                path,
                std::io::ErrorKind::NotFound.into(),
            )));
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if pro::is_special_file(&name) {
            return Continue(Outcome::Skipped);
        }
        if !self.opts.overwrite && is_already_unpacked(path) {
            (self.on_event)(&Event::AlreadyUnpacked(path));
            return Continue(Outcome::AlreadyUnpacked);
        }
        if !second_run {
            (self.on_event)(&Event::Unpacking(path));
        }

        match self.decrypt(path, on_file) {
            Ok(Some((mode, stats))) => {
                (self.on_event)(&Event::Done {
                    path,
                    mode: &mode,
                    stats,
                });
                Continue(Outcome::Extracted { mode, stats })
            }
            Ok(None) => {
                let err = Error::io(
                    path,
                    std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "extraction stopped by the caller",
                    ),
                );
                (self.on_event)(&Event::Failed { path, error: &err });
                Break(Outcome::Failed(err))
            }
            Err(err) => {
                if !second_run {
                    if self.game.is_none() {
                        self.find_game_from_archive(path);
                    }
                    match self.find_pro_key() {
                        Ok(true) => return self.unpack_archive_inner(path, true, on_file),
                        Ok(false) => {}
                        Err(e) => (self.on_event)(&Event::Warning(&e)),
                    }
                }
                (self.on_event)(&Event::Failed { path, error: &err });
                Continue(Outcome::Failed(err))
            }
        }
    }

    /// `WolfDec::UnpackArchive`: choose the mode, then extract. `None` when
    /// `on_file` stopped the extraction.
    fn decrypt(
        &mut self,
        path: &Path,
        on_file: &mut OnFile<'_>,
    ) -> Result<Option<(String, ExtractStats)>> {
        let idx = match self.current {
            Some(i) => i,
            None => {
                let cv = crypt_version(path)?;
                if cv == 0 {
                    return self.detect_mode(path, on_file);
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
        Ok(extract_with(path, &mode, on_file)?.map(|stats| (mode.name, stats)))
    }

    /// Try every mode in order; the first that decodes the whole archive wins.
    /// A stop from `on_file` ends the search.
    fn detect_mode(
        &mut self,
        path: &Path,
        on_file: &mut OnFile<'_>,
    ) -> Result<Option<(String, ExtractStats)>> {
        for i in 0..self.modes.len() {
            let mode = self.modes[i].clone();
            match extract_with(path, &mode, on_file) {
                Ok(Some(stats)) => {
                    self.current = Some(i);
                    return Ok(Some((mode.name, stats)));
                }
                Ok(None) => return Ok(None),
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
        let bytes = fs::read(&key_file).at(&key_file)?;
        let k = pro::dx_arc_key(&bytes)?;
        if self
            .modes
            .iter()
            .any(|m| m.name == PRO_MODE_NAME && same_key(&m.key, &k.key))
        {
            // Found earlier in this run: the archive fails for another reason.
            return Ok(false);
        }
        (self.on_event)(&Event::ProDetected);
        self.modes.push(CryptMode {
            name: PRO_MODE_NAME.into(),
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
            .find(|m| m.crypt_version == 0 && same_key(&m.key, &k.key));
        let name = match known {
            Some(m) => m.name.clone(),
            None => match config::add_key(&self.opts.config_path, &k.key) {
                Ok(n) => n,
                // The key stays in memory: this run goes on, the next one
                // derives it again.
                Err(e) => {
                    (self.on_event)(&Event::Warning(&e));
                    PRO_MODE_NAME.to_owned()
                }
            },
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
/// into place. Nothing is left behind on failure, nor when `on_file` stops
/// the extraction (`Ok(None)`).
fn extract_with(
    archive: &Path,
    mode: &CryptMode,
    on_file: &mut OnFile<'_>,
) -> Result<Option<ExtractStats>> {
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
    .and_then(|a| {
        extract_with_progress(&a, &tmp, &mut |path, index, total| {
            on_file(&FileProgress {
                archive,
                path,
                index,
                total,
            })
        })
    });

    match result {
        Ok(Some(stats)) => {
            if out.exists() {
                merge_move(&tmp, &out)?;
            } else {
                fs::rename(&tmp, &out).at(&out)?;
            }
            Ok(Some(stats))
        }
        Ok(None) => {
            if let Err(e) = fs::remove_dir_all(&tmp) {
                log::warn!("cannot remove {}: {e}", tmp.display());
            }
            Ok(None)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::dxa::DxaFormat;

    /// A fresh folder under the system temporary folder.
    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("unwolf-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Files packed into the test archives, sorted like the archive entries.
    const FILES: [(&str, &[u8]); 3] = [
        ("a.txt", b"first"),
        ("b.txt", b"second"),
        ("sub/c.txt", b"third"),
    ];

    fn pack(base: &Path, archive: &Path, mode: &CryptMode) {
        let src = base.join("src");
        for (p, data) in FILES {
            let full = src.join(p);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, data).unwrap();
        }
        pack_directory(&src, archive, mode).unwrap();
    }

    /// A synthetic Pro v2 game in `base`: `Game.exe`, the key file
    /// `Data/Game.wolf` and `Data/MapData.wolf` encrypted with its key.
    /// Returns the archive.
    fn pro_game(base: &Path) -> PathBuf {
        let data = base.join("Data");
        fs::create_dir_all(&data).unwrap();
        fs::write(base.join("Game.exe"), b"").unwrap();
        let mut key_file: Vec<u8> = (0..256u32).map(|i| (i * 7 + 3) as u8).collect();
        key_file[0] = 0x10; // neither Pro v1 (0xA0) nor cc2 (0xF1)
        key_file[7] = 0; // key bytes start right after the header
        key_file[19] = 8; // key length
        fs::write(data.join("Game.wolf"), &key_file).unwrap();
        let k = pro::dx_arc_key(&key_file).unwrap();
        assert!(k.crypt_version >= 1000);
        let archive = data.join("MapData.wolf");
        let mode = CryptMode {
            name: "test".into(),
            crypt_version: k.crypt_version,
            format: DxaFormat::V8,
            key: k.key,
        };
        pack(base, &archive, &mode);
        archive
    }

    fn mode_named(name: &str) -> CryptMode {
        default_modes()
            .into_iter()
            .find(|m| m.name == name)
            .unwrap()
    }

    /// A session that records its events as text.
    fn session(config_path: PathBuf, overwrite: bool) -> (Session, Rc<RefCell<Vec<String>>>) {
        let events = Rc::new(RefCell::new(Vec::new()));
        let log = Rc::clone(&events);
        let s = Session::new(
            Options {
                overwrite,
                config_path,
            },
            Box::new(move |e: &Event<'_>| log.borrow_mut().push(format!("{e:?}"))),
        );
        (s, events)
    }

    fn assert_extracted(archive: &Path) {
        for (p, data) in FILES {
            assert_eq!(fs::read(output_dir(archive).join(p)).unwrap(), data);
        }
    }

    /// The config file of a Pro game is saved in a folder that does not
    /// exist yet, and the first archive is extracted.
    #[test]
    fn pro_key_saved_in_missing_folder() {
        let base = temp_dir("pro-mkdir");
        let archive = pro_game(&base);
        let config = base.join("config/sub").join(config::CONFIG_FILE_NAME);
        let (mut s, events) = session(config.clone(), false);

        let r = s.unpack_files(std::slice::from_ref(&archive));
        assert!(matches!(r[0].1, Outcome::Extracted { .. }), "{:?}", r[0].1);
        assert_extracted(&archive);
        let (modes, err) = config::load(&config);
        assert!(err.is_none());
        assert_eq!(modes.len(), 1);
        let events = events.borrow();
        assert!(events.iter().any(|e| e.contains("\"UNKNOWN_0\"")));
        assert!(!events.iter().any(|e| e.starts_with("Warning")));
        fs::remove_dir_all(&base).unwrap();
    }

    /// When the config file cannot be written, a warning is sent and the
    /// archive is extracted with the key kept in memory.
    #[test]
    fn pro_key_kept_when_config_cannot_be_written() {
        let base = temp_dir("pro-ro");
        let archive = pro_game(&base);
        // A folder in place of the file: writing fails, even as root.
        let config = base.join(config::CONFIG_FILE_NAME);
        fs::create_dir_all(&config).unwrap();
        let (mut s, events) = session(config.clone(), false);

        let r = s.unpack_files(std::slice::from_ref(&archive));
        assert!(matches!(r[0].1, Outcome::Extracted { .. }), "{:?}", r[0].1);
        assert_extracted(&archive);
        {
            let events = events.borrow();
            let warning = events.iter().position(|e| e.starts_with("Warning"));
            let found = events.iter().position(|e| e.contains("\"UNKNOWN_PRO\""));
            assert!(warning.is_some() && found.is_some(), "{events:?}");
            assert!(warning < found);
            assert!(!events.iter().any(|e| e.starts_with("Failed")));
        }
        assert!(config.is_dir());

        // The key is reused for the next archive without a new attempt.
        events.borrow_mut().clear();
        let second = base.join("Data/Second.wolf");
        fs::copy(&archive, &second).unwrap();
        let r = s.unpack_files(std::slice::from_ref(&second));
        assert!(matches!(r[0].1, Outcome::Extracted { .. }), "{:?}", r[0].1);
        assert!(!events.borrow().iter().any(|e| e.starts_with("ProDetected")));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn progress_reports_every_file() {
        let base = temp_dir("progress");
        let archive = base.join("Map.wolf");
        pack(&base, &archive, &mode_named("Wolf RPG v3.50"));
        let (mut s, _) = session(base.join(config::CONFIG_FILE_NAME), false);

        let mut seen = Vec::new();
        let r = s.unpack_files_with_progress(std::slice::from_ref(&archive), |f| {
            assert_eq!(f.archive, archive.as_path());
            seen.push((f.path.to_path_buf(), f.index, f.total));
            ControlFlow::Continue(())
        });
        let Outcome::Extracted { stats, .. } = &r[0].1 else {
            panic!("{:?}", r[0].1);
        };
        assert_eq!(stats.files, FILES.len() as u64);
        let expected: Vec<_> = FILES
            .iter()
            .enumerate()
            .map(|(i, (p, _))| (PathBuf::from(p), i as u64 + 1, FILES.len() as u64))
            .collect();
        assert_eq!(seen, expected);
        assert_extracted(&archive);
        fs::remove_dir_all(&base).unwrap();
    }

    /// A stop fails the current archive with `Interrupted`, removes its
    /// temporary folder, keeps an existing output folder as it was and
    /// leaves the next archives alone.
    #[test]
    fn progress_stop_leaves_no_partial_output() {
        let base = temp_dir("progress-stop");
        let mode = mode_named("Wolf RPG v3.50");
        let first = base.join("First.wolf");
        pack(&base, &first, &mode);
        let second = base.join("Second.wolf");
        fs::copy(&first, &second).unwrap();
        let paths = [first.clone(), second.clone()];

        for overwrite in [false, true] {
            let out = output_dir(&first);
            if overwrite {
                fs::create_dir_all(&out).unwrap();
                fs::write(out.join("a.txt"), b"old").unwrap();
            }
            let (mut s, events) = session(base.join(config::CONFIG_FILE_NAME), overwrite);
            let mut calls = 0;
            let r = s.unpack_files_with_progress(&paths, |f| {
                calls += 1;
                if f.index == 2 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            });
            assert_eq!(calls, 2);
            assert_eq!(r.len(), 1, "the second archive is not opened");
            match &r[0].1 {
                Outcome::Failed(Error::Io { path, source }) => {
                    assert_eq!(path, &first);
                    assert_eq!(source.kind(), std::io::ErrorKind::Interrupted);
                }
                other => panic!("{other:?}"),
            }
            assert!(events.borrow().iter().any(|e| e.starts_with("Failed")));
            if overwrite {
                let names: Vec<_> = fs::read_dir(&out).unwrap().collect();
                assert_eq!(names.len(), 1);
                assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"old");
            } else {
                assert!(!out.exists());
            }
            assert!(!output_dir(&second).exists());
            let leftovers: Vec<_> = fs::read_dir(&base)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".unwolf-tmp"))
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
        }
        fs::remove_dir_all(&base).unwrap();
    }

    /// A Pro v2 key stored in the config file, then loaded again, matches the
    /// key derived from the game: it is not written a second time.
    #[test]
    fn pro_key_from_config_matches_derived_key() {
        let dir = std::env::temp_dir().join(format!("unwolf-prokey-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(config::CONFIG_FILE_NAME);

        // No final NUL, with one inside, like the key of a real Pro 3.7 game.
        let derived = [0x9C, 0xC8, 0xF8, 0x00, 0x84, 0xBA, 0x09, 0x70];
        assert_eq!(config::add_key(&path, &derived).unwrap(), "UNKNOWN_0");
        let (modes, err) = config::load(&path);
        assert!(err.is_none());
        assert_eq!(modes[0].key.last(), Some(&0));
        assert!(same_key(&modes[0].key, &derived));
        assert!(!same_key(&modes[0].key, &derived[..7]));
        fs::remove_dir_all(&dir).unwrap();
    }
}
