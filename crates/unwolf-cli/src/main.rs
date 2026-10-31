//! `unwolf`: command line front end, modelled on UberWolfCli.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use unwolf::fsutil::{has_extension_ci, list_files};
use unwolf::game::{Event, Options, Outcome, PackOutcome, Session};
use unwolf::modes::default_modes;
use unwolf::unprotect::FileStatus;

fn pack_help() -> String {
    let modes = default_modes()
        .iter()
        .enumerate()
        .map(|(i, m)| format!("{i} - {}", m.name))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Repack the game's data folders with the given mode (experimental: \
         the archives are read back by UberWolfCli but not yet by the game)\n\n{modes}"
    )
}

#[derive(Parser)]
#[command(
    name = "unwolf",
    version,
    about = "Decrypt and extract Wolf RPG Editor archives (Rust port of UberWolfCli)"
)]
struct Cli {
    /// <Game[Pro].exe>, <data_folder> or archive files (.wolf, ...)
    #[arg(value_name = "FILE", required = true)]
    files: Vec<PathBuf>,

    /// Re-extract archives whose output folder already exists
    #[arg(short = 'o', long = "override")]
    overwrite: bool,

    /// Remove the protection of Wolf RPG Pro data files
    #[arg(short = 'u', long)]
    unprotect: bool,

    /// Decrypt WolfX files if present
    #[arg(short = 'x', long)]
    wolfx: bool,

    /// Repack the game's data folders with the given mode (experimental)
    #[arg(short = 'p', long = "pack", value_name = "VER_IDX", long_help = pack_help())]
    pack: Option<usize>,

    /// Configuration file with extra keys
    #[arg(long, value_name = "PATH", default_value = unwolf::config::CONFIG_FILE_NAME)]
    config: PathBuf,
}

fn print_event(e: &Event<'_>) {
    let name = |p: &std::path::Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let mut out = std::io::stdout();
    match e {
        Event::Unpacking(p) => {
            let _ = write!(out, "Unpacking: {} ... ", name(p));
            let _ = out.flush();
        }
        Event::AlreadyUnpacked(p) => println!("{} is already unpacked, skipping", name(p)),
        Event::Done { stats, mode, .. } => {
            println!("Done ({} files, {mode})", stats.files);
        }
        Event::Failed { error, .. } => {
            println!("Failed");
            eprintln!("  {error}");
        }
        Event::SearchingGame(p) => println!("Searching for game executable in: {}", p.display()),
        Event::GameFound(p) => println!("Found game executable: {}", name(p)),
        Event::ProDetected => println!("WolfPro game detected, trying to get decryption key ..."),
        Event::ProKeyFound { config_name } => {
            println!("Found the decryption key ({config_name}), restarting extraction")
        }
        Event::Warning(err) => eprintln!("warning: {err}"),
        Event::Packing(p) => {
            let _ = write!(out, "Packing: {} ... ", name(p));
            let _ = out.flush();
        }
        Event::Packed { result, .. } => match result {
            Ok(s) => println!("Done ({} files, {} bytes)", s.files, s.archive_size),
            Err(e) => {
                println!("Failed");
                eprintln!("  {e}");
            }
        },
    }
}

/// Print the protection key of a Pro game and, with `-u`, remove the
/// protection. Returns false when `-u` was requested and did not succeed.
fn protection(session: &mut Session, unprotect: bool) -> bool {
    let key = match session.protection_key() {
        Ok(Some(k)) => k,
        Ok(None) => {
            if unprotect {
                eprintln!(
                    "error: unable to remove protection, this does not look like a WolfPro game"
                );
            }
            return !unprotect;
        }
        Err(e) => {
            eprintln!("error: protection key: {e}");
            return !unprotect;
        }
    };
    println!("Protection key: {key}");
    if !unprotect {
        return true;
    }
    let report = match session.unprotect(key.version()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return false;
        }
    };
    let mut ok = true;
    for f in &report.files {
        print!("Removing protection from: {} ... ", f.name);
        match &f.status {
            FileStatus::Done => println!("Done"),
            FileStatus::NotProtected => println!("not protected, skipped"),
            FileStatus::Failed(e) => {
                ok = false;
                println!("Failed");
                eprintln!("  {e}");
            }
        }
    }
    println!(
        "Unprotected files can be found in: {}",
        report.location.display()
    );
    ok
}

/// `-x`. Returns false when a `.wolfx` file could not be decrypted.
fn wolfx(session: &Session) -> bool {
    let report = match session.decrypt_wolfx() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: WolfX: {e}");
            return false;
        }
    };
    for w in &report.warnings {
        eprintln!("warning: {w}");
    }
    if report.files.is_empty() {
        println!("No WolfX files found");
        return true;
    }
    let (keys, strings, ints) = report.candidates;
    println!(
        "Found {} WolfX files ({keys} keys, {strings} string values, {ints} integer values)",
        report.files.len()
    );
    let mut ok = true;
    for f in &report.files {
        if let Err(e) = &f.outcome {
            ok = false;
            eprintln!("  {}: {e}", f.path.display());
        }
    }
    let done = report.files.iter().filter(|f| f.outcome.is_ok()).count();
    println!("Decrypted {done}/{} WolfX files", report.files.len());
    ok
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let cli = Cli::parse();

    let opts = Options {
        overwrite: cli.overwrite,
        config_path: cli.config.clone(),
    };
    let mut session = Session::new(opts, Box::new(print_event));
    let first = &cli.files[0];

    let mut failed_extra = 0;
    let results = if first.is_file() && has_extension_ci(first, "exe") {
        if let Err(e) = session.init_game(first) {
            eprintln!("Failed to initialize game with the provided executable: {e}");
            return ExitCode::FAILURE;
        }
        if let Some(idx) = cli.pack {
            if idx >= session.modes().len() {
                eprintln!("Invalid package version index");
                return ExitCode::FAILURE;
            }
            return match session.pack_data(idx) {
                Ok(r) => {
                    let failed = r
                        .iter()
                        .filter(|(_, o)| matches!(o, PackOutcome::Failed(_)))
                        .count();
                    if failed > 0 {
                        eprintln!("{failed} folder(s) failed");
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        let results = match session.unpack_data() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };
        if !protection(&mut session, cli.unprotect) {
            failed_extra += 1;
        }
        if cli.wolfx && !wolfx(&session) {
            failed_extra += 1;
        }
        results
    } else {
        if cli.unprotect || cli.wolfx {
            eprintln!("warning: -u and -x are only used with a game executable");
        }
        if cli.pack.is_some() {
            eprintln!("[ERROR] Currently, packing can only be used with an executable");
            return ExitCode::FAILURE;
        }
        let paths: Vec<PathBuf> = if first.is_dir() {
            match list_files(first) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            cli.files.iter().filter(|p| p.is_file()).cloned().collect()
        };
        if paths.is_empty() {
            println!("No valid files found.");
            return ExitCode::FAILURE;
        }
        session.unpack_files(&paths)
    };

    // UberWolfCli exits with 0 even when archives fail; here any failure is
    // reported in the exit status.
    let failed = results
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Failed(_)))
        .count();
    if failed > 0 {
        eprintln!("{failed} archive(s) failed");
    }
    if failed + failed_extra > 0 {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
