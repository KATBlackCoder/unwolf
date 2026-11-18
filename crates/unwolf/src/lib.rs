//! Decrypt and extract Wolf RPG Editor archives.
//!
//! This crate is a Rust port of UberWolfLib by Sinflower
//! (<https://github.com/Sinflower/UberWolf>, MIT License).
//!
//! Entry points: [`game::Session`] for whole games and folders, or
//! [`dxa::Archive`] for a single archive with a known [`modes::CryptMode`].
//!
//! # Example
//!
//! To use the library without the `unwolf` command and its dependencies
//! (`clap`, `env_logger`), turn off the default features:
//!
//! ```toml
//! [dependencies]
//! unwolf = { version = "0.2", default-features = false }
//! ```
//!
//! Extract every archive of a game, then remove the protection of a Wolf RPG
//! Pro game. Each archive `X.wolf` is extracted to `X/` next to it.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use unwolf::game::{Event, Options, Outcome, ProtectionStatus, Session};
//!
//! fn main() -> unwolf::Result<()> {
//!     // Keys found for Wolf RPG Pro games are saved in this file.
//!     let opts = Options::new("/path/to/settings/UberWolfConfig.json");
//!     // Events report progress as it happens; only warnings are shown here.
//!     // The handler is `Send`: the session can run on a worker thread.
//!     let on_event = |e: &Event<'_>| {
//!         if let Event::Warning(err) = e {
//!             eprintln!("warning: {err}");
//!         }
//!     };
//!     let mut session = Session::new(opts, Box::new(on_event));
//!     session.init_game(Path::new("/path/to/game/Game.exe"))?;
//!
//!     for (archive, outcome) in session.unpack_data()? {
//!         let name = archive.display();
//!         match outcome {
//!             Outcome::Extracted { mode, stats } => {
//!                 println!("{name}: {} files ({mode})", stats.files)
//!             }
//!             Outcome::AlreadyUnpacked => println!("{name}: already unpacked"),
//!             Outcome::Failed(err) => eprintln!("{name}: {err}"),
//!             // `Skipped`, and outcomes added by later versions.
//!             _ => {}
//!         }
//!     }
//!
//!     if let ProtectionStatus::Protected(version) = session.protection_status()? {
//!         let report = session.unprotect(version)?;
//!         println!("unprotected files in {}", report.location.display());
//!     }
//!     Ok(())
//! }
//! ```
//!
//! [`game::Session::unpack_data_with_progress`] and
//! [`game::Session::unpack_files_with_progress`] also report each extracted
//! file and can stop the extraction.
//!
//! # Stability
//!
//! The public enums and result structs are `#[non_exhaustive]`: a later
//! 0.2.x version may add variants and fields, so `match` them with a
//! wildcard arm and build [`game::Options`] with [`game::Options::new`].
//! Modules hidden from this documentation (cipher layers, Wolf RPG data
//! files, WolfX, file helpers) are used by the `unwolf` command, the tests
//! and the examples; they are not part of the stable API and may change in
//! any version.

pub mod config;
#[doc(hidden)]
pub mod crypto;
pub mod dxa;
mod error;
#[doc(hidden)]
pub mod fsutil;
pub mod game;
pub mod modes;
#[doc(hidden)]
pub mod pro;
pub mod protkey;
#[doc(hidden)]
pub mod rng;
pub mod unprotect;
#[doc(hidden)]
pub mod wolfrpg;
#[doc(hidden)]
pub mod wolfx;

pub use error::{Error, Result};
