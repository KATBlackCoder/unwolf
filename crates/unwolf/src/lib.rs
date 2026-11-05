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
//! unwolf = { version = "0.1", default-features = false }
//! ```
//!
//! Extract every archive of a game. Each archive `X.wolf` is extracted to
//! `X/` next to it.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use unwolf::game::{Event, Options, Outcome, Session};
//!
//! fn main() -> unwolf::Result<()> {
//!     let opts = Options {
//!         // Keys found for Wolf RPG Pro games are saved here. The default
//!         // is `UberWolfConfig.json` in the current folder.
//!         config_path: "/path/to/settings/UberWolfConfig.json".into(),
//!         ..Options::default()
//!     };
//!     // Events report progress as it happens; only warnings are shown here.
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
//!             Outcome::Skipped => {}
//!             Outcome::Failed(err) => eprintln!("{name}: {err}"),
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! [`game::Session::unpack_data_with_progress`] also reports each extracted
//! file and can stop the extraction.

pub mod config;
pub mod crypto;
pub mod dxa;
mod error;
pub mod fsutil;
pub mod game;
pub mod modes;
pub mod pro;
pub mod protkey;
pub mod rng;
pub mod unprotect;
pub mod wolfrpg;
pub mod wolfx;

pub use error::{Error, Result};
