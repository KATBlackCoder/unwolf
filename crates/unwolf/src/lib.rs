//! Decrypt and extract Wolf RPG Editor archives.
//!
//! This crate is a Rust port of UberWolfLib by Sinflower
//! (<https://github.com/Sinflower/UberWolf>, MIT License).
//!
//! Entry points: [`game::Session`] for whole games and folders, or
//! [`dxa::Archive`] for a single archive with a known [`modes::CryptMode`].

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
