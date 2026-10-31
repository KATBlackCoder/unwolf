//! Pseudo-random generators used by the Wolf RPG crypto layers.
//!
//! UberWolf relies on global generator state (CRT `srand`/`rand`, a static
//! `xorshift32`). Every generator here is an explicit value instead; callers
//! reproduce the original call order.

pub mod chain;
mod msvc;
mod mt19937;
mod xorshift;

pub use msvc::MsvcRand;
pub use mt19937::Mt19937;
pub use xorshift::Xorshift32;
