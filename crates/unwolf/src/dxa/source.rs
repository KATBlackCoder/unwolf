//! Byte access to an archive file, with the Wolf RPG whole-file layers.
//!
//! UberWolf decrypts the whole archive in memory, writes it to
//! `decrypt_temp` and reads that copy back. Every layer is a position-keyed
//! XOR stream, so here each requested range is decrypted on the fly from a
//! read-only memory map instead.

use std::fs::File;
use std::ops::Deref;
use std::path::Path;

use memmap2::Mmap;

use crate::crypto::aes::AesCtr;
use crate::crypto::wolf::WolfKey;
use crate::error::{Error, IoContext, Result};

enum Bytes {
    Map(Mmap),
    Owned(Vec<u8>),
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Map(m) => m,
            Bytes::Owned(v) => v,
        }
    }
}

/// Layers applied over the raw file by Wolf RPG 3.31+ (`newCrypt`).
pub struct WolfLayers {
    /// XOR table over `[64, size - 64)`.
    pub whole: WolfKey,
    pub whole_end: u64,
    pub aes: AesCtr,
    /// First AES region: `[64, body_end)`.
    pub body_end: u64,
    /// Second AES region: `[tables_start, size)`, continuing the counter.
    pub tables_start: u64,
}

pub struct Source {
    bytes: Bytes,
    layers: Option<WolfLayers>,
}

/// Start of the data area: every DXA v8 layer skips the 64-byte header.
const LAYER_START: u64 = 64;

impl Source {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).at(path)?;
        // SAFETY: the map is read-only and private to this process. Another
        // process truncating the file while it is mapped would raise SIGBUS;
        // the archive is an input that is not expected to change during
        // extraction.
        let map = unsafe { Mmap::map(&file) }.at(path)?;
        Ok(Self {
            bytes: Bytes::Map(map),
            layers: None,
        })
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::Owned(data),
            layers: None,
        }
    }

    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn raw(&self) -> &[u8] {
        &self.bytes
    }

    pub fn set_layers(&mut self, layers: WolfLayers) {
        self.layers = Some(layers);
    }

    /// Copy `len` bytes at `offset`, with the whole-file layers removed.
    pub fn read(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(len)
            .filter(|&e| e <= self.len())
            .ok_or_else(|| Error::format("read past the end of the archive"))?;
        let mut buf = self.bytes[offset as usize..end as usize].to_vec();
        if let Some(l) = &self.layers {
            l.apply(offset, &mut buf, self.len());
        }
        Ok(buf)
    }
}

impl WolfLayers {
    /// XOR the layers over `buf`, located at `offset` in a file of
    /// `file_len` bytes. The layers are XOR streams, so this both encrypts
    /// and decrypts.
    pub fn apply(&self, offset: u64, buf: &mut [u8], file_len: u64) {
        let end = offset + buf.len() as u64;
        if let Some((a, b)) = overlap(offset, end, LAYER_START, self.whole_end) {
            self.whole
                .xor_at(a, &mut buf[(a - offset) as usize..(b - offset) as usize]);
        }
        let body_counter = self.aes.counter_after(0);
        if let Some((a, b)) = overlap(offset, end, LAYER_START, self.body_end) {
            self.aes.xor_at(
                body_counter,
                a - LAYER_START,
                &mut buf[(a - offset) as usize..(b - offset) as usize],
            );
        }
        let tables_counter = self.aes.counter_after(self.body_end - LAYER_START);
        if let Some((a, b)) = overlap(offset, end, self.tables_start, file_len) {
            self.aes.xor_at(
                tables_counter,
                a - self.tables_start,
                &mut buf[(a - offset) as usize..(b - offset) as usize],
            );
        }
    }
}

fn overlap(a0: u64, a1: u64, b0: u64, b1: u64) -> Option<(u64, u64)> {
    let s = a0.max(b0);
    let e = a1.min(b1);
    (s < e).then_some((s, e))
}
