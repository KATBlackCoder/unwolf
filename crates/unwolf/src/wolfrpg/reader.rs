use std::ops::Range;

use crate::error::{Error, Result};

/// Bounds-checked little-endian reader (`FileReader` in the original).
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

/// Position of a length-prefixed string in the buffer being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringField {
    /// Offset of the 4-byte length.
    pub start: usize,
    /// The stored bytes, terminating NUL included.
    pub content: Range<usize>,
}

impl StringField {
    /// The whole field, length prefix included.
    pub fn span(&self) -> Range<usize> {
        self.start..self.content.end
    }
}

fn eof() -> Error {
    Error::format("WolfRPG: unexpected end of data")
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn is_eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(eof)?;
        let s = self.data.get(self.pos..end).ok_or_else(eof)?;
        self.pos = end;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a byte and fail unless it equals `expected`.
    pub fn expect_u8(&mut self, expected: u8, what: &str) -> Result<()> {
        let b = self.u8()?;
        if b != expected {
            return Err(Error::format(format!(
                "WolfRPG: {what}: expected {expected:#04x}, got {b:#04x}"
            )));
        }
        Ok(())
    }

    /// `ReadString`: a `u32` length then the bytes. Empty strings are an
    /// error, as in the original.
    pub fn string(&mut self) -> Result<StringField> {
        let start = self.pos;
        let len = self.u32()? as usize;
        if len == 0 {
            return Err(Error::format("WolfRPG: zero length string"));
        }
        let content_start = self.pos;
        self.skip(len)?;
        Ok(StringField {
            start,
            content: content_start..self.pos,
        })
    }

    /// The bytes of a field read from this buffer.
    pub fn get(&self, f: &StringField) -> &'a [u8] {
        &self.data[f.content.clone()]
    }

    /// A `u32` count followed by that many strings.
    pub fn string_array(&mut self) -> Result<Vec<StringField>> {
        let n = self.u32()?;
        (0..n).map(|_| self.string()).collect()
    }

    /// A `u32` count followed by that many items of `size` bytes.
    pub fn skip_array(&mut self, size: usize) -> Result<()> {
        let n = self.u32()? as usize;
        self.skip(n.checked_mul(size).ok_or_else(eof)?)
    }
}
