//! Database project files (`*.project`, `WolfRPG/Database.hpp`). The
//! matching `.dat` files hold the values; only the project part is needed
//! here.

use super::{Reader, StringField, splice_strings, strip_control_chars};
use crate::error::{Error, Result};

/// One database type as stored in the project file.
#[derive(Debug, Clone)]
pub struct ProjectType {
    pub name: StringField,
    pub fields: Vec<StringField>,
    pub data: Vec<StringField>,
    pub description: StringField,
}

/// A parsed, decrypted `.project` file. Fields point into [`Self::data`].
#[derive(Debug, Clone)]
pub struct Project {
    pub data: Vec<u8>,
    pub types: Vec<ProjectType>,
}

impl Project {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let mut r = Reader::new(&data);
        let n = r.u32()?;
        let types = (0..n)
            .map(|_| parse_type(&mut r))
            .collect::<Result<Vec<_>>>()?;
        if !r.is_eof() {
            return Err(Error::format("WolfRPG: project file has trailing data"));
        }
        Ok(Self { data, types })
    }

    pub fn string(&self, f: &StringField) -> &[u8] {
        &self.data[f.content.clone()]
    }

    /// `FixPro35TypeDescriptions` followed by `DumpProject`.
    pub fn fix_pro35_descriptions(&self, utf8: bool) -> Vec<u8> {
        let fields: Vec<StringField> = self.types.iter().map(|t| t.description.clone()).collect();
        splice_strings(&self.data, &fields, |s| strip_control_chars(s, utf8))
    }
}

/// `Type::Type(FileCoder&)`.
fn parse_type(r: &mut Reader<'_>) -> Result<ProjectType> {
    let name = r.string()?;
    let fields = r.string_array()?;
    let data = r.string_array()?;
    let description = r.string()?;
    // One type byte per field, padded to the stored size. The original
    // reads the field types then skips the rest, which always consumes
    // exactly this many bytes.
    let type_list_size = r.u32()? as usize;
    r.skip(type_list_size)?;
    r.string_array()?;
    for _ in 0..r.u32()? {
        r.string_array()?;
    }
    for _ in 0..r.u32()? {
        r.skip_array(4)?;
    }
    r.skip_array(4)?;
    Ok(ProjectType {
        name,
        fields,
        data,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_str(v: &mut Vec<u8>, s: &[u8]) {
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
        v.extend_from_slice(s);
    }

    fn put_u32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    pub(crate) fn encode_type(description: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        put_str(&mut v, b"Type\0");
        put_u32(&mut v, 2);
        put_str(&mut v, b"f1\0");
        put_str(&mut v, b"f2\0");
        put_u32(&mut v, 1);
        put_str(&mut v, b"d1\0");
        put_str(&mut v, description);
        put_u32(&mut v, 4);
        v.extend_from_slice(&[1, 2, 0, 0]);
        put_u32(&mut v, 2);
        put_str(&mut v, b"\0");
        put_str(&mut v, b"\0");
        put_u32(&mut v, 2);
        put_u32(&mut v, 1);
        put_str(&mut v, b"arg\0");
        put_u32(&mut v, 0);
        put_u32(&mut v, 2);
        put_u32(&mut v, 1);
        put_u32(&mut v, 5);
        put_u32(&mut v, 0);
        put_u32(&mut v, 2);
        put_u32(&mut v, 0);
        put_u32(&mut v, 9);
        v
    }

    #[test]
    fn parses_and_fixes_descriptions() {
        let mut data = Vec::new();
        put_u32(&mut data, 2);
        data.extend_from_slice(&encode_type(b"a\x03b\0"));
        data.extend_from_slice(&encode_type(b"plain\0"));
        let p = Project::parse(data.clone()).unwrap();
        assert_eq!(p.types.len(), 2);
        assert_eq!(p.string(&p.types[0].fields[1]), b"f2\0");

        let fixed = Project::parse(p.fix_pro35_descriptions(true)).unwrap();
        assert_eq!(fixed.string(&fixed.types[0].description), b"ab\0");
        assert_eq!(fixed.data.len(), data.len() - 1);

        data.push(0);
        assert!(Project::parse(data).is_err());
    }
}
