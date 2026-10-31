//! `UberWolfConfig.json`: extra decryption modes, and keys found for Pro
//! games. The format is the one written by UberWolf:
//!
//! ```json
//! {"keys": {"UNKNOWN_0": {"mode": "VER8", "key": ["0x9C", "0xC8", "0x00"]}}}
//! ```
//!
//! `key` may also be a plain string. `mode` is `VER5`, `VER6` or `VER8`.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use crate::dxa::DxaFormat;
use crate::error::{Error, IoContext, Result};
use crate::modes::CryptMode;

pub const CONFIG_FILE_NAME: &str = "UberWolfConfig.json";

/// Read the modes of a config file. A missing or empty file yields none.
///
/// Like UberWolf, modes read before an invalid entry are kept and the error
/// is returned alongside them.
pub fn load(path: &Path) -> (Vec<CryptMode>, Option<Error>) {
    let mut modes = Vec::new();
    let text = match fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => t,
        _ => return (modes, None),
    };
    let err = |message: String| Error::Config {
        path: path.to_path_buf(),
        message,
    };
    let root: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return (modes, Some(err(e.to_string()))),
    };
    let Some(keys) = root.get("keys").and_then(Value::as_object) else {
        return (modes, None);
    };
    for (name, v) in keys {
        let (Some(mode), Some(key)) = (v.get("mode"), v.get("key")) else {
            continue;
        };
        let format = match mode.as_str().map(str::to_lowercase).as_deref() {
            Some("ver5") => DxaFormat::V5,
            Some("ver6") => DxaFormat::V6,
            Some("ver8") => DxaFormat::V8,
            _ => return (modes, Some(err(format!("invalid mode: {mode}")))),
        };
        let key = match parse_key(key) {
            Ok(k) => k,
            Err(m) => return (modes, Some(err(format!("{name}: {m}")))),
        };
        // UberWolf gives loaded modes crypt version 0.
        modes.push(CryptMode {
            name: name.clone(),
            crypt_version: 0,
            format,
            key,
        });
    }
    (modes, None)
}

fn parse_key(v: &Value) -> std::result::Result<Vec<u8>, String> {
    let mut key = match v {
        Value::Array(items) => {
            let mut k = Vec::with_capacity(items.len() + 1);
            for it in items {
                let s = it.as_str().ok_or("key bytes must be strings")?;
                let digits = s.trim_start_matches("0x").trim_start_matches("0X");
                let b = u8::from_str_radix(digits, 16).map_err(|_| format!("bad byte {s:?}"))?;
                k.push(b);
            }
            if k.last() != Some(&0) {
                k.push(0);
            }
            return Ok(k);
        }
        Value::String(s) => s.as_bytes().to_vec(),
        _ => return Err("key must be an array or a string".into()),
    };
    key.push(0);
    Ok(key)
}

/// Add a key under the first free `UNKNOWN_<n>` name and write the file
/// with 4-space indentation, keeping existing entries in order.
pub fn add_key(path: &Path, key: &[u8]) -> Result<String> {
    let mut root: Map<String, Value> = match fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => serde_json::from_str(&t).map_err(|e| Error::Config {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?,
        _ => Map::new(),
    };
    let keys = root
        .entry("keys")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(keys) = keys else {
        return Err(Error::Config {
            path: path.to_path_buf(),
            message: "\"keys\" is not an object".into(),
        });
    };
    let name = (0..)
        .map(|n| format!("UNKNOWN_{n}"))
        .find(|n| !keys.contains_key(n))
        .unwrap_or_default();
    let mut entry = Map::new();
    entry.insert("mode".into(), Value::String("VER8".into()));
    entry.insert(
        "key".into(),
        Value::Array(
            key.iter()
                .map(|b| Value::String(format!("0x{b:02X}")))
                .collect(),
        ),
    );
    keys.insert(name.clone(), Value::Object(entry));

    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    serde::Serialize::serialize(&Value::Object(root), &mut ser).map_err(|e| Error::Config {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    fs::write(path, out).at(path)?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_like_uberwolf() {
        let dir = std::env::temp_dir().join(format!("unwolf-cfg-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join(CONFIG_FILE_NAME);
        let _ = fs::remove_file(&p);
        assert_eq!(add_key(&p, &[0x9C, 0x00, 0x84]).unwrap(), "UNKNOWN_0");
        assert_eq!(add_key(&p, &[0x01]).unwrap(), "UNKNOWN_1");
        let text = fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"0x9C\""));
        let (modes, err) = load(&p);
        assert!(err.is_none());
        assert_eq!(modes.len(), 2);
        assert_eq!(modes[0].key, vec![0x9C, 0x00, 0x84, 0x00]);
        assert_eq!(modes[1].key, vec![0x01, 0x00]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
