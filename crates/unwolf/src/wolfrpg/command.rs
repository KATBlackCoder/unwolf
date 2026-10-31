//! Event commands (`WolfRPG/Command.hpp` and `RouteCommand.hpp`).

use super::{Reader, StringField};
use crate::error::{Error, Result};

pub const SET_VARIABLE: u32 = 121;
pub const SET_STRING: u32 = 122;
pub const MOVE: u32 = 201;
pub const PRO_FEATURE: u32 = 1000;

/// `ProFeature` sub-command 7: set the `.wolfx` decryption key.
pub const PRO_FEATURE_SET_WOLFX_KEY: u32 = 7;

#[derive(Debug, Clone)]
pub struct Command {
    pub code: u32,
    pub args: Vec<u32>,
    pub strings: Vec<StringField>,
}

/// `Command::Init`. In Wolf RPG 3.5 data (`v35`) every command is followed
/// by a byte count and that many unknown bytes.
pub fn read(r: &mut Reader<'_>, v35: bool) -> Result<Command> {
    // The stored count includes the code; 0 wraps to 255 like the original.
    let arg_count = r.u8()?.wrapping_sub(1);
    let code = r.u32()?;
    let args = (0..arg_count)
        .map(|_| r.u32())
        .collect::<Result<Vec<_>>>()?;
    let _indent = r.u8()?;
    let string_count = r.u8()?;
    let strings = (0..string_count)
        .map(|_| r.string())
        .collect::<Result<Vec<_>>>()?;
    match r.u8()? {
        // Movement commands carry a route; the original also reads one for
        // code 201 with the plain terminator.
        1 => skip_move(r)?,
        0 if code == MOVE => skip_move(r)?,
        0 => {}
        t => {
            return Err(Error::format(format!(
                "WolfRPG: unexpected command terminator {t}"
            )));
        }
    }
    if v35 {
        let n = r.u8()?;
        r.skip(usize::from(n))?;
    }
    Ok(Command {
        code,
        args,
        strings,
    })
}

/// `CommandSpecialClasses::Move`: 5 unknown bytes, flags, then the route.
fn skip_move(r: &mut Reader<'_>) -> Result<()> {
    r.skip(5 + 1)?;
    skip_route(r)
}

/// A `u32` count of route commands (`RouteCommand::Init`): id, argument
/// count, arguments, then the bytes `01 00`.
pub(crate) fn skip_route(r: &mut Reader<'_>) -> Result<()> {
    let routes = r.u32()?;
    for _ in 0..routes {
        let _id = r.u8()?;
        let n = r.u8()?;
        r.skip(usize::from(n) * 4)?;
        if r.bytes(2)? != [0x01, 0x00] {
            return Err(Error::format("WolfRPG: bad route command terminator"));
        }
    }
    Ok(())
}

/// A `u32` count followed by that many commands.
pub fn read_list(r: &mut Reader<'_>, v35: bool) -> Result<Vec<Command>> {
    let n = r.u32()?;
    (0..n).map(|_| read(r, v35)).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Serialise a command the way `Command::Dump` does.
    pub(crate) fn encode(code: u32, args: &[u32], strings: &[&[u8]], v35: bool) -> Vec<u8> {
        let mut v = vec![(args.len() + 1) as u8];
        v.extend_from_slice(&code.to_le_bytes());
        for a in args {
            v.extend_from_slice(&a.to_le_bytes());
        }
        v.push(0); // indent
        v.push(strings.len() as u8);
        for s in strings {
            v.extend_from_slice(&(s.len() as u32).to_le_bytes());
            v.extend_from_slice(s);
        }
        v.push(0);
        if v35 {
            v.extend_from_slice(&[2, 0xAA, 0xBB]);
        }
        v
    }

    #[test]
    fn reads_plain_and_v35_commands() {
        for v35 in [false, true] {
            let mut data = encode(SET_STRING, &[3_000_005, 0], &[b"key\0"], v35);
            data.push(0xEE);
            let mut r = Reader::new(&data);
            let c = read(&mut r, v35).unwrap();
            assert_eq!(c.code, SET_STRING);
            assert_eq!(c.args, [3_000_005, 0]);
            assert_eq!(r.get(&c.strings[0]), b"key\0");
            assert_eq!(r.u8().unwrap(), 0xEE);
        }
    }

    #[test]
    fn reads_move_route() {
        let mut data = vec![1u8];
        data.extend_from_slice(&MOVE.to_le_bytes());
        data.extend_from_slice(&[0, 0, 1]); // indent, no strings, move terminator
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&2u32.to_le_bytes());
        for _ in 0..2 {
            data.extend_from_slice(&[9, 1, 4, 0, 0, 0, 1, 0]);
        }
        let mut r = Reader::new(&data);
        let c = read(&mut r, false).unwrap();
        assert_eq!(c.code, MOVE);
        assert!(r.is_eof());

        let last = data.len() - 1;
        data[last] = 2;
        assert!(read(&mut Reader::new(&data), false).is_err());
    }
}
