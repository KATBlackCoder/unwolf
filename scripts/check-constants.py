#!/usr/bin/env python3
"""Compare the constant tables of the Rust port with UberWolf's C++ source.

Usage: scripts/check-constants.py <path to an UberWolf checkout at f419137>

Each check extracts a bracketed block (or a single value) from a C++ file
and from a Rust file, then compares the integer literals, or the string
literals, in order. Exits with status 1 on the first mismatch report.
"""

import re
import sys
from pathlib import Path

RS = Path(__file__).resolve().parent.parent / "crates" / "unwolf" / "src"

INT_RE = re.compile(r"\b(0[xX][0-9A-Fa-f_]+|\d[\d_]*)(?:ULL|ull|UL|ul|LL|ll|U|u|L|l)?\b")
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
OPEN = "[{("
CLOSE = "]})"


def strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def block(path, anchor):
    """Text of the first bracketed block after `anchor` (after its `=` when
    the anchor line has one)."""
    text = path.read_text(encoding="utf-8")
    m = re.search(anchor, text)
    if not m:
        sys.exit(f"anchor {anchor!r} not found in {path}")
    i = m.end()
    if "fn " in anchor:
        # A function: its body, not its parameter list or return type.
        i = text.index("{", i)
    line_end = text.find("\n", m.start())
    eq = text.find("=", m.start(), line_end)
    if eq != -1 and "fn " not in anchor:
        i = max(i, eq + 1)
    while text[i] not in OPEN:
        i += 1
    depth = 0
    j = i
    while j < len(text):
        ch = text[j]
        if ch == '"':
            # Skip string literals: keys such as "nGui9('&1=@3#a" hold brackets.
            j += 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
        elif ch in OPEN:
            depth += 1
        elif ch in CLOSE:
            depth -= 1
            if depth == 0:
                return strip_comments(text[i : j + 1])
        j += 1
    sys.exit(f"unbalanced block after {anchor!r} in {path}")


def to_int(v):
    v = v.replace("_", "")
    return int(v, 16) if v[:2] in ("0x", "0X") else int(v, 10)


def ints(text):
    # Numbers inside string literals (mode names) are not constants.
    return [to_int(v) for v in INT_RE.findall(STR_RE.sub("", text))]


def strings(text):
    return [s for s in STR_RE.findall(text) if s]


def scalar(path, pattern):
    m = re.search(pattern, path.read_text(encoding="utf-8"))
    if not m:
        sys.exit(f"pattern {pattern!r} not found in {path}")
    return [to_int(m.group(1))]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    src = Path(sys.argv[1])
    lib = src / "UberWolfLib"
    crypt = lib / "WolfCrypt"

    # (name, kind, C++ file, C++ anchor, Rust file, Rust anchor)
    blocks = [
        ("AES S-box", "ints", crypt / "WolfAes.hpp", r"sbox\[256\]", RS / "crypto/aes.rs", r"const SBOX"),
        ("AES Rcon", "ints", crypt / "WolfAes.hpp", r"Rcon\[11\]", RS / "crypto/aes.rs", r"const RCON"),
        ("SHA-512 Wolf H0", "ints", crypt / "WolfSha512.hpp", r"hPrime\[8\]", RS / "crypto/sha512.rs", r"const WOLF_H0"),
        ("SHA-512 K", "ints", crypt / "WolfSha512.hpp", r"uint64_t k\[80\]", RS / "crypto/sha512.rs", r"const K:"),
        ("cc2 mod1", "ints", crypt / "WolfDxArcKey.hpp", r"mod1\[4\]", RS / "pro.rs", r"const MOD1"),
        ("cc2 mod2", "ints", crypt / "WolfDxArcKey.hpp", r"mod2\[4\]", RS / "pro.rs", r"const MOD2"),
        ("cc2 mod3", "ints", crypt / "WolfDxArcKey.hpp", r"mod3\[4\]", RS / "pro.rs", r"const MOD3"),
        ("ChaCha key", "ints", src / "3rdParty/DXLib/DXArchive.cpp", r"g_cc20Key\[32\]", RS / "dxa/v8.rs", r"const CHACHA_V1_KEY"),
        ("ChaCha nonce", "ints", src / "3rdParty/DXLib/DXArchive.cpp", r"g_cc20Nonce\[12\]", RS / "dxa/v8.rs", r"const CHACHA_V1_NONCE"),
        ("mode table (numbers)", "ints", lib / "WolfDec.cpp", r"DEFAULT_CRYPT_MODES =", RS / "modes.rs", r"pub fn default_modes"),
        ("mode table (strings)", "strings", lib / "WolfDec.cpp", r"DEFAULT_CRYPT_MODES =", RS / "modes.rs", r"pub fn default_modes"),
        ("data decrypt intervals", "ints", crypt / "WolfDataDecrypt.hpp", r"DECRYPT_INTERVALS\[\]", RS / "crypto/datadecrypt.rs", r"const INTERVALS"),
        ("Pro v3.5 headers", "ints", crypt / "WolfDataDecrypt.hpp", r"PRO_MAGIC =", RS / "crypto/datadecrypt.rs", r"pub fn magic\(self\)"),
        ("Pro v3.5 salts", "strings", crypt / "WolfDataDecrypt.hpp", r"PRO_MAGIC =", RS / "crypto/datadecrypt.rs", r"pub fn static_salt\(self\)"),
        ("Pro v1 plain header", "ints", lib / "WolfPro.cpp", r"DEC_START =", RS / "unprotect.rs", r"const DEC_START"),
        ("v3.5 protected files", "strings", lib / "WolfUnprotect.hpp", r"PROTECTED_FILES =", RS / "unprotect.rs", r"const V35_FILES"),
        ("CommonEvent magic", "ints-utf8", lib / "WolfRPG/CommonEvents.hpp", r"MagicNumber MAGIC_NUMBER =", RS / "wolfrpg/mod.rs", r"const COMMON_EVENT_MAGIC"),
        ("Map magic", "ints-last", lib / "WolfRPG/Map.hpp", r"MagicNumber MAGIC_NUMBER(?=\{)", RS / "wolfrpg/map.rs", r"const MAP_MAGIC"),
        ("WolfX magic", "ints", lib / "WolfX/detail/CrackDetail.hpp", r"WOLFX_MAGIC =", RS / "wolfx.rs", r"pub fn wolfx_magic_bytes"),
        ("Database magic", "ints-utf8", lib / "WolfRPG/Database.hpp", r"DAT_MAGIC_NUMBER(?=\{)", RS / "wolfrpg/mod.rs", r"const DATABASE_MAGIC"),
    ]
    scalars = [
        ("protection key seed", crypt.parent / "WolfPro.cpp", r"KEY_SEED\s*=\s*(0x[0-9A-Fa-f]+)", RS / "protkey.rs", r"KEY_SEED: u32 = (0x[0-9A-Fa-f_]+)"),
        ("v3.5 key offset", crypt / "WolfDataDecrypt.hpp", r"KEY_START_OFFSET\s*=\s*(\d+)", RS / "crypto/datadecrypt.rs", r"KEY_START: usize = (\d+)"),
        ("v3.5 IV offset", crypt / "WolfDataDecrypt.hpp", r"IV_START_OFFSET\s*=\s*(\d+)", RS / "crypto/datadecrypt.rs", r"IV_START: usize = (\d+)"),
        ("v3.5 header size", crypt / "WolfDataDecrypt.hpp", r"PRO_SPECIAL_SIZE\s*=\s*(\d+)", RS / "crypto/datadecrypt.rs", r"PRO_V35_HEADER_SIZE: usize = (\d+)"),
        ("AES data offset", crypt / "WolfDataDecrypt.hpp", r"AES_DATA_OFFSET\s*=\s*(\d+)", RS / "crypto/datadecrypt.rs", r"AES_DATA_OFFSET: usize = (\d+)"),
        ("map UTF-8 flag index", lib / "WolfRPG/Map.hpp", r"0x00, 0x00, 0x00 \},\s*(\d+) \}", RS / "wolfrpg/map.rs", r"MAP_UTF8_INDEX: usize = (\d+)"),
        ("WolfX FNV-1 offset basis", lib / "WolfX/detail/GeneratorDetail.hpp", r"hash\s*=\s*(0x[0-9A-F]+)", RS / "wolfx.rs", r"fold\((0x[0-9A-F_]+)u32"),
        ("WolfX FNV-1 prime", lib / "WolfX/detail/GeneratorDetail.hpp", r"prime\s*=\s*(0x[0-9A-F]+)", RS / "wolfx.rs", r"(0x0100_0193)u32"),
        ("WolfX LCG multiplier", lib / "WolfX/detail/GeneratorDetail.hpp", r"seed \* (\d+)", RS / "wolfx.rs", r"seed\.wrapping_mul\(([\d_]+)\)"),
        ("WolfX LCG increment", lib / "WolfX/detail/GeneratorDetail.hpp", r"seed \* \d+ \+ (\d+)", RS / "wolfx.rs", r"seed\.wrapping_mul\([\d_]+\)\.wrapping_add\(([\d_]+)\)"),
        ("WolfX static blob fill", lib / "WolfX/detail/GeneratorDetail.hpp", r"data\.fill\((0x[0-9A-F]+)\)", RS / "wolfx.rs", r"\[(0xAA)u8; STATIC_BLOB_LEN\]"),
        ("WolfX static blob start", lib / "WolfX/detail/GeneratorDetail.hpp", r"dynamicVal = (0x[0-9A-F]+);", RS / "wolfx.rs", r"dynamic: u8 = (0x[0-9A-F]+);"),
        ("WolfX static blob factor", lib / "WolfX/detail/GeneratorDetail.hpp", r"\((0x[0-9A-F]+) \* dynamicVal\)", RS / "wolfx.rs", r"(0xB3)u8\.wrapping_mul"),
        ("WolfX integer hash factor", lib / "WolfX/detail/CrackDetail.hpp", r"\^ \((\d+) \* params\.magicInt\)", RS / "wolfx.rs", r"([\d_]+)u32\.wrapping_mul\(v\)"),
        ("WolfX data offset base", lib / "WolfX/detail/CrackDetail.hpp", r"dataOffset = (\d+) \+ staticBlob", RS / "wolfx.rs", r"data_offset = (\d+) \+"),
        ("WolfX string index limit", lib / "WolfX/detail/CrackDetail.hpp", r"magicStrIndex < (\d+)", RS / "wolfx.rs", r"STRING_INDEX_LIMIT: u32 = ([\d_]+)"),
        ("WolfX integer index limit", lib / "WolfX/detail/CrackDetail.hpp", r"intIndex < (\d+)", RS / "wolfx.rs", r"INT_INDEX_LIMIT: u32 = ([\d_]+)"),
        ("MSVC LCG multiplier", crypt / "WolfRng.hpp", r"s_winRngSeed \* (\d+)", RS / "rng/msvc.rs", r"wrapping_mul\(([\d_]+)\)"),
        ("MSVC LCG increment", crypt / "WolfRng.hpp", r"\* \d+ \+ (\d+);", RS / "rng/msvc.rs", r"wrapping_add\(([\d_]+)\)"),
    ]

    failed = 0
    for name, kind, cf, ca, rf, ra in blocks:
        extract = strings if kind == "strings" else ints
        c, r = extract(block(cf, ca)), extract(block(rf, ra))
        if kind == "ints-last":
            # `MagicNumber{bytes, utf8Idx}`: the index is checked on its own.
            c = c[:-1]
        if kind == "ints-utf8":
            # `MagicNumber{bytes, utf8Idx}`: the index is UTF8_FLAG_INDEX.
            c, r = c[:-1], r
            r_idx = scalar(RS / "wolfrpg/mod.rs", r"UTF8_FLAG_INDEX: usize = (\d+)")
            c_idx = ints(block(cf, ca))[-1:]
            if c_idx != r_idx:
                c, r = c + c_idx, r + r_idx
        if c != r:
            failed += 1
            print(f"MISMATCH {name}:\n  C++  {c}\n  Rust {r}")
        else:
            print(f"ok  {name} ({len(c)} values)")
    for name, cf, cp, rf, rp in scalars:
        c, r = scalar(cf, cp), scalar(rf, rp)
        if c != r:
            failed += 1
            print(f"MISMATCH {name}: C++ {c} Rust {r}")
        else:
            print(f"ok  {name} ({c[0]:#x})")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
