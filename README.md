# unwolf

Native Linux tool and Rust library to decrypt and extract Wolf RPG Editor
archives (`.wolf` and the other extensions Wolf RPG uses), without Wine.

It is a Rust port of [UberWolf / UberWolfCli](https://github.com/Sinflower/UberWolf)
by Sinflower (MIT License), studied at commit `f419137`.

## Status

"Matches UberWolfCli" means that the extracted files have the same contents
and modification times as the files extracted by the original executable under
Wine. "Tested on synthetic data" means round-trip unit tests only: no real game
was available for this feature yet.

| Feature | State |
| --- | --- |
| DXA v8, Wolf 2.225 – 3.14 (classic DX keys) | done, matches UberWolfCli on a real 3.14 game |
| DXA v8, Wolf 3.31 / 3.50 (Wolf AES and XOR layers) | done, matches UberWolfCli on real 3.31 and 3.50 games |
| DXA v6 (Wolf 2.20) / v5 (2.01, 2.10) | v6 matches UberWolfCli on a real game; v5 tested on synthetic data |
| ChaCha20 modes | tested on synthetic data |
| Wolf RPG Pro archive keys | implemented, untested |
| Pro protection key, `-u` unprotect | tested on synthetic data |
| `-x` WolfX | decrypts the WolfX fonts of a real non-Pro 3.14 game; not compared with UberWolfCli, which refuses non-Pro games |
| `-p` repack (experimental) | round trip tested for the 11 built-in modes; on real 3.14 and 3.50 games, UberWolfCli extracts unwolf's archives and unwolf extracts UberWolfCli's, with the same results; 2.20 and 3.31 not checked on a real game; never loaded by the game engine |

## Build

```bash
cargo build --release      # binary: target/release/unwolf
```

Rust 1.85 or later.

## Usage

```bash
unwolf /path/to/Game.exe                  # every archive of the game
unwolf /path/to/Data                      # every archive in a folder
unwolf /path/to/Data/BasicData.wolf ...   # given archives
```

Each archive `X.wolf` is extracted to `X/` next to it. An archive whose output
folder already exists and is not empty is skipped.

| Option | Effect |
| --- | --- |
| `-o`, `--override` | Extract again into existing output folders; with `-p`, overwrite existing archives. |
| `-u`, `--unprotect` | Wolf RPG Pro: remove the protection of the `BasicData` files (needs `Game.exe`). |
| `-x`, `--wolfx` | Decrypt the `.wolfx` files of the game (needs `Game.exe`). |
| `-p N`, `--pack N` | Experimental. Pack each folder of the data folder into `<folder>.wolf` with mode `N` (needs `Game.exe`). |
| `--config PATH` | `UberWolfConfig.json` to read and update (default: current folder). |

`unwolf --help` lists the mode indices accepted by `-p`. Modes added to the
configuration file follow the built-in ones.

### Decryption modes

The mode of each archive is taken from the crypt version in its header when
there is one, otherwise each mode is tried in turn. The first mode that decodes
an archive is reused for the next ones, like the original. Extra keys can be
listed in `UberWolfConfig.json`, in the original's format.

For Wolf RPG Pro games, the archive key is derived from the game's key file
(`Game.wolf`, `List.wolf`...). It is added to the configuration file as
`UNKNOWN_<n>`.

### With `Game.exe`

After extraction, the protection key of a Pro game is printed:

```
Protection key: <key>
```

Wolf RPG 3.5 stores only a hash of that key, so for those games the line reads
`NOT POSSIBLE FOR WolfRPG v3.5`, as with the original.

- `-u` on Pro 3.5: the files of `BasicData` are decrypted in place. The originals
  are copied to `BasicData/backup/` (an existing backup is never replaced).
  Running `-u` again finds nothing left to decrypt.
- `-u` on Pro v1: decrypted copies go to `<data>/unprotected/`.
- `-u` on Pro v2: not supported (not implemented in UberWolf either).
- `-x`: every `foo.ext.wolfx` under the game folder is decrypted to `foo.ext`
  next to it; the `.wolfx` file is kept. The keys come from the game's own
  `SetWolfxKey`, `SetString` and `SetVariable` commands in `CommonEvent.dat` and
  the maps (`.mps`), so the archives must be extracted first.
- `-p N`: packs the folders but does not extract. `-o` replaces existing archives.

### Exit status

0 when everything succeeded, 1 when an archive, a `-u` file, a `.wolfx` file or a
packed folder failed (UberWolfCli returns 0 in most of these cases). Failures
do not stop the remaining work.

## Differences from UberWolfCli

Deliberate, to be portable or more robust. Behaviour that is not listed here
follows the original.

General and extraction:

- No subprocess per mode attempt and no `decrypt_temp` file. Each attempt is a
  bounds-checked decode into a temporary folder that is renamed on success.
  There is no 2 GiB limit.
- File names are looked up without regard to case (`Data.wolf`, `BasicData`,
  `CDataBase.dat`...), as NTFS does for the original.
- Archive names are checked: absolute paths, `..` and separators are rejected.
- With `NO_HEAD_PRESS`, the tables are read at the name table offset. The
  original reads them at offset 64.
- A `newCrypt` archive (3.31+) smaller than 1088 bytes is read as the original
  encoder writes it: plain header, no AES layer and no whole-file XOR (tables
  and data keep their usual key). The original decoder reports success on such
  an archive without extracting anything. The result is the same for an empty
  folder; for a small folder with files, this port extracts them and the
  original does not.
- A Pro key already in `UberWolfConfig.json` is not written again.
- With `-o`, the output is merged into the existing folder; it is not deleted
  when extraction fails.
- Non-zero exit status on failure (see above).

`-u`:

- Only the event and type descriptions are rewritten; the rest of each file is
  copied byte for byte. The original re-encodes every string and normalises some
  counters.
- `DataBase.dat`, `CDataBase.dat` and `SysDatabase.dat` stay as decrypted. The
  original rewrites them with identical content but a new LZ4 compression.
  `CommonEvent.dat` is LZ4 compressed again here too, so it differs at byte
  level from the original's output but decompresses to the same data.
- Pro v1: output files keep the actual names found on disk. Nothing is written
  for a file that fails (the original writes an empty file).
- `-u` and `-x` without `Game.exe` print a warning (the original ignores them
  silently).

`-x`:

- Each file gets a full search over the candidates, after trying the solution of
  the previous file. The original shares one result between files and retries
  failures in up to 5 rounds. The results differ only if two candidates pass the
  5-byte checksum.
- `.wolfx` files are searched in the whole game folder, with the extension
  matched without regard to case, and non-Pro games are accepted. The original
  searches the data folder only and refuses games without a Pro key file.
- Databases are not loaded (they hold no commands). A data file that cannot be
  read gives a warning instead of aborting `-x`.
- A map protected by Pro 3.5 is skipped with a warning (the original throws an
  exception).
- Shift-JIS text is decoded with `encoding_rs` (WHATWG Shift_JIS, close to
  CP932). Invalid UTF-8 is decoded with replacement characters instead of
  aborting.

`-p`:

- The archives are not byte-identical to the original's. The LZ and Huffman
  encoders are this project's own, and entries are sorted by upper-case name
  (the original follows the NTFS enumeration). Files get attribute 0x20 and
  folders 0x10. When the file system has no creation date, the modification
  date is used.
- A `newCrypt` archive smaller than 1088 bytes is padded with zeros after its
  tables so that the encryption layers apply; UberWolfCli reads it back. The
  original writes it with a plain header and without the AES and whole-file
  layers. This reader opens that layout too; the original extracts nothing
  from it (see above).
- A file name that Shift-JIS cannot represent is an error instead of a `?`.
- A failing folder does not stop the next ones.

## Verification

- `cargo test`: unit tests, including round trips of every cipher layer, of
  `-u` and `-x` on synthetic files, and of `-p` for every built-in mode.
- `scripts/check-constants.py <UberWolf checkout>` compares the constant tables
  and magic values of the port with the C++ source: S-box, SHA-512 values, mode
  table, Pro headers and salts, WolfX constants, and more.
- `scripts/reference-wine.sh` and `scripts/manifest.sh` compare against the
  original `UberWolfCli.exe` under Wine on local copies of games. Game files,
  archives and executables are never committed (`.gitignore`).

- `crates/unwolf/tests/real_games.rs` (ignored by default) extracts real games
  and compares the result with the Wine reference, and can check a repack round
  trip on them; its header lists the environment variables. Example:

  ```bash
  UBERWOLF_GAMES_DIR=game-test UBERWOLF_REF_DIR=work/ref UBERWOLF_REPACK=1 \
      cargo test --release -p unwolf --test real_games -- --ignored --nocapture
  ```

  `cargo test` runs the test from `crates/unwolf`; relative paths in these
  variables are resolved from the workspace root, so the command works as is
  from any folder of the repository.

## Layout

- `crates/unwolf`: the library.
  - `game::Session`: the whole-game workflow.
  - `dxa`: archive reader and writer, LZ and Huffman.
  - `crypto`, `rng`: cipher layers.
  - `protkey`, `unprotect`: Pro protection.
  - `wolfrpg`, `wolfx`: Wolf RPG data files and WolfX.
- `crates/unwolf-cli`: the `unwolf` binary.
- `scripts/`: Wine comparison and constant checks.

## Support

If unwolf saved you time, you can send a tip. GitHub Sponsors, PayPal and
Stripe do not pay out in the country where I live, so tips are crypto only.
Tips are a thank-you: they do not buy features or support.

| Coin | Network | Address |
| --- | --- | --- |
| BTC | Bitcoin | `bc1qmr578evx5fzwyr754a00j9hkekd2gzpvs8zxzz` |
| ETH, USDT, USDC | Ethereum (ERC-20) | `0x29652Fd86095913d472fF08BFEE5a15c5E7C9D51` |
| SOL, USDT, USDC | Solana | `3RKD9MEzUrSvR8T7DACY3vRuQ8nJrPBocnhTkL5PE1h5` |
| USDT, TRX | Tron (TRC-20) | `TCkSqo15TxuS6RuEbWqFhDYpwbN8X73sLj` |

Check the network before sending: only the networks listed here are watched,
and coins sent on another network may be lost.

## License and attribution

MIT, see `LICENSE`. UberWolf is Copyright (c) 2023 Sinflower. The DX Library
archive format is reimplemented from its description; see `NOTICE` for the
DX Library attribution (Copyright (C) 2001-2026 Takumi Yamada).
