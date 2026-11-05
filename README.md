# unwolf

Extract the files of a Wolf RPG Editor game (`.wolf` archives) on Linux,
without Wine. One command, no setup: the decryption key is found for you,
including for Wolf RPG Pro games.

unwolf is a Rust port of [UberWolf / UberWolfCli](https://github.com/Sinflower/UberWolf)
by Sinflower (MIT License). It is still young: it works on the games it was
tested on, and bug reports are welcome.

## Install

We recommend installing with Cargo, Rust's package manager: it is the
simplest way, works on any Linux system and makes updates easy. With Rust
1.85 or later ([install Rust](https://rustup.rs)):

```bash
cargo install unwolf
```

Run the same command again to update.

Without Rust: download `unwolf-<version>-x86_64-linux-gnu.tar.gz` from the
[Releases](https://github.com/KATBlackCoder/unwolf/releases) page, check it
against the `.sha256` file next to it, extract it and put `unwolf` in your
`PATH`. It needs glibc 2.34 or later (Ubuntu 22.04, Debian 12, Fedora 35 and
later).

## Quick start

```bash
unwolf "/path/to/MyGame/Game.exe"
```

Every archive of the game is extracted next to it: `Data/Picture.wolf` gives
`Data/Picture/`. The archives themselves are not changed.

Put the path in quotes when it contains spaces or Japanese characters.

## Common situations

**Extract a whole game.** Give the game's executable (`Game.exe`, or
`GamePro.exe` for Pro games) or its `Data` folder:

```bash
unwolf "/path/to/MyGame/GamePro.exe"
unwolf "/path/to/MyGame/Data"
```

**Extract only some archives:**

```bash
unwolf "/path/to/MyGame/Data/Picture.wolf" "/path/to/MyGame/Data/BGM.wolf"
```

**Extract again.** Archives that already have their folder are skipped
(`Picture.wolf is already unpacked, skipping`). Add `-o` to extract them again:

```bash
unwolf -o "/path/to/MyGame/Game.exe"
```

**A Wolf RPG Pro game.** Nothing special to do: unwolf finds the key and saves
it in `UberWolfConfig.json`, in the folder you run the command from, so it
is not searched again next time. To keep that file somewhere else:

```bash
unwolf --config ~/.config/unwolf/UberWolfConfig.json "/path/to/MyGame/GamePro.exe"
```

**Encrypted fonts or other `.wolfx` files.** Add `-x`; they are decrypted
after the extraction:

```bash
unwolf -x "/path/to/MyGame/Game.exe"
```

Each `foo.otf.wolfx` gives `foo.otf` next to it.

**Read the data files of a Pro game** (to edit or translate them): `-u` removes
the protection of the files in `BasicData`, after the extraction. On Pro 3.5
the files are decrypted in place and the originals kept in `BasicData/backup/`;
for other Pro versions, see the details below.

```bash
unwolf -u "/path/to/MyGame/GamePro.exe"
```

## Reading the output

```
Unpacking: Picture.wolf ... Done (577 files, Wolf RPG v3.50)
Unpacking: MapData.wolf ... Failed
  <reason>
Protection key: NOT POSSIBLE FOR WolfRPG v3.5
```

- `Done (577 files, ...)`: the archive was extracted. The name in brackets is
  the decryption method that worked (`UNKNOWN_PRO` or `UNKNOWN_<n>` for a
  Pro game key).
- `Failed`: this archive could not be extracted; the next ones still are.
  The command then ends with exit status 1.
- `Protection key: ...`: shown for Pro games only. It is information for
  modders, not an error. `NOT POSSIBLE FOR WolfRPG v3.5` is normal for those
  games and does not affect extraction.

## Problems

- **The path is cut or "no matches found":** put the path in quotes.
- **An archive fails:** try again with `-o`.
- **`GLIBC_2.34 not found` with the downloaded binary:** your system is too
  old for it; install with `cargo install unwolf` instead.

Found a bug? Please
[open an issue](https://github.com/KATBlackCoder/unwolf/issues/new/choose)
and tell me what happened. Give the unwolf version (`unwolf --version`), the
game's Wolf RPG version if you know it and the full output. Screenshots or
other proof of the problem are very welcome when possible: they make the fix
much easier. Please do not attach game files, archives or executables.

## All options

| Option | Effect |
| --- | --- |
| `-o`, `--override` | Extract again into existing folders; with `-p`, replace existing archives. |
| `-x`, `--wolfx` | Decrypt the `.wolfx` files (needs the executable). |
| `-u`, `--unprotect` | Pro games: remove the protection of `BasicData` (needs the executable). |
| `-p N`, `--pack N` | Experimental: pack each data folder back into a `.wolf` archive with mode `N` (needs the executable; `unwolf --help` lists the modes). The game itself has not loaded such archives yet. |
| `--config PATH` | Where to read and save `UberWolfConfig.json` (default: current folder). |

## Use as a Rust library

```toml
unwolf = { version = "0.1", default-features = false }
```

`default-features = false` leaves out the command and its dependencies. See
the example on [docs.rs](https://docs.rs/unwolf).

## More details

Tested versions, behaviour of each option, differences from UberWolfCli and
how the port is checked against it:
[docs/details.md](https://github.com/KATBlackCoder/unwolf/blob/main/docs/details.md).

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
