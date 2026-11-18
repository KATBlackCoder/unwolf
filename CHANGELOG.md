# Changelog

All notable changes to unwolf are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, a minor version may
break the API).

## [0.2.0] - Unreleased

This version prepares the library for use in applications: the breaking
changes are grouped here so that later 0.2.x versions only add things.

### Added

- `game::Session::protection_status` and `game::ProtectionStatus`: tell a
  game that is not Wolf RPG Pro, a Pro game whose protection was already
  removed, and a protected one (v1, v2 or v3.5).
- `protkey::is_unprotected`: whether a `Game.dat` is in plain form.
- `game::Options::new` and `Options::with_overwrite`.
- `game::EventHandler`, the type of the event handler.
- `game::FileResult`, re-exported from the WolfX module.
- Continuous integration: format, Clippy, tests (with and without the
  command), documentation, minimum Rust version and semver checks.

### Changed

- The event handler must be `Send`, so `Session` is `Send` and can run on a
  worker thread.
- Public enums (`Error`, `game::Event`, `Outcome`, `PackOutcome`,
  `ProtectionStatus`, `protkey::ProVersion`, `ProtectionKey`,
  `unprotect::FileStatus`) and result structs (`game::Options`, `GameInfo`,
  `Unprotected`, `WolfxReport`, `dxa::ExtractStats`, `PackStats`,
  `unprotect::FileReport`, `FileResult`) are `#[non_exhaustive]`.
- `Session::protection_key` returns `None` for a Pro game whose protection
  was already removed, and `protkey::protection_key` fails on a plain
  `Game.dat`, instead of trying a v1 key on it.
- `unwolf -u` on a game whose protection was already removed says so and
  succeeds, instead of failing on a wrong v1 key.
- The modules `crypto`, `rng`, `wolfrpg`, `wolfx`, `pro`, `fsutil`,
  `dxa::lz` and `dxa::huffman` are hidden from the documentation and are not
  part of the stable API.

### Migration from 0.1

- Build options with `Options::new(config_path)` (and `.with_overwrite(true)`)
  instead of a struct literal.
- Give `Session::new` a `Send` handler: replace `Rc<RefCell<…>>` captures with
  `Arc<Mutex<…>>`.
- Add a wildcard arm (`_ => …`) to `match` expressions on the enums above.
- Before `Session::unprotect`, call `Session::protection_status` and pass the
  version of `ProtectionStatus::Protected`; a game reported as `Unprotected`
  needs nothing.

## [0.1.2] - 2026-11-05

### Changed

- New README for users; details moved to `docs/details.md`.

## [0.1.1] - 2026-11-05

### Added

- `Session::unpack_data_with_progress` and `unpack_files_with_progress`:
  report each extracted file and can stop the extraction.

### Fixed

- A Pro archive key is used for the run even when the configuration file
  cannot be written; missing folders of that file are created.
- Small Pro archives (under 1088 bytes) are read.
- A Pro key already in the configuration file is not written again.

## [0.1.0] - 2026-10-31

### Added

- First release: extraction of Wolf RPG Editor archives (DXA v5, v6, v8),
  Wolf RPG Pro archive keys, protection key and `-u`, WolfX decryption and
  experimental repacking, as a library and the `unwolf` command. Rust port of
  UberWolf / UberWolfCli.

[0.2.0]: https://github.com/KATBlackCoder/unwolf/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/KATBlackCoder/unwolf/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/KATBlackCoder/unwolf/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/KATBlackCoder/unwolf/releases/tag/v0.1.0
