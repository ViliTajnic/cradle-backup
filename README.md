# Cradle

Complete backup and restore for iPhone and iPad. Talks the `mobilebackup2`
protocol directly, writes standard iTunes/Finder-format backups, and reports
real progress instead of an indeterminate spinner.

See [`CLAUDE.md`](./CLAUDE.md) for the project's non-negotiables and
architecture, and [`ROADMAP.md`](./ROADMAP.md) for the milestone plan. This
repo is at **M0** — protocol spike, unverified against real hardware.

## Status

M0 is scaffolded but has never been run against a real device. Per
`ROADMAP.md`, every milestone must be green against real hardware before the
next one starts — expect small fixes on first real run.

## Layout

- `crates/cradle-core` — device discovery, prechecks, and the
  `mobilebackup2` backup path. No UI, no database, no destinations (those
  are later milestones).
- `crates/cradle-cli` — the `cradle` binary: `cradle devices`,
  `cradle backup`.

## Building

Requires Rust 1.85+ (edition 2024); `rust-toolchain.toml` tracks stable,
since the pinned `idevice` dependency's own source uses if-let chains that
need a newer stable than 1.85 alone.

```sh
cargo build
```

On macOS, `usbmuxd` is part of the OS — nothing else to install.

## Usage

```sh
cradle devices                 # list attached devices
cradle backup --udid <UDID>    # back up into ./working/<UDID>/
```

`working/` is the canonical working directory (see `CLAUDE.md`): it is
never moved, archived in place, or pointed at a network mount. Run `backup`
twice against the same device — the second run should be dramatically
faster, since MobileBackup2 computes incrementals on the device by
inspecting what's already sitting in `working/<UDID>/`.

## License

MIT — see [`LICENSE`](./LICENSE).
