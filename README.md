# Cradle

Complete backup and restore for iPhone and iPad. Talks the `mobilebackup2`
protocol directly, writes standard iTunes/Finder-format backups, and reports
real progress instead of an indeterminate spinner.

See [`CLAUDE.md`](./CLAUDE.md) for the project's non-negotiables and
architecture, and [`ROADMAP.md`](./ROADMAP.md) for the milestone plan. This
repo is at **M2** — protocol spike + verification gate + catalog, partially
verified against real hardware.

## Status

Real-device testing (one iPhone, iOS 26.6.1, over USB) has confirmed device
connection, prechecks, live progress reporting, and — after two real bugs
found and fixed this way — that the on-device passcode/Face ID prompt
(MBErrorDomain 208) is caught and surfaced live instead of silently failing
the backup. **Not yet confirmed: a full backup completing, and the second
run being dramatically faster than the first** — the one real transfer so
far was deliberately stopped partway through as a smoke test. Per
`ROADMAP.md`, that's the exit criterion that actually validates the
project's core architecture assumption, and M0-M2's checkmarks reflect
exactly what has and hasn't been exercised yet — see the top of that file.

M1's verification gate is intentionally reduced-scope until M5's crypto
layer exists: see the doc comment at the top of
`crates/cradle-core/src/verify.rs` for what's checked now versus what
`CLAUDE.md` specifies.

## Layout

- `crates/cradle-core` — device discovery, prechecks, the `mobilebackup2`
  backup path, the post-backup verification gate, and the catalog
  (`devices`/`runs`/`snapshots` in SQLite). No UI, no archiving, no restore
  (those are later milestones).
- `crates/cradle-cli` — the `cradle` binary: `cradle devices`,
  `cradle backup`, `cradle history`.

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
cradle devices                              # list attached devices
cradle backup --udid <UDID>                 # back up into ./working/<UDID>/
cradle history --udid <UDID>                # show recorded runs/snapshots
```

`working/` is the canonical working directory (see `CLAUDE.md`): it is
never moved, archived in place, or pointed at a network mount. Run `backup`
twice against the same device — the second run should be dramatically
faster, since MobileBackup2 computes incrementals on the device by
inspecting what's already sitting in `working/<UDID>/`.

The catalog lives at the platform data directory by default (e.g.
`~/Library/Application Support/Cradle/catalog.db` on macOS) — override with
`--catalog <path>` on any command.

## License

MIT — see [`LICENSE`](./LICENSE).
