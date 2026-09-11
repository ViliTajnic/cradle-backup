# Cradle

Complete backup and restore for iPhone and iPad. Talks the `mobilebackup2`
protocol directly, writes standard iTunes/Finder-format backups, and reports
real progress instead of an indeterminate spinner.

See [`CLAUDE.md`](./CLAUDE.md) for the project's non-negotiables and
architecture, and [`ROADMAP.md`](./ROADMAP.md) for the milestone plan. This
repo is at **M3** — protocol spike + verification gate + catalog + archive
layer, partially verified against real hardware and real infrastructure.

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

M3's archive layer is integration-tested against a real `restic` binary and
the real macOS Keychain (not just unit tests) — see `ROADMAP.md`'s M3
section for two real bugs that testing caught, including one that would
have hung real users' terminals indefinitely on a macOS Keychain dialog.

## Layout

- `crates/cradle-core` — device discovery, prechecks, the `mobilebackup2`
  backup path, the post-backup verification gate, the catalog
  (`devices`/`runs`/`snapshots`/`destinations`/`archives` in SQLite), the
  restic-backed archive layer, and Keychain access for repository
  passwords. No UI, no restore yet (later milestones).
- `crates/cradle-cli` — the `cradle` binary: `cradle devices`,
  `cradle backup`, `cradle history`, `cradle destination add/list`,
  `cradle archive run/list/prune/check`.

## Building

Requires Rust 1.85+ (edition 2024); `rust-toolchain.toml` tracks stable,
since the pinned `idevice` dependency's own source uses if-let chains that
need a newer stable than 1.85 alone.

```sh
cargo build
```

On macOS, `usbmuxd` is part of the OS — nothing else to install. The
archive layer needs `restic` on `PATH` (`brew install restic`).

## Usage

```sh
cradle devices                              # list attached devices
cradle backup --udid <UDID>                 # back up into ./working/<UDID>/
cradle history --udid <UDID>                # show recorded runs/snapshots

cradle destination add --name nas --uri /Volumes/backups/cradle-repo
cradle archive run --udid <UDID> --destination nas
cradle archive list --destination nas       # snapshots actually in the repo
cradle archive prune --destination nas --keep-last 10
cradle archive check --destination nas      # full repo integrity check
```

`working/` is the canonical working directory (see `CLAUDE.md`): it is
never moved, archived in place, or pointed at a network mount. Run `backup`
twice against the same device — the second run should be dramatically
faster, since MobileBackup2 computes incrementals on the device by
inspecting what's already sitting in `working/<UDID>/`.

`--uri` for `destination add` is any restic-compatible repository location
— a local path, `sftp:user@host:/path`, `s3:s3.amazonaws.com/bucket`,
`b2:bucket:path`. `archive run` only works on a snapshot that passed the
M1 verification gate.

The catalog lives at the platform data directory by default (e.g.
`~/Library/Application Support/Cradle/catalog.db` on macOS) — override with
`--catalog <path>` on any command. Each destination's restic repository
password is generated automatically and stored in the macOS Keychain,
never in the catalog or anywhere on disk in the clear.

## License

MIT — see [`LICENSE`](./LICENSE).
