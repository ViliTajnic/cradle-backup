# Cradle

Complete backup and restore for iPhone and iPad. Talks the `mobilebackup2`
protocol directly, writes standard iTunes/Finder-format backups, and reports
real progress instead of an indeterminate spinner.

See [`CLAUDE.md`](./CLAUDE.md) for the project's non-negotiables and
architecture, and [`ROADMAP.md`](./ROADMAP.md) for the milestone plan. This
repo is at **M7** — protocol spike + verification gate + catalog + archive
layer + restore + backup decryption + CLI polish + a Tauri desktop app,
partially verified against real hardware and real infrastructure. A real
backup-and-restore-to-another-device test — and eyes on the actual running
UI — are deliberately deferred until now that the whole stack exists. See
`ROADMAP.md` for exactly what has and hasn't been exercised at each
milestone.

## Status

Real-device testing (one iPhone, iOS 26.6.1, over USB) has confirmed device
connection, prechecks, live progress reporting, and — after two real bugs
found and fixed this way — that the on-device passcode/Face ID prompt
(MBErrorDomain 208) is caught and surfaced live instead of silently failing
the backup. **Not yet confirmed: a full backup completing, and the second
run being dramatically faster than the first** — the one real transfer so
far was deliberately stopped partway through as a smoke test. Per
`ROADMAP.md`, that's the exit criterion that actually validates the
project's core architecture assumption, and every milestone's checkmarks
reflect exactly what has and hasn't been exercised — see the top of that
file.

M3's archive layer is integration-tested against a real `restic` binary and
the real macOS Keychain (not just unit tests) — see `ROADMAP.md`'s M3
section for two real bugs that testing caught, including one that would
have hung real users' terminals indefinitely on a macOS Keychain dialog.

M4's restore path is built and its staging/precheck logic exercised for
real, but the actual on-device restore protocol call has not yet run
against a real target device — see `ROADMAP.md`'s M4 section.

M5's crypto layer (`BackupKeyBag` parsing, PBKDF2, AES-256-CBC) is a
faithful port of a proven reference implementation, unit-tested against
self-constructed keybags, but not yet checked against a real device's
actual keybag — see `ROADMAP.md`'s M5 section, including a real Keychain
authorization-prompt hang that testing caught (same class of bug as M3's).
M1's verification gate now does the real `PRAGMA integrity_check` when a
backup password has been stored (`cradle password set`); without one it
still falls back to the reduced check from M1's original build.

M7's desktop app builds, passes clippy, and launches — a real window opens
and becomes key. Nothing past that has been visually confirmed: whether
the device list populates, a live backup renders correctly, or the
attention banner and history table actually work needs eyes on the
running window, which this environment can't substitute for — see
`ROADMAP.md`'s M7 section.

## Layout

- `crates/cradle-core` — device discovery, prechecks, the `mobilebackup2`
  backup path, the post-backup verification gate, the catalog
  (`devices`/`runs`/`snapshots`/`destinations`/`archives` in SQLite), the
  restic-backed archive layer, Keychain access, restore (including
  cross-device migration), and backup decryption.
- `crates/cradle-cli` — the `cradle` binary: `cradle devices`,
  `cradle backup`, `cradle history`, `cradle destination add/list`,
  `cradle archive run/list/prune/check`, `cradle restore`,
  `cradle password set/forget`, `cradle decrypt`, `cradle completions`.
- `crates/cradle-app` — the Tauri desktop app: device list, backup with
  live progress, run history. Static HTML/CSS/JS frontend (`dist/`), no
  npm build step.

## Building

Requires Rust 1.85+ (edition 2024); `rust-toolchain.toml` tracks stable,
since the pinned `idevice` dependency's own source uses if-let chains that
need a newer stable than 1.85 alone.

```sh
cargo build
```

On macOS, `usbmuxd` is part of the OS — nothing else to install. The
archive layer needs `restic` on `PATH` (`brew install restic`).

To run the desktop app:

```sh
cargo run -p cradle-app
```

No Node/npm needed to *run* it (the frontend in `crates/cradle-app/dist`
is static HTML/CSS/JS); `npx @tauri-apps/cli` is only needed for
packaging a distributable bundle later (M8).

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

cradle restore --udid <UDID>                              # restore a device's own backup onto itself
cradle restore --udid <NEW_UDID> --source-udid <OLD_UDID> # cross-device migration
cradle restore --udid <UDID> --from-archive nas --restic-snapshot <id>

cradle password set --udid <UDID>           # store the backup password (hidden prompt)
cradle decrypt --udid <UDID> --input <relative-path> --output <file> --encryption-key <hex>

cradle completions zsh > ~/.zfunc/_cradle    # shell completions (bash/zsh/fish/elvish/powershell)
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
`--catalog <path>` on any command. Every stored secret (a destination's
restic repository password, a device's backup password) is generated or
supplied once and kept in the macOS Keychain, never in the catalog or
anywhere on disk in the clear. **Never inspect Cradle's own Keychain
entries with the `security` CLI** — reading an item Cradle created from a
different process triggers a macOS authorization dialog with no terminal
to answer it (see `ROADMAP.md`'s M3 and M5 sections). Use `cradle password
forget` / re-run `cradle destination add` instead.

## License

MIT — see [`LICENSE`](./LICENSE).
