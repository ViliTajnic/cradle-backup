# Cradle

Complete backup and restore for iPhone and iPad. macOS first, Windows later.

Cradle talks the `mobilebackup2` protocol directly, produces standard
iTunes/Finder-format backups, archives them anywhere the user has space
(local, NAS, S3, B2, SFTP), and restores them — including onto a new device.

## Non-negotiables

Read these before proposing any feature or refactor.

1. **Restore is free, unconditional, forever.** No license check, no
   network call, no tier gate anywhere on the restore path. A user whose
   phone was stolen must never hit a paywall. If a change puts *anything*
   between a user and their own data in a bad moment, reject it.
2. **Never gate access to data — only its transformation.** Raw extraction
   (any file, decrypted SQLite databases, attachments) is free. Formatted
   export (threaded PDF, resolved contacts, inline media) is paid.
3. **A partial backup must never become a snapshot.** Every archive is
   guarded by the verification gate. No exceptions, no "just this once"
   flags.
4. **No phone-home.** License validation is an offline signature check.
   A backup tool that asks a server for permission has a failure mode the
   user cannot control.
5. **Never put `iPhone`, `iOS`, `Apple`, `iTunes` or `Mac` in a product
   name, binary name, crate name, or bundle identifier.** Compatibility
   statements in prose and marketing are fine ("for iPhone and iPad").
   Names are not.

## The rule that shapes the architecture

MobileBackup2 computes incrementals **on the device**, by inspecting the
existing backup directory (`Status.plist`, `Manifest.plist`, `Manifest.db`).

Therefore:

- `working/<UDID>/` is **canonical**. It lives on fast local storage and
  stays in exactly the state the device left it.
- Archiving copies **out of** it. Never move it, never archive in place,
  never point the device at a network mount or an archived snapshot.
- Restore copies a snapshot **into a scratch directory** and runs the
  restore protocol from there. It does not touch the working set.

Break this and every backup becomes a full transfer. If you find yourself
writing a file-level diff engine, you have taken a wrong turn — that work
belongs to the device, not to us.

```
iPhone ──mobilebackup2──▶ working/<UDID>/   (canonical, local, never moved)
                                 │
                                 ├─ restic ──▶ NAS
                                 ├─ restic ──▶ S3 / B2
                                 └─ restic ──▶ external disk
```

## Stack

- **Core:** Rust. Pure, no C dependencies, no LGPL obligations.
- **Device protocol:** the `idevice` crate (MIT), pinned `=0.1.65`.
  It ships breaking changes on every point release until 0.2.0 —
  **never use a caret range.** Bumping the pin is a deliberate task with
  a full re-test against a real device, not a routine dependency update.
- **UI:** Tauri. One webview frontend for both platforms.
- **Catalog:** SQLite via `rusqlite`.
- **Archive:** `restic` (BSD-2) as a subprocess; `rclone` (MIT) for
  exotic destinations.
- **Async:** tokio.

On macOS `usbmuxd` is part of the OS — nothing to install, nothing to
ship. On Windows it requires Apple Devices or iTunes for the
AppleMobileDeviceService driver; detect this on first run and deep-link
to the Microsoft Store. We never ship our own usbmuxd (GPL-2.0, and it
would fight Apple's driver for the device claim).

## The extension seam

`BackupDelegate` abstracts **all** filesystem I/O — `open_file_read`,
`create_file_write`, `create_dir_all`, `list_dir`, `exists`, `remove`,
`rename`, `copy` — plus `on_progress(bytes_done, bytes_total, overall)`
and `on_file_received(path, count)`.

This trait is where "backup to anywhere" lives. Destinations are alternate
delegate implementations, not a copy step bolted on afterwards. Design
new storage support around this trait.

It is also the source of honest progress. Finder shows an indeterminate
barber-pole while moving 70+ GB; that failure is the reason this project
exists. Every long-running operation reports files done/total, bytes,
rate, ETA, and current domain. Never ship an indeterminate spinner for
an operation whose progress we can measure.

## Verification gate

Runs after every backup, before any archive. All three must pass:

1. `Status.plist` reports the run finished
2. `Manifest.db` opens and passes `PRAGMA integrity_check`
3. File count matches the manifest

Failure marks the run failed and archives nothing.

## Prechecks

Run before starting any transfer. Never begin an operation we already
know will fail:

- Pairing record valid (stale pairing is the most common failure; surface
  "tap Trust on the device" as a UI state, not an error)
- Backup encryption enabled — without it, Keychain, Health, call history
  and saved passwords are silently omitted
- Sufficient free space on the working volume
- **Restore only:** Find My iPhone disabled on target
- **Restore only:** target iOS version >= backup's iOS version
  (read `Product Version` from `Info.plist`)

## Catalog schema

Keep it small. It tracks devices, runs and snapshots — not file-level
deltas.

```
devices(udid PK, name, product_type, ios_version, last_seen, encrypted, credential_ref)
runs(id PK, udid FK, kind, started_at, ended_at, status, bytes, files, error)
snapshots(id PK, udid FK, run_id FK, taken_at, size, ios_version, verified_at)
archives(id PK, snapshot_id FK, destination_id FK, restic_id, state, verified_at)
destinations(id PK, kind, uri, credential_ref, retention_json)
```

Secrets go in the macOS Keychain / Windows DPAPI, referenced by
`credential_ref`. **Never store a secret in the database.**

## Tiers

Free is everything that protects your data. Paid is everything that
saves your time.

**Free / OSS (MIT):**
backup to any destination · restore from anywhere, always · raw
extraction including decrypted SQLite and attachments · manifest browsing
· verification · prechecks · encryption management · full CLI · full source

**Paid:**
formatted export (Messages/WhatsApp as threaded PDF/HTML, contacts
resolved, media inline) · scheduling daemon (Wi-Fi + charging + on-home-
network triggers, retention, alerts) · snapshot diffing · multi-device
fleet view · signed auto-updating build · human support

If a proposed paid feature is a destination path or a restore capability,
it is on the wrong side of the line.

## Do not build

restic and rclone already solve these. Wrap, don't reimplement:

- diff engines, dedup, retention logic
- archive encryption or compression
- cloud transports
- our own usbmuxd, on any platform

Also out of scope for v1: **selective restore.** MobileBackup2 restore is
all-or-nothing. Faking it means extracting files and re-injecting through
app-specific channels — fragile, breaks on iOS updates, and a bigger
project than everything else combined. Do not start it.

## Framing

Cradle is a downstream consumer of already-published clean-room protocol
work. It is **not** a reverse-engineered clone of any commercial product.
Never describe it as one, in code comments, docs, commit messages or
marketing.

## Working agreements

- Every protocol change is tested against a real device before merge.
  There is no meaningful test double for `mobilebackup2`.
- After any change to the backup path, run twice. The second run must be
  dramatically faster. If it is not, incrementals are broken — stop and
  fix that before anything else.
- Prefer failing a precheck over failing mid-transfer.
- Error messages name the fix, not the symptom. "Pairing record expired —
  unlock the device and tap Trust" beats "lockdown error -5".
- The CLI is not a debug tool. It ships, it is supported, and it is the
  free tier's complete interface.
