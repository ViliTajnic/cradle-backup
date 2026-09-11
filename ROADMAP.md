# Cradle — Roadmap

Sequential. Each milestone must be green against a real device before the
next one starts. Do not work ahead.

## M0 — Protocol spike 🟡 partially verified on real hardware

One binary. Connect, precheck, back up with a real progress line.
No UI, no database, no destinations.

Exit criteria:
- [x] Connects to a device on current iOS — confirmed against a real
      iPhone (iPhone18,3, iOS 26.6.1) over USB.
- [x] Backup encryption check returns true — confirmed via lockdown's
      `WillEncrypt` (the `idevice` crate's own `check_backup_encryption()`
      is a stub that errors; we don't use it — see `precheck.rs`).
- [x] Progress line shows moving bytes, rate, file count, ETA — confirmed
      with real numbers (files/%/rate/bytes/ETA) on a live transfer.
- [ ] **Second run is dramatically faster than the first** — **not yet
      tested.** No first run has been allowed to finish; the one real
      transfer so far was deliberately stopped partway through as a
      smoke test. This is the exit criterion that actually validates the
      architecture ("The rule that shapes the architecture") and must be
      confirmed before trusting anything built on top of it.

Two real bugs found and fixed via actual device testing, not written
into the original scaffold:
- MBErrorDomain 208 (device locked mid-backup) turned out to mean iOS
  is showing an on-device passcode/Face ID prompt, not an Auto-Lock
  problem — `backup::run` now watches `notification_proxy` for
  `com.apple.LocalAuthentication.ui.presented` and surfaces it live via
  `ProgressSink::on_attention_needed`, with `run_resilient` as an
  automatic-retry safety net behind it.
- MBErrorDomain 105/106 (free space) and a handful of other device error
  codes now get human-readable, fix-naming messages instead of a raw
  `Integer(n)` dump — see `device_error_hint` in `backup.rs`.

Requires Rust 1.85+ (edition 2024); `rust-toolchain.toml` tracks `stable`
in practice, since `idevice`'s own source needs a newer stable than 1.85
for if-let chains.

## M1 — Verification gate 🟡 implemented, unexercised against a completed run

Status.plist finished + `PRAGMA integrity_check` on Manifest.db + file
count match. Failing runs archive nothing.

This lands before any destination work. A pipeline that can archive a
corrupt backup is worse than no pipeline.

Built with reduced scope versus the check above, by design: backup
encryption (required by non-negotiable #2) makes `Manifest.db` an
AES-encrypted blob that can't be opened with `PRAGMA integrity_check`
until M5's crypto layer exists to decrypt it. Until then, `verify.rs`
checks ciphertext well-formedness and an on-disk file count instead —
see the doc comment at the top of that file for the exact gap and the
`# M5` markers showing where to swap in the real checks.

Has never actually run against a completed backup — the only real
transfer so far was stopped intentionally before `Status.plist` could
report `"finished"`. Needs a full run to exercise for real.

## M2 — Catalog 🟡 built, unexercised against a completed run

SQLite via rusqlite. Devices, runs, snapshots. Secrets in Keychain,
referenced only. No file-level tracking.

`catalog.rs` has exactly the three tables this milestone asks for —
`archives`/`destinations` join the schema in M3 once there's an archive
layer to populate them, not before. `devices.credential_ref` exists per
the schema but nothing writes to it yet: nothing in Cradle needs a stored
secret before M5. Unit-tested (run lifecycle, failed-run error text,
verified vs. unverified snapshots, upsert-not-duplicate) against an
in-memory database, but never against a real completed backup — `cradle
backup` now opens the catalog, records the device, opens a `running` row,
and on completion (or failure) closes it out with bytes/files/error and,
if the verification gate passed, a snapshot row. `cradle history --udid
<UDID>` reads it back without needing the device attached. All of that
needs a real end-to-end run to confirm, which is still blocked on the
same thing M0 is: letting one full backup actually finish.

## M3 — Archive layer

restic subprocess wrapper. Local first, then NAS mount, then S3/B2.
Snapshot listing and retention (`forget --prune`).

Working set stays canonical. Archives copy out of it.

## M4 — Restore

`restic restore` into scratch, then restore protocol from there.
Full prechecks: Find My off, target iOS >= backup iOS, pairing valid.
Cross-device migration via `source_identifier`.

Free forever, no license check on this path.

## M5 — Crypto layer

Parse `BackupKeyBag` from Manifest.plist → PBKDF2 → unwrap class keys →
AES-256-CBC per file. Needed to open an encrypted `Manifest.db`.

Unlocks manifest browsing and raw extraction. Budget a full day; this is
fiddly but well documented.

## M6 — CLI v1.0

Ship it. Complete, supported, the free tier's full interface.
Not a debug tool.

## M7 — Tauri UI

The progress rendering is the whole point. Files done/total, bytes/sec,
ETA, current domain. Never an indeterminate spinner.

## M8 — Signing and distribution

- macOS: Developer ID, hardened runtime, `notarytool`, universal binary
- Direct download only. Mac App Store is impossible — the sandbox blocks
  the usbmuxd socket at `/var/run/usbmuxd`, and there is no entitlement
  for it.

## M9 — Windows

Same Rust core. Additional work:
- First-run check for Apple Devices / iTunes (AppleMobileDeviceService),
  deep-link to Microsoft Store
- Path handling: long paths (`\\?\`), case-insensitivity, hardlink
  differences. Abstract early or it breaks at 200k files.
- Authenticode signing. Try Azure Artifact Signing first (~$10/month,
  no hardware token, native CI integration, EU sole proprietors eligible
  as of April 2026, requires a paid Azure subscription). Fall back to an
  OV cert + cloud HSM if identity validation fails.

## Paid tier — after M9, not before

Formatted export is the first paid feature: Messages/WhatsApp as threaded
PDF/HTML with contacts resolved and media inline. It is the hardest to
replicate and the clearest value over raw extraction.

Then: scheduling daemon, snapshot diffing, fleet view.

## Deliberately not on this roadmap

- Selective restore — protocol does not support it
- Any diff/dedup/retention engine — restic owns this
- Cloud transport implementations — rclone owns this
- An iOS companion app — the sandbox cannot reach the backup protocol,
  so it could only ever be a photos/contacts sync tool. That space is
  already served by Immich.
