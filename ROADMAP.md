# Cradle — Roadmap

Sequential. Each milestone must be green against a real device before the
next one starts. Do not work ahead.

## M0 — Protocol spike ✅ scaffolded, unverified

One binary. Connect, precheck, back up with a real progress line.
No UI, no database, no destinations.

Exit criteria:
- Connects to a device on current iOS
- `check_backup_encryption()` returns true
- Progress line shows moving bytes, rate, file count, ETA
- **Second run is dramatically faster than the first**

If M0 fails, nothing downstream matters. Existing scaffold is written
against the real `idevice` 0.1.65 API but has never been compiled —
expect small fixes on first build. Requires Rust 1.85+ (edition 2024).

## M1 — Verification gate

Status.plist finished + `PRAGMA integrity_check` on Manifest.db + file
count match. Failing runs archive nothing.

This lands before any destination work. A pipeline that can archive a
corrupt backup is worse than no pipeline.

## M2 — Catalog

SQLite via rusqlite. Devices, runs, snapshots. Secrets in Keychain,
referenced only. No file-level tracking.

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
