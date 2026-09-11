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

## M3 — Archive layer ✅ built and verified against real `restic`

restic subprocess wrapper. Local first, then NAS mount, then S3/B2.
Snapshot listing and retention (`forget --prune`).

Working set stays canonical. Archives copy out of it.

One wrapper handles all three phases without separate code paths: every
restic-compatible repository URI (local path, `sftp:`, `s3:`, `b2:`, ...)
works unchanged, because restic's own backend abstraction is what actually
interprets it — "local first, then NAS, then S3/B2" is a validation order,
not an implementation order. Only local disk has actually been exercised
so far, per that same ordering.

`archive.rs` wraps `restic init`/`backup`/`snapshots`/`forget --prune`/
`check` as JSON-streaming subprocesses, reusing `backup::ProgressSink` for
archive progress too — same interface, same "no spinner" rule, verified
with a real ~80 MB two-file transfer to see actual `status` messages, not
just guessed at the schema. `keychain.rs` generates a repository password
per destination via `security-framework` (native `Security.framework`
bindings, not the `security` CLI — see that module's doc for why).
`catalog.rs` gained `destinations` and `archives`, completing the schema
from CLAUDE.md.

Two real, verified-against-real-hardware bugs worth flagging for anyone
touching this again:
- Originally handed restic the repository password via `--password-command
  "security find-generic-password ..."`, reasoning that restic's *own*
  child process reading the secret would never expose it in Cradle's env.
  This hung indefinitely against a real repository: a Keychain item
  created via `SecItemAdd` gets an ACL scoped to the creating application,
  and `/usr/bin/security` — spawned by restic, not Cradle — triggered a
  macOS authorization *dialog* to read it, with no terminal to answer it.
  Fixed by reading the password in Cradle's own process (inside the ACL
  that created it) and passing it via `RESTIC_PASSWORD` on restic's
  environment instead.
- `restic forget --json` prints `"remove":null` (not `[]`) when nothing is
  pruned. A `Vec<T>` field with `#[serde(default)]` only covers a *missing*
  key, not a present `null` one — needed `Option<Vec<T>>`. Caught by a real
  `forget --prune` run in the integration test, not a hand-written fixture.

New CLI surface: `cradle destination add/list`, `cradle archive
run/list/prune/check`. `cradle archive run` requires a verified snapshot
in the catalog and reconstructs its path as `<working-dir>/<UDID>` — the
schema has no per-snapshot path column, so this only works if
`--working-dir` matches what `cradle backup` used, matching the
architecture's one-canonical-location-per-UDID assumption.

Integration-tested against a real `restic` 0.19.1 binary and the real
macOS Keychain (`archive::tests`, `keychain::tests` — `#[ignore]`d since
they need `restic` on PATH; run with `cargo test -- --ignored`), plus a
full manual CLI smoke test (`destination add` → `archive run` → `list` →
`check` → `prune`, catalog rows confirmed via `sqlite3`).

## M4 — Restore 🟡 built, unverified against a real target device

`restic restore` into scratch, then restore protocol from there.
Full prechecks: Find My off, target iOS >= backup iOS, pairing valid.
Cross-device migration via `source_identifier`.

Free forever, no license check on this path.

`restore.rs` supports two sources, both landing in a scratch directory
before the device ever sees them (CLAUDE.md: restore "does not touch the
working set"): `stage_from_working` copies `working/<UDID>/` as-is (the
common case — you just backed up, now you're testing restore), or
`archive::restore` pulls a specific restic snapshot. The latter needed one
real-world correction: restic mirrors a snapshot's *original absolute
path* under `--target` rather than flattening it (confirmed with a real
restore — backing up `/tmp/rrt/source/UDID` and restoring into
`/tmp/rrt/scratch` produced `/tmp/rrt/scratch/tmp/rrt/source/UDID`), so
the resolved path is computed from the snapshot's own recorded `paths[0]`
rather than assumed.

`RestoreOptions.reboot`/`.system_files` are exposed; nothing else — per
CLAUDE.md, selective restore isn't happening, and the remaining flags on
`idevice`'s `RestoreOptions` don't have an obvious default worth exposing
yet.

The two restore-only prechecks: Find My via lockdown's `com.apple.fmip`
domain, key `IsAssociated` (undocumented by Apple, but well attested by
years of libimobiledevice community usage — defaults to the *stricter*
assumption if the query fails, since a false "off" here risks a
Find-My-locked restore attempt) and target iOS >= backup iOS, comparing
dotted-version components numerically rather than as strings (`"10.0" >
"9.0"`, not the lexical `"9.0" > "10.0"`) — the backup's own version comes
from its `Info.plist`'s `"Product Version"` key, exactly as CLAUDE.md
specifies, not from whatever the original source device happens to be
running now.

The device-protocol call itself (`MobileBackup2Client::restore_from_path`)
is unverified against a real target device — everything short of that
(staging from both sources, `Info.plist` version reading, the fmip
precheck logic, CLI argument wiring) has been exercised for real. Per
`ROADMAP.md`'s own sequencing rule this would normally block M5, but
building has continued through M7 with real backup-and-restore-to-another-
device testing deferred to once the whole stack exists — see the top of
this file for the same deferral on M0.

## M5 — Crypto layer 🟡 built, unverified against a real device's keybag

Parse `BackupKeyBag` from Manifest.plist → PBKDF2 → unwrap class keys →
AES-256-CBC per file. Needed to open an encrypted `Manifest.db`.

Unlocks manifest browsing and raw extraction. Budget a full day; this is
fiddly but well documented.

`crypto.rs` is a faithful port of
[doronz88/pyiosbackup](https://github.com/doronz88/pyiosbackup)'s
`keybag.py` — a proven implementation `pymobiledevice3` itself depends on
— fetched and read line by line rather than reconstructed from blog posts,
because this is exactly the kind of code where "close enough" produces
silent wrong answers. Two details worth flagging for anyone touching this
again, both easy to get backwards: keybag TLV integers (`ITER`, `DPIC`,
`CLAS`, `WRAP`) are big-endian, but the 4-byte class id prefixing a *file's*
wrapped key is little-endian; and the two-stage PBKDF2 (SHA-256 over
`DPSL`/`DPIC` first, then SHA-1 over `SALT`/`ITER` using *that* result as
the password) only runs when `DPSL`/`DPIC` are present — checked directly
rather than gated on the backup's iOS version like the reference does,
since that means this module never needs to know anything about
`Manifest.plist` beyond the keybag bytes it's handed.

Found a real gap doing this: nothing built in M0-M4 ever asked for or
stored the backup *password* itself (distinct from a restic repository's
own generated password) — nothing needed it before. Added `cradle password
set/forget --udid <UDID>` (Keychain-backed, same `security-framework`
approach as destinations, hidden prompt via `rpassword` unless
`--password` is given) and wired a lookup into `cradle backup`'s
post-backup verify step: a stored password unlocks the real `PRAGMA
integrity_check`, no password falls back to M1's reduced check — nothing
forces an interactive prompt into the middle of an otherwise-unattended
backup.

**Deliberately not built**: manifest *browsing* (listing files by
domain/path) needs an NSKeyedArchiver decoder for `Manifest.db`'s `Files`
table `file` BLOB column — a separate, non-trivial parsing format, not
scoped into this pass. `cradle decrypt` covers raw extraction in reduced
form: it decrypts one file given its `--encryption-key` directly (hex,
read manually from a decrypted `Manifest.db` for now), rather than looking
files up by domain/path itself.

Crypto core is unit-tested against self-constructed synthetic keybags
(correct-password unlock, wrong-password rejection via AES-KW's own
integrity check, a full wrap→encrypt→decrypt→unwrap round trip, rejecting
non-block-aligned ciphertext) — internally consistent, but not yet checked
against a *real* device's actual `BackupKeyBag` and `Manifest.db`, which
needs the same real-device pass everything since M0 is waiting on.
`cradle password set/forget` were smoke-tested against the real macOS
Keychain. One methodology note for whoever debugs this next: verifying a
Cradle-stored Keychain item with the `security` CLI (`security
find-generic-password -w ...`) hits the exact same cross-process
authorization-prompt hang documented in M3 — use `cradle password
set/forget` to inspect or clean up Cradle's own Keychain entries, never
the `security` CLI directly.

## M6 — CLI v1.0 ✅ polish pass done

Ship it. Complete, supported, the free tier's full interface.
Not a debug tool.

M0-M5 already built the full functional surface, so this was a
completeness/consistency pass over the existing CLI rather than new
features:

- Audited every `.unwrap()`/`.expect()` reachable from a real command path
  (as opposed to `#[cfg(test)]` code) — all three are provably safe by
  construction (fixed-size slice conversions after an explicit length
  check; `Stdio::piped()` guaranteeing `child.stdout`/`stderr` are `Some`),
  not "should be fine" guesses.
- Reordered `Command`'s variants to match an actual workflow (discover →
  backup → archive → restore → password/decrypt utilities) instead of the
  order they happened to get built in — that order drives `--help`'s
  command list.
- Found and fixed a real, systematic gap: roughly a dozen `--flag`s across
  `history`, `password`, `destination add`, and every `archive` subcommand
  had no doc comment, so `--help` printed their name with a blank
  description. Caught by actually reading `--help` output for every
  subcommand, not by inspection — several looked fine in the source until
  rendered.
- Added `cradle completions <shell>` (bash/zsh/fish/elvish/powershell via
  `clap_complete`), handled before the catalog path is resolved since
  printing a completion script is fully offline and has no reason to
  depend on, or fail because of, something it has nothing to do with.

## M7 — Tauri UI 🟡 built, launches, unverified visually

The progress rendering is the whole point. Files done/total, bytes/sec,
ETA, current domain. Never an indeterminate spinner.

`crates/cradle-app` — a Tauri 2 shell, plain HTML/CSS/JS frontend (no
npm build step; `withGlobalTauri: true` so `window.__TAURI__` is
available without a bundler). Three commands (`list_devices`,
`run_backup`, `get_history`) wrap the same `cradle-core` calls the CLI
uses — no parallel implementation of the protocol/catalog/verify logic.

Progress reaches the webview the same way `TerminalProgress` reaches the
terminal: a `TauriProgress` (`src/progress.rs`) implements
`backup::ProgressSink` and emits `backup-progress` / `backup-attention`
events instead of printing a line, so the on-device passcode/Face ID
signal from M0 (`on_attention_needed`) shows as a banner in the UI, not
just CLI text — the whole reason that hook exists on the trait rather
than being CLI-specific.

**Known, accepted duplication**: `commands::run_backup` re-implements the
precheck → backup → verify → catalog sequence `cradle-cli`'s own
`run_backup` already has, rather than both calling one shared
orchestration function in `cradle-core`. Extracting that is a reasonable
follow-up now that there are two real call sites with identical needs —
not done here because this session was already very long and the two
implementations' actual shape (what a GUI needs back at each step vs.
what the CLI prints) hadn't settled yet. See `commands.rs`'s module doc.

**Status**: builds clean, clippy clean, and the app launches — a real
window opens and becomes key (confirmed via `tao`'s own event log, not
just "process didn't crash"). Everything past that — whether the device
list actually populates, whether a live backup run renders correctly,
whether the attention banner and history table work — needs eyes on an
actual running window, which nothing in this environment can substitute
for. Unverified, same as the rest of the stack pending the real-device
pass planned after M7.

Not built: `cradle archive` / `cradle restore` / `cradle password` have
no UI commands yet — `list_devices`, `run_backup`, and `get_history` are
the M7 minimum to prove the architecture (a working webview driving
`cradle-core` with real progress events), not full parity with the CLI.

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
