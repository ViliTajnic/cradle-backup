//! Tauri commands: the desktop app's entire surface toward `cradle-core`.
//!
//! Deliberately thin wrappers over the same primitives `cradle-cli` calls —
//! no separate "app edition" of the backup logic, per CLAUDE.md's
//! "one webview frontend" framing and the project's broader rule that the
//! UI is a consumer of the core, not a parallel implementation.
//!
//! `run_backup` currently re-implements the precheck → backup → verify →
//! catalog sequence `cradle-cli`'s `run_backup` also has, rather than both
//! calling one shared orchestration function in `cradle-core`. That's a
//! real, known duplication — worth extracting once this UI's actual
//! shape (what a GUI needs back at each step, versus what the CLI prints)
//! has settled, not before.

use std::path::PathBuf;
use std::sync::Arc;

use cradle_core::catalog::{Catalog, DestinationRecord, RunKind, RunStatus};
use cradle_core::lock::WorkingSetLock;
use cradle_core::power::SleepGuard;
use cradle_core::{archive, backup, keychain, libimobiledevice, precheck, restore, verify, workflow};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::progress::TauriProgress;

/// The app has no natural "current directory" the way a terminal-launched
/// CLI does, so this falls back to `cradle_core::paths::default_working_dir`
/// (`~/Cradle/working`) — the same default the CLI now uses, so a CLI
/// backup and an app backup of the same device land in the same place
/// unless something overrides it. The frontend lets the user override it
/// (persisted in `localStorage`, not read back here) and passes that value
/// as `working_dir` to `run_backup`/`run_archive` — real devices routinely
/// need more room than a laptop's internal drive has free (see
/// MBErrorDomain 105 in `backup::device_error_hint`), so a fixed default
/// alone isn't enough.
fn resolve_working_dir(working_dir: Option<String>) -> PathBuf {
    match working_dir.map(|d| d.trim().to_string()) {
        Some(dir) if !dir.is_empty() => expand_tilde(&dir),
        _ => cradle_core::paths::default_working_dir(),
    }
}

fn resolve_scratch_dir(scratch_dir: Option<String>) -> PathBuf {
    match scratch_dir.map(|d| d.trim().to_string()) {
        Some(dir) if !dir.is_empty() => expand_tilde(&dir),
        _ => cradle_core::paths::default_scratch_dir(),
    }
}

/// A GUI text field invites typing `~/...` out of habit — unlike a shell,
/// nothing expands that for us before it reaches `PathBuf`, so it would
/// otherwise create a literal directory named `~`.
fn expand_tilde(path: &str) -> PathBuf {
    match path.strip_prefix("~/").or_else(|| (path == "~").then_some("")) {
        Some(rest) => dirs::home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(path)),
        None => PathBuf::from(path),
    }
}

fn open_catalog() -> Result<Catalog, String> {
    let path = Catalog::default_path().map_err(|e| e.to_string())?;
    Catalog::open(&path).map_err(|e| e.to_string())
}

#[derive(Serialize, Clone)]
pub struct DeviceEntry {
    udid: String,
    transport: String,
    name: Option<String>,
    product_type: Option<String>,
    ios_version: Option<String>,
    reachable: bool,
    pairing_message: Option<String>,
    /// Whether the device already has backup encryption on — lets the
    /// frontend decide up front whether "Back Up Now" needs to walk the
    /// user through setting a backup password first, instead of only
    /// finding out from a failed `run_backup` precheck.
    encryption_enabled: bool,
    /// Unix seconds of the most recent *verified* snapshot, if any — the
    /// UI's "Last backed up …" line. `None` covers both "never backed up"
    /// and "not reachable right now", which the frontend already
    /// distinguishes via `reachable`/`pairing_message`.
    last_backup_at: Option<i64>,
}

/// Lists devices usbmuxd sees, best-effort resolving name/model/iOS
/// version for each — mirrors `cradle devices`, not a new capability.
#[tauri::command]
pub async fn list_devices() -> Result<Vec<DeviceEntry>, String> {
    let attached = libimobiledevice::list_devices().await.map_err(|e| e.to_string())?;
    let catalog = open_catalog()?;
    let mut out = Vec::with_capacity(attached.len());

    for a in attached {
        let mut entry = DeviceEntry {
            udid: a.udid.clone(),
            transport: format!("{:?}", a.transport),
            name: None,
            product_type: None,
            ios_version: None,
            reachable: false,
            pairing_message: None,
            encryption_enabled: false,
            last_backup_at: None,
        };

        match libimobiledevice::device_info(&a.udid).await {
            Ok(info) => {
                entry.name = Some(info.name);
                entry.product_type = Some(info.product_type);
                entry.ios_version = Some(info.ios_version);
                entry.reachable = true;
                entry.encryption_enabled = libimobiledevice::will_encrypt(&a.udid).await;
            }
            Err(e) => entry.pairing_message = Some(e.to_string()),
        }

        entry.last_backup_at = catalog
            .latest_verified_snapshot(&a.udid)
            .ok()
            .flatten()
            .map(|s| s.taken_at);

        out.push(entry);
    }

    Ok(out)
}

/// Turns on backup encryption on the device itself, over the wire, and
/// stores the new password in the Keychain — mirrors `cradle password
/// enable`. iOS has no on-device Settings toggle for this: it's purely a
/// computer-side setting normally set via Finder's "Encrypt local backup"
/// checkbox, which Finder's own local-backup bookkeeping can wedge behind
/// a "backup was corrupt" dialog with no way through. This exists so a
/// user is never sent to fight with Finder for a setting that lives
/// entirely on the wire — the password is typed here, in this panel,
/// never in a terminal or shell history.
#[tauri::command]
pub async fn enable_encryption(udid: String, password: String) -> Result<(), String> {
    if password.is_empty() {
        return Err("Password was empty — not enabling encryption.".to_string());
    }
    let working_root = cradle_core::paths::default_working_dir();
    backup::set_encryption(&udid, &working_root, None, Some(&password))
        .await
        .map_err(|e| e.to_string())?;
    keychain::store(&keychain::device_account(&udid), &password).map_err(|e| e.to_string())?;
    Ok(())
}

/// Records a backup password Cradle didn't set itself — a device that
/// already had encryption on before it ever met Cradle (turned on via
/// Finder, or from a previous backup tool), or one whose backup was made
/// under a password no longer in the Keychain. Unlike `enable_encryption`,
/// this never touches the device over the wire; it only stores what the
/// user already knows is true. Mirrors `cradle password set`.
///
/// CODEBASE_ANALYSIS.md: "Existing backup password entry: The desktop
/// only offers enabling encryption. An already encrypted phone needs a
/// way to store/validate its existing password before transfer/restore."
/// This doesn't validate it against the device up front (that needs a
/// real `Manifest.db` to check against, which won't exist until a backup
/// has actually run) — a wrong password here shows up honestly as
/// `Outcome::Invalid` on the very next backup's verification gate rather
/// than silently succeeding.
#[tauri::command]
pub async fn store_existing_password(udid: String, password: String) -> Result<(), String> {
    if password.is_empty() {
        return Err("Password was empty — not storing it.".to_string());
    }
    keychain::store(&keychain::device_account(&udid), &password).map_err(|e| e.to_string())
}

#[derive(Serialize, Clone)]
pub struct PasswordVerifyResult {
    verified: bool,
    files: u64,
    bytes: u64,
    problems: Vec<String>,
}

/// Stores `password` and immediately re-runs the verification gate's
/// manifest checks (2 and 3) against the *already-downloaded* backup —
/// answering "is this the right password" without a repeat device
/// transfer. This is exactly the check `run_backup` would otherwise defer
/// to "back up again", made available on demand because nothing about it
/// actually needs the device: `Manifest.db` is already on disk, only the
/// password to decrypt it was missing.
#[tauri::command]
pub async fn verify_stored_password(
    udid: String,
    working_dir: Option<String>,
    password: String,
) -> Result<PasswordVerifyResult, String> {
    if password.is_empty() {
        return Err("Password was empty — not storing it.".to_string());
    }
    let working_root = resolve_working_dir(working_dir);
    let backup_dir = working_root.join(&udid);
    if !backup_dir.is_dir() {
        return Err("No backup found for this device yet — back it up first.".to_string());
    }

    let catalog = open_catalog()?;
    let snapshot = catalog
        .latest_snapshot(&udid)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No recorded snapshot for this device yet — back it up first.".to_string())?;

    let report = verify::run(&backup_dir, 0, Some(&password))
        .await
        .map_err(|e| e.to_string())?;

    // Only overwrite whatever's stored once the password has actually
    // proven itself against real data — an unverified guess must never
    // clobber a working password that was already on file.
    if report.passed() {
        keychain::store(&keychain::device_account(&udid), &password).map_err(|e| e.to_string())?;
        catalog
            .mark_snapshot_verified(snapshot.id)
            .map_err(|e| e.to_string())?;
    }

    Ok(PasswordVerifyResult {
        verified: report.passed(),
        files: report.files_on_disk,
        bytes: report.total_bytes,
        problems: report.problems,
    })
}

#[derive(Serialize, Clone)]
pub struct BackupSummary {
    backup_dir: String,
    files: u64,
    bytes: u64,
    verified: bool,
    manifest_integrity_checked: bool,
    /// `true` only for `verify::Outcome::NeedsPassword` — distinct from a
    /// real `!verified` failure so the frontend can show "back up
    /// complete, just tell us the password to confirm it" rather than
    /// "something went wrong" for a run that actually succeeded.
    needs_password: bool,
    problems: Vec<String>,
}

/// Runs prechecks, then a backup, then the verification gate, recording
/// everything in the catalog — the same sequence `cradle backup` runs.
/// Progress streams to the frontend as [`crate::progress::PROGRESS_EVENT`]
/// / [`crate::progress::ATTENTION_EVENT`] events rather than being
/// returned here; this only resolves once the whole run is over.
#[tauri::command]
pub async fn run_backup(
    app: AppHandle,
    udid: String,
    working_dir: Option<String>,
    force_full: bool,
) -> Result<BackupSummary, String> {
    // Real bug, found via actually running this: a ~75GB backup to an
    // external drive ran for the better part of an hour and failed near
    // the end with MBErrorDomain 104 (host-side read/write error),
    // consistent with the Mac sleeping mid-transfer. Held for the
    // function's whole duration.
    let _sleep_guard = SleepGuard::engage();

    let working_root = resolve_working_dir(working_dir);
    let catalog = open_catalog()?;

    let _ = app.emit("backup-status", "Running prechecks...");
    let progress = Arc::new(TauriProgress::for_backup(app.clone()));
    let retry_app = app.clone();
    let status_app = app.clone();
    let request = workflow::BackupRequest {
        udid: udid.clone(),
        working_root: working_root.clone(),
        full: force_full,
    };
    let result = workflow::run_backup(
        catalog,
        request,
        progress,
        |_info| {},
        move || {
            let _ = status_app.emit("backup-status", "Verifying backup...");
        },
        move |reason, attempt, max| {
            let reason_str = match reason {
                backup::RetryReason::DeviceLocked => "device_locked",
                backup::RetryReason::HostIo => "host_io",
                backup::RetryReason::Stalled => "stalled",
            };
            let _ = retry_app.emit(
                "backup-retry",
                serde_json::json!({ "reason": reason_str, "attempt": attempt, "max": max }),
            );
        },
    )
    .await;

    match result {
        Ok(outcome) => {
            let verified = outcome.gate.outcome == verify::Outcome::Verified;
            let problems = match outcome.gate.outcome {
                verify::Outcome::Verified => Vec::new(),
                verify::Outcome::NeedsPassword => vec![
                    "No stored backup password — Manifest.db integrity was never checked, so \
                     this cannot be archived yet. Set a backup password, then back up again to \
                     verify it."
                        .to_string(),
                ],
                verify::Outcome::Invalid => outcome.gate.problems.clone(),
            };
            Ok(BackupSummary {
                backup_dir: outcome.backup_dir.display().to_string(),
                files: outcome.gate.files_on_disk,
                bytes: outcome.gate.total_bytes,
                verified,
                manifest_integrity_checked: outcome.gate.manifest_integrity_checked,
                needs_password: outcome.gate.outcome == verify::Outcome::NeedsPassword,
                problems,
            })
        }
        Err(workflow::WorkflowError::NotStarted(workflow::NotStartedReason::Precheck(report))) => {
            if !report.pairing_valid {
                return Err(report.pairing_message.unwrap_or_else(|| "Pairing check failed.".to_string()));
            }
            if !report.encryption_enabled {
                return Err(
                    "Backup encryption is off on this device. Use the \"Set backup password\" \
                     panel to turn it on before continuing — without it, Keychain, Health, call \
                     history and saved passwords are silently omitted from the backup."
                        .to_string(),
                );
            }
            match report.free_space_bytes {
                Some(bytes) => Err(format!(
                    "Only {bytes} bytes free on the working volume; want at least {} bytes \
                     before starting a backup.",
                    precheck::MIN_FREE_BYTES,
                )),
                None => Err(
                    "Could not measure free space on the working volume — is it mounted? (An \
                     external drive that's unplugged or asleep looks like this.)"
                        .to_string(),
                ),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Serialize, Clone)]
pub struct HistoryEntry {
    id: i64,
    kind: String,
    status: String,
    started_at: i64,
    ended_at: Option<i64>,
    bytes: Option<i64>,
    files: Option<i64>,
    error: Option<String>,
}

/// Reads recorded runs for a device from the catalog — no device needs to
/// be attached.
#[tauri::command]
pub async fn get_history(udid: String) -> Result<Vec<HistoryEntry>, String> {
    let catalog = open_catalog()?;
    let runs = catalog.list_runs(&udid).map_err(|e| e.to_string())?;
    Ok(runs
        .into_iter()
        .map(|r| HistoryEntry {
            id: r.id,
            kind: r.kind,
            status: r.status,
            started_at: r.started_at,
            ended_at: r.ended_at,
            bytes: r.bytes,
            files: r.files,
            error: r.error,
        })
        .collect())
}

#[derive(Serialize, Clone)]
pub struct DestinationEntry {
    name: String,
    kind: String,
    uri: String,
}

/// Lists configured archive destinations — mirrors `cradle destination
/// list`.
#[tauri::command]
pub async fn list_destinations() -> Result<Vec<DestinationEntry>, String> {
    let catalog = open_catalog()?;
    let destinations = catalog.list_destinations().map_err(|e| e.to_string())?;
    Ok(destinations
        .into_iter()
        .map(|d| DestinationEntry {
            name: d.name,
            kind: d.kind,
            uri: d.uri,
        })
        .collect())
}

#[derive(Serialize, Clone)]
pub struct ArchiveSnapshotEntry {
    id: String,
    short_id: String,
    time: String,
    /// The device this snapshot was archived from, derived from restic's
    /// own recorded `paths[0]` the same way `archive::restore` locates the
    /// restored files afterward — a destination shared by more than one
    /// device (the normal case: everything archives to the same NAS/S3
    /// bucket) otherwise lists every snapshot from every device
    /// undifferentiated by anything but a raw timestamp, with no way to
    /// tell which one belongs to which device, let alone pick a specific
    /// generation of *one* device's history.
    source_udid: Option<String>,
    /// The friendly name for `source_udid`, when it's a device Cradle's
    /// catalog already knows about. `None` for a UDID with no matching
    /// row — an archive made on a different Mac's catalog, say — in which
    /// case the frontend falls back to showing the bare UDID.
    source_name: Option<String>,
}

/// Lists the snapshots actually stored in a destination's repository —
/// restic's own view, not the local catalog — mirrors `cradle archive
/// list`. Feeds the "restore from an archive" picker: the app could
/// otherwise create an archive but never restore one back, unlike the CLI.
#[tauri::command]
pub async fn list_archive_snapshots(destination: String) -> Result<Vec<ArchiveSnapshotEntry>, String> {
    let catalog = open_catalog()?;
    let destination_record = catalog
        .destination_by_name(&destination)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No destination named '{destination}'."))?;
    let devices = catalog.list_devices().map_err(|e| e.to_string())?;
    let snapshots = archive::list_snapshots(&destination_record).await.map_err(|e| e.to_string())?;
    Ok(snapshots
        .into_iter()
        .map(|s| {
            let source_udid = s
                .paths
                .first()
                .and_then(|p| restore::source_udid_from_staged_dir(std::path::Path::new(p)));
            let source_name = source_udid
                .as_deref()
                .and_then(|udid| devices.iter().find(|d| d.udid == udid))
                .map(|d| d.name.clone());
            ArchiveSnapshotEntry {
                id: s.id,
                short_id: s.short_id,
                time: s.time,
                source_udid,
                source_name,
            }
        })
        .collect())
}

/// Registers a new archive destination and initializes its repository —
/// mirrors `cradle destination add`. `uri` is any restic-compatible
/// repository location (a local path, `sftp:`, `s3:`, `b2:`, ...).
#[tauri::command]
pub async fn add_destination(name: String, kind: String, uri: String) -> Result<(), String> {
    let catalog = open_catalog()?;
    if catalog
        .destination_by_name(&name)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(format!("A destination named '{name}' already exists."));
    }

    let credential_ref = keychain::new_destination_account(&name);
    keychain::generate_and_store(&credential_ref).map_err(|e| e.to_string())?;

    // Probe with a throwaway record (id doesn't matter — archive::
    // only reads uri/credential_ref) so init runs *before* the catalog
    // insert: if it fails, nothing gets recorded at all. Same ordering
    // as cradle-cli's `destination add` and for the same reason.
    let probe = DestinationRecord {
        id: 0,
        name: name.clone(),
        kind: kind.clone(),
        uri: uri.clone(),
        credential_ref: credential_ref.clone(),
        retention_json: None,
    };
    if let Err(e) = archive::ensure_initialized(&probe).await {
        let _ = keychain::delete(&credential_ref);
        return Err(e.to_string());
    }

    catalog
        .create_destination(&name, &kind, &uri, &credential_ref)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Forgets a destination — mirrors `cradle destination remove`. Does not
/// touch the restic repository itself, only Cradle's record of it and its
/// Keychain-stored password (see that command's own doc for the
/// consequence: without the password recorded elsewhere, Cradle can't get
/// back into that repository after this).
#[tauri::command]
pub async fn remove_destination(name: String, delete_credential: bool) -> Result<(), String> {
    let catalog = open_catalog()?;
    let destination = catalog
        .destination_by_name(&name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No destination named '{name}'."))?;
    catalog
        .delete_destination(destination.id)
        .map_err(|e| e.to_string())?;
    // Keeping the credential by default is the safe choice: Cradle
    // generated this password and it's the only copy anywhere, so
    // deleting it makes the repository's existing data permanently
    // unreadable even though its bytes are untouched. Callers that really
    // want it gone pass `delete_credential: true` explicitly — mirrors
    // `cradle destination remove`'s own `--delete-credential` flag.
    if delete_credential {
        let _ = keychain::delete(&destination.credential_ref);
    }
    Ok(())
}

/// Returns a destination's repository password so it can be written down
/// somewhere durable — the recovery-kit equivalent of `cradle destination
/// show-password`. Anyone with this password and the destination's `uri`
/// can read and modify that restic repository.
#[tauri::command]
pub async fn show_destination_password(name: String) -> Result<String, String> {
    let catalog = open_catalog()?;
    let destination = catalog
        .destination_by_name(&name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No destination named '{name}'."))?;
    keychain::read(&destination.credential_ref).map_err(|e| e.to_string())
}

/// Registers a destination pointing at a repository that already exists,
/// validating `password` by actually opening it before anything is
/// recorded — mirrors `cradle destination connect`. Recovers a destination
/// after its Keychain credential was deleted, or connects to archives made
/// on another Mac.
#[tauri::command]
pub async fn connect_destination(name: String, kind: String, uri: String, password: String) -> Result<(), String> {
    let catalog = open_catalog()?;
    if catalog
        .destination_by_name(&name)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(format!("A destination named '{name}' already exists."));
    }

    let credential_ref = keychain::new_destination_account(&name);
    keychain::store(&credential_ref, &password).map_err(|e| e.to_string())?;

    let probe = DestinationRecord {
        id: 0,
        name: name.clone(),
        kind: kind.clone(),
        uri: uri.clone(),
        credential_ref: credential_ref.clone(),
        retention_json: None,
    };
    if let Err(e) = archive::list_snapshots(&probe).await {
        let _ = keychain::delete(&credential_ref);
        return Err(format!("Could not open the repository at {uri} with that password: {e}"));
    }

    catalog
        .create_destination(&name, &kind, &uri, &credential_ref)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize, Clone)]
pub struct ArchiveSummary {
    snapshot_id: String,
    data_added: u64,
    total_bytes_processed: u64,
    total_files_processed: u64,
}

/// Archives the latest verified snapshot for `udid` to `destination` —
/// mirrors `cradle archive run`. Progress streams as
/// [`crate::progress::ARCHIVE_PROGRESS_EVENT`] events, same pattern as
/// [`run_backup`].
#[tauri::command]
pub async fn run_archive(
    app: AppHandle,
    udid: String,
    destination: String,
    working_dir: Option<String>,
) -> Result<ArchiveSummary, String> {
    // See run_backup's own comment.
    let _sleep_guard = SleepGuard::engage();

    let working_root = resolve_working_dir(working_dir);
    let catalog = open_catalog()?;

    let destination_record = catalog
        .destination_by_name(&destination)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No destination named '{destination}'."))?;

    let progress = Arc::new(TauriProgress::for_archive(app));
    let request = workflow::ArchiveRequest {
        udid: udid.clone(),
        working_root,
        destination: &destination_record,
    };
    match workflow::run_archive(catalog, request, progress).await {
        Ok(outcome) => Ok(ArchiveSummary {
            snapshot_id: outcome.summary.snapshot_id,
            data_added: outcome.summary.data_added,
            total_bytes_processed: outcome.summary.total_bytes_processed,
            total_files_processed: outcome.summary.total_files_processed,
        }),
        Err(workflow::ArchiveError::NoVerifiedSnapshot) => {
            Err(format!("No verified snapshot for {udid} yet — back it up first."))
        }
        Err(workflow::ArchiveError::SourceMissing(dir)) => Err(format!(
            "Backup directory {} not found — was it moved since the last backup?",
            dir.display()
        )),
        Err(workflow::ArchiveError::NoLongerVerified(gate)) if gate.outcome == verify::Outcome::NeedsPassword => {
            Err("Re-checking right before archiving found no stored backup password, so the \
                 current contents can't be confirmed — set a backup password and back up again \
                 to get a verified snapshot."
                .to_string())
        }
        Err(workflow::ArchiveError::NoLongerVerified(gate)) => Err(format!(
            "Re-checking right before archiving found it no longer verifies, even though an \
             earlier backup for {udid} was verified — something has changed it since (a newer \
             backup run, most likely). Not archiving it:\n{}",
            gate.problems.join("\n"),
        )),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Serialize, Clone)]
pub struct RestoreSourceEntry {
    udid: String,
    name: String,
    product_type: String,
    ios_version: String,
    /// Whether `working_dir/<udid>` actually exists on this Mac right now
    /// — a device can be in the catalog (it's been backed up before)
    /// without its backup still being present locally (moved, archived
    /// and cleaned up, etc.), so this is what the UI should gate "can
    /// restore from this" on, not just catalog membership.
    has_local_backup: bool,
}

/// Lists every device Cradle knows about, annotated with whether a local
/// backup for it is actually available to restore from — feeds the
/// desktop app's source-device picker for cross-device restore (mirrors
/// `cradle restore --source-udid`).
#[tauri::command]
pub async fn list_restore_sources(working_dir: Option<String>) -> Result<Vec<RestoreSourceEntry>, String> {
    let working_root = resolve_working_dir(working_dir);
    let catalog = open_catalog()?;
    let devices = catalog.list_devices().map_err(|e| e.to_string())?;
    Ok(devices
        .into_iter()
        .map(|d| {
            let has_local_backup = working_root.join(&d.udid).is_dir();
            RestoreSourceEntry {
                udid: d.udid,
                name: d.name,
                product_type: d.product_type,
                ios_version: d.ios_version,
                has_local_backup,
            }
        })
        .collect())
}

#[derive(Serialize, Clone)]
pub struct LocalBackupEntry {
    udid: String,
    name: String,
    product_type: String,
    ios_version: String,
    /// From the latest recorded snapshot's own `size` column — the actual
    /// on-disk footprint of `working_dir/<udid>`, not re-measured by
    /// walking the tree here (that tree can be tens of gigabytes; a stat
    /// on one already-known number is instant, a fresh walk isn't).
    /// Slightly stale if something changed the directory outside Cradle,
    /// same tradeoff `verify::Report::files_reported` already accepts.
    size_bytes: Option<i64>,
    last_backup_at: Option<i64>,
    /// Whether the latest snapshot has at least one successful archive
    /// copy anywhere — the UI's cue for whether deleting the local copy
    /// loses the backup outright or just its fastest-to-restore-from copy.
    archived: bool,
}

/// Lists every device with an actual local backup sitting in
/// `working_dir` right now — the thing a "delete old backups" feature
/// needs to show, deliberately not scoped to currently-attached devices
/// the way `list_devices` is: a backup worth deleting to reclaim space is
/// usually for a device that's long since been unplugged (replaced, sold,
/// recycled), which would never show up in "Your devices" at all.
#[tauri::command]
pub async fn list_local_backups(working_dir: Option<String>) -> Result<Vec<LocalBackupEntry>, String> {
    let working_root = resolve_working_dir(working_dir);
    let catalog = open_catalog()?;
    let devices = catalog.list_devices().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for d in devices {
        if !working_root.join(&d.udid).is_dir() {
            continue;
        }
        let snapshot = catalog.latest_snapshot(&d.udid).map_err(|e| e.to_string())?;
        let (size_bytes, last_backup_at, archived) = match &snapshot {
            Some(s) => {
                let archived = catalog
                    .list_archives_for_snapshot(s.id)
                    .map(|archives| archives.iter().any(|a| a.state == "succeeded"))
                    .unwrap_or(false);
                (Some(s.size), Some(s.taken_at), archived)
            }
            None => (None, None, false),
        };
        out.push(LocalBackupEntry {
            udid: d.udid,
            name: d.name,
            product_type: d.product_type,
            ios_version: d.ios_version,
            size_bytes,
            last_backup_at,
            archived,
        });
    }
    Ok(out)
}

/// Permanently deletes `working_dir/<udid>` — the entire local backup for
/// one device, freeing whatever it was using on disk. Does not touch the
/// catalog's history (past runs/snapshots stay visible), only the actual
/// files; does not touch any archived copy either, per CLAUDE.md's
/// architecture ("Archiving copies out of it" — the working set and its
/// archives are always independent copies, deleting one is never supposed
/// to reach the other).
///
/// Takes the same [`WorkingSetLock`] every other operation on this
/// device's working set does, so this can't run concurrently with a
/// backup, archive, or restore-staging step that's reading or writing the
/// same directory out from under it.
#[tauri::command]
pub async fn delete_local_backup(udid: String, working_dir: Option<String>) -> Result<(), String> {
    let working_root = resolve_working_dir(working_dir);
    let backup_dir = working_root.join(&udid);
    if !backup_dir.is_dir() {
        return Err("No local backup found for this device.".to_string());
    }
    tokio::task::spawn_blocking(move || {
        let _lock = WorkingSetLock::acquire(&working_root, &udid)?;
        std::fs::remove_dir_all(&backup_dir).map_err(cradle_core::CradleError::from)
    })
    .await
    .map_err(|e| format!("delete task panicked: {e}"))?
    .map_err(|e| e.to_string())
}

#[derive(Serialize, Clone)]
pub struct RestoreSummary {
    target_udid: String,
    source_udid: String,
    rebooted: bool,
}

/// Restores a backup onto `udid` — the *target* device, which must be
/// attached. `source_udid` is the UDID the backup was originally taken
/// from; pass the same value as `udid` to restore a device's own backup
/// onto itself, or a different one for cross-device migration onto a new
/// device. Mirrors `cradle restore`'s from-working-directory path — and,
/// when `from_archive`/`restic_snapshot` are both given, its
/// `--from-archive`/`--restic-snapshot` archive-restore path too: before
/// this, the app could create an archive but never restore one back
/// (CODEBASE_ANALYSIS.md's "Desktop archive restore" gap).
///
/// Free, unconditional, forever — no license check, no network call
/// (CLAUDE.md non-negotiable #1).
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one flat arg per Tauri invoke() param — same as cradle-cli's own run_restore
pub async fn run_restore(
    app: AppHandle,
    udid: String,
    source_udid: String,
    working_dir: Option<String>,
    scratch_dir: Option<String>,
    reboot: bool,
    system_files: bool,
    from_archive: Option<String>,
    restic_snapshot: Option<String>,
    password_override: Option<String>,
) -> Result<RestoreSummary, String> {
    // See run_backup's own comment.
    let _sleep_guard = SleepGuard::engage();

    let working_root = resolve_working_dir(working_dir);
    let scratch_root = resolve_scratch_dir(scratch_dir);
    let catalog = open_catalog()?;

    let staged_dir = match (from_archive, restic_snapshot) {
        (Some(destination_name), Some(snapshot_id)) => {
            let destination = catalog
                .destination_by_name(&destination_name)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("No destination named '{destination_name}'."))?;
            let _ = app.emit("restore-status", "Restoring from the archive into scratch...");
            let progress = Arc::new(TauriProgress::for_restore(app.clone()));
            let summary = archive::restore(&destination, &snapshot_id, &scratch_root, progress)
                .await
                .map_err(|e| e.to_string())?;
            summary.path
        }
        _ => {
            let _ = app.emit("restore-status", "Staging backup for restore...");
            let progress = Arc::new(TauriProgress::for_restore(app.clone()));
            workflow::stage_restore_from_working(&working_root, &source_udid, &scratch_root, progress)
                .await
                .map_err(|e| e.to_string())?
        }
    };
    // Authoritative over whatever `source_udid` the frontend sent — see
    // that function's own doc for why this matters most for the
    // from-archive path above.
    let source_udid = restore::source_udid_from_staged_dir(&staged_dir).unwrap_or(source_udid);

    let backup_ios = restore::backup_ios_version(&staged_dir).map_err(|e| e.to_string())?;
    let backup_size_bytes = restore::staged_backup_size(&staged_dir).map_err(|e| e.to_string())?;

    let _ = app.emit("restore-status", "Running restore prechecks...");
    let report = precheck::run_restore(&udid, &backup_ios, backup_size_bytes)
        .await
        .map_err(|e| e.to_string())?;

    if !report.pairing_valid {
        return Err(report
            .pairing_message
            .unwrap_or_else(|| "Pairing check failed.".to_string()));
    }
    if !report.find_my_disabled {
        return Err(
            "Find My is enabled on the target device. Disable it under Settings > [name] > \
             Find My > Find My iPhone before restoring."
                .to_string(),
        );
    }
    if !report.target_ios_ok {
        return Err(format!(
            "Target device is on iOS {}, but this backup is from iOS {} — restoring backward \
             isn't supported. Update the target device first.",
            report.target_ios_version.as_deref().unwrap_or("unknown"),
            report.backup_ios_version,
        ));
    }
    if !report.enough_target_space {
        return Err(match report.target_free_bytes {
            Some(free) => format!(
                "Not enough free space on the target device: this backup needs {:.1} GB, but \
                 only {:.1} GB is free. Free up space on the device (or delete some apps/media) \
                 and try again.",
                backup_size_bytes as f64 / 1e9,
                free as f64 / 1e9,
            ),
            None => "Could not read how much free space the target device has — check that it's \
                      unlocked and reachable, then try again."
                .to_string(),
        });
    }

    // See cradle-cli's `run_restore` for why this precedes `start_run`.
    // `encrypted` is resolved into a plain local first, not inline in the
    // call below: a `&Catalog` held across that `.await` would make this
    // whole command's future `!Send`, which Tauri requires (`Catalog`
    // wraps a `rusqlite::Connection`, `Send` but not `Sync`).
    if let Some(info) = &report.device {
        let encrypted = libimobiledevice::will_encrypt(&udid).await;
        catalog
            .upsert_device(&cradle_core::catalog::DeviceRecord {
                udid: info.udid.clone(),
                name: info.name.clone(),
                product_type: info.product_type.clone(),
                ios_version: info.ios_version.clone(),
                encrypted,
            })
            .map_err(|e| e.to_string())?;
    }
    let run_id = catalog
        .start_run(&udid, RunKind::Restore)
        .map_err(|e| e.to_string())?;

    let config = restore::RestoreConfig {
        reboot,
        system_files,
        ..Default::default()
    };
    // An explicit override never touches the Keychain, only bypasses it —
    // see cradle-cli's `restore --password` for why this exists (an
    // archive made under an older password than what's currently stored).
    let stored_password = match password_override {
        Some(p) => Some(p),
        None => keychain::try_read(&keychain::device_account(&source_udid)).map_err(|e| e.to_string())?,
    };
    let progress = Arc::new(TauriProgress::for_restore(app.clone()));
    let _ = app.emit("restore-status", "Restoring...");
    let result = restore::run(&udid, &staged_dir, &source_udid, &config, stored_password.as_deref(), progress).await;

    match result {
        Ok(outcome) => {
            catalog
                .finish_run(run_id, RunStatus::Succeeded, 0, 0, None)
                .map_err(|e| e.to_string())?;
            Ok(RestoreSummary {
                target_udid: outcome.target_udid,
                source_udid,
                rebooted: config.reboot,
            })
        }
        Err(e) => {
            let _ = catalog.finish_run(run_id, RunStatus::Failed, 0, 0, Some(&e.to_string()));
            Err(e.to_string())
        }
    }
}
