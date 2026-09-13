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

use cradle_core::catalog::{ArchiveState, Catalog, DestinationRecord, DeviceRecord, RunKind, RunStatus};
use cradle_core::power::SleepGuard;
use cradle_core::{archive, backup, device, keychain, precheck, restore, verify};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::progress::TauriProgress;

/// `~/Cradle/working` — a GUI app has no natural "current directory" the
/// way a terminal-launched CLI does, so this is a fixed, visible location
/// rather than the CLI's relative `./working` default. Just a fallback:
/// the frontend lets the user override it (persisted in `localStorage`,
/// not read back here) and passes that value as `working_dir` to
/// `run_backup`/`run_archive` — real devices routinely need more room
/// than a laptop's internal drive has free (see MBErrorDomain 105 in
/// `backup::device_error_hint`), so a fixed default alone isn't enough.
fn default_working_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Cradle")
        .join("working")
}

fn resolve_working_dir(working_dir: Option<String>) -> PathBuf {
    match working_dir.map(|d| d.trim().to_string()) {
        Some(dir) if !dir.is_empty() => expand_tilde(&dir),
        _ => default_working_dir(),
    }
}

/// `~/Cradle/scratch` — where a restore is staged before the protocol
/// touches the target device. Per CLAUDE.md's architecture rule, this is
/// never `working/<UDID>/` itself: restore only ever reads the working
/// set, via [`restore::stage_from_working`]'s copy, and runs against this
/// separate scratch copy.
fn default_scratch_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Cradle")
        .join("scratch")
}

fn resolve_scratch_dir(scratch_dir: Option<String>) -> PathBuf {
    match scratch_dir.map(|d| d.trim().to_string()) {
        Some(dir) if !dir.is_empty() => expand_tilde(&dir),
        _ => default_scratch_dir(),
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
}

/// Lists devices usbmuxd sees, best-effort resolving name/model/iOS
/// version for each — mirrors `cradle devices`, not a new capability.
#[tauri::command]
pub async fn list_devices() -> Result<Vec<DeviceEntry>, String> {
    let attached = device::list().await.map_err(|e| e.to_string())?;
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
        };

        match device::info(&a.udid).await {
            Ok(info) => {
                entry.name = Some(info.name);
                entry.product_type = Some(info.product_type);
                entry.ios_version = Some(info.ios_version);
                entry.reachable = true;
            }
            Err(e) => entry.pairing_message = Some(e.to_string()),
        }

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
    let working_root = default_working_dir();
    backup::set_encryption(&udid, &working_root, None, Some(&password))
        .await
        .map_err(|e| e.to_string())?;
    keychain::store(&keychain::device_account(&udid), &password).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize, Clone)]
pub struct BackupSummary {
    backup_dir: String,
    files: u64,
    bytes: u64,
    verified: bool,
    manifest_integrity_checked: bool,
    problems: Vec<String>,
}

/// Runs prechecks, then a backup, then the verification gate, recording
/// everything in the catalog — the same sequence `cradle backup` runs.
/// Progress streams to the frontend as [`crate::progress::PROGRESS_EVENT`]
/// / [`crate::progress::ATTENTION_EVENT`] events rather than being
/// returned here; this only resolves once the whole run is over.
#[tauri::command]
pub async fn run_backup(app: AppHandle, udid: String, working_dir: Option<String>) -> Result<BackupSummary, String> {
    // Real bug, found via actually running this: a ~75GB backup to an
    // external drive ran for the better part of an hour and failed near
    // the end with MBErrorDomain 104 (host-side read/write error),
    // consistent with the Mac sleeping mid-transfer. Held for the
    // function's whole duration.
    let _sleep_guard = SleepGuard::engage();

    let working_root = resolve_working_dir(working_dir);
    let catalog = open_catalog()?;

    let _ = app.emit("backup-status", "Running prechecks...");
    let precheck_report = precheck::run(&udid, &working_root)
        .await
        .map_err(|e| e.to_string())?;

    if !precheck_report.pairing_valid {
        return Err(precheck_report
            .pairing_message
            .unwrap_or_else(|| "Pairing check failed.".to_string()));
    }
    if !precheck_report.encryption_enabled {
        return Err(
            "Backup encryption is off on this device. Use the \"Set backup password\" panel to \
             turn it on before continuing — without it, Keychain, Health, call history and \
             saved passwords are silently omitted from the backup."
                .to_string(),
        );
    }
    if !precheck_report.free_space_ok {
        return Err(format!(
            "Only {} bytes free on the working volume; want at least {} bytes before starting \
             a backup.",
            precheck_report.free_space_bytes,
            precheck::MIN_FREE_BYTES,
        ));
    }
    let device_info = precheck_report
        .device
        .clone()
        .ok_or_else(|| "prechecks passed but returned no device info — this is a bug".to_string())?;

    catalog
        .upsert_device(&DeviceRecord {
            udid: device_info.udid.clone(),
            name: device_info.name.clone(),
            product_type: device_info.product_type.clone(),
            ios_version: device_info.ios_version.clone(),
            encrypted: precheck_report.encryption_enabled,
        })
        .map_err(|e| e.to_string())?;
    let run_id = catalog
        .start_run(&udid, RunKind::Backup)
        .map_err(|e| e.to_string())?;

    let progress = Arc::new(TauriProgress::for_backup(app.clone()));
    let retry_app = app.clone();
    let attempt = backup::run_resilient(&udid, &working_root, false, progress, move |reason, attempt, max| {
        let reason_str = match reason {
            backup::RetryReason::DeviceLocked => "device_locked",
            backup::RetryReason::HostIo => "host_io",
            backup::RetryReason::Stalled => "stalled",
        };
        let _ = retry_app.emit(
            "backup-retry",
            serde_json::json!({ "reason": reason_str, "attempt": attempt, "max": max }),
        );
    })
    .await;

    let outcome = match attempt {
        Ok(outcome) => outcome,
        Err(backup_err) => {
            let _ = catalog.finish_run(
                run_id,
                RunStatus::Failed,
                backup_err.bytes_transferred,
                backup_err.files_received,
                Some(&backup_err.source.to_string()),
            );
            return Err(backup_err.source.to_string());
        }
    };

    let _ = app.emit("backup-status", "Verifying backup...");
    let stored_password = match keychain::try_read(&keychain::device_account(&udid)) {
        Ok(password) => password,
        Err(e) => {
            // Record the failure before propagating it — a run left
            // "running" forever in the catalog would be its own bug (same
            // reasoning as cradle-cli's run_backup).
            let _ = catalog.finish_run(
                run_id,
                RunStatus::Failed,
                outcome.bytes_transferred,
                outcome.files_received,
                Some(&e.to_string()),
            );
            return Err(e.to_string());
        }
    };
    let gate = match verify::run(&outcome.backup_dir, outcome.files_received, stored_password.as_deref()).await {
        Ok(gate) => gate,
        Err(e) => {
            let _ = catalog.finish_run(
                run_id,
                RunStatus::Failed,
                outcome.bytes_transferred,
                outcome.files_received,
                Some(&e.to_string()),
            );
            return Err(e.to_string());
        }
    };

    if !gate.passed() {
        let problems = gate_problems(&gate);
        let _ = catalog.finish_run(
            run_id,
            RunStatus::Failed,
            outcome.bytes_transferred,
            gate.files_on_disk,
            Some(&problems.join(" ")),
        );
        return Ok(BackupSummary {
            backup_dir: outcome.backup_dir.display().to_string(),
            files: gate.files_on_disk,
            bytes: gate.total_bytes,
            verified: false,
            manifest_integrity_checked: gate.manifest_integrity_checked,
            problems,
        });
    }

    catalog
        .finish_run(
            run_id,
            RunStatus::Succeeded,
            outcome.bytes_transferred,
            gate.files_on_disk,
            None,
        )
        .map_err(|e| e.to_string())?;
    catalog
        .record_snapshot(&udid, run_id, gate.total_bytes, &device_info.ios_version, true)
        .map_err(|e| e.to_string())?;

    Ok(BackupSummary {
        backup_dir: outcome.backup_dir.display().to_string(),
        files: gate.files_on_disk,
        bytes: gate.total_bytes,
        verified: true,
        manifest_integrity_checked: gate.manifest_integrity_checked,
        problems: Vec::new(),
    })
}

fn gate_problems(gate: &verify::Report) -> Vec<String> {
    let mut problems = Vec::new();
    if !gate.status_finished {
        problems.push(
            "Status.plist does not report a finished snapshot — the device may have cancelled \
             or the transfer was interrupted."
                .to_string(),
        );
    }
    if !gate.manifest_present {
        problems.push(if gate.manifest_integrity_checked {
            "Manifest.db failed PRAGMA integrity_check after decryption — it's corrupt, not \
             just incomplete."
                .to_string()
        } else {
            "Manifest.db is missing, empty, or truncated — it did not arrive intact.".to_string()
        });
    }
    if !gate.file_count_match {
        problems.push(format!(
            "File count mismatch: {} files on disk vs. {} expected.",
            gate.files_on_disk, gate.files_expected
        ));
    }
    problems
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

    let credential_ref = keychain::destination_account(&name);
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
pub async fn remove_destination(name: String) -> Result<(), String> {
    let catalog = open_catalog()?;
    let destination = catalog
        .destination_by_name(&name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No destination named '{name}'."))?;
    catalog
        .delete_destination(destination.id)
        .map_err(|e| e.to_string())?;
    let _ = keychain::delete(&destination.credential_ref);
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

    let snapshot = catalog
        .latest_verified_snapshot(&udid)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!("No verified snapshot for {udid} yet — back it up first.")
        })?;

    let source_dir = working_root.join(&udid);
    if !source_dir.is_dir() {
        return Err(format!(
            "Backup directory {} not found — was it moved since the last backup?",
            source_dir.display()
        ));
    }

    archive::ensure_initialized(&destination_record)
        .await
        .map_err(|e| e.to_string())?;
    let archive_id = catalog
        .start_archive(snapshot.id, destination_record.id)
        .map_err(|e| e.to_string())?;

    let progress = Arc::new(TauriProgress::for_archive(app));
    match archive::backup(&destination_record, &source_dir, progress).await {
        Ok(summary) => {
            catalog
                .finish_archive(archive_id, ArchiveState::Succeeded, Some(&summary.snapshot_id), None)
                .map_err(|e| e.to_string())?;
            Ok(ArchiveSummary {
                snapshot_id: summary.snapshot_id,
                data_added: summary.data_added,
                total_bytes_processed: summary.total_bytes_processed,
                total_files_processed: summary.total_files_processed,
            })
        }
        Err(e) => {
            let _ = catalog.finish_archive(archive_id, ArchiveState::Failed, None, Some(&e.to_string()));
            Err(e.to_string())
        }
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
pub struct RestoreSummary {
    target_udid: String,
    source_udid: String,
    rebooted: bool,
}

/// Restores a backup onto `udid` — the *target* device, which must be
/// attached. `source_udid` is the UDID the backup was originally taken
/// from; pass the same value as `udid` to restore a device's own backup
/// onto itself, or a different one for cross-device migration onto a new
/// device. Mirrors `cradle restore`'s from-working-directory path.
///
/// Free, unconditional, forever — no license check, no network call
/// (CLAUDE.md non-negotiable #1).
#[tauri::command]
pub async fn run_restore(
    app: AppHandle,
    udid: String,
    source_udid: String,
    working_dir: Option<String>,
    scratch_dir: Option<String>,
    reboot: bool,
    system_files: bool,
) -> Result<RestoreSummary, String> {
    // See run_backup's own comment.
    let _sleep_guard = SleepGuard::engage();

    let working_root = resolve_working_dir(working_dir);
    let scratch_root = resolve_scratch_dir(scratch_dir);
    let catalog = open_catalog()?;

    let _ = app.emit("restore-status", "Staging backup for restore...");
    let staged_dir = restore::stage_from_working(&working_root, &source_udid, &scratch_root)
        .await
        .map_err(|e| e.to_string())?;

    let backup_ios = restore::backup_ios_version(&staged_dir).map_err(|e| e.to_string())?;

    let _ = app.emit("restore-status", "Running restore prechecks...");
    let report = precheck::run_restore(&udid, &backup_ios)
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

    let run_id = catalog
        .start_run(&udid, RunKind::Restore)
        .map_err(|e| e.to_string())?;

    let config = restore::RestoreConfig { reboot, system_files };
    let stored_password =
        keychain::try_read(&keychain::device_account(&source_udid)).map_err(|e| e.to_string())?;
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
