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

use cradle_core::catalog::{Catalog, DeviceRecord, RunKind, RunStatus};
use cradle_core::{backup, device, keychain, precheck, verify};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::progress::TauriProgress;

/// `~/Cradle/working` — a GUI app has no natural "current directory" the
/// way a terminal-launched CLI does, so this is a fixed, visible location
/// rather than the CLI's relative `./working` default.
fn default_working_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Cradle")
        .join("working")
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

        match device::provider_for(&a.udid).await {
            Ok(provider) => match device::lockdown_session(&*provider).await {
                Ok(mut lockdown) => match device::info(&mut lockdown).await {
                    Ok(info) => {
                        entry.name = Some(info.name);
                        entry.product_type = Some(info.product_type);
                        entry.ios_version = Some(info.ios_version);
                        entry.reachable = true;
                    }
                    Err(e) => entry.pairing_message = Some(e.to_string()),
                },
                Err(_) => {
                    entry.pairing_message =
                        Some("Pairing record invalid — unlock the device and tap Trust.".to_string());
                }
            },
            Err(e) => entry.pairing_message = Some(e.to_string()),
        }

        out.push(entry);
    }

    Ok(out)
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
pub async fn run_backup(app: AppHandle, udid: String) -> Result<BackupSummary, String> {
    let working_root = default_working_dir();
    let catalog = open_catalog()?;
    let provider = device::provider_for(&udid).await.map_err(|e| e.to_string())?;

    let _ = app.emit("backup-status", "Running prechecks...");
    let precheck_report = precheck::run(&*provider, &working_root)
        .await
        .map_err(|e| e.to_string())?;

    if !precheck_report.pairing_valid {
        return Err(precheck_report
            .pairing_message
            .unwrap_or_else(|| "Pairing check failed.".to_string()));
    }
    if !precheck_report.encryption_enabled {
        return Err(
            "Backup encryption is off on this device. Enable it under Settings > General > \
             Transfer or Reset iPhone > Encrypted Backup (or via Finder) before continuing — \
             without it, Keychain, Health, call history and saved passwords are silently \
             omitted from the backup."
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

    let progress = Arc::new(TauriProgress::new(app.clone()));
    let retry_app = app.clone();
    let attempt = backup::run_resilient(&*provider, &working_root, false, progress, move |attempt, max| {
        let _ = retry_app.emit(
            "backup-retry",
            serde_json::json!({ "attempt": attempt, "max": max }),
        );
    })
    .await;

    let outcome = match attempt {
        Ok(outcome) => outcome,
        Err(e) => {
            let _ = catalog.finish_run(run_id, RunStatus::Failed, 0, 0, Some(&e.to_string()));
            return Err(e.to_string());
        }
    };

    let _ = app.emit("backup-status", "Verifying backup...");
    let stored_password = keychain::try_read(&keychain::device_account(&udid)).map_err(|e| e.to_string())?;
    let gate = match verify::run(&outcome.backup_dir, outcome.files_received, stored_password.as_deref()).await {
        Ok(gate) => gate,
        Err(e) => {
            let _ = catalog.finish_run(
                run_id,
                RunStatus::Failed,
                outcome.bytes_transferred,
                0,
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
            "File count mismatch: {} files on disk vs. {} the device reported sending.",
            gate.files_on_disk, gate.files_reported
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
