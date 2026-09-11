//! Cradle CLI — M0 connect/precheck/backup, M1 verification gate, M2 catalog.
//!
//! Per CLAUDE.md, the CLI is not a debug tool: it ships, it is supported,
//! and it is the free tier's complete interface.

mod progress;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use cradle_core::CradleError;
use cradle_core::catalog::{Catalog, DeviceRecord, RunKind, RunStatus};
use cradle_core::{backup, device, precheck, verify};

use progress::{TerminalProgress, human_bytes};

#[derive(Parser)]
#[command(name = "cradle", version, about = "Backup and restore for iPhone and iPad.")]
struct Cli {
    /// Catalog database path. Defaults to the platform data directory
    /// (e.g. `~/Library/Application Support/Cradle/catalog.db` on macOS).
    #[arg(long, global = true)]
    catalog: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List devices usbmuxd currently sees.
    Devices,
    /// Back up a device into the local working directory.
    Backup {
        /// Device UDID. Required when more than one device is attached.
        #[arg(long)]
        udid: Option<String>,
        /// Canonical working directory root; `<root>/<UDID>/` is used underneath it.
        /// Never point this at a network mount or an archive.
        #[arg(long, default_value = "working")]
        working_dir: PathBuf,
        /// Force a full backup instead of letting the device compute an incremental.
        #[arg(long)]
        full: bool,
    },
    /// Show recorded runs and snapshots for a device from the catalog.
    ///
    /// Reads only the local catalog database — the device doesn't need to
    /// be attached.
    History {
        #[arg(long)]
        udid: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let catalog_path = match cli.catalog {
        Some(path) => path,
        None => Catalog::default_path()?,
    };

    match cli.command {
        Command::Devices => run_devices().await,
        Command::Backup {
            udid,
            working_dir,
            full,
        } => run_backup(udid, working_dir, full, catalog_path).await,
        Command::History { udid } => run_history(udid, catalog_path),
    }
}

async fn run_devices() -> anyhow::Result<()> {
    let devices = device::list().await?;
    if devices.is_empty() {
        println!("No devices attached.");
        return Ok(());
    }

    for attached in devices {
        print!("{}\t{:?}", attached.udid, attached.transport);
        match describe(&attached.udid).await {
            Ok(line) => println!("\t{line}"),
            Err(e) => println!("\t({e})"),
        }
    }
    Ok(())
}

async fn describe(udid: &str) -> anyhow::Result<String> {
    let provider = device::provider_for(udid).await?;
    let mut lockdown = device::lockdown_session(&*provider)
        .await
        .map_err(|_| anyhow::anyhow!("pairing record invalid — unlock the device and tap Trust"))?;
    let info = device::info(&mut lockdown).await?;
    Ok(format!(
        "{} ({}, iOS {})",
        info.name, info.product_type, info.ios_version
    ))
}

async fn resolve_udid(udid: Option<String>) -> anyhow::Result<String> {
    if let Some(udid) = udid {
        return Ok(udid);
    }
    let devices = device::list().await?;
    match devices.as_slice() {
        [only] => Ok(only.udid.clone()),
        [] => anyhow::bail!("No devices attached. Connect an iPhone or iPad and unlock it."),
        _ => anyhow::bail!("Multiple devices attached — pass --udid to choose one."),
    }
}

async fn run_backup(
    udid: Option<String>,
    working_root: PathBuf,
    full: bool,
    catalog_path: PathBuf,
) -> anyhow::Result<()> {
    let udid = resolve_udid(udid).await?;
    let provider = device::provider_for(&udid).await?;

    println!("Running prechecks...");
    let precheck_report = precheck::run(&*provider, &working_root).await?;

    if let Some(info) = &precheck_report.device {
        println!(
            "Device: {} ({}, iOS {})",
            info.name, info.product_type, info.ios_version
        );
    }

    if !precheck_report.pairing_valid {
        anyhow::bail!(precheck_report
            .pairing_message
            .unwrap_or_else(|| "Pairing check failed.".to_string()));
    }
    if !precheck_report.encryption_enabled {
        anyhow::bail!(
            "Backup encryption is off on this device. Enable it under Settings > General > \
             Transfer or Reset iPhone > Encrypted Backup (or via Finder) before continuing — \
             without it, Keychain, Health, call history and saved passwords are silently \
             omitted from the backup."
        );
    }
    if !precheck_report.free_space_ok {
        anyhow::bail!(
            "Only {} free on the working volume; want at least {} before starting a backup.",
            human_bytes(precheck_report.free_space_bytes),
            human_bytes(precheck::MIN_FREE_BYTES),
        );
    }

    let device_info = precheck_report.device.clone().ok_or_else(|| {
        anyhow::anyhow!("prechecks passed but returned no device info — this is a bug")
    })?;

    let catalog = Catalog::open(&catalog_path)?;
    catalog.upsert_device(&DeviceRecord {
        udid: device_info.udid.clone(),
        name: device_info.name.clone(),
        product_type: device_info.product_type.clone(),
        ios_version: device_info.ios_version.clone(),
        encrypted: precheck_report.encryption_enabled,
    })?;
    let run_id = catalog.start_run(&udid, RunKind::Backup)?;

    println!("Prechecks passed. Backing up into {}...", working_root.display());

    let progress = Arc::new(TerminalProgress::new());
    let attempt: Result<(backup::Outcome, verify::Report), CradleError> = async {
        let outcome = backup::run_resilient(
            &*provider,
            &working_root,
            full,
            progress.clone(),
            |attempt, max_attempts| {
                eprintln!(
                    "\nDevice locked mid-backup — unlock it now. Retrying in {}s (attempt {}/{})...",
                    backup::LOCK_RETRY_DELAY.as_secs(),
                    attempt,
                    max_attempts
                );
            },
        )
        .await?;
        progress.finish();

        println!("Verifying backup...");
        let gate = verify::run(&outcome.backup_dir, outcome.files_received).await?;
        Ok((outcome, gate))
    }
    .await;

    match attempt {
        Ok((outcome, gate)) if gate.passed() => {
            catalog.finish_run(
                run_id,
                RunStatus::Succeeded,
                outcome.bytes_transferred,
                gate.files_on_disk,
                None,
            )?;
            catalog.record_snapshot(
                &udid,
                run_id,
                gate.total_bytes,
                &device_info.ios_version,
                true,
            )?;
            println!(
                "Backup verified: {} ({} files, {}).",
                outcome.backup_dir.display(),
                gate.files_on_disk,
                human_bytes(gate.total_bytes)
            );
            Ok(())
        }
        Ok((outcome, gate)) => {
            let problems = gate_problems(&gate);
            catalog.finish_run(
                run_id,
                RunStatus::Failed,
                outcome.bytes_transferred,
                gate.files_on_disk,
                Some(&problems.join(" ")),
            )?;
            anyhow::bail!(
                "Backup did not pass verification — treat {} as failed, not a usable snapshot:\n{}",
                outcome.backup_dir.display(),
                problems.join("\n"),
            );
        }
        Err(e) => {
            // Record the failure before propagating it — a run left
            // "running" forever in the catalog would be its own bug.
            catalog.finish_run(run_id, RunStatus::Failed, 0, 0, Some(&e.to_string()))?;
            Err(e.into())
        }
    }
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
        problems.push(
            "Manifest.db is missing, empty, or truncated — it did not arrive intact.".to_string(),
        );
    }
    if !gate.file_count_match {
        problems.push(format!(
            "File count mismatch: {} files on disk vs. {} the device reported sending.",
            gate.files_on_disk, gate.files_reported
        ));
    }
    problems
}

fn run_history(udid: String, catalog_path: PathBuf) -> anyhow::Result<()> {
    let catalog = Catalog::open(&catalog_path)?;
    let runs = catalog.list_runs(&udid)?;

    if runs.is_empty() {
        println!(
            "No runs recorded for {udid} in {}.",
            catalog_path.display()
        );
        return Ok(());
    }

    for run in &runs {
        let started = format_timestamp(run.started_at);
        let duration = run
            .ended_at
            .map(|ended| format!("{}s", (ended - run.started_at).max(0)))
            .unwrap_or_else(|| "still running".to_string());

        let mut line = format!(
            "#{:<4} {:<9} {:<10} {started}  ({duration})",
            run.id, run.kind, run.status
        );
        if let Some(bytes) = run.bytes {
            line.push_str(&format!("  {} moved", human_bytes(bytes as u64)));
        }
        if let Some(files) = run.files {
            line.push_str(&format!("  {files} files"));
        }
        if let Some(err) = &run.error {
            line.push_str(&format!("  — {err}"));
        }
        println!("{line}");
    }

    let snapshots = catalog.list_snapshots(&udid)?;
    if !snapshots.is_empty() {
        println!("\nSnapshots:");
        for snap in snapshots {
            let taken = format_timestamp(snap.taken_at);
            let verified = if snap.verified_at.is_some() {
                "verified"
            } else {
                "unverified"
            };
            println!(
                "  snapshot #{}  run #{}  {taken}  {}  iOS {}  [{verified}]",
                snap.id,
                snap.run_id,
                human_bytes(snap.size as u64),
                snap.ios_version
            );
        }
    }

    Ok(())
}

fn format_timestamp(unix_secs: i64) -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    OffsetDateTime::from_unix_timestamp(unix_secs)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix_secs.to_string())
}
