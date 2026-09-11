//! Cradle CLI — M0 connect/precheck/backup, M1 verification gate, M2
//! catalog, M3 archive layer, M4 restore, M5 decryption, M6 polish.
//!
//! Per CLAUDE.md, the CLI is not a debug tool: it ships, it is supported,
//! and it is the free tier's complete interface. Restore in particular is
//! free, unconditional, forever (non-negotiable #1) — nothing on the
//! `run_restore` path below checks a license or calls out to a server.

mod progress;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use cradle_core::CradleError;
use cradle_core::catalog::{ArchiveState, Catalog, DestinationRecord, DeviceRecord, RunKind, RunStatus};
use cradle_core::crypto::Keybag;
use cradle_core::{archive, backup, device, keychain, precheck, restore, verify};

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
        /// Device UDID.
        #[arg(long)]
        udid: String,
    },
    /// Manage archive destinations (restic repositories).
    Destination {
        #[command(subcommand)]
        command: DestinationCommand,
    },
    /// Archive a verified snapshot out to a destination.
    ///
    /// Per CLAUDE.md's architecture: "Archiving copies out of it [the
    /// working directory]" — never in place, never touching the source.
    Archive {
        #[command(subcommand)]
        command: ArchiveCommand,
    },
    /// Restore a backup onto a device.
    ///
    /// Free, unconditional, forever — no license check, no network call
    /// (CLAUDE.md non-negotiable #1).
    Restore {
        /// Target device UDID — the device being restored *onto*.
        #[arg(long)]
        udid: Option<String>,
        /// UDID the backup was originally taken from, if different from
        /// `--udid`. Omit to restore a device's own backup onto itself;
        /// set this for cross-device migration.
        #[arg(long)]
        source_udid: Option<String>,
        /// Pull from this archive destination instead of the local
        /// working directory. Requires `--restic-snapshot`.
        #[arg(long, requires = "restic_snapshot")]
        from_archive: Option<String>,
        /// Which restic snapshot to restore, when `--from-archive` is
        /// given (see `cradle archive list`).
        #[arg(long, requires = "from_archive")]
        restic_snapshot: Option<String>,
        /// Where the local backup lives, when not restoring from an
        /// archive. Must match what `cradle backup` used.
        #[arg(long, default_value = "working")]
        working_dir: PathBuf,
        /// Staging area the restore is run from — never the working
        /// directory itself (see CLAUDE.md's architecture rule).
        #[arg(long, default_value = "scratch")]
        scratch_dir: PathBuf,
        /// Don't reboot the target device once the restore finishes.
        #[arg(long)]
        no_reboot: bool,
        /// Also restore system files (off by default, matching
        /// `idevice`'s own `RestoreOptions` default).
        #[arg(long)]
        system_files: bool,
    },
    /// Manage a device's backup password in the macOS Keychain.
    ///
    /// Storing it unlocks the real `Manifest.db` integrity check on
    /// `cradle backup` (see `verify.rs`) instead of the reduced one, and
    /// is needed for `cradle decrypt`. This is the password set on the
    /// *device* (Settings/Finder's "Encrypted Backup") — Cradle never
    /// generates or changes it.
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    /// Decrypt a single file from a backup, given its encryption key.
    ///
    /// Needs the `Manifest.db` row's own `EncryptionKey` for the target
    /// file, which nothing in Cradle currently looks up by domain/path —
    /// pass `--encryption-key <hex>` directly until manifest browsing
    /// exists (see `crypto.rs`'s module doc for that gap).
    Decrypt {
        /// Device UDID. Required when more than one device is attached.
        #[arg(long)]
        udid: Option<String>,
        /// Where the backup lives; `<root>/<UDID>/` is read underneath it.
        #[arg(long, default_value = "working")]
        working_dir: PathBuf,
        /// Path (relative to the backup root) to the encrypted file.
        #[arg(long)]
        input: PathBuf,
        /// Where to write the decrypted output.
        #[arg(long)]
        output: PathBuf,
        /// The file's wrapped encryption key, hex-encoded — from
        /// `Manifest.db`'s `Files.file` blob's `EncryptionKey` field.
        #[arg(long)]
        encryption_key: String,
    },
    /// Print a shell completion script to stdout.
    ///
    /// e.g. `cradle completions zsh > ~/.zfunc/_cradle` (with `~/.zfunc` on
    /// `fpath` and `compinit` run), or `cradle completions bash | sudo tee
    /// /etc/bash_completion.d/cradle`.
    Completions { shell: Shell },
}

#[derive(Subcommand)]
enum PasswordCommand {
    /// Store a device's backup password. Prompts with hidden input if
    /// `--password` isn't given (preferred — `--password` is visible in
    /// shell history and process listings for as long as this runs).
    Set {
        /// Device UDID.
        #[arg(long)]
        udid: String,
        /// The backup password. Prefer the hidden prompt (omit this) —
        /// see the command's own doc for why.
        #[arg(long)]
        password: Option<String>,
    },
    /// Remove a device's stored backup password.
    Forget {
        /// Device UDID.
        #[arg(long)]
        udid: String,
    },
}

#[derive(Subcommand)]
enum DestinationCommand {
    /// Register a new archive destination and initialize its repository.
    ///
    /// `--uri` is any restic-compatible repository location: a local
    /// path, `sftp:user@host:/path`, `s3:s3.amazonaws.com/bucket`,
    /// `b2:bucket:path`, etc. — restic's own backend abstraction
    /// interprets it, Cradle doesn't parse it.
    Add {
        /// Short name to refer to this destination by in other commands.
        #[arg(long)]
        name: String,
        /// Informational only (e.g. "local", "nas", "s3", "b2") — every
        /// kind is wrapped identically; see the `archive` module.
        #[arg(long, default_value = "local")]
        kind: String,
        /// Restic-compatible repository location — see this command's
        /// own doc above for examples.
        #[arg(long)]
        uri: String,
    },
    /// List configured destinations.
    List,
}

#[derive(Subcommand)]
enum ArchiveCommand {
    /// Archives the latest verified snapshot for a device to a destination.
    Run {
        /// Device UDID.
        #[arg(long)]
        udid: String,
        /// Destination name (see `cradle destination list`).
        #[arg(long)]
        destination: String,
        /// Must match the `--working-dir` the snapshot was backed up
        /// into — the catalog doesn't store a path, only that one
        /// canonical `<root>/<UDID>/` convention (see CLAUDE.md).
        #[arg(long, default_value = "working")]
        working_dir: PathBuf,
    },
    /// Lists snapshots actually stored at a destination's repository
    /// (restic's own view, not the local catalog's `archives` table).
    List {
        /// Destination name (see `cradle destination list`).
        #[arg(long)]
        destination: String,
    },
    /// Applies a retention policy, deleting data no longer kept.
    ///
    /// At least one `--keep-*` flag is required — restic (and Cradle)
    /// refuse to guess at "keep nothing" by omission.
    Prune {
        /// Destination name (see `cradle destination list`).
        #[arg(long)]
        destination: String,
        /// Keep the last N snapshots, regardless of age.
        #[arg(long)]
        keep_last: Option<u32>,
        /// Keep the most recent snapshot from each of the last N days.
        #[arg(long)]
        keep_daily: Option<u32>,
        /// Keep the most recent snapshot from each of the last N weeks.
        #[arg(long)]
        keep_weekly: Option<u32>,
        /// Keep the most recent snapshot from each of the last N months.
        #[arg(long)]
        keep_monthly: Option<u32>,
    },
    /// Runs a full repository integrity check. Heavier than the
    /// integrity restic already confirms during every `archive run` —
    /// see `archive::check`'s doc comment.
    Check {
        /// Destination name (see `cradle destination list`).
        #[arg(long)]
        destination: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Printing a completion script is fully offline, so it's handled
    // before the catalog path (below) is resolved — no reason for it to
    // depend on, or fail because of, something it has nothing to do with.
    let Command::Completions { shell } = cli.command else {
        return run_command(cli).await;
    };
    clap_complete::generate(shell, &mut Cli::command(), "cradle", &mut std::io::stdout());
    Ok(())
}

async fn run_command(cli: Cli) -> anyhow::Result<()> {
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
        Command::Destination { command } => run_destination(command, catalog_path).await,
        Command::Archive { command } => run_archive(command, catalog_path).await,
        Command::Restore {
            udid,
            source_udid,
            from_archive,
            restic_snapshot,
            working_dir,
            scratch_dir,
            no_reboot,
            system_files,
        } => {
            run_restore(
                udid,
                source_udid,
                from_archive,
                restic_snapshot,
                working_dir,
                scratch_dir,
                no_reboot,
                system_files,
                catalog_path,
            )
            .await
        }
        Command::Password { command } => run_password(command),
        Command::Decrypt {
            udid,
            working_dir,
            input,
            output,
            encryption_key,
        } => run_decrypt(udid, working_dir, input, output, encryption_key).await,
        // Handled in `main` before `run_command` is ever called.
        Command::Completions { .. } => unreachable!(),
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
        // A stored backup password unlocks the real Manifest.db integrity
        // check instead of the reduced one — see verify.rs's module doc.
        // Not finding one is the common case, not an error: nothing here
        // prompts for it mid-backup.
        let stored_password = keychain::try_read(&keychain::device_account(&udid))?;
        let gate = verify::run(
            &outcome.backup_dir,
            outcome.files_received,
            stored_password.as_deref(),
        )
        .await?;
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
                "Backup verified: {} ({} files, {}, Manifest.db integrity {}).",
                outcome.backup_dir.display(),
                gate.files_on_disk,
                human_bytes(gate.total_bytes),
                if gate.manifest_integrity_checked {
                    "confirmed"
                } else {
                    "not checked — no stored backup password; see `cradle password set`"
                }
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

async fn run_destination(command: DestinationCommand, catalog_path: PathBuf) -> anyhow::Result<()> {
    let catalog = Catalog::open(&catalog_path)?;
    match command {
        DestinationCommand::Add { name, kind, uri } => {
            if catalog.destination_by_name(&name)?.is_some() {
                anyhow::bail!("A destination named '{name}' already exists.");
            }

            let credential_ref = keychain::destination_account(&name);
            keychain::generate_and_store(&credential_ref)?;

            // A throwaway record (id doesn't matter — archive:: only reads
            // uri/credential_ref) so init can run *before* the catalog
            // insert: if it fails, nothing gets recorded at all, rather
            // than needing to roll back a row that pointed at a repo we
            // never actually opened.
            let probe = DestinationRecord {
                id: 0,
                name: name.clone(),
                kind: kind.clone(),
                uri: uri.clone(),
                credential_ref: credential_ref.clone(),
                retention_json: None,
            };

            println!("Initializing repository at {uri}...");
            let created = match archive::ensure_initialized(&probe).await {
                Ok(created) => created,
                Err(e) => {
                    let _ = keychain::delete(&credential_ref);
                    return Err(e.into());
                }
            };

            catalog.create_destination(&name, &kind, &uri, &credential_ref)?;

            if created {
                println!("Destination '{name}' created and repository initialized.");
            } else {
                println!(
                    "Destination '{name}' created — a repository already existed at {uri}, reusing it."
                );
            }
            Ok(())
        }
        DestinationCommand::List => {
            let destinations = catalog.list_destinations()?;
            if destinations.is_empty() {
                println!("No destinations configured. Add one with `cradle destination add`.");
                return Ok(());
            }
            for d in destinations {
                println!("{:<12} {:<8} {}", d.name, d.kind, d.uri);
            }
            Ok(())
        }
    }
}

fn resolve_destination(catalog: &Catalog, name: &str) -> anyhow::Result<DestinationRecord> {
    catalog.destination_by_name(name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No destination named '{name}'. Run `cradle destination list` to see what's configured."
        )
    })
}

async fn run_archive(command: ArchiveCommand, catalog_path: PathBuf) -> anyhow::Result<()> {
    let catalog = Catalog::open(&catalog_path)?;
    match command {
        ArchiveCommand::Run {
            udid,
            destination,
            working_dir,
        } => run_archive_run(&catalog, &udid, &destination, &working_dir).await,
        ArchiveCommand::List { destination } => run_archive_list(&catalog, &destination).await,
        ArchiveCommand::Prune {
            destination,
            keep_last,
            keep_daily,
            keep_weekly,
            keep_monthly,
        } => {
            let policy = archive::RetentionPolicy {
                keep_last,
                keep_daily,
                keep_weekly,
                keep_monthly,
            };
            run_archive_prune(&catalog, &destination, policy).await
        }
        ArchiveCommand::Check { destination } => run_archive_check(&catalog, &destination).await,
    }
}

async fn run_archive_run(
    catalog: &Catalog,
    udid: &str,
    destination_name: &str,
    working_root: &Path,
) -> anyhow::Result<()> {
    let destination = resolve_destination(catalog, destination_name)?;

    let snapshot = catalog.latest_verified_snapshot(udid)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No verified snapshot for {udid} yet — run `cradle backup --udid {udid}` first. Per \
             CLAUDE.md, an unverified backup is never treated as an archivable snapshot."
        )
    })?;

    let source_dir = working_root.join(udid);
    if !source_dir.is_dir() {
        anyhow::bail!(
            "Catalog has a verified snapshot for {udid}, but {} doesn't exist. Did --working-dir \
             change since that backup ran?",
            source_dir.display()
        );
    }

    archive::ensure_initialized(&destination).await?;
    let archive_id = catalog.start_archive(snapshot.id, destination.id)?;

    println!(
        "Archiving {} to '{}' ({})...",
        source_dir.display(),
        destination.name,
        destination.uri
    );
    let progress = Arc::new(TerminalProgress::new());
    let result = archive::backup(&destination, &source_dir, progress.clone()).await;
    progress.finish();

    match result {
        Ok(summary) => {
            catalog.finish_archive(
                archive_id,
                ArchiveState::Succeeded,
                Some(&summary.snapshot_id),
                None,
            )?;
            println!(
                "Archived: restic snapshot {} — {} new data written ({} processed, {} files).",
                summary.snapshot_id,
                human_bytes(summary.data_added),
                human_bytes(summary.total_bytes_processed),
                summary.total_files_processed,
            );
            Ok(())
        }
        Err(e) => {
            catalog.finish_archive(archive_id, ArchiveState::Failed, None, Some(&e.to_string()))?;
            Err(e.into())
        }
    }
}

async fn run_archive_list(catalog: &Catalog, destination_name: &str) -> anyhow::Result<()> {
    let destination = resolve_destination(catalog, destination_name)?;
    let snapshots = archive::list_snapshots(&destination).await?;
    if snapshots.is_empty() {
        println!("No snapshots in '{destination_name}' yet.");
        return Ok(());
    }
    for s in snapshots {
        println!("{}  {}  {}", s.short_id, s.time, s.paths.join(", "));
    }
    Ok(())
}

async fn run_archive_prune(
    catalog: &Catalog,
    destination_name: &str,
    policy: archive::RetentionPolicy,
) -> anyhow::Result<()> {
    let destination = resolve_destination(catalog, destination_name)?;
    println!("Applying retention policy to '{destination_name}'...");
    let summary = archive::forget_and_prune(&destination, &policy).await?;
    catalog.set_destination_retention(destination.id, &policy.to_json())?;
    println!(
        "Kept {} snapshot(s), removed {}.",
        summary.kept, summary.removed
    );
    Ok(())
}

async fn run_archive_check(catalog: &Catalog, destination_name: &str) -> anyhow::Result<()> {
    let destination = resolve_destination(catalog, destination_name)?;
    println!(
        "Checking repository integrity for '{destination_name}' (reads the whole repo, may take a while)..."
    );
    let summary = archive::check(&destination).await?;
    if summary.num_errors == 0 {
        println!("No errors found.");
        Ok(())
    } else {
        anyhow::bail!(
            "restic check found {} error(s) in '{destination_name}'.",
            summary.num_errors
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_restore(
    udid: Option<String>,
    source_udid: Option<String>,
    from_archive: Option<String>,
    restic_snapshot: Option<String>,
    working_root: PathBuf,
    scratch_root: PathBuf,
    no_reboot: bool,
    system_files: bool,
    catalog_path: PathBuf,
) -> anyhow::Result<()> {
    let udid = resolve_udid(udid).await?;
    let source_udid = source_udid.unwrap_or_else(|| udid.clone());
    let provider = device::provider_for(&udid).await?;
    let catalog = Catalog::open(&catalog_path)?;

    println!("Staging backup for restore...");
    let staged_dir = match (from_archive, restic_snapshot) {
        (Some(destination_name), Some(snapshot_id)) => {
            let destination = resolve_destination(&catalog, &destination_name)?;
            let progress = Arc::new(TerminalProgress::new());
            let summary = archive::restore(&destination, &snapshot_id, &scratch_root, progress.clone()).await?;
            progress.finish();
            println!(
                "Restored {} file(s) ({}) from '{destination_name}' into scratch.",
                summary.files_restored,
                human_bytes(summary.total_bytes)
            );
            summary.path
        }
        _ => restore::stage_from_working(&working_root, &source_udid, &scratch_root).await?,
    };

    let backup_ios = restore::backup_ios_version(&staged_dir)?;

    println!("Running restore prechecks...");
    let report = precheck::run_restore(&*provider, &backup_ios).await?;

    if let Some(info) = &report.device {
        println!(
            "Target device: {} ({}, iOS {})",
            info.name, info.product_type, info.ios_version
        );
    }
    if !report.pairing_valid {
        anyhow::bail!(report
            .pairing_message
            .unwrap_or_else(|| "Pairing check failed.".to_string()));
    }
    if !report.find_my_disabled {
        anyhow::bail!(
            "Find My is enabled on the target device. Disable it under Settings > [name] > \
             Find My > Find My iPhone before restoring."
        );
    }
    if !report.target_ios_ok {
        anyhow::bail!(
            "Target device is on iOS {}, but this backup is from iOS {} — restoring backward \
             isn't supported. Update the target device first.",
            report.target_ios_version.as_deref().unwrap_or("unknown"),
            report.backup_ios_version,
        );
    }

    let run_id = catalog.start_run(&udid, RunKind::Restore)?;

    let config = restore::RestoreConfig {
        reboot: !no_reboot,
        system_files,
    };

    println!(
        "Restoring {} (source {source_udid}) onto target {udid}...",
        staged_dir.display()
    );
    let progress = Arc::new(TerminalProgress::new());
    let result = restore::run(&*provider, &staged_dir, &source_udid, &config, progress.clone()).await;
    progress.finish();

    match result {
        Ok(outcome) => {
            catalog.finish_run(run_id, RunStatus::Succeeded, 0, 0, None)?;
            println!(
                "Restore complete on {}.{}",
                outcome.target_udid,
                if config.reboot {
                    " Device will reboot."
                } else {
                    ""
                }
            );
            Ok(())
        }
        Err(e) => {
            catalog.finish_run(run_id, RunStatus::Failed, 0, 0, Some(&e.to_string()))?;
            Err(e.into())
        }
    }
}

fn run_password(command: PasswordCommand) -> anyhow::Result<()> {
    match command {
        PasswordCommand::Set { udid, password } => {
            let password = match password {
                Some(p) => p,
                None => rpassword::prompt_password("Backup password: ")?,
            };
            if password.is_empty() {
                anyhow::bail!("Password was empty — not storing it.");
            }
            keychain::store(&keychain::device_account(&udid), &password)?;
            println!("Stored the backup password for {udid} in the Keychain.");
            Ok(())
        }
        PasswordCommand::Forget { udid } => {
            keychain::delete(&keychain::device_account(&udid))?;
            println!("Removed the stored backup password for {udid}.");
            Ok(())
        }
    }
}

async fn run_decrypt(
    udid: Option<String>,
    working_root: PathBuf,
    input: PathBuf,
    output: PathBuf,
    encryption_key_hex: String,
) -> anyhow::Result<()> {
    let udid = resolve_udid(udid).await?;
    let password = keychain::try_read(&keychain::device_account(&udid))?.ok_or_else(|| {
        anyhow::anyhow!(
            "No stored backup password for {udid} — run `cradle password set --udid {udid}` first."
        )
    })?;

    let backup_dir = working_root.join(&udid);
    let keybag = Keybag::unlock_from_backup_dir(&backup_dir, &password)?;

    let encryption_key = hex::decode(encryption_key_hex.trim())
        .map_err(|e| anyhow::anyhow!("--encryption-key is not valid hex: {e}"))?;
    let ciphertext = std::fs::read(backup_dir.join(&input))
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", input.display()))?;
    let decrypted = keybag.decrypt(&ciphertext, &encryption_key)?;

    std::fs::write(&output, &decrypted)
        .map_err(|e| anyhow::anyhow!("could not write {}: {e}", output.display()))?;
    println!(
        "Decrypted {} ({} bytes) to {}. Note: output may have trailing pad bytes past the \
         file's true size — see crypto.rs's `Keybag::decrypt` doc if that matters for this file.",
        input.display(),
        decrypted.len(),
        output.display()
    );
    Ok(())
}
