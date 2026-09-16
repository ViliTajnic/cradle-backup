//! Cradle CLI — device connect/precheck/backup, verification gate,
//! catalog, archive layer, restore, decryption.
//!
//! The CLI is not a debug tool: it ships, it is supported, and it is the
//! free tier's complete interface. Restore in particular is free,
//! unconditional, forever — nothing on the `run_restore` path below
//! checks a license or calls out to a server.

mod json;
mod progress;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use cradle_core::catalog::{Catalog, DestinationRecord, RunKind, RunStatus};
use cradle_core::crypto::Keybag;
use cradle_core::power::SleepGuard;
use cradle_core::{archive, backup, keychain, libimobiledevice, precheck, restore, verify, workflow};

use progress::{TerminalProgress, human_bytes};

#[derive(Parser)]
#[command(name = "cradle", version, about = "Backup and restore for iPhone and iPad.")]
struct Cli {
    /// Catalog database path. Defaults to the platform data directory
    /// (e.g. `~/Library/Application Support/Cradle/catalog.db` on macOS).
    #[arg(long, global = true)]
    catalog: Option<PathBuf>,

    /// Print one JSON object to stdout instead of human-readable text —
    /// `devices`, `history`, `backup`, `archive run`, `restore`, and
    /// `doctor` support this. Progress still streams to stderr as plain
    /// text either way (see `progress.rs`), so a script can capture
    /// stdout alone and still let a human watch stderr scroll by.
    /// CODEBASE_ANALYSIS.md: "Add structured JSON results/events and
    /// stable error categories."
    #[arg(long, global = true)]
    json: bool,

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
        /// Defaults to the same location the desktop app uses
        /// (`~/Cradle/working`) when omitted.
        #[arg(long)]
        working_dir: Option<PathBuf>,
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
    /// Archiving copies out of the working directory — never in place,
    /// never touching the source.
    Archive {
        #[command(subcommand)]
        command: ArchiveCommand,
    },
    /// Restore a backup onto a device.
    ///
    /// Free, unconditional, forever — no license check, no network call.
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
        /// Defaults to the same location the desktop app uses
        /// (`~/Cradle/working`) when omitted.
        #[arg(long)]
        working_dir: Option<PathBuf>,
        /// Staging area the restore is run from — never the working
        /// directory itself.
        /// Defaults to the same location the desktop app uses
        /// (`~/Cradle/scratch`) when omitted.
        #[arg(long)]
        scratch_dir: Option<PathBuf>,
        /// Don't reboot the target device once the restore finishes.
        #[arg(long)]
        no_reboot: bool,
        /// Also restore system files (off by default, matching
        /// `idevicebackup2 restore`'s own default).
        #[arg(long)]
        system_files: bool,
        /// The source backup's password, if it's not (or is no longer)
        /// what's stored in the Keychain for it — e.g. restoring an
        /// archive made before a later `cradle password set` changed
        /// what's on file. Overrides the stored password rather than
        /// replacing it; nothing here touches the Keychain. Restore must
        /// stay possible even after Cradle's own stored copy no longer
        /// matches — this is that path.
        #[arg(long)]
        password: Option<String>,
    },
    /// Manage a device's backup encryption password.
    ///
    /// `set`/`forget` only manage the copy stored in the macOS Keychain —
    /// storing it unlocks the real `Manifest.db` integrity check on
    /// `cradle backup` (see `verify.rs`) instead of the reduced one, and
    /// is needed for `cradle decrypt`. `enable` actually turns encryption
    /// on on the device itself, over the wire — see its own doc for why
    /// that's needed at all.
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
        /// Defaults to the same location the desktop app uses
        /// (`~/Cradle/working`) when omitted.
        #[arg(long)]
        working_dir: Option<PathBuf>,
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
        /// This backup's password, if it's not (or is no longer) what's
        /// stored in the Keychain for this device — see `restore`'s own
        /// `--password` for why. Overrides the stored password rather
        /// than replacing it.
        #[arg(long)]
        password: Option<String>,
    },
    /// Print a shell completion script to stdout.
    ///
    /// e.g. `cradle completions zsh > ~/.zfunc/_cradle` (with `~/.zfunc` on
    /// `fpath` and `compinit` run), or `cradle completions bash | sudo tee
    /// /etc/bash_completion.d/cradle`.
    Completions { shell: Shell },
    /// Checks that Cradle's actual dependencies are in place: the
    /// libimobiledevice tools, restic, `usbmuxd` reachability, and the
    /// default working/scratch/catalog locations — sanitized output safe
    /// to paste into a bug report. CODEBASE_ANALYSIS.md: "Diagnostic
    /// command and portable logs."
    Doctor,
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
    /// Turns on backup encryption on the device itself, over the wire.
    ///
    /// iOS has no Settings toggle for this — it's purely a computer-side
    /// setting the device stores, normally set via Finder's "Encrypt local
    /// backup" checkbox. Use this instead when Finder's own local-backup
    /// bookkeeping is stuck (e.g. a "backup was corrupt" dialog blocking
    /// that checkbox). Also stores the password in the Keychain on
    /// success, same as `password set`.
    Enable {
        /// Device UDID. Required when more than one device is attached.
        #[arg(long)]
        udid: Option<String>,
        /// The new backup password. Prefer the hidden prompt (omit this)
        /// — see `password set`'s doc for why.
        #[arg(long)]
        password: Option<String>,
        /// Scratch directory the protocol call needs to be pointed at.
        /// No backup files are written here for this operation.
        /// Defaults to the same location the desktop app uses
        /// (`~/Cradle/working`) when omitted.
        #[arg(long)]
        working_dir: Option<PathBuf>,
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
    /// Forgets a destination — removes it from the catalog. Keeps its
    /// Keychain-stored password by default (pass `--delete-credential` to
    /// also delete it) — since Cradle generated that password and it's
    /// the only copy, deleting it makes the repository's existing data
    /// permanently unreadable, even though the bytes at its URI are
    /// otherwise untouched. Use `cradle destination connect` to bring a
    /// forgotten (but not credential-deleted) destination back.
    Remove {
        #[arg(long)]
        name: String,
        /// Also delete the Keychain-stored password — only pass this if
        /// you're certain you'll never need this repository again, or
        /// have its password recorded elsewhere.
        #[arg(long)]
        delete_credential: bool,
    },
    /// Prints a destination's repository password so it can be written
    /// down or stored somewhere durable (a password manager, printed
    /// recovery sheet, ...) — the closest thing to a recovery-kit export
    /// today. Anyone with this password and the destination's `uri` can
    /// read and modify that restic repository.
    ShowPassword {
        #[arg(long)]
        name: String,
    },
    /// Registers a destination pointing at a repository that already
    /// exists — recovering a destination after its Keychain credential
    /// was deleted, or setting Cradle up on a fresh Mac against archives
    /// made elsewhere. `--password` is validated by actually opening the
    /// repository before anything is stored; a wrong password fails
    /// clearly rather than silently recording a destination Cradle can
    /// never use.
    Connect {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "local")]
        kind: String,
        #[arg(long)]
        uri: String,
        #[arg(long)]
        password: String,
    },
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
        /// canonical `<root>/<UDID>/` convention.
        /// Defaults to the same location the desktop app uses
        /// (`~/Cradle/working`) when omitted.
        #[arg(long)]
        working_dir: Option<PathBuf>,
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
        /// Show which snapshots this policy would keep and remove without
        /// actually removing anything. CODEBASE_ANALYSIS.md's "Retention
        /// preview."
        #[arg(long)]
        dry_run: bool,
    },
    /// Checks a repository's integrity. Heavier than the integrity restic
    /// already confirms during every `archive run` — see
    /// `archive::check`'s doc comment. By default this only checks
    /// structure (fast) — pass `--full` or `--sample` to actually read
    /// pack contents; see each flag's own help for the difference.
    Check {
        /// Destination name (see `cradle destination list`).
        #[arg(long)]
        destination: String,
        /// Read and checksum every byte in the repository, not just its
        /// structure — can take as long as the original archive did.
        /// Mutually exclusive with `--sample`.
        #[arg(long, conflicts_with = "sample")]
        full: bool,
        /// Read and checksum a random N% sample of the repository instead
        /// of everything — catches the same silent storage-level
        /// corruption `--full` does, much faster. Mutually exclusive with
        /// `--full`.
        #[arg(long, value_name = "PERCENT")]
        sample: Option<u8>,
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
        // Raced against a signal listener for the whole rest of the
        // command: see `signals.rs` for why — a killed `cradle` process
        // must not leave an orphaned `idevicebackup2`/`restic` behind
        // with the working-set lock it held already released.
        return tokio::select! {
            result = run_command(cli) => result,
            _ = cradle_core::signals::wait_and_propagate_termination() => unreachable!(),
        };
    };
    clap_complete::generate(shell, &mut Cli::command(), "cradle", &mut std::io::stdout());
    Ok(())
}

async fn run_command(cli: Cli) -> anyhow::Result<()> {
    let json = cli.json;
    let catalog_path = match cli.catalog {
        Some(path) => path,
        None => Catalog::default_path()?,
    };

    match cli.command {
        Command::Devices => run_devices(json).await,
        Command::Backup {
            udid,
            working_dir,
            full,
        } => {
            let working_dir = working_dir.unwrap_or_else(cradle_core::paths::default_working_dir);
            run_backup(udid, working_dir, full, catalog_path, json).await
        }
        Command::History { udid } => run_history(udid, catalog_path, json),
        Command::Destination { command } => run_destination(command, catalog_path).await,
        Command::Archive { command } => run_archive(command, catalog_path, json).await,
        Command::Restore {
            udid,
            source_udid,
            from_archive,
            restic_snapshot,
            working_dir,
            scratch_dir,
            no_reboot,
            system_files,
            password,
        } => {
            let working_dir = working_dir.unwrap_or_else(cradle_core::paths::default_working_dir);
            let scratch_dir = scratch_dir.unwrap_or_else(cradle_core::paths::default_scratch_dir);
            run_restore(
                udid,
                source_udid,
                from_archive,
                restic_snapshot,
                working_dir,
                scratch_dir,
                no_reboot,
                system_files,
                password,
                catalog_path,
                json,
            )
            .await
        }
        Command::Password { command } => run_password(command).await,
        Command::Decrypt {
            udid,
            working_dir,
            input,
            output,
            encryption_key,
            password,
        } => {
            let working_dir = working_dir.unwrap_or_else(cradle_core::paths::default_working_dir);
            run_decrypt(udid, working_dir, input, output, encryption_key, password).await
        }
        // Handled in `main` before `run_command` is ever called.
        Command::Completions { .. } => unreachable!(),
        Command::Doctor => run_doctor(catalog_path, json).await,
    }
}

#[derive(serde::Serialize)]
struct JsonDevice {
    udid: String,
    transport: String,
    name: Option<String>,
    product_type: Option<String>,
    ios_version: Option<String>,
    reachable: bool,
    pairing_error: Option<String>,
}

async fn run_devices(json: bool) -> anyhow::Result<()> {
    let devices = libimobiledevice::list_devices().await?;

    if json {
        let mut out = Vec::with_capacity(devices.len());
        for attached in devices {
            let info = libimobiledevice::device_info(&attached.udid).await;
            out.push(JsonDevice {
                udid: attached.udid,
                transport: format!("{:?}", attached.transport),
                name: info.as_ref().ok().map(|i| i.name.clone()),
                product_type: info.as_ref().ok().map(|i| i.product_type.clone()),
                ios_version: info.as_ref().ok().map(|i| i.ios_version.clone()),
                reachable: info.is_ok(),
                pairing_error: info.err().map(|e| e.to_string()),
            });
        }
        crate::json::print_ok(out);
        return Ok(());
    }

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
    let info = libimobiledevice::device_info(udid).await?;
    Ok(format!(
        "{} ({}, iOS {})",
        info.name, info.product_type, info.ios_version
    ))
}

#[derive(serde::Serialize)]
struct DoctorCheck {
    label: String,
    ok: bool,
    detail: String,
}

/// Checks that Cradle's actual runtime dependencies are in place — safe to
/// paste into a bug report as-is (text or `--json`), since nothing here
/// prints a password, a Keychain value, or file contents. Never fails the
/// process on its own checks failing: a missing tool is exactly the kind
/// of thing this command exists to surface, not to error out on — the
/// exit code still reflects it at the end (see the `!ok` check below).
async fn run_doctor(catalog_path: PathBuf, json: bool) -> anyhow::Result<()> {
    let mut checks = Vec::new();
    let mut check = |label: String, result: Result<String, String>| {
        let (ok, detail) = match result {
            Ok(detail) => (true, detail),
            Err(reason) => (false, reason),
        };
        checks.push(DoctorCheck { label, ok, detail });
    };

    for tool in ["idevice_id", "ideviceinfo", "idevicepair", "idevicebackup2"] {
        check(
            tool.to_string(),
            cradle_core::tools::resolve(tool)
                .map(|p| p.display().to_string())
                .map_err(|e| e.to_string()),
        );
    }
    check(
        "restic".to_string(),
        cradle_core::tools::resolve("restic")
            .map(|p| p.display().to_string())
            .map_err(|e| format!("{e} (try `brew install restic`)")),
    );

    match libimobiledevice::list_devices().await {
        Ok(devices) => check(
            "usbmuxd".to_string(),
            Ok(format!("reachable, {} device(s) currently seen", devices.len())),
        ),
        Err(e) => check("usbmuxd".to_string(), Err(e.to_string())),
    }

    for (label, dir) in [
        ("working directory", cradle_core::paths::default_working_dir()),
        ("scratch directory", cradle_core::paths::default_scratch_dir()),
    ] {
        let free = precheck::free_disk_space(&dir);
        check(
            format!("{label} ({})", dir.display()),
            match free {
                Some(bytes) => Ok(format!("{} free", human_bytes(bytes))),
                None => Err("could not measure free space — is its volume mounted?".to_string()),
            },
        );
    }

    check(
        format!("catalog ({})", catalog_path.display()),
        Catalog::open(&catalog_path).map(|_| "opens fine".to_string()).map_err(|e| e.to_string()),
    );

    let all_ok = checks.iter().all(|c| c.ok);
    if json {
        crate::json::print_ok(checks);
    } else {
        for c in &checks {
            let tag = if c.ok { "[ok]  " } else { "[FAIL]" };
            println!("{tag} {}: {}", c.label, c.detail);
        }
    }

    if !all_ok {
        anyhow::bail!("One or more checks failed.");
    }
    Ok(())
}

async fn resolve_udid(udid: Option<String>) -> anyhow::Result<String> {
    if let Some(udid) = udid {
        return Ok(udid);
    }
    let devices = libimobiledevice::list_devices().await?;
    match devices.as_slice() {
        [only] => Ok(only.udid.clone()),
        [] => anyhow::bail!("No devices attached. Connect an iPhone or iPad and unlock it."),
        _ => anyhow::bail!("Multiple devices attached — pass --udid to choose one."),
    }
}

#[derive(serde::Serialize)]
struct BackupJson {
    backup_dir: String,
    files: u64,
    bytes: u64,
    verified: bool,
    needs_password: bool,
    manifest_integrity_checked: bool,
    problems: Vec<String>,
}

async fn run_backup(
    udid: Option<String>,
    working_root: PathBuf,
    full: bool,
    catalog_path: PathBuf,
    json: bool,
) -> anyhow::Result<()> {
    // A real ~75GB backup over USB took the better part of an hour and
    // failed near the end with MBErrorDomain 104 ("computer-side errors
    // during backup") — consistent with the Mac going to sleep mid-
    // transfer during that unattended hour. Held for the whole function.
    let _sleep_guard = SleepGuard::engage();

    let udid = resolve_udid(udid).await.map_err(|e| crate::json::bail(json, "device_not_found", e))?;
    let catalog = Catalog::open(&catalog_path).map_err(|e| crate::json::bail(json, "catalog_error", e))?;
    let progress = Arc::new(TerminalProgress::new());

    if !json {
        println!("Running prechecks...");
    }
    let request = workflow::BackupRequest {
        udid: udid.clone(),
        working_root: working_root.clone(),
        full,
    };
    let result = workflow::run_backup(
        catalog,
        request,
        progress.clone(),
        |info| {
            if !json {
                println!("Device: {} ({}, iOS {})", info.name, info.product_type, info.ios_version);
                println!("Prechecks passed. Backing up into {}...", working_root.display());
            }
        },
        move || {
            if !json {
                println!("Verifying backup...");
            }
        },
        // Retries always narrate to stderr regardless of --json: they're
        // progress, not the final result, same reasoning as progress.rs.
        |reason, attempt, max_attempts| match reason {
            backup::RetryReason::DeviceLocked => eprintln!(
                "\nDevice locked mid-backup — unlock it now. Retrying in {}s (attempt {}/{})...",
                backup::LOCK_RETRY_DELAY.as_secs(),
                attempt,
                max_attempts
            ),
            backup::RetryReason::HostIo => eprintln!(
                "\nHost-side I/O error (device error 104) — usually low memory on this Mac. \
                 Retrying in {}s (attempt {}/{})...",
                backup::HOST_IO_RETRY_DELAY.as_secs(),
                attempt,
                max_attempts
            ),
            backup::RetryReason::Stalled => eprintln!(
                "\nDevice stopped responding, no error reported — check the cable/USB \
                 connection and that the device is unlocked and awake. Retrying in {}s \
                 (attempt {}/{})...",
                backup::STALL_RETRY_DELAY.as_secs(),
                attempt,
                max_attempts
            ),
        },
    )
    .await;
    progress.finish();

    match result {
        Ok(outcome) => {
            let verified = outcome.gate.outcome == verify::Outcome::Verified;
            let needs_password = outcome.gate.outcome == verify::Outcome::NeedsPassword;
            if json {
                crate::json::print_ok(BackupJson {
                    backup_dir: outcome.backup_dir.display().to_string(),
                    files: outcome.gate.files_on_disk,
                    bytes: outcome.gate.total_bytes,
                    verified,
                    needs_password,
                    manifest_integrity_checked: outcome.gate.manifest_integrity_checked,
                    problems: outcome.gate.problems.clone(),
                });
                if verified || needs_password {
                    return Ok(());
                }
                anyhow::bail!("Backup did not pass verification.");
            }
            if verified {
                println!(
                    "Backup verified: {} ({} files, {}, Manifest.db integrity confirmed).",
                    outcome.backup_dir.display(),
                    outcome.gate.files_on_disk,
                    human_bytes(outcome.gate.total_bytes),
                );
                Ok(())
            } else if needs_password {
                println!(
                    "Backup completed but not verified: {} ({} files, {}). No stored backup \
                     password — Manifest.db integrity was never checked, so this cannot be \
                     archived yet. Run `cradle password set` and re-run `cradle backup` to \
                     verify it.",
                    outcome.backup_dir.display(),
                    outcome.gate.files_on_disk,
                    human_bytes(outcome.gate.total_bytes),
                );
                Ok(())
            } else {
                anyhow::bail!(
                    "Backup did not pass verification — treat {} as failed, not a usable snapshot:\n{}",
                    outcome.backup_dir.display(),
                    outcome.gate.problems.join("\n"),
                )
            }
        }
        Err(workflow::WorkflowError::NotStarted(workflow::NotStartedReason::Precheck(report))) => {
            if !json && let Some(info) = &report.device {
                println!("Device: {} ({}, iOS {})", info.name, info.product_type, info.ios_version);
            }
            let (category, message) = if !report.pairing_valid {
                (
                    "pairing_invalid",
                    report.pairing_message.clone().unwrap_or_else(|| "Pairing check failed.".to_string()),
                )
            } else if !report.encryption_enabled {
                (
                    "encryption_disabled",
                    format!(
                        "Backup encryption is off on this device. Run `cradle password enable \
                         --udid {udid}` to turn it on before continuing — without it, Keychain, \
                         Health, call history and saved passwords are silently omitted from the \
                         backup."
                    ),
                )
            } else {
                match report.free_space_bytes {
                    Some(bytes) => (
                        "insufficient_space",
                        format!(
                            "Only {} free on the working volume; want at least {} before \
                             starting a backup.",
                            human_bytes(bytes),
                            human_bytes(precheck::MIN_FREE_BYTES),
                        ),
                    ),
                    None => (
                        "space_unknown",
                        "Could not measure free space on the working volume — is it mounted? \
                         (An external drive that's unplugged or asleep looks like this.)"
                            .to_string(),
                    ),
                }
            };
            if json {
                crate::json::print_err(category, &message);
            }
            anyhow::bail!(message)
        }
        Err(e) => {
            if json {
                crate::json::print_err("failed", &e);
            }
            Err(e.into())
        }
    }
}

#[derive(serde::Serialize)]
struct HistoryJson {
    runs: Vec<cradle_core::catalog::RunRecord>,
    snapshots: Vec<cradle_core::catalog::SnapshotRecord>,
}

fn run_history(udid: String, catalog_path: PathBuf, json: bool) -> anyhow::Result<()> {
    let catalog = Catalog::open(&catalog_path)?;
    let runs = catalog.list_runs(&udid)?;

    if json {
        let snapshots = catalog.list_snapshots(&udid)?;
        crate::json::print_ok(HistoryJson { runs, snapshots });
        return Ok(());
    }

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

            let credential_ref = keychain::new_destination_account(&name);
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
        DestinationCommand::Remove { name, delete_credential } => {
            let destination = resolve_destination(&catalog, &name)?;
            catalog.delete_destination(destination.id)?;
            if delete_credential {
                let _ = keychain::delete(&destination.credential_ref);
                println!(
                    "Removed destination '{name}' and deleted its stored password. The \
                     repository at {} still has its data, but Cradle can no longer read or \
                     write it without that password.",
                    destination.uri
                );
            } else {
                println!(
                    "Forgot destination '{name}'. Its stored password was kept — run `cradle \
                     destination connect --name {name} --uri {} --password <password>` (get the \
                     password first with `cradle destination show-password --name {name}` if \
                     you still have it, before forgetting again) to bring it back.",
                    destination.uri
                );
            }
            Ok(())
        }
        DestinationCommand::ShowPassword { name } => {
            let destination = resolve_destination(&catalog, &name)?;
            let password = keychain::read(&destination.credential_ref)?;
            println!("{password}");
            Ok(())
        }
        DestinationCommand::Connect { name, kind, uri, password } => {
            if catalog.destination_by_name(&name)?.is_some() {
                anyhow::bail!("A destination named '{name}' already exists.");
            }
            let credential_ref = keychain::new_destination_account(&name);
            keychain::store(&credential_ref, &password)?;

            let probe = DestinationRecord {
                id: 0,
                name: name.clone(),
                kind: kind.clone(),
                uri: uri.clone(),
                credential_ref: credential_ref.clone(),
                retention_json: None,
            };
            // Actually open the repository with this password before
            // recording anything — a wrong password must fail here, not
            // silently produce a destination Cradle can never archive to.
            println!("Validating password against {uri}...");
            if let Err(e) = archive::list_snapshots(&probe).await {
                let _ = keychain::delete(&credential_ref);
                anyhow::bail!("Could not open the repository at {uri} with that password: {e}");
            }

            catalog.create_destination(&name, &kind, &uri, &credential_ref)?;
            println!("Destination '{name}' connected to the existing repository at {uri}.");
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

async fn run_archive(command: ArchiveCommand, catalog_path: PathBuf, json: bool) -> anyhow::Result<()> {
    // `Run` opens its own `Catalog` rather than sharing the one below,
    // because it hands ownership of it to `workflow::run_archive` — that
    // function holds it across several `.await` points, which needs an
    // owned `Catalog` to stay `Send` (a `rusqlite::Connection` reference
    // is not `Sync`, but the connection itself is `Send`).
    if let ArchiveCommand::Run { udid, destination, working_dir } = command {
        let working_dir = working_dir.unwrap_or_else(cradle_core::paths::default_working_dir);
        return run_archive_run(&catalog_path, &udid, &destination, &working_dir, json).await;
    }

    let catalog = Catalog::open(&catalog_path)?;
    match command {
        ArchiveCommand::Run { .. } => unreachable!("handled above"),
        ArchiveCommand::List { destination } => run_archive_list(&catalog, &destination).await,
        ArchiveCommand::Prune {
            destination,
            keep_last,
            keep_daily,
            keep_weekly,
            keep_monthly,
            dry_run,
        } => {
            let policy = archive::RetentionPolicy {
                keep_last,
                keep_daily,
                keep_weekly,
                keep_monthly,
            };
            if dry_run {
                run_archive_prune_preview(&catalog, &destination, policy).await
            } else {
                run_archive_prune(&catalog, &destination, policy).await
            }
        }
        ArchiveCommand::Check { destination, full, sample } => {
            let mode = match (full, sample) {
                (true, _) => archive::CheckMode::Full,
                (false, Some(percent)) => archive::CheckMode::Sample { percent },
                (false, None) => archive::CheckMode::Quick,
            };
            run_archive_check(&catalog, &destination, mode).await
        }
    }
}

#[derive(serde::Serialize)]
struct ArchiveJson {
    snapshot_id: String,
    data_added: u64,
    total_bytes_processed: u64,
    total_files_processed: u64,
}

async fn run_archive_run(
    catalog_path: &Path,
    udid: &str,
    destination_name: &str,
    working_root: &Path,
    json: bool,
) -> anyhow::Result<()> {
    // See run_backup's own comment — archiving to a NAS/cloud destination
    // is exactly as susceptible to a sleep-induced host I/O failure over a
    // long, unattended run.
    let _sleep_guard = SleepGuard::engage();

    let catalog = Catalog::open(catalog_path).map_err(|e| crate::json::bail(json, "catalog_error", e))?;
    let destination =
        resolve_destination(&catalog, destination_name).map_err(|e| crate::json::bail(json, "destination_not_found", e))?;
    let progress = Arc::new(TerminalProgress::new());
    let request = workflow::ArchiveRequest {
        udid: udid.to_string(),
        working_root: working_root.to_path_buf(),
        destination: &destination,
    };

    let result = workflow::run_archive(catalog, request, progress.clone()).await;
    progress.finish();

    let outcome_err = match result {
        Ok(outcome) => {
            if json {
                crate::json::print_ok(ArchiveJson {
                    snapshot_id: outcome.summary.snapshot_id.clone(),
                    data_added: outcome.summary.data_added,
                    total_bytes_processed: outcome.summary.total_bytes_processed,
                    total_files_processed: outcome.summary.total_files_processed,
                });
            } else {
                println!(
                    "Archived: restic snapshot {} — {} new data written ({} processed, {} files).",
                    outcome.summary.snapshot_id,
                    human_bytes(outcome.summary.data_added),
                    human_bytes(outcome.summary.total_bytes_processed),
                    outcome.summary.total_files_processed,
                );
            }
            return Ok(());
        }
        Err(e) => e,
    };

    // Stable category first, human message second — the category is what
    // a script should actually match on; see json.rs's own doc.
    let (category, message): (&str, String) = match outcome_err {
        workflow::ArchiveError::NoVerifiedSnapshot => (
            "no_verified_snapshot",
            format!(
                "No verified snapshot for {udid} yet — run `cradle backup --udid {udid}` first. \
                 An unverified backup is never treated as an archivable snapshot."
            ),
        ),
        workflow::ArchiveError::SourceMissing(dir) => (
            "source_missing",
            format!(
                "Catalog has a verified snapshot for {udid}, but {} doesn't exist. Did \
                 --working-dir change since that backup ran?",
                dir.display()
            ),
        ),
        workflow::ArchiveError::NoLongerVerified(gate) if gate.outcome == verify::Outcome::NeedsPassword => (
            "needs_password",
            "Re-checking right before archiving found no stored backup password, so the current \
             contents can't be confirmed — run `cradle password set` and back up again to get a \
             verified snapshot."
                .to_string(),
        ),
        workflow::ArchiveError::NoLongerVerified(gate) => (
            "stale_verification",
            format!(
                "Re-checking the backup right before archiving found it no longer verifies, even \
                 though the catalog has an earlier verified snapshot for {udid} — something has \
                 changed it since (a newer backup run, most likely). Not archiving it:\n{}",
                gate.problems.join("\n"),
            ),
        ),
        workflow::ArchiveError::Locked(e) => ("locked", e.to_string()),
        workflow::ArchiveError::Failed(e) => ("failed", e.to_string()),
    };

    if json {
        crate::json::print_err(category, &message);
    }
    anyhow::bail!(message)
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

async fn run_archive_prune_preview(
    catalog: &Catalog,
    destination_name: &str,
    policy: archive::RetentionPolicy,
) -> anyhow::Result<()> {
    let destination = resolve_destination(catalog, destination_name)?;
    println!("Previewing retention policy for '{destination_name}' — nothing will actually be removed.");
    let preview = archive::preview_retention(&destination, &policy).await?;

    if preview.removed.is_empty() {
        println!("Would remove: none.");
    } else {
        println!("Would remove {} snapshot(s):", preview.removed.len());
        for s in &preview.removed {
            println!("  {}  {}", s.short_id, s.time);
        }
    }
    println!("Would keep {} snapshot(s).", preview.kept.len());
    println!("Run without --dry-run to actually apply this policy.");
    Ok(())
}

async fn run_archive_check(catalog: &Catalog, destination_name: &str, mode: archive::CheckMode) -> anyhow::Result<()> {
    let destination = resolve_destination(catalog, destination_name)?;
    println!("Checking '{destination_name}': {}...", mode.description());
    let summary = archive::check(&destination, mode).await?;
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

#[derive(serde::Serialize)]
struct RestoreJson {
    target_udid: String,
    source_udid: String,
    rebooted: bool,
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
    password_override: Option<String>,
    catalog_path: PathBuf,
    json: bool,
) -> anyhow::Result<()> {
    // See run_backup's own comment.
    let _sleep_guard = SleepGuard::engage();

    let udid = resolve_udid(udid).await.map_err(|e| crate::json::bail(json, "device_not_found", e))?;
    let source_udid = source_udid.unwrap_or_else(|| udid.clone());
    let catalog = Catalog::open(&catalog_path).map_err(|e| crate::json::bail(json, "catalog_error", e))?;

    if !json {
        println!("Staging backup for restore...");
    }
    let staged_dir = match (from_archive, restic_snapshot) {
        (Some(destination_name), Some(snapshot_id)) => {
            let destination = resolve_destination(&catalog, &destination_name)
                .map_err(|e| crate::json::bail(json, "destination_not_found", e))?;
            let progress = Arc::new(TerminalProgress::new());
            let summary = archive::restore(&destination, &snapshot_id, &scratch_root, progress.clone())
                .await
                .map_err(|e| crate::json::bail(json, "staging_failed", e.to_string()))?;
            progress.finish();
            if !json {
                println!(
                    "Restored {} file(s) ({}) from '{destination_name}' into scratch.",
                    summary.files_restored,
                    human_bytes(summary.total_bytes)
                );
            }
            summary.path
        }
        _ => {
            let progress = Arc::new(TerminalProgress::new());
            let staged = workflow::stage_restore_from_working(&working_root, &source_udid, &scratch_root, progress.clone())
                .await
                .map_err(|e| crate::json::bail(json, "staging_failed", e.to_string()))?;
            progress.finish();
            staged
        }
    };
    // Authoritative over the `--source-udid` default above — see that
    // function's own doc for why this matters most for `--from-archive`.
    let source_udid = restore::source_udid_from_staged_dir(&staged_dir).unwrap_or(source_udid);

    let backup_ios =
        restore::backup_ios_version(&staged_dir).map_err(|e| crate::json::bail(json, "invalid_backup", e))?;
    let backup_size_bytes =
        restore::staged_backup_size(&staged_dir).map_err(|e| crate::json::bail(json, "invalid_backup", e))?;

    if !json {
        println!("Running restore prechecks...");
    }
    let report = precheck::run_restore(&udid, &backup_ios, backup_size_bytes)
        .await
        .map_err(|e| crate::json::bail(json, "precheck_error", e))?;

    if !json && let Some(info) = &report.device {
        println!(
            "Target device: {} ({}, iOS {})",
            info.name, info.product_type, info.ios_version
        );
    }
    if !report.pairing_valid {
        return Err(crate::json::bail(
            json,
            "pairing_invalid",
            report.pairing_message.unwrap_or_else(|| "Pairing check failed.".to_string()),
        ));
    }
    if !report.find_my_disabled {
        return Err(crate::json::bail(
            json,
            "find_my_enabled",
            "Find My is enabled on the target device. Disable it under Settings > [name] > Find \
             My > Find My iPhone before restoring."
                .to_string(),
        ));
    }
    if !report.target_ios_ok {
        return Err(crate::json::bail(
            json,
            "ios_version_mismatch",
            format!(
                "Target device is on iOS {}, but this backup is from iOS {} — restoring backward \
                 isn't supported. Update the target device first.",
                report.target_ios_version.as_deref().unwrap_or("unknown"),
                report.backup_ios_version,
            ),
        ));
    }
    if !report.enough_target_space {
        return Err(crate::json::bail(
            json,
            "not_enough_space",
            match report.target_free_bytes {
                Some(free) => format!(
                    "Not enough free space on the target device: this backup needs {:.1} GB, but \
                     only {:.1} GB is free. Free up space on the device and try again.",
                    backup_size_bytes as f64 / 1e9,
                    free as f64 / 1e9,
                ),
                None => "Could not read how much free space the target device has — check that \
                          it's unlocked and reachable, then try again."
                    .to_string(),
            },
        ));
    }

    // `runs.udid` references `devices(udid)` — without this, restoring
    // onto a target Cradle has never backed up before records a run
    // against a device row that doesn't exist yet (harmless only because
    // SQLite foreign keys aren't enforced here; see CODEBASE_ANALYSIS.md).
    if let Some(info) = &report.device {
        catalog.upsert_device(&cradle_core::catalog::DeviceRecord {
            udid: info.udid.clone(),
            name: info.name.clone(),
            product_type: info.product_type.clone(),
            ios_version: info.ios_version.clone(),
            encrypted: libimobiledevice::will_encrypt(&udid).await,
        })?;
    }
    let run_id = catalog.start_run(&udid, RunKind::Restore)?;

    let config = restore::RestoreConfig {
        reboot: !no_reboot,
        system_files,
        ..Default::default()
    };

    // An explicit `--password` overrides whatever's in the Keychain —
    // never replaces it there — so an archive made under an older
    // password stays restorable after a later `password set` changes
    // what's on file. See the flag's own doc.
    let stored_password = match password_override {
        Some(p) => Some(p),
        None => keychain::try_read(&keychain::device_account(&source_udid))?,
    };

    if !json {
        println!("Restoring {} (source {source_udid}) onto target {udid}...", staged_dir.display());
    }
    let progress = Arc::new(TerminalProgress::new());
    let result = restore::run(
        &udid,
        &staged_dir,
        &source_udid,
        &config,
        stored_password.as_deref(),
        progress.clone(),
    )
    .await;
    progress.finish();

    match result {
        Ok(outcome) => {
            catalog.finish_run(run_id, RunStatus::Succeeded, 0, 0, None)?;
            if json {
                crate::json::print_ok(RestoreJson {
                    target_udid: outcome.target_udid,
                    source_udid,
                    rebooted: config.reboot,
                });
            } else {
                println!(
                    "Restore complete on {}.{}",
                    outcome.target_udid,
                    if config.reboot { " Device will reboot." } else { "" }
                );
            }
            Ok(())
        }
        Err(e) => {
            catalog.finish_run(run_id, RunStatus::Failed, 0, 0, Some(&e.to_string()))?;
            if json {
                crate::json::print_err("failed", &e);
            }
            Err(e.into())
        }
    }
}

async fn run_password(command: PasswordCommand) -> anyhow::Result<()> {
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
        PasswordCommand::Enable {
            udid,
            password,
            working_dir,
        } => {
            let udid = resolve_udid(udid).await?;
            let password = match password {
                Some(p) => p,
                None => rpassword::prompt_password("New backup password: ")?,
            };
            if password.is_empty() {
                anyhow::bail!("Password was empty — not enabling encryption.");
            }
            println!("Sending ChangePassword to the device — check it for a prompt if this hangs...");
            let working_dir = working_dir.unwrap_or_else(cradle_core::paths::default_working_dir);
            backup::set_encryption(&udid, &working_dir, None, Some(&password)).await?;
            keychain::store(&keychain::device_account(&udid), &password)?;
            println!(
                "Backup encryption is now on for {udid}. Password stored in the Keychain."
            );
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
    password_override: Option<String>,
) -> anyhow::Result<()> {
    let udid = resolve_udid(udid).await?;
    // See `restore`'s own `--password` doc: an explicit override here
    // works the same way, for the same reason (a backup made under an
    // older password than what's currently stored).
    let password = match password_override {
        Some(p) => p,
        None => keychain::try_read(&keychain::device_account(&udid))?.ok_or_else(|| {
            anyhow::anyhow!(
                "No stored backup password for {udid} — run `cradle password set --udid {udid}` \
                 first, or pass --password directly if it's changed since this backup was made."
            )
        })?,
    };

    let backup_dir = working_root.join(&udid);
    let keybag = Keybag::unlock_from_backup_dir(&backup_dir, &password)?;

    let encryption_key = hex::decode(encryption_key_hex.trim())
        .map_err(|e| anyhow::anyhow!("--encryption-key is not valid hex: {e}"))?;
    let mut buf = std::fs::read(backup_dir.join(&input))
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", input.display()))?;
    // Decrypted in place — see `Keybag::decrypt`'s doc for why this
    // doesn't allocate a second same-sized buffer for the plaintext.
    keybag.decrypt(&mut buf, &encryption_key)?;

    std::fs::write(&output, &buf).map_err(|e| anyhow::anyhow!("could not write {}: {e}", output.display()))?;
    println!(
        "Decrypted {} ({} bytes) to {}. Note: output may have trailing pad bytes past the \
         file's true size — see crypto.rs's `Keybag::decrypt` doc if that matters for this file.",
        input.display(),
        buf.len(),
        output.display()
    );
    Ok(())
}
