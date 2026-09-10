//! Cradle CLI — M0: connect, precheck, back up with a real progress line.
//!
//! Per CLAUDE.md, the CLI is not a debug tool: it ships, it is supported,
//! and it is the free tier's complete interface.

mod progress;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use cradle_core::{backup, device, precheck};

use progress::{TerminalProgress, human_bytes};

#[derive(Parser)]
#[command(name = "cradle", version, about = "Backup and restore for iPhone and iPad.")]
struct Cli {
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Devices => run_devices().await,
        Command::Backup {
            udid,
            working_dir,
            full,
        } => run_backup(udid, working_dir, full).await,
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

async fn run_backup(udid: Option<String>, working_root: PathBuf, full: bool) -> anyhow::Result<()> {
    let udid = resolve_udid(udid).await?;
    let provider = device::provider_for(&udid).await?;

    println!("Running prechecks...");
    let report = precheck::run(&*provider, &working_root).await?;

    if let Some(info) = &report.device {
        println!(
            "Device: {} ({}, iOS {})",
            info.name, info.product_type, info.ios_version
        );
    }

    if !report.pairing_valid {
        anyhow::bail!(report
            .pairing_message
            .unwrap_or_else(|| "Pairing check failed.".to_string()));
    }
    if !report.encryption_enabled {
        anyhow::bail!(
            "Backup encryption is off on this device. Enable it under Settings > General > \
             Transfer or Reset iPhone > Encrypted Backup (or via Finder) before continuing — \
             without it, Keychain, Health, call history and saved passwords are silently \
             omitted from the backup."
        );
    }
    if !report.free_space_ok {
        anyhow::bail!(
            "Only {} free on the working volume; want at least {} before starting a backup.",
            human_bytes(report.free_space_bytes),
            human_bytes(precheck::MIN_FREE_BYTES),
        );
    }

    println!("Prechecks passed. Backing up into {}...", working_root.display());

    let progress = Arc::new(TerminalProgress::new());
    let outcome = backup::run(&*provider, &working_root, full, progress.clone()).await?;
    progress.finish();

    println!("Backup complete: {}", outcome.backup_dir.display());
    Ok(())
}
