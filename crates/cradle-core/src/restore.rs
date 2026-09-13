//! Restores a backup onto a device.
//!
//! Per CLAUDE.md's non-negotiable #1: "Restore is free, unconditional,
//! forever. No license check, no network call, no tier gate anywhere on
//! the restore path." Nothing in this module touches licensing or makes a
//! network call beyond the device/restic protocols it already needs.
//!
//! Per the architecture: "Restore copies a snapshot into a scratch
//! directory and runs the restore protocol from there. It does not touch
//! the working set." [`stage_from_working`] only ever *reads* from
//! `working/<UDID>/`; [`run`] only ever touches the scratch directory it's
//! given, never the working set.
//!
//! The restore protocol itself is driven by `idevicebackup2 restore` (see
//! [`crate::libimobiledevice`]) as a subprocess — see `backup.rs`'s module
//! doc for why this replaced the `idevice` Rust crate.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::CradleError;
use crate::backup::ProgressSink;
use crate::libimobiledevice;

/// Copies `working_root.join(source_udid)` into `scratch_dir`, leaving the
/// source untouched — the "backup is still on this machine" path, no
/// restic involved. Returns the path [`run`] should be pointed at
/// (`scratch_dir.join(source_udid)`).
pub async fn stage_from_working(
    working_root: &Path,
    source_udid: &str,
    scratch_dir: &Path,
) -> Result<PathBuf, CradleError> {
    let source = working_root.join(source_udid);
    if !source.is_dir() {
        return Err(CradleError::Other(format!(
            "no backup found at {} — run `cradle backup` first, or use --from-archive instead",
            source.display()
        )));
    }
    let dest = scratch_dir.join(source_udid);
    let (src, dst) = (source, dest.clone());
    tokio::task::spawn_blocking(move || copy_dir(&src, &dst))
        .await
        .map_err(|e| CradleError::Other(format!("copy task panicked: {e}")))??;
    Ok(dest)
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), CradleError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

/// Reads the backup's own recorded iOS version from its `Info.plist`
/// (the `"Product Version"` key — CLAUDE.md is explicit about this being
/// the source of truth for the restore precheck: the *backup's* version,
/// not whatever the original source device happens to be running now).
pub fn backup_ios_version(staged_dir: &Path) -> Result<String, CradleError> {
    let value = plist::Value::from_file(staged_dir.join("Info.plist"))
        .map_err(|e| CradleError::Other(format!("could not read Info.plist: {e}")))?;
    value
        .as_dictionary()
        .and_then(|d| d.get("Product Version"))
        .and_then(|v| v.as_string())
        .map(str::to_string)
        .ok_or_else(|| CradleError::Other("Info.plist has no \"Product Version\" key".into()))
}

/// Restore configuration — a thin, Cradle-flavored subset of
/// `idevicebackup2 restore`'s own flags. Deliberately not everything that
/// tool exposes: CLAUDE.md is explicit that selective restore isn't
/// happening, and the remaining flags don't have a meaningful default
/// worth exposing yet.
#[derive(Debug, Clone)]
pub struct RestoreConfig {
    pub reboot: bool,
    pub system_files: bool,
}

impl Default for RestoreConfig {
    fn default() -> Self {
        Self {
            reboot: true,
            system_files: false,
        }
    }
}

/// The outcome of a restore run.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub target_udid: String,
}

/// Runs the MobileBackup2 restore protocol against the device identified by
/// `target_udid`, reading from `staged_dir` — already staged in a scratch
/// directory by [`stage_from_working`] or `archive::restore`, never
/// `working/<UDID>/` directly.
///
/// `source_udid` is the UDID the backup was originally taken from, which
/// may differ from the target device's own UDID — that's cross-device
/// migration (`ROADMAP.md` M4: "Cross-device migration via
/// `source_identifier`"). `staged_dir`'s *parent* becomes the backup
/// root passed to the protocol, since it expects `backup_root/<source_udid>/`
/// to exist underneath it — the same convention [`crate::backup::run`]
/// writes into, which both staging functions preserve.
///
/// `password`, if the backup is encrypted, is the *source* backup's own
/// password (the one `cradle password set`/`enable` stored for
/// `source_udid`) — `idevicebackup2 restore` needs it to decrypt files as
/// it writes them, and refuses outright ("a backup password is required
/// to restore an encrypted backup") without it. Passed via the
/// `BACKUP_PASSWORD` environment variable, never a CLI argument, so it
/// never shows up in `ps` or shell history.
pub async fn run(
    target_udid: &str,
    staged_dir: &Path,
    source_udid: &str,
    config: &RestoreConfig,
    password: Option<&str>,
    progress: Arc<dyn ProgressSink>,
) -> Result<Outcome, CradleError> {
    let backup_root = staged_dir.parent().ok_or_else(|| {
        CradleError::Other(format!(
            "staged directory {} has no parent directory — expected <root>/{source_udid}",
            staged_dir.display()
        ))
    })?;
    let dir = backup_root
        .to_str()
        .ok_or_else(|| CradleError::Other(format!("backup root {} is not valid UTF-8", backup_root.display())))?;

    let mut args = vec!["-u", target_udid, "-s", source_udid, "restore"];
    if config.system_files {
        args.push("--system");
    }
    if !config.reboot {
        args.push("--no-reboot");
    }
    args.push(dir);

    let env: Vec<(&str, &str)> = password.map(|p| ("BACKUP_PASSWORD", p)).into_iter().collect();
    let result = libimobiledevice::run_idevicebackup2(&args, &env, progress).await;
    result.outcome?;

    Ok(Outcome {
        target_udid: target_udid.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stage_from_working_copies_files_without_touching_source() {
        let base = std::env::temp_dir().join(format!("cradle-restore-test-{}", std::process::id()));
        let working_root = base.join("working");
        let scratch_root = base.join("scratch");
        let source = working_root.join("UDID123");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("Manifest.db"), b"fake manifest").unwrap();
        std::fs::write(source.join("sub").join("file.bin"), b"fake file").unwrap();

        let staged = stage_from_working(&working_root, "UDID123", &scratch_root)
            .await
            .unwrap();

        assert_eq!(staged, scratch_root.join("UDID123"));
        assert!(staged.join("Manifest.db").is_file());
        assert!(staged.join("sub").join("file.bin").is_file());
        // Source untouched.
        assert!(source.join("Manifest.db").is_file());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn stage_from_working_errors_clearly_when_source_missing() {
        let base = std::env::temp_dir().join(format!("cradle-restore-test-missing-{}", std::process::id()));
        let err = stage_from_working(&base.join("working"), "NOPE", &base.join("scratch"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cradle backup"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn backup_ios_version_reads_product_version() {
        let base = std::env::temp_dir().join(format!("cradle-restore-plist-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "Product Version".to_string(),
            plist::Value::String("18.1".to_string()),
        );
        plist::Value::Dictionary(dict)
            .to_file_xml(base.join("Info.plist"))
            .unwrap();

        assert_eq!(backup_ios_version(&base).unwrap(), "18.1");
        let _ = std::fs::remove_dir_all(&base);
    }
}
