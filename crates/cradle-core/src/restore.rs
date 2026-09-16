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
///
/// The destination is a fresh directory every time, not a merge into
/// whatever a previous, possibly different-generation restore left behind
/// (CODEBASE_ANALYSIS.md: "Staging merges files into a persistent scratch
/// tree and leaves files that no longer exist in the source"), and is
/// rejected outright if it *is*, or sits inside, the source — copying a
/// directory into itself is not a staging bug worth discovering mid-copy.
///
/// Reports real progress through `progress` — a snapshot can be tens of
/// gigabytes moving from a slow external drive, and until this reported
/// anything, staging looked identical to a hung restore for as long as
/// the copy took (found via a real cross-device restore of a 48 GB
/// backup: ~18 minutes of a flat progress bar and "Staging backup for
/// restore..." with no other sign anything was happening).
pub async fn stage_from_working(
    working_root: &Path,
    source_udid: &str,
    scratch_dir: &Path,
    progress: Arc<dyn ProgressSink>,
) -> Result<PathBuf, CradleError> {
    let source = working_root.join(source_udid);
    if !source.is_dir() {
        return Err(CradleError::Other(format!(
            "no backup found at {} — run `cradle backup` first, or use --from-archive instead",
            source.display()
        )));
    }
    let dest = scratch_dir.join(source_udid);
    reject_overlapping_paths(&source, &dest)?;

    let (src, dst) = (source, dest.clone());
    tokio::task::spawn_blocking(move || {
        // A clean slate, not a merge: remove whatever a previous restore
        // (of this or a different snapshot) left staged here first.
        if dst.exists() {
            remove_dir_all_retrying(&dst)?;
        }
        let (_files_total, bytes_total) = dir_totals(&src)?;
        let mut bytes_done = 0u64;
        let mut files_done = 0u32;
        copy_dir(&src, &dst, progress.as_ref(), bytes_total, &mut bytes_done, &mut files_done)
    })
    .await
    .map_err(|e| CradleError::Other(format!("copy task panicked: {e}")))??;
    Ok(dest)
}

/// Total file count and byte size under `path`, walked up front so the
/// copy loop can report a real percentage instead of an indeterminate
/// spinner.
fn dir_totals(path: &Path) -> Result<(u64, u64), CradleError> {
    let mut files = 0u64;
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let (f, b) = dir_totals(&entry.path())?;
            files += f;
            bytes += b;
        } else {
            files += 1;
            bytes += entry.metadata()?.len();
        }
    }
    Ok((files, bytes))
}

/// Total on-disk size of a staged backup directory — the restore
/// precheck's own "how much room does the target device actually need"
/// number, computed from the *already-staged* copy (spun over from
/// [`stage_from_working`]/`archive::restore`'s own accounting) rather than
/// trusting a catalog `size` column that may be stale or belong to a
/// different snapshot than the one just staged.
pub fn staged_backup_size(staged_dir: &Path) -> Result<u64, CradleError> {
    let (_files, bytes) = dir_totals(staged_dir)?;
    Ok(bytes)
}

/// Resolves symlinks on whichever leading part of `path` already exists —
/// which may be none of it, for a scratch directory about to be created —
/// and re-appends the rest lexically, so overlap can be checked without
/// requiring `path` (or even its immediate parent) to exist yet.
fn resolve_existing_prefix(path: &Path) -> Result<PathBuf, CradleError> {
    let mut existing = path;
    let mut pending = Vec::new();
    while !existing.exists() {
        pending.push(existing.file_name().ok_or_else(|| {
            CradleError::Other(format!("path {} has no existing ancestor to resolve", path.display()))
        })?);
        existing = existing.parent().ok_or_else(|| {
            CradleError::Other(format!("path {} has no existing ancestor to resolve", path.display()))
        })?;
    }
    let mut resolved = std::fs::canonicalize(existing)?;
    resolved.extend(pending.into_iter().rev());
    Ok(resolved)
}

/// Refuses if `source` and `dest` are the same path, or either is nested
/// inside the other — including through a symlink alias, not just a
/// literal string prefix.
fn reject_overlapping_paths(source: &Path, dest: &Path) -> Result<(), CradleError> {
    let real_source = resolve_existing_prefix(source)?;
    let real_dest = resolve_existing_prefix(dest)?;

    if real_dest == real_source || real_dest.starts_with(&real_source) || real_source.starts_with(&real_dest) {
        return Err(CradleError::Other(format!(
            "restore staging destination {} overlaps with its source {} — refusing to copy a \
             directory into itself",
            dest.display(),
            source.display()
        )));
    }
    Ok(())
}

/// `std::fs::remove_dir_all` on macOS can fail with `ENOTEMPTY` (os error
/// 66) on a large tree when Spotlight or Finder briefly recreates an entry
/// (typically `.DS_Store`) inside a directory between its final readdir
/// and rmdir — confirmed on a real restore restaging a ~76,000-file
/// backup, large enough for the window to actually get hit in practice.
/// Nothing about the target changed on Cradle's side; retrying the whole
/// removal clears it without needing to know which entry reappeared.
fn remove_dir_all_retrying(path: &Path) -> std::io::Result<()> {
    const ATTEMPTS: u32 = 5;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);
    for attempt in 1..=ATTEMPTS {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(66) && attempt < ATTEMPTS => {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop always returns by the last attempt")
}

fn copy_dir(
    src: &Path,
    dst: &Path,
    progress: &dyn ProgressSink,
    bytes_total: u64,
    bytes_done: &mut u64,
    files_done: &mut u32,
) -> Result<(), CradleError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir(&entry.path(), &dst_path, progress, bytes_total, bytes_done, files_done)?;
        } else if file_type.is_file() {
            *bytes_done += std::fs::copy(entry.path(), &dst_path)?;
            *files_done += 1;
            let overall_progress = if bytes_total > 0 {
                (*bytes_done as f64 / bytes_total as f64) * 100.0
            } else {
                -1.0
            };
            progress.on_progress(*bytes_done, bytes_total, overall_progress);
            progress.on_file(&entry.file_name().to_string_lossy(), *files_done);
        }
    }
    Ok(())
}

/// The UDID a staged backup directory was originally taken from — its own
/// directory name, which both [`stage_from_working`] and
/// [`crate::archive::restore`] preserve (`archive::restore`'s summary path
/// resolves to `scratch_dir.join(<original absolute path>)`, whose last
/// component is the source UDID exactly the same way).
///
/// Authoritative over any caller-supplied `--source-udid` guess: a
/// frontend that defaults an unset "source" field to the *target* device
/// (the common case — most restores are a device restoring its own
/// backup) would otherwise send the wrong identifier to `idevicebackup2
/// restore -s` and look up the wrong device's stored password whenever
/// the actual source differs, e.g. every `--from-archive` restore where
/// `--source-udid` wasn't also given. `None` only if `staged_dir` is
/// somehow rootless (`/`), which neither staging path ever produces.
pub fn source_udid_from_staged_dir(staged_dir: &Path) -> Option<String> {
    staged_dir.file_name()?.to_str().map(str::to_string)
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
    /// `idevicebackup2 restore --settings` — maps to the protocol's
    /// `RestorePreserveSettings = false`, meaning the target's own
    /// settings get *overwritten* by the backup's instead of preserved.
    ///
    /// Defaulted to `true` for one release this session, on the theory
    /// that restoring Wi-Fi from the backup would help a factory-reset
    /// target reach the App Store sooner for third-party app redownload.
    /// Reverted back to `false` after a real cross-device restore showed
    /// the actual cost: the fully-restored profile appeared for a moment
    /// after reboot, then reverted to a default/no-apps state — consistent
    /// with a documented community report of the same flag causing app
    /// restoration to fail outright, fixed there by dropping `--settings`
    /// in favor of `--system --no-reboot` instead. Overwriting the
    /// *target* device's own settings with a *different* device's appears
    /// to risk exactly the kind of activation/account-state mismatch
    /// CLAUDE.md's non-negotiable #1 can't tolerate any risk of — a
    /// restore that looks like it worked and then silently doesn't is
    /// worse than the slower app-redownload this was meant to fix.
    pub restore_settings: bool,
}

impl Default for RestoreConfig {
    fn default() -> Self {
        Self {
            reboot: true,
            system_files: false,
            restore_settings: false,
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
    if config.restore_settings {
        args.push("--settings");
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
    use crate::backup::NullProgress;

    #[tokio::test]
    async fn stage_from_working_copies_files_without_touching_source() {
        let base = std::env::temp_dir().join(format!("cradle-restore-test-{}", std::process::id()));
        let working_root = base.join("working");
        let scratch_root = base.join("scratch");
        let source = working_root.join("UDID123");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("Manifest.db"), b"fake manifest").unwrap();
        std::fs::write(source.join("sub").join("file.bin"), b"fake file").unwrap();

        let staged = stage_from_working(&working_root, "UDID123", &scratch_root, Arc::new(NullProgress))
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
    async fn stage_from_working_replaces_rather_than_merges_a_stale_scratch_dir() {
        let base = std::env::temp_dir().join(format!("cradle-restore-test-stale-{}", std::process::id()));
        let working_root = base.join("working");
        let scratch_root = base.join("scratch");
        let source = working_root.join("UDID123");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("Manifest.db"), b"current manifest").unwrap();

        // A previous restore's leftovers: a file the *current* source no
        // longer has at all.
        let stale_dest = scratch_root.join("UDID123");
        std::fs::create_dir_all(&stale_dest).unwrap();
        std::fs::write(stale_dest.join("stale-leftover.bin"), b"old").unwrap();

        let staged = stage_from_working(&working_root, "UDID123", &scratch_root, Arc::new(NullProgress))
            .await
            .unwrap();

        assert!(staged.join("Manifest.db").is_file());
        assert!(
            !staged.join("stale-leftover.bin").exists(),
            "staging must not leave files from a previous, different-generation copy behind"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn stage_from_working_rejects_a_scratch_dir_nested_inside_the_source() {
        let base = std::env::temp_dir().join(format!("cradle-restore-test-nested-{}", std::process::id()));
        let working_root = base.join("working");
        let source = working_root.join("UDID123");
        std::fs::create_dir_all(&source).unwrap();

        // Scratch nested *inside* the working set's own UDID directory.
        let nested_scratch = source.join("scratch");

        let err = stage_from_working(&working_root, "UDID123", &nested_scratch, Arc::new(NullProgress))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("overlaps with its source"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn stage_from_working_errors_clearly_when_source_missing() {
        let base = std::env::temp_dir().join(format!("cradle-restore-test-missing-{}", std::process::id()));
        let err = stage_from_working(&base.join("working"), "NOPE", &base.join("scratch"), Arc::new(NullProgress))
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

    #[test]
    fn source_udid_is_read_from_the_staged_directorys_own_name() {
        let staged = PathBuf::from("/tmp/cradle-scratch/UDID-ABC-123");
        assert_eq!(source_udid_from_staged_dir(&staged), Some("UDID-ABC-123".to_string()));
    }

    #[test]
    fn source_udid_matches_what_archive_restore_actually_produces() {
        // Mirrors `archive::restore`'s own path construction: scratch_dir
        // joined with the snapshot's original absolute path.
        let staged = PathBuf::from("/scratch").join("Users/vili/Library/Application Support/Cradle/working/REAL-SOURCE-UDID");
        assert_eq!(
            source_udid_from_staged_dir(&staged),
            Some("REAL-SOURCE-UDID".to_string())
        );
    }
}
