//! The verification gate: runs after every backup, before any archive.
//!
//! Per CLAUDE.md, all three must pass or the run is marked failed and
//! nothing gets archived:
//!
//! 1. `Status.plist` reports the run finished
//! 2. `Manifest.db` opens and passes `PRAGMA integrity_check`
//! 3. File count matches the manifest
//!
//! **Gap against that spec, by design for now:** when backup encryption is
//! on — which non-negotiable #2 in CLAUDE.md requires for every backup
//! Cradle makes — `Manifest.db` is itself an AES-encrypted blob, not a
//! plain SQLite file. Decrypting it needs the `BackupKeyBag` /
//! PBKDF2 / class-key machinery scheduled for `ROADMAP.md` M5, four
//! milestones out. Until that lands:
//!
//! - Check 2 becomes: `Manifest.db` exists, is non-empty, and (for an
//!   encrypted backup) its ciphertext length is AES-block-aligned. That
//!   catches truncation and corruption but not row-level damage.
//! - Check 3 becomes: the number of files actually written to disk under
//!   the backup directory equals the number of files the device told the
//!   delegate it sent during *this run* — not a query against
//!   `Manifest.db`'s `Files` table, which isn't readable yet either.
//!
//! Both checks should be swapped for the literal spec once M5 exists —
//! search for `M5` in this file.

use std::path::Path;

use crate::CradleError;

/// AES-CBC block size backup file encryption uses.
const AES_BLOCK_SIZE: u64 = 16;

/// Result of running the verification gate against one backup directory.
#[derive(Debug, Clone)]
pub struct Report {
    pub status_finished: bool,
    pub manifest_present: bool,
    pub files_on_disk: u64,
    pub files_reported: u64,
    pub file_count_match: bool,
    /// Total bytes of every file under `backup_dir`, from the same walk
    /// that produced `files_on_disk`. This is the on-disk size of the
    /// *snapshot*, not bytes transferred this run — an incremental run
    /// moves far less than this over the wire. Feeds
    /// `catalog::Catalog::record_snapshot`'s `size` column.
    pub total_bytes: u64,
}

impl Report {
    /// `true` only if every check passed. CLAUDE.md: failure marks the run
    /// failed and archives nothing — callers must not proceed past a
    /// failing gate.
    pub fn passed(&self) -> bool {
        self.status_finished && self.manifest_present && self.file_count_match
    }
}

/// Runs the verification gate against `backup_dir` (a `working/<UDID>/`
/// snapshot). `files_reported` is [`crate::backup::Outcome::files_received`]
/// from the run that just finished.
pub async fn run(backup_dir: &Path, files_reported: u64) -> Result<Report, CradleError> {
    let dir = backup_dir.to_path_buf();
    tokio::task::spawn_blocking(move || run_blocking(&dir, files_reported))
        .await
        .map_err(|e| CradleError::Other(format!("verification gate task panicked: {e}")))?
}

fn run_blocking(backup_dir: &Path, files_reported: u64) -> Result<Report, CradleError> {
    let status_finished = status_finished(backup_dir);
    let encrypted = backup_is_encrypted(backup_dir);
    let manifest_present = manifest_db_present(backup_dir, encrypted);
    let (files_on_disk, total_bytes) = scan_backup_dir(backup_dir)?;
    let file_count_match = files_on_disk == files_reported;

    Ok(Report {
        status_finished,
        manifest_present,
        files_on_disk,
        files_reported,
        file_count_match,
        total_bytes,
    })
}

/// Check 1: `Status.plist`'s `SnapshotState` reads `"finished"`.
///
/// This is exactly what `idevicebackup2` itself checks before trusting a
/// backup directory enough to restore from it — same key, same value.
fn status_finished(backup_dir: &Path) -> bool {
    let Ok(value) = plist::Value::from_file(backup_dir.join("Status.plist")) else {
        return false;
    };
    value
        .as_dictionary()
        .and_then(|d| d.get("SnapshotState"))
        .and_then(|v| v.as_string())
        == Some("finished")
}

/// Reads `Manifest.plist`'s `IsEncrypted` flag. Defaults to `true` (the
/// stricter check) if the file can't be read, since every backup Cradle
/// makes is supposed to be encrypted per CLAUDE.md's non-negotiables.
fn backup_is_encrypted(backup_dir: &Path) -> bool {
    plist::Value::from_file(backup_dir.join("Manifest.plist"))
        .ok()
        .and_then(|v| {
            v.as_dictionary()
                .and_then(|d| d.get("IsEncrypted"))
                .and_then(|v| v.as_boolean())
        })
        .unwrap_or(true)
}

/// Check 2 (reduced scope — see module docs): `Manifest.db` exists, is
/// non-empty, and — for an encrypted backup — is AES-block-aligned.
///
/// # M5
/// Replace with: decrypt using the manifest key unwrapped from
/// `Manifest.plist`'s `BackupKeyBag`, open with `rusqlite`, run
/// `PRAGMA integrity_check`.
fn manifest_db_present(backup_dir: &Path, encrypted: bool) -> bool {
    let Ok(meta) = std::fs::metadata(backup_dir.join("Manifest.db")) else {
        return false;
    };
    if !meta.is_file() || meta.len() == 0 {
        return false;
    }
    !encrypted || meta.len() % AES_BLOCK_SIZE == 0
}

/// Check 3 (reduced scope — see module docs): counts every regular file
/// under `backup_dir`, recursively, and sums their sizes along the way —
/// one walk serving both the file-count check and the catalog's snapshot
/// size, rather than walking the tree twice.
///
/// # M5
/// Replace the count with `SELECT COUNT(*) FROM Files` against the
/// decrypted `Manifest.db`, which is the device's own authoritative
/// record — this walk only proves our delegate persisted everything it
/// was told about, not that the device's manifest agrees. The byte total
/// can stay a disk walk even then; nothing in the manifest replaces it.
fn scan_backup_dir(backup_dir: &Path) -> Result<(u64, u64), CradleError> {
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![backup_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                files += 1;
                bytes += entry.metadata()?.len();
            }
        }
    }

    Ok((files, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn scan_is_zero_for_missing_directory() {
        let missing = PathBuf::from("/does/not/exist/cradle-test");
        assert_eq!(scan_backup_dir(&missing).unwrap(), (0, 0));
    }
}
