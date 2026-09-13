//! The verification gate: runs after every backup, before any archive.
//!
//! Per CLAUDE.md, all three must pass or the run is marked failed and
//! nothing gets archived:
//!
//! 1. `Status.plist` reports the run finished
//! 2. `Manifest.db` opens and passes `PRAGMA integrity_check`
//! 3. File count matches the manifest
//!
//! Check 1 has always been the real thing. Checks 2 and 3 started
//! reduced-scope (M1) because backup encryption — required by
//! non-negotiable #2 — makes `Manifest.db` an AES-encrypted blob, not a
//! plain SQLite file, and decrypting it needed the `crypto` module M5
//! added. Check 2 is now the real thing too, *when a backup password is
//! available* (see [`run`]'s `password` parameter): decrypt `Manifest.db`
//! via [`crate::crypto::Keybag`] and run `PRAGMA integrity_check` on the
//! result. Without a password on hand, it falls back to the M1-era check
//! (ciphertext present, non-empty, AES-block-aligned) rather than forcing
//! an interactive prompt into the middle of a backup run — callers decide
//! whether to look one up first (see `keychain::try_read`).
//!
//! Check 3 is still reduced-scope: on-disk file count against what
//! `idevicebackup2` reported receiving, not a `SELECT COUNT(*) FROM Files`
//! against the manifest. Nothing blocks that upgrade now that
//! `Manifest.db` is readable — it just isn't built yet. It's also not
//! exact equality (see [`file_count_matches`]): confirmed against a real
//! device that "files received" can run a little ahead of distinct files
//! on disk, since MobileBackup2's storage is content-addressed and
//! identical-content files collapse into one on-disk file.

use std::path::Path;

use crate::CradleError;

/// AES-CBC block size backup file encryption uses.
const AES_BLOCK_SIZE: u64 = 16;

/// Result of running the verification gate against one backup directory.
#[derive(Debug, Clone)]
pub struct Report {
    pub status_finished: bool,
    pub manifest_present: bool,
    /// `true` if `manifest_present` reflects a real `PRAGMA
    /// integrity_check` on decrypted data, `false` if it's the reduced
    /// ciphertext-shape check (no password was available).
    pub manifest_integrity_checked: bool,
    pub files_on_disk: u64,
    pub files_reported: u64,
    /// What `files_on_disk` was actually checked against — the manifest's
    /// own `Files` count when the manifest could be read (accurate for
    /// both full and incremental runs), otherwise `files_reported` (only
    /// accurate for a full run). Distinct from `files_reported` so a
    /// mismatch message can name the number that was actually compared,
    /// not always the transfer count.
    pub files_expected: u64,
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
/// from the run that just finished. `password`, if given, unlocks the real
/// `Manifest.db` integrity check instead of the reduced ciphertext-shape
/// one — see the module doc.
pub async fn run(
    backup_dir: &Path,
    files_reported: u64,
    password: Option<&str>,
) -> Result<Report, CradleError> {
    let dir = backup_dir.to_path_buf();
    let password = password.map(str::to_string);
    tokio::task::spawn_blocking(move || run_blocking(&dir, files_reported, password.as_deref()))
        .await
        .map_err(|e| CradleError::Other(format!("verification gate task panicked: {e}")))?
}

fn run_blocking(
    backup_dir: &Path,
    files_reported: u64,
    password: Option<&str>,
) -> Result<Report, CradleError> {
    let status_finished = status_finished(backup_dir);
    let encrypted = backup_is_encrypted(backup_dir);
    let (manifest_present, manifest_integrity_checked, manifest_file_count) =
        manifest_db_ok(backup_dir, encrypted, password);
    let (files_on_disk, total_bytes) = scan_backup_dir(backup_dir)?;
    // Prefer the manifest's own file count when it's available (it always
    // reflects the *whole current snapshot*, full or incremental) over
    // `files_reported` (only what this run itself transferred — correct
    // for a full backup, meaningless for an incremental one, which by
    // design only sends changed files). Found necessary on a real
    // incremental run: 52 files transferred, 20,388 in the snapshot on
    // disk — comparing disk count against the transfer count alone can
    // never work for anything but a full backup.
    //
    // The manifest's `Files` table only tracks the device's own backed-up
    // content — not `idevicebackup2`'s own local bookkeeping files, which
    // `scan_backup_dir`'s disk walk does count since they're real regular
    // files sitting right there at the backup root. Confirmed against a
    // real, completely fresh single-shot backup: disk count ran exactly
    // `BACKUP_METADATA_FILES.len()` ahead of the manifest count, every
    // time, with nothing else going on.
    let files_expected = manifest_file_count
        .map(|n| n + count_present(backup_dir, &BACKUP_METADATA_FILES))
        .unwrap_or(files_reported);
    let file_count_match = file_count_matches(files_on_disk, files_expected);

    Ok(Report {
        status_finished,
        manifest_present,
        manifest_integrity_checked,
        files_on_disk,
        files_reported,
        files_expected,
        file_count_match,
        total_bytes,
    })
}

/// `idevicebackup2`'s own local bookkeeping files, written at the backup
/// root once the transfer finishes — real regular files `scan_backup_dir`
/// counts, but never part of the device's own manifest `Files` table
/// (checked directly against a real backup: not present there at all).
const BACKUP_METADATA_FILES: [&str; 4] = ["Status.plist", "Manifest.plist", "Manifest.db", "Info.plist"];

/// How many of `names` actually exist as files directly under `dir`.
fn count_present(dir: &Path, names: &[&str]) -> u64 {
    names.iter().filter(|name| dir.join(name).is_file()).count() as u64
}

/// How many fewer files [`file_count_matches`] tolerates seeing on disk
/// than expected before treating it as a real gap rather than dedup (see
/// that function's doc).
const MAX_DEDUP_SHORTFALL: u64 = 50;

/// Check 3's actual comparison. Not exact equality: confirmed against a
/// real device, with the bare `idevicebackup2` tool itself (not a
/// Cradle-specific quirk), that a reported/expected count can run a little
/// ahead of distinct files on disk — MobileBackup2's storage is content-
/// addressed by SHA1, so two device-side files with identical bytes
/// collapse into one file on disk even though the device reported both. A
/// real dropped-file problem shows up as a gap of hundreds or thousands,
/// not a handful, so [`MAX_DEDUP_SHORTFALL`] is deliberately generous
/// while still catching that. More files on disk than expected is never
/// dedup — that's stale contamination from a previous run — so it's not
/// tolerated at all.
fn file_count_matches(files_on_disk: u64, expected: u64) -> bool {
    files_on_disk <= expected && expected - files_on_disk <= MAX_DEDUP_SHORTFALL
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

/// Check 2's dispatcher: real `PRAGMA integrity_check` when `password` is
/// given and decryption succeeds, otherwise the reduced ciphertext-shape
/// check. Returns `(passed, was_real_check, manifest_file_count)` — the
/// third field is `Some` only when the manifest was actually opened, and
/// feeds check 3 (see [`run_blocking`]).
fn manifest_db_ok(backup_dir: &Path, encrypted: bool, password: Option<&str>) -> (bool, bool, Option<u64>) {
    if let Some(password) = password
        && encrypted
    {
        match real_manifest_integrity_check(backup_dir, password) {
            Ok((ok, file_count)) => return (ok, true, file_count),
            // A password that's present but wrong, or any other failure
            // decrypting, is a real gate failure — not a reason to fall
            // back to the weaker check, which could mask exactly that.
            Err(_) => return (false, true, None),
        }
    }
    (manifest_db_present(backup_dir, encrypted), false, None)
}

/// Check 2, reduced scope (see module docs): `Manifest.db` exists, is
/// non-empty, and — for an encrypted backup — is AES-block-aligned. Used
/// when no backup password is available to run the real check.
fn manifest_db_present(backup_dir: &Path, encrypted: bool) -> bool {
    let Ok(meta) = std::fs::metadata(backup_dir.join("Manifest.db")) else {
        return false;
    };
    if !meta.is_file() || meta.len() == 0 {
        return false;
    }
    !encrypted || meta.len() % AES_BLOCK_SIZE == 0
}

/// Check 2, real spec: decrypt `Manifest.db` with the keybag unlocked by
/// `password`, write it to a private (0600 on Unix) temp file, open with
/// `rusqlite`, and run `PRAGMA integrity_check`. The temp file is removed
/// on every exit path via [`TempManifestFile`]'s `Drop` — a decrypted
/// backup manifest (Keychain/Health/message metadata) sitting in `/tmp`
/// any longer than it has to is exactly the kind of thing non-negotiable
/// #2 exists to avoid.
///
/// Also reads the manifest's own file count (`Files` table, `flags = 1`
/// for a regular file — the standard MobileBackup2 schema shared by every
/// tool that reads it, not a Cradle-specific convention), since it's the
/// only accurate total for check 3 on an incremental run: `Files` always
/// lists the *whole current snapshot*, unlike `files_reported`, which is
/// only what this run itself transferred. `None` if the query fails for
/// any reason (e.g. an unexpected schema) — check 3 falls back to
/// `files_reported` rather than failing the gate over this alone.
fn real_manifest_integrity_check(backup_dir: &Path, password: &str) -> Result<(bool, Option<u64>), CradleError> {
    let manifest_plist = plist::Value::from_file(backup_dir.join("Manifest.plist"))
        .map_err(|e| CradleError::Other(format!("could not read Manifest.plist: {e}")))?;
    let manifest_key = manifest_plist
        .as_dictionary()
        .and_then(|d| d.get("ManifestKey"))
        .and_then(|v| v.as_data())
        .ok_or_else(|| CradleError::Other("Manifest.plist has no ManifestKey".into()))?;

    let keybag = crate::crypto::Keybag::unlock_from_backup_dir(backup_dir, password)?;
    let ciphertext = std::fs::read(backup_dir.join("Manifest.db"))?;
    let decrypted = keybag.decrypt(&ciphertext, manifest_key)?;

    let temp = TempManifestFile::write(&decrypted)?;
    let conn = rusqlite::Connection::open(&temp.0)?;
    let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let file_count = conn
        .query_row("SELECT COUNT(*) FROM Files WHERE flags = 1", [], |row| row.get::<_, i64>(0))
        .ok()
        .map(|n| n.max(0) as u64);
    Ok((result == "ok", file_count))
}

/// A decrypted `Manifest.db` written to a private temp file, deleted on
/// drop regardless of how the caller's function returns.
struct TempManifestFile(std::path::PathBuf);

impl TempManifestFile {
    fn write(decrypted: &[u8]) -> Result<Self, CradleError> {
        let path = std::env::temp_dir().join(format!(
            "cradle-manifest-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            std::io::Write::write_all(&mut file, decrypted)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, decrypted)?;
        }

        Ok(Self(path))
    }
}

impl Drop for TempManifestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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

    #[test]
    fn exact_match_passes() {
        assert!(file_count_matches(19066, 19066));
    }

    #[test]
    fn small_dedup_shortfall_passes() {
        // The real, confirmed case: idevicebackup2 itself reported 19068
        // received against 19066 distinct files on disk.
        assert!(file_count_matches(19066, 19068));
    }

    #[test]
    fn large_shortfall_fails() {
        assert!(!file_count_matches(100, 19068));
    }

    #[test]
    fn more_on_disk_than_reported_fails() {
        assert!(!file_count_matches(19068, 19066));
    }
}
