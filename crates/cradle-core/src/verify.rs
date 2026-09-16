//! The verification gate: runs after every backup, before any archive.
//!
//! Per CLAUDE.md, all three must pass or the run is marked failed and
//! nothing gets archived:
//!
//! 1. `Status.plist` reports the run finished
//! 2. `Manifest.db` opens and passes `PRAGMA integrity_check`
//! 3. File count matches the manifest
//!
//! [`Outcome`] makes the actual three-way result explicit instead of a
//! single pass/fail bit: [`Outcome::Verified`] means checks 1-3 all ran
//! for real and passed; [`Outcome::NeedsPassword`] means the run looks
//! structurally complete but no backup password was available to decrypt
//! `Manifest.db`, so checks 2 and 3 could not run at all — this is not a
//! failure of the backup, but it must never be treated as archivable
//! either, since nothing has actually confirmed the payload; only
//! [`Outcome::Invalid`] is a real, named problem. Collapsing
//! `NeedsPassword` into either "passed" or "failed" was exactly the gap
//! that let an unconfirmed manifest reach the archive step looking safe.
//!
//! Check 3 enumerates the manifest's own `Files` table (the device's
//! authoritative list of what this snapshot should contain) and checks
//! each entry's on-disk path directly, rather than comparing aggregate
//! counts with a tolerance band — a missing file is named as itself, not
//! absorbed into a fudge factor.

use std::collections::HashSet;
use std::path::Path;

use crate::CradleError;

/// The gate's three-way result. Only [`Outcome::Verified`] means the
/// snapshot is safe to archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Verified,
    /// Structurally complete, but `Manifest.db` was never actually opened
    /// — no backup password was available. Distinct from `Invalid`: nothing
    /// here says the backup is bad, only that nothing has confirmed it's
    /// good.
    NeedsPassword,
    Invalid,
}

/// Result of running the verification gate against one backup directory.
#[derive(Debug, Clone)]
pub struct Report {
    pub outcome: Outcome,
    pub status_finished: bool,
    /// `true` only when `Manifest.db` was actually decrypted (or, for an
    /// unencrypted backup, opened directly) and put through `PRAGMA
    /// integrity_check` — as opposed to `NeedsPassword`, where none of
    /// that ran.
    pub manifest_integrity_checked: bool,
    /// Regular files [`Manifest.db`]'s `Files` table lists for this
    /// snapshot. `None` when the manifest was never opened (`NeedsPassword`).
    pub files_expected: Option<u64>,
    /// How many of `files_expected` have no corresponding file on disk.
    /// Always `0` when `files_expected` is `None`.
    pub files_missing: u64,
    /// Every regular file actually found under `backup_dir`, from the same
    /// walk that produced `total_bytes` — includes `idevicebackup2`'s own
    /// bookkeeping files at the backup root, unlike `files_expected`.
    pub files_on_disk: u64,
    /// What this run's transfer reported receiving — informational only.
    /// An incremental run's count is only a fraction of `files_on_disk`
    /// (the rest carried over from before), so this cannot itself gate
    /// pass/fail; confirmed against a real incremental run: 52 files
    /// transferred, 20,388 files in the resulting snapshot on disk.
    pub files_reported: u64,
    /// Total bytes of every file under `backup_dir` — the on-disk size of
    /// the *snapshot*, not bytes transferred this run. Feeds
    /// `catalog::Catalog::record_snapshot`'s `size` column.
    pub total_bytes: u64,
    /// Human-readable reasons behind a non-`Verified` outcome, built once
    /// here so callers don't each re-derive the same wording.
    pub problems: Vec<String>,
}

impl Report {
    /// `true` only for [`Outcome::Verified`]. CLAUDE.md: failure marks the
    /// run failed and archives nothing — callers must not archive past
    /// anything else, `NeedsPassword` included.
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Verified
    }
}

/// Runs the verification gate against `backup_dir` (a `working/<UDID>/`
/// snapshot). `files_reported` is [`crate::backup::Outcome::files_received`]
/// from the run that just finished, purely for display — see [`Report`]'s
/// doc. `password`, if given, unlocks the real `Manifest.db` check for an
/// encrypted backup.
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

/// What check 2/3 found, before it's turned into an [`Outcome`] and
/// problem strings.
enum ManifestCheck {
    /// Backup is encrypted and no password was supplied — checks 2 and 3
    /// did not run.
    NeedsPassword,
    /// The manifest could not be trusted: wrong password, unreadable
    /// file, or a failed `PRAGMA integrity_check`.
    Failed(String),
    /// Opened and passed `PRAGMA integrity_check`; carries every regular
    /// file id it lists for check 3.
    Ok(Vec<String>),
}

fn run_blocking(backup_dir: &Path, files_reported: u64, password: Option<&str>) -> Result<Report, CradleError> {
    let mut problems = Vec::new();

    let status_finished = status_finished(backup_dir);
    if !status_finished {
        problems.push(
            "Status.plist does not report a finished snapshot — the device may have cancelled \
             or the transfer was interrupted."
                .to_string(),
        );
    }

    let (files_on_disk, total_bytes) = scan_backup_dir(backup_dir)?;
    let encrypted = backup_is_encrypted(backup_dir);
    let manifest_check = check_manifest(backup_dir, encrypted, password);

    let (manifest_integrity_checked, files_expected, files_missing) = match &manifest_check {
        ManifestCheck::NeedsPassword => (false, None, 0),
        ManifestCheck::Failed(reason) => {
            problems.push(reason.clone());
            (true, None, 0)
        }
        ManifestCheck::Ok(file_ids) => {
            let missing = missing_payload_files(backup_dir, file_ids);
            if missing > 0 {
                problems.push(format!(
                    "{missing} of {} file(s) listed in Manifest.db are missing on disk.",
                    file_ids.len()
                ));
            }
            (true, Some(file_ids.len() as u64), missing)
        }
    };

    let outcome = if !status_finished {
        Outcome::Invalid
    } else {
        match &manifest_check {
            ManifestCheck::NeedsPassword => Outcome::NeedsPassword,
            ManifestCheck::Failed(_) => Outcome::Invalid,
            ManifestCheck::Ok(_) if files_missing > 0 => Outcome::Invalid,
            ManifestCheck::Ok(_) => Outcome::Verified,
        }
    };

    Ok(Report {
        outcome,
        status_finished,
        manifest_integrity_checked,
        files_expected,
        files_missing,
        files_on_disk,
        files_reported,
        total_bytes,
        problems,
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

/// Checks 2 and 3's dispatcher. An unencrypted `Manifest.db` is plain
/// SQLite and needs no password at all to check for real — only an
/// encrypted one without a supplied password falls back to
/// [`ManifestCheck::NeedsPassword`].
fn check_manifest(backup_dir: &Path, encrypted: bool, password: Option<&str>) -> ManifestCheck {
    if !encrypted {
        return match open_plain_manifest(backup_dir) {
            Ok(conn) => run_integrity_and_list_files(&conn),
            Err(e) => ManifestCheck::Failed(e.to_string()),
        };
    }
    let Some(password) = password else {
        return ManifestCheck::NeedsPassword;
    };
    match decrypt_manifest(backup_dir, password) {
        Ok(temp) => match rusqlite::Connection::open(&temp.0) {
            Ok(conn) => run_integrity_and_list_files(&conn),
            Err(e) => ManifestCheck::Failed(format!("could not open decrypted Manifest.db: {e}")),
        },
        Err(e) => ManifestCheck::Failed(e.to_string()),
    }
}

fn open_plain_manifest(backup_dir: &Path) -> Result<rusqlite::Connection, CradleError> {
    let path = backup_dir.join("Manifest.db");
    if !path.is_file() {
        return Err(CradleError::Other(
            "Manifest.db is missing — the backup did not arrive intact.".into(),
        ));
    }
    rusqlite::Connection::open(&path).map_err(CradleError::from)
}

/// Runs `PRAGMA integrity_check` and, if that passes, lists every regular
/// file (`flags = 1` — the standard MobileBackup2 schema shared by every
/// tool that reads it) for check 3.
fn run_integrity_and_list_files(conn: &rusqlite::Connection) -> ManifestCheck {
    let integrity: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0));
    match integrity {
        Ok(result) if result == "ok" => {}
        Ok(result) => return ManifestCheck::Failed(format!("Manifest.db failed integrity check: {result}")),
        Err(e) => return ManifestCheck::Failed(format!("could not run integrity check on Manifest.db: {e}")),
    }

    let mut stmt = match conn.prepare("SELECT fileID FROM Files WHERE flags = 1") {
        Ok(stmt) => stmt,
        Err(e) => return ManifestCheck::Failed(format!("could not read Manifest.db's Files table: {e}")),
    };
    let file_ids: Result<Vec<String>, _> =
        stmt.query_map([], |row| row.get::<_, String>(0)).and_then(Iterator::collect);
    match file_ids {
        Ok(ids) => ManifestCheck::Ok(ids),
        Err(e) => ManifestCheck::Failed(format!("could not read Manifest.db's Files table: {e}")),
    }
}

/// Decrypts `Manifest.db` with the keybag unlocked by `password` and
/// writes it to a private (0600 on Unix) temp file, removed on every exit
/// path via [`TempManifestFile`]'s `Drop` — a decrypted backup manifest
/// (Keychain/Health/message metadata) sitting in `/tmp` any longer than it
/// has to is exactly the kind of thing non-negotiable #2 exists to avoid.
fn decrypt_manifest(backup_dir: &Path, password: &str) -> Result<TempManifestFile, CradleError> {
    let manifest_plist = plist::Value::from_file(backup_dir.join("Manifest.plist"))
        .map_err(|e| CradleError::Other(format!("could not read Manifest.plist: {e}")))?;
    let manifest_key = manifest_plist
        .as_dictionary()
        .and_then(|d| d.get("ManifestKey"))
        .and_then(|v| v.as_data())
        .ok_or_else(|| CradleError::Other("Manifest.plist has no ManifestKey".into()))?;

    let keybag = crate::crypto::Keybag::unlock_from_backup_dir(backup_dir, password)?;
    let mut buf = std::fs::read(backup_dir.join("Manifest.db"))?;
    keybag.decrypt(&mut buf, manifest_key)?;
    TempManifestFile::write(&buf)
}

/// Check 3: how many of `file_ids` have no file at their expected on-disk
/// path (`<fileID[0:2]>/<fileID>`, relative to `backup_dir` — the standard
/// MobileBackup2 fan-out layout).
fn missing_payload_files(backup_dir: &Path, file_ids: &[String]) -> u64 {
    file_ids
        .iter()
        .filter(|id| match id.get(0..2) {
            Some(prefix) => !backup_dir.join(prefix).join(id.as_str()).is_file(),
            None => true, // malformed id from a corrupt manifest row: treat as missing
        })
        .count() as u64
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

/// Check 3's disk side (reduced-scope fallback verification's byte total
/// too): counts every regular file under `backup_dir`, recursively, and
/// sums their sizes along the way.
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

/// Distinct on-disk file ids under `backup_dir`'s two-character fan-out
/// directories — exposed for [`crate::archive`]'s pre-archive re-check,
/// which needs to know not just "does the manifest's list of ids exist"
/// but whether the directory has changed at all since a prior look.
pub fn on_disk_file_ids(backup_dir: &Path) -> Result<HashSet<String>, CradleError> {
    let mut ids = HashSet::new();
    let entries = match std::fs::read_dir(backup_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.file_name().len() == 2 {
            for file in std::fs::read_dir(entry.path())? {
                let file = file?;
                if file.file_type()?.is_file()
                    && let Some(name) = file.file_name().to_str()
                {
                    ids.insert(name.to_string());
                }
            }
        }
    }
    Ok(ids)
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cradle-verify-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_status_finished(dir: &Path) {
        std::fs::write(
            dir.join("Status.plist"),
            r#"<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>SnapshotState</key><string>finished</string></dict></plist>"#,
        )
        .unwrap();
    }

    fn write_unencrypted_manifest_plist(dir: &Path) {
        std::fs::write(
            dir.join("Manifest.plist"),
            r#"<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>IsEncrypted</key><false/></dict></plist>"#,
        )
        .unwrap();
    }

    fn write_plain_manifest_db(dir: &Path, file_ids: &[&str]) {
        write_unencrypted_manifest_plist(dir);
        let conn = rusqlite::Connection::open(dir.join("Manifest.db")).unwrap();
        conn.execute_batch("CREATE TABLE Files (fileID TEXT, flags INTEGER)").unwrap();
        for id in file_ids {
            conn.execute("INSERT INTO Files (fileID, flags) VALUES (?1, 1)", rusqlite::params![id])
                .unwrap();
        }
    }

    fn write_payload_file(dir: &Path, file_id: &str) {
        let sub = dir.join(&file_id[0..2]);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(file_id), b"payload").unwrap();
    }

    #[tokio::test]
    async fn unencrypted_backup_with_every_file_present_is_verified() {
        let dir = temp_dir("verified");
        write_status_finished(&dir);
        write_plain_manifest_db(&dir, &["aa11", "bb22"]);
        write_payload_file(&dir, "aa11");
        write_payload_file(&dir, "bb22");

        let report = run(&dir, 2, None).await.unwrap();
        assert_eq!(report.outcome, Outcome::Verified);
        assert!(report.manifest_integrity_checked);
        assert_eq!(report.files_missing, 0);
        assert_eq!(report.files_expected, Some(2));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unencrypted_backup_missing_a_payload_file_is_invalid() {
        let dir = temp_dir("missing-payload");
        write_status_finished(&dir);
        write_plain_manifest_db(&dir, &["aa11", "bb22"]);
        write_payload_file(&dir, "aa11"); // bb22 never written

        let report = run(&dir, 2, None).await.unwrap();
        assert_eq!(report.outcome, Outcome::Invalid);
        assert_eq!(report.files_missing, 1);
        assert!(report.problems.iter().any(|p| p.contains("missing on disk")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unfinished_status_is_invalid_even_with_a_perfect_manifest() {
        let dir = temp_dir("unfinished");
        // No Status.plist at all — the interrupted-transfer case.
        write_plain_manifest_db(&dir, &["aa11"]);
        write_payload_file(&dir, "aa11");

        let report = run(&dir, 1, None).await.unwrap();
        assert_eq!(report.outcome, Outcome::Invalid);
        assert!(!report.status_finished);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn encrypted_backup_without_a_password_needs_one_rather_than_passing() {
        let dir = temp_dir("needs-password");
        write_status_finished(&dir);
        std::fs::write(
            dir.join("Manifest.plist"),
            r#"<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>IsEncrypted</key><true/></dict></plist>"#,
        )
        .unwrap();
        std::fs::write(dir.join("Manifest.db"), [0u8; 32]).unwrap(); // block-aligned ciphertext-shaped filler

        let report = run(&dir, 1, None).await.unwrap();
        assert_eq!(report.outcome, Outcome::NeedsPassword);
        assert!(!report.manifest_integrity_checked);
        assert!(!report.passed());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_disk_file_ids_reads_the_fan_out_layout() {
        let dir = temp_dir("fanout-ids");
        write_payload_file(&dir, "aa112233");
        write_payload_file(&dir, "bb445566");

        let ids = on_disk_file_ids(&dir).unwrap();
        assert_eq!(ids, HashSet::from(["aa112233".to_string(), "bb445566".to_string()]));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
