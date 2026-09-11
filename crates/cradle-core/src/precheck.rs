//! Prechecks: never start a transfer we already know will fail.
//!
//! Per CLAUDE.md, M0's share of this is pairing validity, backup encryption,
//! and free space on the working volume. Restore-only prechecks (Find My
//! off, target iOS >= backup iOS) land in M4 alongside restore itself.

use std::path::Path;

use idevice::{
    IdeviceError,
    mobilebackup2::{BackupDelegate, FsBackupDelegate},
    provider::IdeviceProvider,
};

use crate::CradleError;
use crate::device::{self, DeviceInfo};

/// Conservative floor for "enough free space to safely start a backup".
///
/// MobileBackup2 doesn't expose the size of the pending backup before the
/// transfer begins — the device streams files without ever declaring a
/// total. So this is a sanity floor, not a precise sizing check; a backup
/// can still run out of space mid-transfer on a nearly-full disk. Getting a
/// tighter bound would mean estimating from the previous snapshot's size
/// once the catalog exists (M2/M3).
pub const MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Conservative floor for "enough free memory to survive a multi-hour
/// backup without a host-side I/O error" (MBErrorDomain 104). Confirmed
/// against a real device — see [`crate::memory`]'s module doc — that this
/// error hit repeatedly, every time free memory was under ~150MB. 1 GiB
/// gives real headroom above that observed failure point without being an
/// unreasonable bar on a modern Mac.
pub const MIN_FREE_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;

/// Result of running all M0 prechecks against one device.
#[derive(Debug, Clone)]
pub struct Report {
    pub pairing_valid: bool,
    pub pairing_message: Option<String>,
    pub encryption_enabled: bool,
    pub free_space_bytes: u64,
    pub free_space_ok: bool,
    /// `None` when free memory couldn't be measured (non-macOS, or
    /// `vm_stat` unavailable) — [`Self::free_memory_ok`] treats that as
    /// passing rather than blocking on an unmeasurable condition.
    pub free_memory_bytes: Option<u64>,
    pub free_memory_ok: bool,
    pub device: Option<DeviceInfo>,
}

impl Report {
    /// `true` only if every check passed. A backup must not start otherwise.
    pub fn passed(&self) -> bool {
        self.pairing_valid && self.encryption_enabled && self.free_space_ok && self.free_memory_ok
    }
}

/// Runs every M0 precheck against `provider`, evaluating free space on the
/// volume backing `working_dir` and free memory on this Mac.
pub async fn run(provider: &dyn IdeviceProvider, working_dir: &Path) -> Result<Report, CradleError> {
    let free_space_bytes = FsBackupDelegate.get_free_disk_space(working_dir);
    let free_space_ok = free_space_bytes >= MIN_FREE_BYTES;
    let free_memory_bytes = crate::memory::free_bytes();
    let free_memory_ok = free_memory_bytes
        .map(|bytes| bytes >= MIN_FREE_MEMORY_BYTES)
        .unwrap_or(true);

    match device::lockdown_session(provider).await {
        Ok(mut lockdown) => {
            let device = device::info(&mut lockdown).await.ok();
            let encryption_enabled = lockdown
                .get_value(Some("WillEncrypt"), Some("com.apple.mobile.backup"))
                .await
                .ok()
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);

            Ok(Report {
                pairing_valid: true,
                pairing_message: None,
                encryption_enabled,
                free_space_bytes,
                free_space_ok,
                free_memory_bytes,
                free_memory_ok,
                device,
            })
        }
        Err(e) => Ok(Report {
            pairing_valid: false,
            pairing_message: Some(pairing_error_message(&e)),
            encryption_enabled: false,
            free_space_bytes,
            free_space_ok,
            free_memory_bytes,
            free_memory_ok,
            device: None,
        }),
    }
}

/// Translates a lockdown failure into the fix, not the symptom — per
/// CLAUDE.md's error-message rule.
fn pairing_error_message(e: &IdeviceError) -> String {
    match e {
        IdeviceError::InvalidHostID => {
            "No pairing record for this device — open it once with Finder or Xcode, unlock the \
             device, and tap Trust."
                .to_string()
        }
        IdeviceError::SessionInactive => {
            "Pairing record is stale — unlock the device and tap Trust when prompted.".to_string()
        }
        other => format!("Pairing check failed: {other}"),
    }
}

/// Result of running the restore-only prechecks against the *target*
/// device. Per CLAUDE.md: "Restore only: Find My iPhone disabled on
/// target" / "Restore only: target iOS version >= backup's iOS version
/// (read `Product Version` from `Info.plist`)".
#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub pairing_valid: bool,
    pub pairing_message: Option<String>,
    pub find_my_disabled: bool,
    pub target_ios_version: Option<String>,
    pub backup_ios_version: String,
    pub target_ios_ok: bool,
    pub device: Option<DeviceInfo>,
}

impl RestoreReport {
    /// `true` only if every check passed. A restore must not start
    /// otherwise — CLAUDE.md's non-negotiable #1 makes restore free and
    /// unconditional, not unchecked.
    pub fn passed(&self) -> bool {
        self.pairing_valid && self.find_my_disabled && self.target_ios_ok
    }
}

/// Runs the restore-only prechecks against `provider` (the *target*
/// device restore will write to), comparing its iOS version against
/// `backup_ios_version` (read by the caller from the backup's own
/// `Info.plist` — see `restore.rs`).
pub async fn run_restore(
    provider: &dyn IdeviceProvider,
    backup_ios_version: &str,
) -> Result<RestoreReport, CradleError> {
    match device::lockdown_session(provider).await {
        Ok(mut lockdown) => {
            let device = device::info(&mut lockdown).await.ok();

            // Domain isn't in lockdownd's enumerable set but answers
            // GetValue queries anyway — same pattern as WillEncrypt above.
            // Confirmed against real-world usage reports (there is no
            // official Apple documentation for this domain): `IsAssociated`
            // is `true` when Find My is linked to an Apple ID on the
            // device. Defaults to the *stricter* assumption (associated)
            // if the query fails, since the failure mode of a false "off"
            // here is a bricked restore attempt on a Find My-locked device.
            let find_my_associated = lockdown
                .get_value(Some("IsAssociated"), Some("com.apple.fmip"))
                .await
                .ok()
                .and_then(|v| v.as_boolean())
                .unwrap_or(true);

            let target_ios_version = device.as_ref().map(|d| d.ios_version.clone());
            let target_ios_ok = target_ios_version
                .as_deref()
                .is_some_and(|target| ios_version_at_least(target, backup_ios_version));

            Ok(RestoreReport {
                pairing_valid: true,
                pairing_message: None,
                find_my_disabled: !find_my_associated,
                target_ios_version,
                backup_ios_version: backup_ios_version.to_string(),
                target_ios_ok,
                device,
            })
        }
        Err(e) => Ok(RestoreReport {
            pairing_valid: false,
            pairing_message: Some(pairing_error_message(&e)),
            find_my_disabled: false,
            target_ios_version: None,
            backup_ios_version: backup_ios_version.to_string(),
            target_ios_ok: false,
            device: None,
        }),
    }
}

/// Dotted-version comparison (`"26.6.1" >= "26.6"`), not string comparison
/// (`"9.0" < "10.0"` lexically fails as strings but must hold as
/// versions). Unparseable components read as 0.
fn ios_version_at_least(target: &str, backup: &str) -> bool {
    parse_version(target) >= parse_version(backup)
}

fn parse_version(v: &str) -> Vec<u32> {
    v.split('.').map(|part| part.parse().unwrap_or(0)).collect()
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn longer_prefix_beats_shorter() {
        assert!(ios_version_at_least("26.6.1", "26.6"));
        assert!(!ios_version_at_least("26.6", "26.6.1"));
    }

    #[test]
    fn numeric_not_lexical() {
        assert!(ios_version_at_least("10.0", "9.0"));
        assert!(!ios_version_at_least("9.0", "10.0"));
    }

    #[test]
    fn equal_versions_pass() {
        assert!(ios_version_at_least("18.1.2", "18.1.2"));
    }
}
