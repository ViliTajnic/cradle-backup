//! Prechecks: never start a transfer we already know will fail.
//!
//! Per CLAUDE.md, M0's share of this is pairing validity, backup encryption,
//! and free space on the working volume. Restore-only prechecks (Find My
//! off, target iOS >= backup iOS) land in M4 alongside restore itself.

use std::path::Path;

use idevice::{IdeviceError, mobilebackup2::FsBackupDelegate, provider::IdeviceProvider};

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

/// Result of running all M0 prechecks against one device.
#[derive(Debug, Clone)]
pub struct Report {
    pub pairing_valid: bool,
    pub pairing_message: Option<String>,
    pub encryption_enabled: bool,
    pub free_space_bytes: u64,
    pub free_space_ok: bool,
    pub device: Option<DeviceInfo>,
}

impl Report {
    /// `true` only if every check passed. A backup must not start otherwise.
    pub fn passed(&self) -> bool {
        self.pairing_valid && self.encryption_enabled && self.free_space_ok
    }
}

/// Runs every M0 precheck against `provider`, evaluating free space on the
/// volume backing `working_dir`.
pub async fn run(provider: &dyn IdeviceProvider, working_dir: &Path) -> Result<Report, CradleError> {
    let free_space_bytes = FsBackupDelegate.get_free_disk_space(working_dir);
    let free_space_ok = free_space_bytes >= MIN_FREE_BYTES;

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
                device,
            })
        }
        Err(e) => Ok(Report {
            pairing_valid: false,
            pairing_message: Some(pairing_error_message(&e)),
            encryption_enabled: false,
            free_space_bytes,
            free_space_ok,
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
