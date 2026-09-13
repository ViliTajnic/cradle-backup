//! Device discovery.
//!
//! Everything here shells out to `libimobiledevice`'s CLI tools (see
//! [`crate::libimobiledevice`]) — `idevice_id` for `usbmuxd`, `ideviceinfo`
//! for `lockdownd`. It does not touch the backup protocol — that lives in
//! [`crate::backup`].

use crate::CradleError;
use crate::libimobiledevice;

pub use libimobiledevice::{AttachedDevice, DeviceInfo, Transport};

/// Lists every device `usbmuxd` currently sees, USB or Wi-Fi sync.
pub async fn list() -> Result<Vec<AttachedDevice>, CradleError> {
    libimobiledevice::list_devices().await
}

/// Reads the handful of lockdown values Cradle needs to identify and
/// display a device.
pub async fn info(udid: &str) -> Result<DeviceInfo, CradleError> {
    libimobiledevice::device_info(udid).await
}
