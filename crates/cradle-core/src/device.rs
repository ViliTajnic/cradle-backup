//! Device discovery and connection setup.
//!
//! Everything here talks to `usbmuxd` (present on macOS out of the box; on
//! Windows it needs Apple Devices / iTunes — see `/ROADMAP.md` M9) and to
//! `lockdownd` on the device itself. It does not touch the backup protocol —
//! that lives in [`crate::backup`].

use idevice::{
    IdeviceError, IdeviceService,
    lockdown::LockdownClient,
    provider::IdeviceProvider,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection},
};

use crate::CradleError;

/// Identifies this host to lockdownd / usbmuxd in place of a generic client name.
pub const LABEL: &str = "cradle";

/// How a device is currently attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Usb,
    Network,
    Unknown,
}

impl From<Connection> for Transport {
    fn from(connection: Connection) -> Self {
        match connection {
            Connection::Usb => Transport::Usb,
            Connection::Network(_) => Transport::Network,
            Connection::Unknown(_) => Transport::Unknown,
        }
    }
}

/// A device usbmuxd currently knows about, before any pairing/session work
/// has happened.
#[derive(Debug, Clone)]
pub struct AttachedDevice {
    pub udid: String,
    pub transport: Transport,
}

/// Display metadata read from lockdownd once a session is established.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
    pub product_type: String,
    pub ios_version: String,
}

/// Lists every device usbmuxd currently sees, USB or Wi-Fi sync.
pub async fn list() -> Result<Vec<AttachedDevice>, CradleError> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let devices = usbmuxd.get_devices().await?;
    Ok(devices
        .into_iter()
        .map(|d| AttachedDevice {
            udid: d.udid,
            transport: d.connection_type.into(),
        })
        .collect())
}

/// Builds a connection provider for a specific device, addressed by UDID.
///
/// This only talks to usbmuxd to resolve the device; it does not establish a
/// lockdown session. Use [`lockdown_session`] for that.
pub async fn provider_for(udid: &str) -> Result<Box<dyn IdeviceProvider>, CradleError> {
    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let device = usbmuxd.get_device(udid).await?;
    let addr = UsbmuxdAddr::from_env_var().map_err(|e| CradleError::Other(e.to_string()))?;
    Ok(Box::new(device.to_provider(addr, LABEL)))
}

/// Connects to lockdownd and starts a session using the device's existing
/// pairing record.
///
/// This is the "is the pairing record valid" check: a stale or missing
/// pairing surfaces here as an `Err`, before any backup work starts. Per
/// CLAUDE.md, that failure must be shown as a UI state ("tap Trust on the
/// device"), not a raw protocol error — see [`crate::precheck`] for the
/// user-facing translation.
pub async fn lockdown_session(
    provider: &dyn IdeviceProvider,
) -> Result<LockdownClient, IdeviceError> {
    let mut lockdown = LockdownClient::connect(provider).await?;
    lockdown
        .start_session(&provider.get_pairing_file().await?)
        .await?;
    Ok(lockdown)
}

/// Reads the handful of lockdown values Cradle needs to identify and display
/// a device. Requires an already-session-started client (see
/// [`lockdown_session`]).
pub async fn info(lockdown: &mut LockdownClient) -> Result<DeviceInfo, IdeviceError> {
    let udid = lockdown.get_value(Some("UniqueDeviceID"), None).await?;
    let name = lockdown.get_value(Some("DeviceName"), None).await?;
    let product_type = lockdown.get_value(Some("ProductType"), None).await?;
    let ios_version = lockdown.get_value(Some("ProductVersion"), None).await?;

    Ok(DeviceInfo {
        udid: udid.as_string().unwrap_or_default().to_string(),
        name: name.as_string().unwrap_or_default().to_string(),
        product_type: product_type.as_string().unwrap_or_default().to_string(),
        ios_version: ios_version.as_string().unwrap_or_default().to_string(),
    })
}
