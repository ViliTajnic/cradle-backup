//! Device protocol, prechecks, backup orchestration and the catalog for
//! Cradle.
//!
//! M0-M2 scope only (see `/ROADMAP.md`): connect to a device over
//! `mobilebackup2`, run prechecks, perform a backup into the canonical
//! working directory with honest progress reporting, verify it, and record
//! it in a small local catalog. No archiving, no restore yet — those land
//! in later milestones and must not be built ahead of schedule.

pub mod backup;
pub mod catalog;
pub mod device;
pub mod precheck;
pub mod verify;

/// Errors that can occur anywhere in the Cradle core: device protocol
/// failures, local filesystem failures, or a handful of Cradle-specific
/// conditions the `idevice` crate has no vocabulary for.
#[derive(Debug, thiserror::Error)]
pub enum CradleError {
    #[error("device error: {0}")]
    Device(#[from] idevice::IdeviceError),

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("device did not report a UDID")]
    MissingUdid,

    #[error("catalog error: {0}")]
    Catalog(#[from] rusqlite::Error),

    /// MBErrorDomain 208. Split out from [`Self::Other`] because it's
    /// recoverable: see [`backup::run_resilient`], which retries on exactly
    /// this variant.
    #[error(
        "the device was locked when iOS needed to access protected data — unlock it and keep \
         it unlocked and awake for the whole backup"
    )]
    DeviceLocked,

    #[error("{0}")]
    Other(String),
}
