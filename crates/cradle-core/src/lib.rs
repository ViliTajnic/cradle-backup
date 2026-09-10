//! Device protocol, prechecks and backup orchestration for Cradle.
//!
//! M0 scope only (see `/ROADMAP.md`): connect to a device over `mobilebackup2`,
//! run prechecks, and perform a backup into the canonical working directory
//! with honest progress reporting. No catalog, no archiving, no restore yet —
//! those land in later milestones and must not be built ahead of schedule.

pub mod backup;
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

    #[error("{0}")]
    Other(String),
}
