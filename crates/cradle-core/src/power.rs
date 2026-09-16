//! Keeps the system awake for the duration of a long transfer.
//!
//! Real bug, not a hypothetical: a ~75GB backup to an external drive ran
//! for the better part of an hour and failed near the very end with
//! MBErrorDomain 104 ("computer-side errors during backup" — the host
//! failed to read/write a backup file), consistent with the Mac or the
//! external drive going to sleep mid-transfer during that unattended hour.
//!
//! macOS only for now (Windows support is a future project). Wraps
//! `caffeinate` as a subprocess rather than binding IOKit's
//! power-assertion API directly — wrap, don't reimplement: `caffeinate`
//! *is* the documented interface Apple ships for exactly this.

/// Holds a system sleep assertion for as long as it's alive. Drop it (or
/// let it fall out of scope) to release the assertion.
#[cfg(target_os = "macos")]
pub struct SleepGuard(std::process::Child);

#[cfg(target_os = "macos")]
impl SleepGuard {
    /// Starts preventing idle system sleep — display sleep is untouched
    /// (and irrelevant: a backup running in the background doesn't need
    /// the screen on, only the system not to suspend, which is what
    /// breaks USB/disk I/O mid-transfer). Returns `None` if `caffeinate`
    /// couldn't be spawned rather than failing the caller's operation
    /// over what's a reliability improvement, not a requirement.
    pub fn engage() -> Option<Self> {
        std::process::Command::new("caffeinate")
            .arg("-s")
            .spawn()
            .ok()
            .map(Self)
    }
}

#[cfg(target_os = "macos")]
impl Drop for SleepGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// No-op elsewhere until M9 adds a Windows equivalent (`SetThreadExecutionState`).
#[cfg(not(target_os = "macos"))]
pub struct SleepGuard;

#[cfg(not(target_os = "macos"))]
impl SleepGuard {
    pub fn engage() -> Option<Self> {
        None
    }
}
