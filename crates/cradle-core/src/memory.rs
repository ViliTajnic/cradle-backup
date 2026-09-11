//! How much physical memory is actually free on this Mac right now.
//!
//! Exists because of a real, repeated failure, not a hypothetical: a real
//! device backup hit MBErrorDomain 104 ("computer-side errors during
//! backup") three separate times across one session, and every single
//! time, free memory measured under ~150MB at the moment of failure. No
//! amount of retry logic in `backup::run_resilient` can outrun a machine
//! that's chronically starved for RAM during a multi-hour transfer — per
//! CLAUDE.md's working agreements, "prefer failing a precheck over
//! failing mid-transfer," so this exists to let `precheck::run` catch a
//! doomed attempt before it burns an hour finding out the hard way.
//!
//! macOS only for now (Windows is M9), via `vm_stat` — same "wrap, don't
//! reimplement" reasoning as `power::SleepGuard`/`notify::alert`: shelling
//! out to the OS's own diagnostic tool is simpler and more portable across
//! macOS versions than binding `host_statistics64` directly for one
//! number.

/// Free physical memory right now, in bytes. `None` if it couldn't be
/// determined (non-macOS, or `vm_stat` unavailable/unparseable) — callers
/// should treat that as "unmeasurable," not "zero."
#[cfg(target_os = "macos")]
pub fn free_bytes() -> Option<u64> {
    let output = std::process::Command::new("vm_stat").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);

    let page_size = text
        .lines()
        .next()?
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;

    let free_pages: u64 = text
        .lines()
        .find(|line| line.starts_with("Pages free:"))?
        .split(':')
        .nth(1)?
        .trim()
        .trim_end_matches('.')
        .parse()
        .ok()?;

    Some(free_pages * page_size)
}

#[cfg(not(target_os = "macos"))]
pub fn free_bytes() -> Option<u64> {
    None
}
