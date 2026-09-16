//! Finds an external tool binary Cradle shells out to (`idevice_id`,
//! `ideviceinfo`, `idevicepair`, `idevicebackup2`, `restic`) — the one
//! resolver every module doing that shares, rather than each trusting a
//! bare `Command::new(name)` to find it via inherited `PATH` alone.
//!
//! CODEBASE_ANALYSIS.md: "Use the same tool resolver for restic and device
//! tools." Before this module, only the device tools got the Homebrew
//! fallback below; `archive.rs` invoked plain `Command::new("restic")`,
//! which finds it fine from a shell (Homebrew's own PATH entry) but not
//! from a GUI app launched via Finder/Dock, which doesn't inherit that —
//! the same asymmetry the device tools were already fixed for. Not
//! hypothetical: a GUI app in this exact repo already needed the fallback
//! for `idevicebackup2` to work at all when launched other than from a
//! terminal.

use std::path::{Path, PathBuf};

use crate::CradleError;

/// Extra places to look beyond `PATH` — Homebrew's default prefixes on
/// Apple Silicon and Intel Macs.
const EXTRA_TOOL_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];

/// Resolves `name` to an absolute path: first via `PATH`, then via
/// [`EXTRA_TOOL_DIRS`]. `name` is `'static` because every caller passes a
/// literal (`"restic"`, `"idevicebackup2"`, ...), never a
/// dynamically-built string — there's no legitimate reason to search for
/// an externally-supplied binary name here.
pub fn resolve(name: &'static str) -> Result<PathBuf, CradleError> {
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for dir in EXTRA_TOOL_DIRS {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CradleError::ToolNotFound(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_real_tool_on_path() {
        // `sh` is guaranteed present on any Unix CI/dev machine this runs
        // on — not one of Cradle's own tools, just a stand-in to exercise
        // the real PATH-search branch without depending on
        // libimobiledevice/restic being installed in the test environment.
        assert!(resolve("sh").is_ok());
    }

    #[test]
    fn reports_a_clear_error_for_a_tool_that_does_not_exist() {
        let err = resolve("cradle-definitely-not-a-real-binary-xyz").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
