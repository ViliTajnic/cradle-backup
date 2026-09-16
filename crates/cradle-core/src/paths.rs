//! The one shared default for where Cradle keeps its canonical working set
//! and restore-staging scratch space, so `cradle-cli` and `cradle-app`
//! resolve the same per-device location when neither is told otherwise.
//!
//! Before this module, the CLI defaulted `--working-dir` to the relative
//! path `working` (wherever the shell's current directory happened to be)
//! while the app defaulted to `~/Cradle/working` — a CLI backup and an app
//! backup of the same device, both left at their defaults, landed in two
//! different places with neither side aware the other existed.
//! CODEBASE_ANALYSIS.md: "Both should resolve the same per-device
//! location."
//!
//! A stable, non-CWD-dependent location is also just less of a foot-gun on
//! its own: running `cradle backup` from different directories under the
//! old default silently split one device's backups across multiple
//! `working/` trees with no indication anything was wrong.

use std::path::PathBuf;

/// `~/Cradle/working` — the canonical working set's default root.
/// `working_root.join(<UDID>)` is what CLAUDE.md calls canonical; this
/// function only supplies where `working_root` itself defaults to when a
/// caller hasn't set `--working-dir` / the app's storage setting.
pub fn default_working_dir() -> PathBuf {
    base_dir().join("working")
}

/// `~/Cradle/scratch` — where a restore is staged before the protocol
/// touches the target device. Per CLAUDE.md's architecture rule, this is
/// never the working set itself.
pub fn default_scratch_dir() -> PathBuf {
    base_dir().join("scratch")
}

fn base_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(std::env::temp_dir).join("Cradle")
}
