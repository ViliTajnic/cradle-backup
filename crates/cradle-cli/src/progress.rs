//! A rewritable terminal progress line with real numbers.
//!
//! Per CLAUDE.md: "Finder shows an indeterminate barber-pole while moving
//! 70+ GB; that failure is the reason this project exists." This prints
//! files done, a percentage, transfer rate, bytes moved, and an ETA —
//! never a spinner.

use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

use cradle_core::backup::ProgressSink;

struct State {
    start: Instant,
    files: u32,
}

pub struct TerminalProgress {
    state: Mutex<State>,
}

impl TerminalProgress {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                start: Instant::now(),
                files: 0,
            }),
        }
    }

    /// Moves the cursor past the progress line once the run is done.
    pub fn finish(&self) {
        eprintln!();
    }
}

impl ProgressSink for TerminalProgress {
    fn on_file(&self, _path: &str, file_count: u32) {
        let mut state = self.state.lock().unwrap();
        state.files = file_count;
    }

    fn on_progress(&self, bytes_done: u64, bytes_total: u64, overall_progress: f64) {
        let (files, elapsed) = {
            let state = self.state.lock().unwrap();
            (state.files, state.start.elapsed().as_secs_f64())
        };

        let rate = if elapsed > 0.0 {
            bytes_done as f64 / elapsed
        } else {
            0.0
        };

        let pct = if overall_progress >= 0.0 {
            Some(overall_progress)
        } else if bytes_total > 0 {
            Some((bytes_done as f64 / bytes_total as f64) * 100.0)
        } else {
            None
        };

        let eta = pct.filter(|p| *p > 0.0 && *p < 100.0).map(|p| {
            let remaining_pct = 100.0 - p;
            (elapsed / p) * remaining_pct
        });

        let pct_str = pct.map(|p| format!("{p:5.1}%")).unwrap_or_else(|| "  ?  %".to_string());
        let eta_str = eta.map(format_duration).unwrap_or_else(|| "?".to_string());

        eprint!(
            "\r\x1b[Kfiles {files:>6}  {pct_str}  {}/s  {} moved  eta {eta_str}",
            human_bytes(rate as u64),
            human_bytes(bytes_done),
        );
        let _ = std::io::stderr().flush();
    }

    fn on_attention_needed(&self, needed: bool) {
        if needed {
            // A terminal line alone is easy to miss once the user isn't
            // watching the window — see `cradle_core::notify`'s module doc
            // for the real-device story: this exact gap is why a backup
            // restarted as a full transfer more than once in a row.
            cradle_core::notify::alert(
                "Cradle needs your attention",
                "Unlock your iPhone/iPad now — it's asking for Face ID or your passcode to continue the backup.",
            );
            eprintln!(
                "\n>>> Look at your device now — enter your passcode (or use Face ID/Touch ID) \
                 to let the backup continue. <<<"
            );
        } else {
            eprintln!("Thanks — continuing.");
        }
    }
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn format_duration(seconds: f64) -> String {
    let total = seconds.max(0.0) as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
