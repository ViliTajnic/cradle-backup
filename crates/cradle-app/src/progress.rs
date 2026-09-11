//! Bridges [`cradle_core::backup::ProgressSink`] to Tauri events, so the
//! webview gets the same honest, real-time progress the CLI's
//! `TerminalProgress` prints — files/bytes/rate/ETA, never a spinner. See
//! CLAUDE.md: "Every long-running operation reports files done/total,
//! bytes, rate, ETA, and current domain."

use std::sync::atomic::{AtomicU32, Ordering};

use cradle_core::backup::ProgressSink;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Event name the frontend listens on for progress snapshots.
pub const PROGRESS_EVENT: &str = "backup-progress";
/// Event name for the on-device passcode/Face ID prompt signal — see
/// `ProgressSink::on_attention_needed`'s doc for why this matters.
pub const ATTENTION_EVENT: &str = "backup-attention";

#[derive(Serialize, Clone)]
struct ProgressPayload {
    files: u32,
    bytes_done: u64,
    bytes_total: u64,
    overall_progress: f64,
}

pub struct TauriProgress {
    app: AppHandle,
    files: AtomicU32,
}

impl TauriProgress {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            files: AtomicU32::new(0),
        }
    }
}

impl ProgressSink for TauriProgress {
    fn on_file(&self, _path: &str, file_count: u32) {
        self.files.store(file_count, Ordering::Relaxed);
    }

    fn on_progress(&self, bytes_done: u64, bytes_total: u64, overall_progress: f64) {
        let files = self.files.load(Ordering::Relaxed);
        let _ = self.app.emit(
            PROGRESS_EVENT,
            ProgressPayload {
                files,
                bytes_done,
                bytes_total,
                overall_progress,
            },
        );
    }

    fn on_attention_needed(&self, needed: bool) {
        let _ = self.app.emit(ATTENTION_EVENT, needed);
    }
}
