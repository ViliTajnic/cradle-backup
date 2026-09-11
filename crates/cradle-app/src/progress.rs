//! Bridges [`cradle_core::backup::ProgressSink`] to Tauri events, so the
//! webview gets the same honest, real-time progress the CLI's
//! `TerminalProgress` prints — files/bytes/rate/ETA, never a spinner. See
//! CLAUDE.md: "Every long-running operation reports files done/total,
//! bytes, rate, ETA, and current domain."
//!
//! Used for both a device backup and an archive run — `archive::backup`
//! takes the same `ProgressSink` the device protocol does (see
//! `archive.rs`'s doc comment on why it reuses the trait), so one type
//! here covers both, parameterized by which event names to emit under.

use std::sync::atomic::{AtomicU32, Ordering};

use cradle_core::backup::ProgressSink;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Event names for a device backup's progress.
pub const BACKUP_PROGRESS_EVENT: &str = "backup-progress";
/// Event name for the on-device passcode/Face ID prompt signal during a
/// backup — see `ProgressSink::on_attention_needed`'s doc for why this
/// matters. Archiving never fires this (restic doesn't need the device
/// unlocked), so [`TauriProgress`] for an archive run just never emits it.
pub const BACKUP_ATTENTION_EVENT: &str = "backup-attention";
/// Event name for an archive run's progress.
pub const ARCHIVE_PROGRESS_EVENT: &str = "archive-progress";

#[derive(Serialize, Clone)]
struct ProgressPayload {
    files: u32,
    bytes_done: u64,
    bytes_total: u64,
    overall_progress: f64,
}

pub struct TauriProgress {
    app: AppHandle,
    progress_event: &'static str,
    attention_event: Option<&'static str>,
    files: AtomicU32,
}

impl TauriProgress {
    pub fn for_backup(app: AppHandle) -> Self {
        Self {
            app,
            progress_event: BACKUP_PROGRESS_EVENT,
            attention_event: Some(BACKUP_ATTENTION_EVENT),
            files: AtomicU32::new(0),
        }
    }

    pub fn for_archive(app: AppHandle) -> Self {
        Self {
            app,
            progress_event: ARCHIVE_PROGRESS_EVENT,
            attention_event: None,
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
            self.progress_event,
            ProgressPayload {
                files,
                bytes_done,
                bytes_total,
                overall_progress,
            },
        );
    }

    fn on_attention_needed(&self, needed: bool) {
        if let Some(event) = self.attention_event {
            let _ = self.app.emit(event, needed);
        }
    }
}
