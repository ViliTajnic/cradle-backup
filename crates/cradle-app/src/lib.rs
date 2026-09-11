//! Cradle desktop app (M7) — a Tauri shell around the same `cradle-core`
//! the CLI drives. Per CLAUDE.md: "The progress rendering is the whole
//! point" — this exists because Finder's indeterminate barber-pole while
//! moving 70+ GB is the failure this whole project responds to, so the
//! backup screen shows real files/bytes/rate/ETA, not a spinner.

mod commands;
mod progress;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // idevice logs through `tracing`, not the `log` facade
    // tauri-plugin-log builds on — the two can't coexist (both try to
    // install themselves as the global `log` logger; tracing-subscriber's
    // log-capture bridge panics on the second attempt at startup), and
    // this is what actually surfaces idevice's internal debug/warn output
    // for diagnosing a device protocol failure. Same setup as cradle-cli's
    // own main() — dropped tauri-plugin-log rather than try to reconcile
    // the two loggers, since nothing here needed its in-webview console
    // bridging.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::list_devices,
            commands::run_backup,
            commands::get_history,
            commands::list_destinations,
            commands::add_destination,
            commands::remove_destination,
            commands::run_archive,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Cradle app");
}
