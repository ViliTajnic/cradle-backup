//! Cradle desktop app — a Tauri shell around the same `cradle-core` the
//! CLI drives. The progress rendering is the whole point: this exists
//! because Finder's indeterminate barber-pole while moving 70+ GB is the
//! failure this whole project responds to, so the backup screen shows
//! real files/bytes/rate/ETA, not a spinner.

mod commands;
mod progress;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // cradle-core logs through `tracing`, not the `log` facade
    // tauri-plugin-log builds on — the two can't coexist (both try to
    // install themselves as the global `log` logger; tracing-subscriber's
    // log-capture bridge panics on the second attempt at startup), and
    // this is what actually surfaces the auth-prompt/error diagnostics
    // `libimobiledevice.rs` logs for diagnosing a device protocol failure.
    // Same setup as cradle-cli's own main() — dropped tauri-plugin-log
    // rather than try to reconcile the two loggers, since nothing here
    // needed its in-webview console bridging.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|_app| {
            // Same reasoning as cradle-cli's main(): a Force Quit via
            // Activity Monitor sends a signal to just this process, not
            // its process group, and would otherwise orphan an in-flight
            // `idevicebackup2`/`restic` — see `signals.rs`.
            tauri::async_runtime::spawn(cradle_core::signals::wait_and_propagate_termination());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_devices,
            commands::enable_encryption,
            commands::store_existing_password,
            commands::verify_stored_password,
            commands::run_backup,
            commands::get_history,
            commands::list_destinations,
            commands::add_destination,
            commands::list_archive_snapshots,
            commands::remove_destination,
            commands::show_destination_password,
            commands::connect_destination,
            commands::run_archive,
            commands::list_restore_sources,
            commands::list_local_backups,
            commands::delete_local_backup,
            commands::run_restore,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Cradle app");
}
