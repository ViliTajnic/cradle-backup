//! Cradle desktop app (M7) — a Tauri shell around the same `cradle-core`
//! the CLI drives. Per CLAUDE.md: "The progress rendering is the whole
//! point" — this exists because Finder's indeterminate barber-pole while
//! moving 70+ GB is the failure this whole project responds to, so the
//! backup screen shows real files/bytes/rate/ETA, not a spinner.

mod commands;
mod progress;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            commands::list_devices,
            commands::run_backup,
            commands::get_history,
            commands::list_destinations,
            commands::add_destination,
            commands::run_archive,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Cradle app");
}
