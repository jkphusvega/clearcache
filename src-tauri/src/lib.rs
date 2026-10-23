// M2: scanner. Rules and quarantine commands arrive in M3–M4 (see SPEC.md).
// The frontend never gets fs access; every command takes target/scan-result ids, not paths.

mod commands;
pub mod core;

use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(core::session::ScanSession::default()))
        .invoke_handler(tauri::generate_handler![
            commands::list_scan_targets,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_scan_result,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
