// M1: empty shell. Scanner, rules and quarantine commands arrive in M2–M4 (see SPEC.md).
// The frontend never gets fs access; every command added later takes scan-result ids, not paths.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
