//! MTKey application shell.
//!
//! Near-zero-permission core: the only plugin is the official opener, and its
//! capability is scoped to Wikipedia and the defuse repository, the two hosts
//! the Learn panel links to. Everything else (clipboard included) uses the
//! web platform.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
