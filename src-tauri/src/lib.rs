//! MTKey application shell.
//!
//! Zero-permission core: no Tauri plugins are enabled. The frontend uses the
//! web platform (for example `navigator.clipboard`) for everything else.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
