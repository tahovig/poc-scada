// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use poc_scada_core::AnalysisReport;

#[tauri::command]
fn analyze_pcap(path: String) -> Result<AnalysisReport, String> {
    poc_scada_core::analyze_pcap(std::path::Path::new(&path)).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![analyze_pcap])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
