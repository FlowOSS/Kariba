#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kariba_core::paths;
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, ScanParams, ScanResult, StatusResult, method,
};
use kariba_ipc::{Client, Notification};
use serde_json::Value;
use tauri::Emitter;

fn connect() -> Result<Client, String> {
    let socket = paths::socket_path();
    Client::connect(&socket).map_err(|e| {
        format!(
            "cannot reach karibad at {} ({e}). Start it first: karibad",
            socket.display()
        )
    })
}

fn call(method: &str, params: Value) -> Result<Value, String> {
    let mut client = connect()?;
    client.call(method, params).map_err(|e| e.to_string())
}

#[tauri::command]
fn daemon_status() -> Result<StatusResult, String> {
    let value = call(method::STATUS, Value::Null)?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}

#[tauri::command]
fn survey() -> Result<Value, String> {
    call(method::SURVEY_RUN, Value::Null)
}

#[tauri::command]
fn quarantine_list() -> Result<Vec<QuarantineItem>, String> {
    let value = call(method::QUARANTINE_LIST, Value::Null)?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}

#[tauri::command]
fn quarantine_restore(id: u64) -> Result<String, String> {
    let params = serde_json::to_value(IdParams { id }).map_err(|e| e.to_string())?;
    let value = call(method::QUARANTINE_RESTORE, params)?;
    Ok(value.as_str().unwrap_or("").to_string())
}

#[tauri::command]
fn quarantine_delete(id: u64) -> Result<bool, String> {
    let params = serde_json::to_value(IdParams { id }).map_err(|e| e.to_string())?;
    let value = call(method::QUARANTINE_DELETE, params)?;
    Ok(value.as_bool().unwrap_or(false))
}

#[tauri::command]
fn scan(app: tauri::AppHandle, paths: Vec<String>, quarantine: bool) -> Result<ScanResult, String> {
    let mut client = connect()?;
    let params = ScanParams {
        paths: paths
            .into_iter()
            .map(|p| kariba_core::paths::expand_tilde(std::path::Path::new(&p)))
            .collect(),
        quarantine,
    };
    let params = serde_json::to_value(params).map_err(|e| e.to_string())?;

    let value = client
        .call_with_notifications(method::SCAN_START, params, |notification: &Notification| {
            let event = match notification.method.as_str() {
                method::SCAN_PROGRESS => "kariba://scan-progress",
                method::SCAN_DETECTION => "kariba://scan-detection",
                _ => return,
            };
            let _ = app.emit(event, &notification.params);
        })
        .map_err(|e| e.to_string())?;

    serde_json::from_value(value).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            survey,
            scan,
            quarantine_list,
            quarantine_restore,
            quarantine_delete
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kariba");
}
