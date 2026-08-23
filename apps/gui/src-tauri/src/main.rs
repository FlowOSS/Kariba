#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kariba_core::paths;
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, ScanHistoryItem, ScanParams, ScanResult, StatusResult, method,
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
async fn daemon_status() -> Result<StatusResult, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let value = call(method::STATUS, Value::Null)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn survey() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| call(method::SURVEY_RUN, Value::Null))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn quarantine_list() -> Result<Vec<QuarantineItem>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let value = call(method::QUARANTINE_LIST, Value::Null)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn quarantine_restore(id: u64) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let params = serde_json::to_value(IdParams { id }).map_err(|e| e.to_string())?;
        let value = call(method::QUARANTINE_RESTORE, params)?;
        Ok(value.as_str().unwrap_or("").to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn quarantine_delete(id: u64) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let params = serde_json::to_value(IdParams { id }).map_err(|e| e.to_string())?;
        let value = call(method::QUARANTINE_DELETE, params)?;
        Ok(value.as_bool().unwrap_or(false))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn scan(
    app: tauri::AppHandle,
    paths: Vec<String>,
    quarantine: bool,
    kind: String,
) -> Result<ScanResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut client = connect()?;
        let params = ScanParams {
            paths: paths
                .into_iter()
                .map(|p| kariba_core::paths::expand_tilde(std::path::Path::new(&p)))
                .collect(),
            quarantine,
            kind,
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
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn scan_cancel(scan_id: u64) -> Result<u32, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let params = serde_json::to_value(IdParams { id: scan_id }).map_err(|e| e.to_string())?;
        let value = call(method::SCAN_CANCEL, params)?;
        Ok(value.get("cancelled").and_then(Value::as_u64).unwrap_or(0) as u32)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn scan_history() -> Result<Vec<ScanHistoryItem>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let value = call(method::SCAN_HISTORY, Value::Null)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Workaround for WebKitGTK crashing on NVIDIA + Wayland with
/// "Gdk-Message: Error 71 (Protocol error) dispatching to Wayland display".
///
/// The proprietary NVIDIA driver's explicit-sync / DMA-BUF implementation
/// breaks WebKitGTK's GPU renderer on Wayland compositors, and the usual
/// XWayland fallback is equally broken on NVIDIA (window renders solid
/// color). Disabling WebKit's DMA-BUF renderer sidesteps the bug entirely.
///
/// Detection uses `/proc/driver/nvidia/version` instead of shelling out to
/// `lspci` (which may not exist on minimal systems). The variable is only
/// set when unset, so an explicit user override always wins. This keeps the
/// fix invisible to end users — no env vars, wrapper scripts, or per-distro
/// instructions needed. Verified on Hyprland + RTX 5060 Ti, 2026-08.
fn apply_nvidia_wayland_workaround() {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return;
    }
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some() {
        return;
    }
    if std::path::Path::new("/proc/driver/nvidia/version").exists() {
        // SAFETY: called at the very start of main(), before GTK/WebKit or
        // any other thread exists, so no getenv/setenv race is possible.
        unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
    }
}

fn main() {
    apply_nvidia_wayland_workaround();
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            survey,
            scan,
            scan_cancel,
            scan_history,
            quarantine_list,
            quarantine_restore,
            quarantine_delete
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kariba");
}
