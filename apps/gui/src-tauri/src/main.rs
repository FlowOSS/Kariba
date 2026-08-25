#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use kariba_core::paths;
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, ScanHistoryItem, ScanParams, ScanResult, Settings, SettingsSetParams,
    StatusResult, ThreatHistoryItem, ThreatStatusFilter, method,
};
use kariba_ipc::{Client, Notification};
use serde_json::Value;
use std::time::Duration;
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

mod tray_ksni;

fn connect() -> Result<Client, String> {
    kariba_ipc::connect_daemon().map_err(|e| {
        let tried = paths::socket_candidates()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("cannot reach karibad (tried {tried}): {e}. Start it first: karibad")
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
async fn settings_get() -> Result<Settings, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let value = call(method::SETTINGS_GET, Value::Null)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Persistent subscription: holds one daemon connection open and forwards
/// every daemon-originated notification (real-time detections) as a Tauri
/// event. Reconnects with backoff if the daemon restarts.
#[tauri::command]
async fn realtime_events(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        loop {
            if let Ok(mut client) = kariba_ipc::connect_daemon() {
                let _ = client.subscribe(|notification| {
                    let event = match notification.method.as_str() {
                        method::REALTIME_DETECTION => "kariba://realtime-detection",
                        _ => return,
                    };
                    let _ = app.emit(event, &notification.params);
                });
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn settings_set(settings: Settings) -> Result<Settings, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let params =
            serde_json::to_value(SettingsSetParams { settings }).map_err(|e| e.to_string())?;
        let value = call(method::SETTINGS_SET, params)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Shared scan launcher used by both the `scan` command (frontend) and the
/// tray menu (headless). `quarantine = None` defers to the daemon's
/// `scan.default_quarantine` setting.
fn start_scan(
    app: tauri::AppHandle,
    paths: Vec<String>,
    quarantine: Option<bool>,
    kind: String,
) -> Result<ScanResult, String> {
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
}

#[tauri::command]
async fn scan(
    app: tauri::AppHandle,
    paths: Vec<String>,
    quarantine: bool,
    kind: String,
) -> Result<ScanResult, String> {
    tauri::async_runtime::spawn_blocking(move || start_scan(app, paths, Some(quarantine), kind))
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

#[tauri::command]
async fn threats_history(status: Option<String>) -> Result<Vec<ThreatHistoryItem>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let filter = ThreatStatusFilter { status };
        let params = serde_json::to_value(filter).map_err(|e| e.to_string())?;
        let value = call(method::THREATS_LIST, params)?;
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
        .setup(setup_tray)
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            survey,
            scan,
            scan_cancel,
            scan_history,
            quarantine_list,
            quarantine_restore,
            quarantine_delete,
            threats_history,
            settings_get,
            settings_set,
            realtime_events,
            show_main_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kariba");
}

// --- System tray -----------------------------------------------------------

const POPUP_LABEL: &str = "popup";
const MAIN_LABEL: &str = "main";
const QUICK_PATHS: &[&str] = &["~/Downloads", "/tmp", "/var/tmp"];
// A detection younger than this keeps the tray red.
const THREAT_FLASH_SECS: u64 = 120;

/// Visual protection state shown by the tray icon.
#[derive(Clone, Copy, PartialEq)]
enum TrayState {
    Protected, // green: protection on, nothing pending
    Attention, // yellow: protection off, or quarantined items to review
    Threat,    // red: detection within the flash window
    Offline,   // gray: daemon unreachable
}

fn tray_icon_bytes(state: TrayState) -> &'static [u8] {
    match state {
        TrayState::Protected => include_bytes!("../icons/tray/green.png"),
        TrayState::Attention => include_bytes!("../icons/tray/yellow.png"),
        TrayState::Threat => include_bytes!("../icons/tray/red.png"),
        TrayState::Offline => include_bytes!("../icons/tray/gray.png"),
    }
}

fn tray_tooltip(state: TrayState, detail: &str) -> String {
    match state {
        TrayState::Protected => "Kariba: protected".into(),
        TrayState::Attention => format!("Kariba: {detail}"),
        TrayState::Threat => "Kariba: recent detection".into(),
        TrayState::Offline => "Kariba: daemon offline".into(),
    }
}

/// Blocking status + recent-threat probe used by the poller.
fn probe_tray_state() -> (TrayState, String) {
    let status: Option<StatusResult> = call(method::STATUS, Value::Null)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok());
    let Some(status) = status else {
        return (TrayState::Offline, "daemon offline".into());
    };
    if !status.protection_enabled {
        return (TrayState::Attention, "protection off".into());
    }
    // Recent detection? Newest threat row within the flash window.
    let recent_threat = call(
        method::THREATS_LIST,
        serde_json::to_value(ThreatStatusFilter { status: None }).unwrap_or(Value::Null),
    )
    .ok()
    .and_then(|v| serde_json::from_value::<Vec<ThreatHistoryItem>>(v).ok())
    .and_then(|items| items.into_iter().next())
    .is_some_and(|latest| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(latest.detected_at) <= THREAT_FLASH_SECS
    });
    if recent_threat {
        return (TrayState::Threat, "recent detection".into());
    }
    if status.quarantined_items > 0 {
        return (
            TrayState::Attention,
            format!("{} quarantined item(s)", status.quarantined_items),
        );
    }
    (TrayState::Protected, "protected".into())
}

fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // Closing the main window hides it to the tray; the tray Quit is the
    // real exit (standard always-on AV behavior).
    if let Some(main) = app.get_webview_window(MAIN_LABEL) {
        let win = main.clone();
        main.on_window_event(move |event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = win.hide();
            }
        });
    }

    // Mini popup window, created hidden; a tray click toggles it.
    let popup = WebviewWindowBuilder::new(
        app,
        POPUP_LABEL,
        WebviewUrl::App("index.html?mode=popup".into()),
    )
    .title("Kariba Panel")
    .inner_size(360.0, 440.0)
    .decorations(false)
    .resizable(false)
    .skip_taskbar(true)
    .always_on_top(true)
    .visible_on_all_workspaces(true)
    .visible(false)
    .build()?;
    let popup_events = popup.clone();
    popup.on_window_event(move |event| match event {
        tauri::WindowEvent::CloseRequested { api, .. } => {
            api.prevent_close();
            let _ = popup_events.hide();
        }
        tauri::WindowEvent::Focused(false) => {
            let _ = popup_events.hide();
        }
        _ => {}
    });

    // Kariba is Linux-only: tauri's tray backend (libappindicator) has no
    // click-event wiring at all, so we own the StatusNotifierItem D-Bus
    // interface directly via ksni and receive real Activate(x, y) events.
    let handle = tray_ksni::setup(&app.handle().clone())?;
    let _ = std::thread::Builder::new()
        .name("kariba-tray-poller".into())
        .spawn(move || {
            loop {
                tray_ksni::refresh(&handle);
                std::thread::sleep(Duration::from_secs(5));
            }
        });

    Ok(())
}

/// Blocking probe for the real-time protection toggle.
fn probe_protection_enabled() -> Option<bool> {
    call(method::SETTINGS_GET, Value::Null)
        .ok()
        .and_then(|v| serde_json::from_value::<Settings>(v).ok())
        .map(|s| s.realtime.enabled)
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window(MAIN_LABEL) {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

#[tauri::command]
fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
    show_main(&app);
    Ok(())
}

/// Fire-and-forget scan from the tray: daemon default quarantine policy,
/// progress flows to any open window via the usual events.
fn spawn_scan(app: &tauri::AppHandle, paths: Vec<String>, kind: &str) {
    let app = app.clone();
    let kind = kind.to_string();
    tauri::async_runtime::spawn(async move {
        let _ =
            tauri::async_runtime::spawn_blocking(move || start_scan(app, paths, None, kind)).await;
    });
}

fn toggle_protection(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = tauri::async_runtime::spawn_blocking(move || {
            let value = call(method::SETTINGS_GET, Value::Null).map_err(|e| e.to_string())?;
            let mut settings: Settings =
                serde_json::from_value(value).map_err(|e| e.to_string())?;
            settings.realtime.enabled = !settings.realtime.enabled;
            let params =
                serde_json::to_value(SettingsSetParams { settings }).map_err(|e| e.to_string())?;
            call(method::SETTINGS_SET, params).map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        })
        .await;
        let _ = app;
    });
}

/// Toggle the mini popup. `icon` is the tray icon's center in screen
/// coordinates (ksni delivers them with Activate). set_position covers
/// compositors that honor position requests; Hyprland ignores them, so the
/// window is also moved into place via hyprctl after mapping.
fn toggle_popup_xy(app: &tauri::AppHandle, icon: Option<(f64, f64)>) {
    let Some(win) = app.get_webview_window(POPUP_LABEL) else {
        return;
    };
    if win.is_visible().unwrap_or(false) {
        let _ = win.hide();
        return;
    }
    position_popup_at(&win, icon);
    let _ = win.show();
    let _ = win.set_focus();
    hyprland_place(&win, icon);
}

fn position_popup_at(win: &tauri::WebviewWindow, icon_center: Option<(f64, f64)>) {
    let Some((x, y)) = icon_center.map(|(cx, cy)| popup_target(win, cx, cy)) else {
        return;
    };
    let _ = win.set_position(tauri::PhysicalPosition::new(x, y));
}

/// Where the 360x440 popup should land for a tray icon at (cx, cy):
/// centered above the icon, or below it when there's no room above.
fn popup_target(win: &tauri::WebviewWindow, cx: f64, cy: f64) -> (f64, f64) {
    const PW: f64 = 360.0;
    const PH: f64 = 440.0;
    let monitor = win
        .current_monitor()
        .ok()
        .flatten()
        .map(|m| (m.size().width as f64, m.size().height as f64));
    let (mw, mh) = monitor.unwrap_or((1920.0, 1080.0));
    let x = (cx - PW / 2.0).clamp(0.0, (mw - PW).max(0.0));
    let mut y = cy - PH - 12.0;
    if y < 0.0 {
        y = (cy + 36.0).min((mh - PH).max(0.0));
    }
    (x, y)
}

/// Hyprland ignores xdg-toplevel position requests (wlroots has no standard
/// positioning protocol for regular toplevels), so after the window is
/// mapped we focus it by title and move it with hyprctl. Runs on a thread
/// with a small delay so the window is mapped first; no-ops on
/// non-Hyprland compositors.
fn hyprland_place(win: &tauri::WebviewWindow, icon: Option<(f64, f64)>) {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return;
    }
    let Some((cx, cy)) = icon else {
        return;
    };
    let (x, y) = popup_target(win, cx, cy);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        let batch =
            format!("dispatch focuswindow title:^Kariba Panel$ ; dispatch movewindow [{x};{y}]");
        let _ = std::process::Command::new("hyprctl")
            .arg("--batch")
            .arg(batch)
            .output();
    });
}
