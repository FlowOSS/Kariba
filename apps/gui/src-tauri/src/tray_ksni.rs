//! Linux tray via ksni (StatusNotifierItem over D-Bus directly).
//!
//! Tauri's tray-icon backend uses libappindicator on Linux, which has no
//! click-event wiring at all (a click can only open the attached menu,
//! `rect()` is None, tooltips are no-ops). Owning the SNI interface
//! ourselves gets us the real `Activate(x, y)` signal with screen
//! coordinates, so left-click can toggle the panel at the click position.

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{Disposition, MenuItem, StandardItem};
use ksni::{Icon, ToolTip, Tray};
use std::sync::OnceLock;

use crate::{
    QUICK_PATHS, TrayState, probe_protection_enabled, probe_tray_state, show_main, spawn_scan,
    toggle_popup_xy, toggle_protection, tray_icon_bytes, tray_tooltip,
};

pub struct KaribaTray {
    app: tauri::AppHandle,
    state: TrayState,
    tooltip: String,
    protection_on: bool,
}

pub type TrayHandle = Handle<KaribaTray>;

/// Decoded tray icon: (width, height, ARGB32 bytes).
type DecodedIcon = (i32, i32, Vec<u8>);

/// Decode the PNG tray icons once, converted RGBA -> ARGB32 (network byte
/// order), which is what SNI's IconPixmap wants.
fn icon_argb(state: TrayState) -> &'static DecodedIcon {
    static CACHE: OnceLock<[Option<DecodedIcon>; 4]> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let states = [
            TrayState::Protected,
            TrayState::Attention,
            TrayState::Threat,
            TrayState::Offline,
        ];
        std::array::from_fn(|i| {
            let img = tauri::image::Image::from_bytes(tray_icon_bytes(states[i])).ok()?;
            let rgba = img.rgba();
            let mut argb = Vec::with_capacity(rgba.len());
            for pixel in rgba.as_chunks::<4>().0 {
                argb.extend_from_slice(&[pixel[3], pixel[0], pixel[1], pixel[2]]);
            }
            Some((img.width() as i32, img.height() as i32, argb))
        })
    });
    let idx = match state {
        TrayState::Protected => 0,
        TrayState::Attention => 1,
        TrayState::Threat => 2,
        TrayState::Offline => 3,
    };
    cache[idx]
        .as_ref()
        .expect("embedded tray icon pngs are valid")
}

fn item<F>(label: &str, activate: F) -> MenuItem<KaribaTray>
where
    F: Fn(&mut KaribaTray) + Send + 'static,
{
    StandardItem {
        label: label.into(),
        disposition: Disposition::Normal,
        activate: Box::new(activate),
        ..Default::default()
    }
    .into()
}

impl Tray for KaribaTray {
    fn id(&self) -> String {
        "kariba".into()
    }

    fn title(&self) -> String {
        "Kariba".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        let (width, height, data) = icon_argb(self.state);
        vec![Icon {
            width: *width,
            height: *height,
            data: data.clone(),
        }]
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
            title: "Kariba".into(),
            description: self.tooltip.clone(),
        }
    }

    /// Left click: toggle the panel, positioned near the click.
    fn activate(&mut self, x: i32, y: i32) {
        toggle_popup_xy(&self.app, Some((x as f64, y as f64)));
    }

    /// Middle click: open the main window.
    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        show_main(&self.app);
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        eprintln!("kariba: tray: StatusNotifierWatcher offline ({reason:?}); staying up");
        true
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let on = if self.protection_on { "on" } else { "off" };
        vec![
            item("Open Kariba", |t| show_main(&t.app)),
            MenuItem::Separator,
            item("Quick Scan", |t| {
                spawn_scan(
                    &t.app,
                    QUICK_PATHS.iter().map(|s| (*s).to_string()).collect(),
                    "quick",
                );
            }),
            item("Full Scan", |t| {
                spawn_scan(&t.app, vec!["/".into()], "full");
            }),
            MenuItem::Separator,
            item(&format!("Real-time protection: {on}"), |t| {
                toggle_protection(&t.app);
            }),
            MenuItem::Separator,
            item("Quit", |t| t.app.exit(0)),
        ]
    }
}

/// Spawn the SNI tray service. Returns the handle used by the status
/// poller to push icon/tooltip/protection updates.
pub fn setup(app: &tauri::AppHandle) -> Result<TrayHandle, String> {
    KaribaTray {
        app: app.clone(),
        state: TrayState::Protected,
        tooltip: tray_tooltip(TrayState::Protected, "protected"),
        protection_on: true,
    }
    .spawn()
    .map_err(|e| format!("tray service failed: {e}"))
}

/// One poller tick: probe the daemon, push the new state into the tray.
/// Blocking (ksni's handle API is); run from a plain thread, never from
/// inside the async runtime.
pub fn refresh(handle: &TrayHandle) {
    let (state, detail) = probe_tray_state();
    let tooltip = tray_tooltip(state, &detail);
    let protection_on = probe_protection_enabled().unwrap_or(true);
    let _ = handle.update(move |tray: &mut KaribaTray| {
        tray.state = state;
        tray.tooltip = tooltip;
        tray.protection_on = protection_on;
    });
}
