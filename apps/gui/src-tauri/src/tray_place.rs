//! Tray panel popup placement.
//!
//! Wayland compositors ignore position requests from regular xdg
//! toplevels, so the windowing protocol cannot place the popup. On
//! Hyprland, `move` window rules are static (applied once when the window
//! opens), so main.rs creates the popup fresh on every tray click and
//! destroys it on close/blur, and `prepare()` injects the placement rule
//! just before creation: it reads the cursor and monitor geometry
//! (including the reserved strips claimed by bars), anchors the popup at
//! the cursor expanding away from the nearest screen edges, and `hyprctl
//! eval`s a window rule (float, no animations, exact monitor-local
//! coordinates) under a fixed name, so each click replaces the previous
//! rule instead of accumulating. GTK/WebKit wrap the requested window size
//! in extra invisible margins, so the compositor-side box is bigger than
//! requested; the real size is measured after the first open and reused
//! (persisted in `tray_popup_size` under the user's config dir). The popup
//! is therefore placed before it is ever painted — no flash at the
//! compositor's default position, and never cut off by screen edges or the
//! bar.
//!
//! Everything here is best-effort and logged with a `[tray]` prefix: any
//! failure degrades to "popup opens wherever the compositor placed it",
//! never a crash. Other compositors get no positioning yet (layer-shell is
//! the proper wlroots-wide answer, future work).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

pub const POPUP_LABEL: &str = "popup";
pub const POPUP_W: f64 = 360.0;
pub const POPUP_H: f64 = 440.0;
pub const POPUP_TITLE: &str = "Kariba Panel";

/// Gap between the cursor/screen edge and the popup.
const MARGIN: f64 = 8.0;

/// Real window size as Hyprland reports it. GTK/WebKit wrap the requested
/// 360x440 content in extra invisible margins, so the compositor-side box
/// is bigger than what we ask for; placement must use the real size.
/// Learned on first open, persisted so it survives restarts.
static ACTUAL_SIZE: Mutex<Option<(f64, f64)>> = Mutex::new(None);

/// Position the popup's next incarnation: inject a Hyprland window rule
/// with exact clamped coordinates for the upcoming window creation. Call
/// from any thread before building the popup window. No-op off Hyprland;
/// on failure the popup simply opens wherever Hyprland puts it.
pub fn prepare() {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return;
    }
    if let Err(e) = prepare_inner() {
        log(&format!("leaving popup where the compositor puts it: {e}"));
    }
}

fn prepare_inner() -> Result<(), String> {
    let (cx, cy) = cursor_pos()?;
    let mon = monitor_containing(cx, cy).ok_or("cursor not on any known monitor")?;
    // Usable area: monitor minus the reserved strips (bars, docks).
    let (ux0, uy0) = (mon.x + mon.reserved.0, mon.y + mon.reserved.1);
    let (ux1, uy1) = (
        mon.x + mon.w - mon.reserved.2,
        mon.y + mon.h - mon.reserved.3,
    );
    let (w, h) = popup_size();
    // Anchor at the cursor and expand away from the nearest screen edges,
    // like a tray popup in any desktop environment: click in the top-right
    // corner, get the panel just below-left of the pointer.
    let x = if cx >= mon.x + mon.w / 2.0 {
        cx - w - MARGIN
    } else {
        cx + MARGIN
    };
    let y = if cy >= mon.y + mon.h / 2.0 {
        cy - h - MARGIN
    } else {
        cy + MARGIN
    };
    // Clamp so the panel keeps at least MARGIN from every edge of the
    // usable area, whatever monitor/corner it opens on.
    let x = x.clamp(ux0 + MARGIN, (ux1 - w - MARGIN).max(ux0 + MARGIN));
    let y = y.clamp(uy0 + MARGIN, (uy1 - h - MARGIN).max(uy0 + MARGIN));
    // Rule coordinates are monitor-local.
    let lx = (x - mon.x).round() as i32;
    let ly = (y - mon.y).round() as i32;
    log(&format!(
        "requesting popup at monitor-local ({lx}, {ly}) [global ({}, {}), usable ({}, {})-({}, {})]",
        x.round(),
        y.round(),
        ux0.round(),
        uy0.round(),
        ux1.round(),
        uy1.round()
    ));

    // Same rule name on every click, so this replaces the previous one
    // instead of accumulating.
    hyprctl(&[
        "eval",
        &format!(
            r#"hl.window_rule({{ name = "kariba-tray-popup", match = {{ title = "^{POPUP_TITLE}$" }}, float = true, no_anim = true, move = {{ {lx}, {ly} }} }})"#
        ),
    ])
    .map(|_| ())
}

/// Window size to place: the real compositor-side size once learned from a
/// previous open (persisted across restarts), else the requested content
/// size.
fn popup_size() -> (f64, f64) {
    let mut guard = ACTUAL_SIZE.lock().unwrap();
    if guard.is_none() {
        *guard = read_size_file();
    }
    guard.unwrap_or((POPUP_W, POPUP_H))
}

fn size_file_path() -> Option<PathBuf> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    let dir = config_home.join("kariba");
    fs::create_dir_all(&dir).ok()?;
    Some(dir.join("tray_popup_size"))
}

fn read_size_file() -> Option<(f64, f64)> {
    let path = size_file_path()?;
    let text = fs::read_to_string(path).ok()?;
    let mut nums = text
        .split_whitespace()
        .filter_map(|s| s.parse::<f64>().ok());
    let (w, h) = (nums.next()?, nums.next()?);
    (w > 0.0 && h > 0.0).then_some((w, h))
}

fn write_size_file(w: f64, h: f64) {
    if let Some(path) = size_file_path() {
        let _ = fs::write(path, format!("{w} {h}\n"));
    }
}

/// Log the popup's actual position/size as Hyprland sees it, shortly after
/// it opens (call from a background thread), and remember the size so the
/// next open is placed with the real dimensions.
pub fn log_geometry() {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return;
    }
    let Ok(out) = hyprctl(&["clients", "-j"]) else {
        return;
    };
    let Ok(clients) = serde_json::from_str::<Vec<serde_json::Value>>(&out) else {
        return;
    };
    for c in &clients {
        if c.get("title").and_then(|t| t.as_str()) == Some(POPUP_TITLE) {
            let at = c.get("at").map(|a| a.to_string()).unwrap_or_default();
            let size = c.get("size").map(|s| s.to_string()).unwrap_or_default();
            if let Some(arr) = c.get("size").and_then(|s| s.as_array())
                && arr.len() == 2
                && let (Some(w), Some(h)) = (arr[0].as_f64(), arr[1].as_f64())
                && w > 0.0
                && h > 0.0
            {
                let mut guard = ACTUAL_SIZE.lock().unwrap();
                if guard.is_none() {
                    log(&format!("learned real popup size {w}x{h}"));
                }
                if guard.as_ref() != Some(&(w, h)) {
                    write_size_file(w, h);
                }
                *guard = Some((w, h));
            }
            log(&format!("actual popup: at {at}, size {size}"));
            return;
        }
    }
    log("actual popup: not found among clients");
}

/// Global cursor position from `hyprctl cursorpos` ("x, y").
fn cursor_pos() -> Result<(f64, f64), String> {
    let out = hyprctl(&["cursorpos"])?;
    let mut parts = out.split(',');
    let x: f64 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| format!("unparseable cursorpos: {out:?}"))?;
    let y: f64 = parts
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| format!("unparseable cursorpos: {out:?}"))?;
    Ok((x, y))
}

/// Monitor geometry (global) plus reserved strips [left, top, right,
/// bottom] claimed by bars/docks.
struct Monitor {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    reserved: (f64, f64, f64, f64),
}

/// The monitor containing the point.
fn monitor_containing(px: f64, py: f64) -> Option<Monitor> {
    let out = hyprctl(&["monitors", "-j"]).ok()?;
    let monitors: Vec<serde_json::Value> = serde_json::from_str(&out).ok()?;
    for m in &monitors {
        let x = m.get("x")?.as_f64()?;
        let y = m.get("y")?.as_f64()?;
        let w = m.get("width")?.as_f64()?;
        let h = m.get("height")?.as_f64()?;
        if px >= x && px < x + w && py >= y && py < y + h {
            let r = m.get("reserved").and_then(|r| r.as_array());
            let at = |i: usize| r.and_then(|r| r.get(i)).and_then(|v| v.as_f64());
            return Some(Monitor {
                x,
                y,
                w,
                h,
                reserved: (
                    at(0).unwrap_or(0.0),
                    at(1).unwrap_or(0.0),
                    at(2).unwrap_or(0.0),
                    at(3).unwrap_or(0.0),
                ),
            });
        }
    }
    None
}

fn hyprctl(args: &[&str]) -> Result<String, String> {
    let out = Command::new("hyprctl")
        .args(args)
        .output()
        .map_err(|e| format!("hyprctl failed to run: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() || stdout.trim_start().starts_with("error") {
        let mut msg = stdout.trim().to_string();
        if !stderr.trim().is_empty() {
            if !msg.is_empty() {
                msg.push_str(" | ");
            }
            msg.push_str(stderr.trim());
        }
        return Err(msg);
    }
    Ok(stdout.into_owned())
}

fn log(msg: &str) {
    eprintln!("[tray] {msg}");
}
