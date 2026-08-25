//! Tray panel popup positioning.
//!
//! Wayland compositors ignore position requests from regular xdg
//! toplevels, so the windowing protocol cannot place the popup. On
//! Hyprland we drive the compositor itself via hyprctl once the window is
//! mapped: find the popup by its window address, set it floating
//! (`float` with `action = "set"`, not a toggle), then `move` it to
//! coordinates computed from the mouse cursor (which is where the user
//! just clicked the tray). Targeting by address means focus is irrelevant.
//!
//! Everything here is best-effort and logged with a `[tray]` prefix: any
//! failure degrades to "popup opens wherever the compositor placed it",
//! never a crash. Other compositors get no positioning yet (layer-shell is
//! the proper wlroots-wide answer, future work).

use std::process::Command;
use std::time::Duration;

pub const POPUP_LABEL: &str = "popup";
pub const POPUP_W: f64 = 360.0;
pub const POPUP_H: f64 = 440.0;
pub const POPUP_TITLE: &str = "Kariba Panel";

/// Entry point: position the (just shown) popup near the cursor. Spawns a
/// thread because the window needs a moment to map before hyprctl can see
/// it. No-op off Hyprland.
pub fn place() {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return;
    }
    std::thread::spawn(move || {
        // Give the compositor time to map the window into its client list.
        std::thread::sleep(Duration::from_millis(300));
        if let Err(e) = place_inner() {
            log(&format!("leaving popup where the compositor put it: {e}"));
        }
    });
}

fn place_inner() -> Result<(), String> {
    let (cx, cy) = cursor_pos()?;
    let mon = monitor_containing(cx, cy).unwrap_or((0.0, 0.0, 1920.0, 1080.0));
    let (x, y) = popup_target(cx, cy, mon);

    let addr = popup_address()?;

    // `float` with action "set" (a toggle would un-float an already
    // floating window), then `move` to the computed spot. Both target the
    // popup by address, so they don't depend on focus.
    dispatch_lua(&format!(
        r#"hl.dsp.window.float({{ action = "set", window = "address:{addr}" }}"#
    ))?;
    std::thread::sleep(Duration::from_millis(150));
    dispatch_lua(&format!(
        r#"hl.dsp.window.move({{ x = {x}, y = {y}, relative = false, window = "address:{addr}" }}"#
    ))?;

    log(&format!(
        "moved popup to ({x}, {y}) near cursor ({cx}, {cy})"
    ));
    Ok(())
}

/// Target top-left for the popup given the cursor and its monitor bounds:
/// centered on the cursor horizontally, placed above the cursor (or below
/// it when there's no room above), always clamped inside the monitor.
fn popup_target(cx: f64, cy: f64, mon: (f64, f64, f64, f64)) -> (i32, i32) {
    let (mx, my, mw, mh) = mon;
    let margin = 12.0;
    let x = (cx - POPUP_W / 2.0).clamp(mx, (mx + mw - POPUP_W).max(mx));
    let mut y = cy - POPUP_H - margin;
    if y < my {
        y = cy + margin;
    }
    let y = y.clamp(my, (my + mh - POPUP_H).max(my));
    (x.round() as i32, y.round() as i32)
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

/// Geometry (x, y, w, h) of the monitor containing the point.
fn monitor_containing(px: f64, py: f64) -> Option<(f64, f64, f64, f64)> {
    let out = hyprctl(&["monitors", "-j"]).ok()?;
    let monitors: Vec<serde_json::Value> = serde_json::from_str(&out).ok()?;
    for m in &monitors {
        let x = m.get("x")?.as_f64()?;
        let y = m.get("y")?.as_f64()?;
        let w = m.get("width")?.as_f64()?;
        let h = m.get("height")?.as_f64()?;
        if px >= x && px < x + w && py >= y && py < y + h {
            return Some((x, y, w, h));
        }
    }
    None
}

/// Window address ("0x…") of the popup, matched by title.
fn popup_address() -> Result<String, String> {
    let out = hyprctl(&["clients", "-j"])?;
    let clients: Vec<serde_json::Value> =
        serde_json::from_str(&out).map_err(|e| format!("bad clients json: {e}"))?;
    for c in &clients {
        let title = c.get("title").and_then(|t| t.as_str()).unwrap_or("");
        if title.contains(POPUP_TITLE) {
            return c
                .get("address")
                .and_then(|a| a.as_str())
                .map(|a| a.to_string())
                .ok_or_else(|| "popup client has no address".to_string());
        }
    }
    Err(format!(
        "popup '{POPUP_TITLE}' not found among Hyprland clients"
    ))
}

/// Run a Hyprland Lua dispatch expression (`hyprctl dispatch '<expr>'`).
fn dispatch_lua(expr: &str) -> Result<(), String> {
    hyprctl(&["dispatch", expr]).map(|_| ())
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
