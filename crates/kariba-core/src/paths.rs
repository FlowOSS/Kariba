use std::fs;
use std::path::{Path, PathBuf};

// System paths are only usable by root; picking them by directory
// existence alone breaks non-root clients when a root daemon also runs on
// the same machine (the dirs already exist but are not writable).
fn running_as_root() -> bool {
    current_uid() == Some(0)
}

pub fn runtime_dir() -> PathBuf {
    if running_as_root() {
        let system = PathBuf::from("/run/kariba");
        if fs::create_dir_all(&system).is_ok() {
            return system;
        }
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(xdg).join("kariba");
        if fs::create_dir_all(&dir).is_ok() {
            return dir;
        }
    }
    let dir = PathBuf::from(format!("/tmp/kariba-{}", current_uid().unwrap_or(0)));
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn data_dir() -> PathBuf {
    if running_as_root() {
        let system = PathBuf::from("/var/lib/kariba");
        if fs::create_dir_all(&system).is_ok() {
            return system;
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        let dir = PathBuf::from(xdg).join("kariba");
        let _ = fs::create_dir_all(&dir);
        return dir;
    }
    let dir = home()
        .map(|h| h.join(".local/share/kariba"))
        .unwrap_or_else(|| PathBuf::from("/tmp/kariba-data"));
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("karibad.sock")
}

/// Sockets a client should try in order. The daemon binds `socket_path()`
/// (euid selection), but a client may need a daemon of the other privilege
/// level — the unprivileged GUI talking to a root daemon is the normal case
/// for real-time protection until polkit lands. The euid path stays first,
/// so a same-user daemon always wins when both run side by side.
pub fn socket_candidates() -> Vec<PathBuf> {
    let primary = socket_path();
    if running_as_root() {
        return vec![primary];
    }
    let system = PathBuf::from("/run/kariba/karibad.sock");
    if primary == system {
        vec![primary]
    } else {
        vec![primary, system]
    }
}

pub fn db_path() -> PathBuf {
    data_dir().join("kariba.db")
}

pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

pub fn config_dir() -> PathBuf {
    if running_as_root() {
        let system = PathBuf::from("/etc/kariba");
        if fs::create_dir_all(&system).is_ok() {
            return system;
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("kariba");
    }
    home()
        .map(|h| h.join(".config/kariba"))
        .unwrap_or_else(|| PathBuf::from("/tmp/kariba-config"))
}

pub fn config_path() -> PathBuf {
    config_dir().join("kariba.toml")
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return home().unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(h) = home()
    {
        return h.join(rest);
    }
    path.to_path_buf()
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn current_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_have_expected_components() {
        assert_eq!(socket_path().file_name().unwrap(), "karibad.sock");
        assert_eq!(db_path().file_name().unwrap(), "kariba.db");
        assert_eq!(quarantine_dir().file_name().unwrap(), "quarantine");
        assert_eq!(config_path().file_name().unwrap(), "kariba.toml");
    }

    #[test]
    fn socket_candidates_include_primary_first() {
        let candidates = socket_candidates();
        assert_eq!(candidates[0], socket_path());
    }

    #[test]
    fn uid_is_present() {
        assert!(current_uid().is_some());
    }

    #[test]
    fn expand_tilde_uses_home() {
        let expanded = expand_tilde(Path::new("~/Downloads"));
        assert!(!expanded.to_string_lossy().starts_with('~'));
        assert!(expanded.ends_with("Downloads"));
        assert_eq!(expand_tilde(Path::new("/tmp/x")), PathBuf::from("/tmp/x"));
    }
}
