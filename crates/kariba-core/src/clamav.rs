use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

pub const CLAMD_CONF: &str = "/etc/clamav/clamd.conf";
pub const FRESHCLAM_CONF: &str = "/etc/clamav/freshclam.conf";
pub const DEFAULT_DB_DIR: &str = "/var/lib/clamav";
pub const DEFAULT_SOCKETS: &[&str] = &[
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.sock",
    "/tmp/clamd.socket",
];

pub fn configured_socket() -> Option<String> {
    let content = fs::read_to_string(CLAMD_CONF).ok()?;
    socket_from_config(&content)
}

pub fn socket_from_config(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("LocalSocket") {
            let path = rest.trim();
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
    }
    None
}

pub fn socket_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(configured) = configured_socket() {
        candidates.push(PathBuf::from(configured));
    }
    for path in DEFAULT_SOCKETS {
        let path = PathBuf::from(path);
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }
    candidates
}

pub fn db_dir() -> PathBuf {
    fs::read_to_string(FRESHCLAM_CONF)
        .ok()
        .and_then(|content| db_dir_from_config(&content))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_DIR))
}

pub fn db_dir_from_config(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("DatabaseDirectory") {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub fn daily_db_file() -> Option<(PathBuf, SystemTime)> {
    daily_db_file_in(&db_dir())
}

pub fn daily_db_file_in(dir: &std::path::Path) -> Option<(PathBuf, SystemTime)> {
    let mut best: Option<(PathBuf, SystemTime)> = None;
    for name in ["daily.cvd", "daily.cld"] {
        let candidate = dir.join(name);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        match &best {
            Some((_, current)) if *current >= modified => {}
            _ => best = Some((candidate, modified)),
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_socket_from_config() {
        let content = "# comment\nLocalSocket /run/clamav/clamd.ctl\n";
        assert_eq!(
            socket_from_config(content),
            Some("/run/clamav/clamd.ctl".into())
        );
    }

    #[test]
    fn ignores_commented_socket() {
        let content = "#LocalSocket /tmp/old.sock\n";
        assert_eq!(socket_from_config(content), None);
    }

    #[test]
    fn parses_db_dir_from_config() {
        let content = "DatabaseDirectory /var/lib/clamav\n";
        assert_eq!(db_dir_from_config(content), Some("/var/lib/clamav".into()));
    }

    #[test]
    fn candidates_start_with_configured() {
        let candidates = socket_candidates();
        assert!(!candidates.is_empty());
    }

    #[test]
    fn daily_db_prefers_newest_variant() {
        let dir = tempfile::tempdir().unwrap();
        let cvd = dir.path().join("daily.cvd");
        fs::write(&cvd, b"old").unwrap();
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        let cld = dir.path().join("daily.cld");
        fs::write(&cld, b"new").unwrap();
        let file = fs::File::open(&cld).unwrap();
        file.set_modified(old_time + std::time::Duration::from_secs(120))
            .unwrap();

        let (path, _) = daily_db_file_in(dir.path()).unwrap();
        assert_eq!(path, cld);

        fs::remove_file(&cld).unwrap();
        let (path, _) = daily_db_file_in(dir.path()).unwrap();
        assert_eq!(path, cvd);
    }
}
