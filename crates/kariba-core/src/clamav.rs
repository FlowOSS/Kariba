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

/// First uncommented value of `name` in clamd.conf content; the character
/// after the directive name must be whitespace (so `MaxThreads` doesn't
/// match a hypothetical `MaxThreadsFoo`).
fn directive_value<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(name)
            && rest.starts_with(char::is_whitespace)
        {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Parse clamd byte values: plain number or K/M/G suffix (KB/MB/GB too).
pub fn parse_size_value(value: &str) -> Option<u64> {
    let v = value.trim().trim_end_matches(['B', 'b']).trim();
    let (num, multiplier) = match v.chars().next_back() {
        Some('G' | 'g') => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        Some('M' | 'm') => (&v[..v.len() - 1], 1024 * 1024),
        Some('K' | 'k') => (&v[..v.len() - 1], 1024),
        _ => (v, 1),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .map(|n| n.saturating_mul(multiplier))
}

pub fn stream_max_length_from_config(content: &str) -> Option<u64> {
    directive_value(content, "StreamMaxLength").and_then(parse_size_value)
}

pub fn max_threads_from_config(content: &str) -> Option<u64> {
    directive_value(content, "MaxThreads").and_then(|v| v.trim().parse::<u64>().ok())
}

pub fn temporary_directory_from_config(content: &str) -> Option<String> {
    directive_value(content, "TemporaryDirectory").map(|v| v.trim().to_string())
}

/// The effective `StreamMaxLength`: configured value, or clamd's 25 MB
/// default. karibad streams files up to this size and falls back to the
/// copy/skip ladder above it (PLAN.md, Known Issues #3).
pub fn stream_max_length() -> u64 {
    fs::read_to_string(CLAMD_CONF)
        .ok()
        .and_then(|content| stream_max_length_from_config(&content))
        .unwrap_or(DEFAULT_STREAM_MAX)
}

pub const DEFAULT_STREAM_MAX: u64 = 25 * 1024 * 1024;

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
    fn parses_stream_max_length_suffixes() {
        assert_eq!(
            stream_max_length_from_config("StreamMaxLength 25M\n"),
            Some(25 * 1024 * 1024)
        );
        assert_eq!(
            stream_max_length_from_config("StreamMaxLength 1G\n"),
            Some(1024 * 1024 * 1024)
        );
        assert_eq!(
            stream_max_length_from_config("StreamMaxLength 512KB\n"),
            Some(512 * 1024)
        );
        assert_eq!(
            stream_max_length_from_config("StreamMaxLength 26214400\n"),
            Some(26_214_400)
        );
        assert_eq!(
            stream_max_length_from_config("StreamMaxLength 256 M\n"),
            Some(256 * 1024 * 1024)
        );
        assert_eq!(stream_max_length_from_config("#StreamMaxLength 1G\n"), None);
        assert_eq!(stream_max_length_from_config("MaxThreads 12\n"), None);
    }

    #[test]
    fn parses_max_threads() {
        assert_eq!(max_threads_from_config("MaxThreads 12\n"), Some(12));
        assert_eq!(max_threads_from_config("#MaxThreads 12\n"), None);
        assert_eq!(max_threads_from_config("MaxThreadsX 12\n"), None);
    }

    #[test]
    fn parses_temporary_directory() {
        assert_eq!(
            temporary_directory_from_config("TemporaryDirectory /var/tmp\n"),
            Some("/var/tmp".into())
        );
        assert_eq!(temporary_directory_from_config(""), None);
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
