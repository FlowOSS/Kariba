use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

/// Kernel pseudo-filesystems that ship as exclusions in every fresh config.
/// Scanning them is pointless at best and can stall scan engines, so clients
/// badge them and warn before removal — but they are ordinary config entries
/// that the user may delete (and restore).
pub const BUILTIN_EXCLUSION_PATHS: [&str; 4] = ["/proc", "/sys", "/dev", "/run"];

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub realtime: RealtimeSettings,
    pub scan: ScanSettings,
    pub exclusions: ExclusionSettings,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RealtimeSettings {
    pub enabled: bool,
    pub auto_quarantine: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanSettings {
    pub default_quarantine: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExclusionSettings {
    pub paths: Vec<String>,
    pub extensions: Vec<String>,
}

impl Default for RealtimeSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_quarantine: true,
        }
    }
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            default_quarantine: true,
        }
    }
}

impl Default for ExclusionSettings {
    fn default() -> Self {
        Self {
            paths: BUILTIN_EXCLUSION_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            extensions: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "io error: {e}"),
            ConfigError::Parse(e) => write!(f, "parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Settings {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path).map_err(ConfigError::Io)?;
        toml::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Loads the config, or writes and returns defaults when the file does
    /// not exist yet. The boolean reports whether defaults were created.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), ConfigError> {
        if path.exists() {
            return Ok((Self::load(path)?, false));
        }
        let settings = Self::default();
        settings.save(path)?;
        Ok((settings, true))
    }

    /// Atomic write: serialize to a temp sibling, then rename into place.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(ConfigError::Io)?;
        }
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, self.to_toml()).map_err(ConfigError::Io)?;
        fs::rename(&tmp, path).map_err(ConfigError::Io)?;
        Ok(())
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Built-in exclusion paths currently missing from the config.
    pub fn missing_builtins(&self) -> Vec<&'static str> {
        BUILTIN_EXCLUSION_PATHS
            .iter()
            .copied()
            .filter(|builtin| !self.exclusions.paths.iter().any(|p| p == builtin))
            .collect()
    }

    /// Re-adds missing built-in exclusions. Reports whether anything changed.
    pub fn restore_builtins(&mut self) -> bool {
        let missing = self.missing_builtins();
        if missing.is_empty() {
            return false;
        }
        for builtin in missing {
            self.exclusions.paths.push(builtin.to_string());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_protective() {
        let s = Settings::default();
        assert!(s.realtime.enabled);
        assert!(s.realtime.auto_quarantine);
        assert!(s.scan.default_quarantine);
        assert_eq!(s.exclusions.paths, BUILTIN_EXCLUSION_PATHS);
        assert!(s.exclusions.extensions.is_empty());
    }

    #[test]
    fn toml_roundtrip() {
        let mut s = Settings::default();
        s.realtime.enabled = false;
        s.exclusions.extensions.push("*.iso".into());
        let back: Settings = toml::from_str(&s.to_toml()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let s: Settings = toml::from_str("[realtime]\nenabled = false\n").unwrap();
        assert!(!s.realtime.enabled);
        assert!(s.realtime.auto_quarantine);
        assert!(s.scan.default_quarantine);
        assert_eq!(s.exclusions.paths, BUILTIN_EXCLUSION_PATHS);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kariba.toml");
        let mut s = Settings::default();
        s.scan.default_quarantine = false;
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), s);
    }

    #[test]
    fn load_or_create_writes_defaults_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/kariba.toml");
        let (settings, created) = Settings::load_or_create(&path).unwrap();
        assert!(created);
        assert_eq!(settings, Settings::default());
        assert!(path.exists());
        let (_, created) = Settings::load_or_create(&path).unwrap();
        assert!(!created);
    }

    #[test]
    fn restore_builtins_only_adds_missing() {
        let mut s = Settings::default();
        s.exclusions.paths.retain(|p| p != "/dev");
        s.exclusions.paths.push("/home/me/vms".into());
        assert_eq!(s.missing_builtins(), vec!["/dev"]);
        assert!(s.restore_builtins());
        assert!(s.exclusions.paths.contains(&"/dev".to_string()));
        assert!(s.exclusions.paths.contains(&"/home/me/vms".to_string()));
        assert!(!s.restore_builtins());
    }
}
