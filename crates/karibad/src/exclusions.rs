use kariba_core::config::Settings;
use kariba_core::paths;
use std::path::{Path, PathBuf};

// User-configurable scan exclusions, snapshotted from Settings when a scan
// starts or the watcher boots. Path entries act as prefixes; extension
// entries are `*.ext` patterns matched case-insensitively against the file
// extension.
pub struct Exclusions {
    prefixes: Vec<PathBuf>,
    extensions: Vec<String>,
}

impl Exclusions {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            prefixes: settings
                .exclusions
                .paths
                .iter()
                .map(|p| paths::expand_tilde(Path::new(p.trim())))
                .filter(|p| !p.as_os_str().is_empty())
                .collect(),
            extensions: settings
                .exclusions
                .extensions
                .iter()
                .filter_map(|e| e.trim().strip_prefix("*."))
                .map(str::to_lowercase)
                .collect(),
        }
    }

    // Structural skips the daemon adds on top of user settings (quarantine
    // blobs must never be re-scanned; the database churns on every event).
    pub fn add_prefix(&mut self, path: PathBuf) {
        if !self.prefixes.contains(&path) {
            self.prefixes.push(path);
        }
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        if self.prefixes.iter().any(|prefix| path.starts_with(prefix)) {
            return true;
        }
        if self.extensions.is_empty() {
            return false;
        }
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| self.extensions.contains(&ext.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with(paths: &[&str], extensions: &[&str]) -> Settings {
        let mut s = Settings::default();
        s.exclusions.paths = paths.iter().map(|s| (*s).to_string()).collect();
        s.exclusions.extensions = extensions.iter().map(|s| (*s).to_string()).collect();
        s
    }

    #[test]
    fn prefix_and_extension_matching() {
        let e = Exclusions::from_settings(&settings_with(&["/home/me/vms"], &["*.iso"]));
        assert!(e.is_excluded(Path::new("/home/me/vms/disk.img")));
        assert!(!e.is_excluded(Path::new("/home/me/docs")));
        assert!(e.is_excluded(Path::new("/anywhere/movie.ISO")));
        assert!(!e.is_excluded(Path::new("/anywhere/movie.is")));
    }

    #[test]
    fn added_prefixes_apply() {
        let mut e = Exclusions::from_settings(&settings_with(&[], &[]));
        e.add_prefix(PathBuf::from("/var/lib/kariba"));
        assert!(e.is_excluded(Path::new("/var/lib/kariba/quarantine/1.quar")));
    }
}
