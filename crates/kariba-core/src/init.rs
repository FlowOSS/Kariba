use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitSystem {
    Systemd,
    OpenRc,
    Runit,
    S6,
    Dinit,
    Unknown,
}

impl fmt::Display for InitSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            InitSystem::Systemd => "systemd",
            InitSystem::OpenRc => "OpenRC",
            InitSystem::Runit => "runit",
            InitSystem::S6 => "s6",
            InitSystem::Dinit => "dinit",
            InitSystem::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

pub fn detect_init() -> InitSystem {
    detect_init_at(Path::new("/"))
}

pub fn detect_init_at(root: &Path) -> InitSystem {
    const RUN_PROBES: [(InitSystem, &str); 5] = [
        (InitSystem::Systemd, "run/systemd/system"),
        (InitSystem::OpenRc, "run/openrc"),
        (InitSystem::Runit, "run/runit"),
        (InitSystem::S6, "run/s6"),
        (InitSystem::Dinit, "run/dinit"),
    ];
    for (init, rel) in RUN_PROBES {
        if root.join(rel).exists() {
            return init;
        }
    }

    const ETC_PROBES: [(InitSystem, &str); 4] = [
        (InitSystem::OpenRc, "etc/runlevels"),
        (InitSystem::Dinit, "etc/dinit.d"),
        (InitSystem::Runit, "etc/sv"),
        (InitSystem::S6, "etc/s6"),
    ];
    for (init, rel) in ETC_PROBES {
        if root.join(rel).exists() {
            return init;
        }
    }

    if let Ok(comm) = fs::read_to_string(root.join("proc/1/comm")) {
        match comm.trim() {
            "systemd" => return InitSystem::Systemd,
            "runit" => return InitSystem::Runit,
            "s6-svscan" => return InitSystem::S6,
            "dinit" => return InitSystem::Dinit,
            _ => {}
        }
    }

    InitSystem::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fake_root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn detects_systemd_via_run() {
        let root = fake_root();
        fs::create_dir_all(root.path().join("run/systemd/system")).unwrap();
        assert_eq!(detect_init_at(root.path()), InitSystem::Systemd);
    }

    #[test]
    fn detects_openrc_via_run() {
        let root = fake_root();
        fs::create_dir_all(root.path().join("run/openrc")).unwrap();
        assert_eq!(detect_init_at(root.path()), InitSystem::OpenRc);
    }

    #[test]
    fn detects_openrc_via_etc_runlevels() {
        let root = fake_root();
        fs::create_dir_all(root.path().join("etc/runlevels")).unwrap();
        assert_eq!(detect_init_at(root.path()), InitSystem::OpenRc);
    }

    #[test]
    fn falls_back_to_proc1_comm() {
        let root = fake_root();
        fs::create_dir_all(root.path().join("proc/1")).unwrap();
        fs::write(root.path().join("proc/1/comm"), "systemd\n").unwrap();
        assert_eq!(detect_init_at(root.path()), InitSystem::Systemd);
    }

    #[test]
    fn empty_root_is_unknown() {
        let root = fake_root();
        assert_eq!(detect_init_at(root.path()), InitSystem::Unknown);
    }

    #[test]
    fn detects_this_host() {
        assert_ne!(detect_init(), InitSystem::Unknown);
    }
}
