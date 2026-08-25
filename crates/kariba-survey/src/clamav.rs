use kariba_core::clamav;
use kariba_core::{Distro, DistroFamily, InitSystem};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::report::{CheckResult, CheckStatus};

const ENGINE: &str = "ClamAV";
const DB_WARN_AGE: Duration = Duration::from_secs(3 * 24 * 3600);
const DB_FAIL_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

pub fn check(distro: &Distro, init: InitSystem) -> Vec<CheckResult> {
    let mut results = Vec::new();
    check_binary(distro, init, &mut results);
    check_service(distro, init, &mut results);
    check_socket(&mut results);
    check_database(distro, &mut results);
    check_config_tuning(init, &mut results);
    results
}

fn ok(component: &str, detail: String) -> CheckResult {
    result(component, CheckStatus::Ok, detail, None)
}

fn warn(component: &str, detail: String, suggestion: Option<String>) -> CheckResult {
    result(component, CheckStatus::Warning, detail, suggestion)
}

fn fail(component: &str, detail: String, suggestion: Option<String>) -> CheckResult {
    result(component, CheckStatus::Failed, detail, suggestion)
}

fn result(
    component: &str,
    status: CheckStatus,
    detail: String,
    suggestion: Option<String>,
) -> CheckResult {
    CheckResult {
        engine: ENGINE.into(),
        component: component.into(),
        status,
        detail,
        suggestion,
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn check_binary(distro: &Distro, init: InitSystem, results: &mut Vec<CheckResult>) {
    match find_in_path("clamd") {
        Some(path) => {
            results.push(ok("clamd binary", format!("{}", path.display())));
        }
        None => {
            let mut suggestion = install_cmd(distro.family);
            if let Some(init_pkg) = init_pkg_hint(distro.family, init) {
                let _ = write!(&mut suggestion, " && {}", init_pkg);
            }
            results.push(fail(
                "clamd binary",
                "clamd not found in PATH".into(),
                Some(suggestion),
            ));
        }
    }
}

fn check_service(distro: &Distro, init: InitSystem, results: &mut Vec<CheckResult>) {
    if process_running("clamd") {
        results.push(ok("clamd process", "running".into()));
        return;
    }

    let detail = "not running".to_string();
    let suggestion = match init {
        InitSystem::OpenRc => {
            if Path::new("/etc/init.d/clamd").exists() {
                Some("sudo rc-service clamd start".into())
            } else {
                init_pkg_hint(distro.family, init)
            }
        }
        InitSystem::Systemd => Some("sudo systemctl start clamav-daemon".into()),
        _ => None,
    };
    results.push(fail("clamd process", detail, suggestion));
}

fn process_running(name: &str) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        if let Ok(comm) = fs::read_to_string(entry.path().join("comm"))
            && comm.trim() == name
        {
            return true;
        }
    }
    false
}

fn check_socket(results: &mut Vec<CheckResult>) {
    for path in clamav::socket_candidates() {
        if let Ok(mut stream) = UnixStream::connect(&path) {
            let detail = match query_version(&mut stream) {
                Some(version) => format!("{} — {}", path.display(), version),
                None => format!("{} reachable", path.display()),
            };
            results.push(ok("clamd socket", detail));
            return;
        }
    }
    results.push(fail(
        "clamd socket",
        "no reachable clamd socket".into(),
        Some("start the clamd service (see process check)".into()),
    ));
}

fn query_version(stream: &mut UnixStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream.write_all(b"VERSION\n").ok()?;
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

/// clamd.conf tuning advice (PLAN.md Known Issues #3): StreamMaxLength
/// drives how much karibad can stream per file; MaxThreads our usable
/// concurrency; TemporaryDirectory must hold the spool.
fn check_config_tuning(init: InitSystem, results: &mut Vec<CheckResult>) {
    let Ok(content) = fs::read_to_string(clamav::CLAMD_CONF) else {
        results.push(warn(
            "clamd tuning",
            format!("{} not found; cannot verify tuning", clamav::CLAMD_CONF),
            None,
        ));
        return;
    };
    let restart = restart_cmd(init);
    let recommended = recommended_stream_max();

    match clamav::stream_max_length_from_config(&content) {
        Some(value) if value >= recommended => {
            results.push(ok(
                "StreamMaxLength",
                format!("{} ({} needed)", mb(value), mb(recommended)),
            ));
        }
        Some(value) => {
            results.push(warn(
                "StreamMaxLength",
                format!("{} is low ({} recommended)", mb(value), mb(recommended)),
                Some(format!(
                    "set 'StreamMaxLength {}M' in {} and restart clamd ({restart})",
                    recommended / (1024 * 1024),
                    clamav::CLAMD_CONF
                )),
            ));
        }
        None => {
            results.push(warn(
                "StreamMaxLength",
                format!(
                    "not set (clamd default {} MB, {} recommended)",
                    clamav::DEFAULT_STREAM_MAX / (1024 * 1024),
                    mb(recommended)
                ),
                Some(format!(
                    "add 'StreamMaxLength {}M' to {} and restart clamd ({restart})",
                    recommended / (1024 * 1024),
                    clamav::CLAMD_CONF
                )),
            ));
        }
    }

    match clamav::max_threads_from_config(&content) {
        Some(threads) if threads < MIN_THREADS => {
            results.push(warn(
                "MaxThreads",
                format!("{threads} is low for real-time scanning"),
                Some(format!(
                    "set 'MaxThreads {MIN_THREADS}' in {} and restart clamd ({restart})",
                    clamav::CLAMD_CONF
                )),
            ));
        }
        Some(threads) => {
            results.push(ok("MaxThreads", format!("{threads}")));
        }
        None => {
            results.push(ok("MaxThreads", "not set (clamd default 10)".to_string()));
        }
    }

    let dir = clamav::temporary_directory_from_config(&content).unwrap_or_else(|| "/tmp".into());
    if let (Some(free), true) = (free_bytes(Path::new(&dir)), recommended > 0)
        && free < recommended
    {
        results.push(warn(
            "TemporaryDirectory",
            format!(
                "{dir} has {} free, less than the {} INSTREAM spool needs",
                mb(free),
                mb(recommended)
            ),
            Some("free space or point TemporaryDirectory at a larger disk".into()),
        ));
    }
}

/// Recommended StreamMaxLength: ~5% of RAM, clamped to 32 MB..256 MB.
fn recommended_stream_max() -> u64 {
    const MIN: u64 = 32 * 1024 * 1024;
    const MAX: u64 = 256 * 1024 * 1024;
    let ram = kariba_core::system::total_ram_bytes().unwrap_or(8 * 1024 * 1024 * 1024);
    (ram / 20).clamp(MIN, MAX)
}

fn restart_cmd(init: InitSystem) -> String {
    match init {
        InitSystem::Systemd => "sudo systemctl restart clamav-daemon".into(),
        InitSystem::OpenRc => "sudo rc-service clamd restart".into(),
        _ => "restart the clamd service".into(),
    }
}

fn mb(bytes: u64) -> String {
    format!("{} MB", bytes / (1024 * 1024))
}

fn free_bytes(path: &Path) -> Option<u64> {
    let c_path = std::ffi::CString::new(path.to_str()?).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

const MIN_THREADS: u64 = 8;

fn check_database(distro: &Distro, results: &mut Vec<CheckResult>) {
    let daily = match clamav::daily_db_file() {
        Some(daily) => daily,
        None => {
            let detail = format!("no signature database in {}", clamav::db_dir().display());
            let suggestion = if find_in_path("freshclam").is_none() {
                install_cmd(distro.family)
            } else {
                "sudo freshclam".into()
            };
            results.push(fail("signature database", detail, Some(suggestion)));
            return;
        }
    };

    let age = daily.1.elapsed().ok().unwrap_or(Duration::ZERO);
    let days = age.as_secs() / (24 * 3600);
    let detail = format!(
        "{} is {} day(s) old",
        daily.0.file_name().unwrap_or_default().to_string_lossy(),
        days
    );

    if age > DB_FAIL_AGE {
        results.push(fail(
            "signature database",
            detail,
            Some("sudo freshclam".into()),
        ));
    } else if age > DB_WARN_AGE {
        results.push(warn(
            "signature database",
            detail,
            Some("sudo freshclam".into()),
        ));
    } else {
        results.push(ok("signature database", detail));
    }
}

fn install_cmd(family: DistroFamily) -> String {
    match family {
        DistroFamily::Arch => "sudo pacman -S clamav".into(),
        DistroFamily::Debian => "sudo apt install clamav-daemon".into(),
        DistroFamily::Fedora => "sudo dnf install clamav".into(),
        DistroFamily::Suse => "sudo zypper install clamav".into(),
        DistroFamily::Unknown => "install ClamAV using your package manager".into(),
    }
}

fn init_pkg_hint(family: DistroFamily, init: InitSystem) -> Option<String> {
    match (family, init) {
        (DistroFamily::Arch, InitSystem::OpenRc) => Some("sudo pacman -S clamav-openrc".into()),
        (DistroFamily::Arch, InitSystem::Runit) => Some("sudo pacman -S clamav-runit".into()),
        (DistroFamily::Arch, InitSystem::S6) => Some("sudo pacman -S clamav-s6".into()),
        (DistroFamily::Arch, InitSystem::Dinit) => Some("sudo pacman -S clamav-dinit".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_cmd_per_family() {
        assert_eq!(install_cmd(DistroFamily::Arch), "sudo pacman -S clamav");
        assert_eq!(
            install_cmd(DistroFamily::Debian),
            "sudo apt install clamav-daemon"
        );
    }

    #[test]
    fn init_pkg_hint_artix_openrc() {
        assert_eq!(
            init_pkg_hint(DistroFamily::Arch, InitSystem::OpenRc),
            Some("sudo pacman -S clamav-openrc".into())
        );
        assert_eq!(
            init_pkg_hint(DistroFamily::Debian, InitSystem::OpenRc),
            None
        );
    }

    #[test]
    fn detects_clamav_on_this_host() {
        let distro = kariba_core::detect_distro();
        let results = check(&distro, kariba_core::detect_init());
        assert!(!results.is_empty());
    }

    #[test]
    fn recommended_stream_max_is_clamped() {
        let rec = recommended_stream_max();
        assert!(rec >= 32 * 1024 * 1024);
        assert!(rec <= 256 * 1024 * 1024);
    }

    #[test]
    fn restart_cmd_per_init() {
        assert_eq!(
            restart_cmd(InitSystem::Systemd),
            "sudo systemctl restart clamav-daemon"
        );
        assert_eq!(
            restart_cmd(InitSystem::OpenRc),
            "sudo rc-service clamd restart"
        );
    }
}
