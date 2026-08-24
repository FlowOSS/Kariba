use clap::{Args, Parser, Subcommand};
use kariba_core::config::Settings;
use kariba_core::paths;
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, ScanParams, ScanProgress, ScanResult, SettingsSetParams,
    StatusResult, ThreatHistoryItem, ThreatStatusFilter, method,
};
use kariba_ipc::{Client, Notification};
use kariba_survey::{CheckStatus, SurveyReport, run_survey};
use serde_json::Value;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "kariba-cli", version, about = "Command-line client for Kariba")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify engines, services, and dependencies (runs locally, no daemon needed)
    Survey,
    /// Show daemon status
    Status,
    /// Scan paths with the daemon
    Scan {
        /// Paths to scan
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Quarantine detected threats (overrides the daemon default)
        #[arg(long, conflicts_with = "no_quarantine")]
        quarantine: bool,
        /// Do not quarantine detected threats (overrides the daemon default)
        #[arg(long)]
        no_quarantine: bool,
    },
    /// Manage quarantined files
    Quarantine(QuarantineArgs),
    /// Show detection history (every verdict, including resolved quarantines)
    Threats {
        /// Filter by status: detected, quarantined, restored, deleted
        #[arg(long)]
        status: Option<String>,
    },
    /// View or change daemon settings
    Settings(SettingsArgs),
}

#[derive(Args)]
struct SettingsArgs {
    #[command(subcommand)]
    action: Option<SettingsAction>,
}

#[derive(Subcommand)]
enum SettingsAction {
    /// Change one setting, e.g. `set realtime.enabled false`
    Set { key: String, value: String },
    /// Re-add any missing built-in exclusions (/proc, /sys, /dev, /run)
    RestoreBuiltins,
}

#[derive(Args)]
struct QuarantineArgs {
    #[command(subcommand)]
    action: QuarantineAction,
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List quarantined items
    List,
    /// Restore a quarantined item to its original location
    Restore { id: u64 },
    /// Permanently delete a quarantined item
    Delete { id: u64 },
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Survey => {
            let report = run_survey();
            print_survey(&report);
            if report.worst() == CheckStatus::Failed {
                1
            } else {
                0
            }
        }
        Command::Status => match with_daemon(|client| {
            let value = client.call(method::STATUS, Value::Null)?;
            let status: StatusResult = serde_json::from_value(value)
                .map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))?;
            println!(
                "karibad {} · up {}s · protection {}",
                status.daemon_version,
                status.uptime_secs,
                if status.protection_enabled {
                    "on"
                } else {
                    "off"
                }
            );
            println!(
                "real-time: {} ({})",
                if status.realtime_active {
                    "active"
                } else {
                    "inactive"
                },
                status.realtime_detail
            );
            println!(
                "scans: {} · threats: {} · quarantined: {}",
                status.scans_total, status.threats_total, status.quarantined_items
            );
            Ok(0)
        }) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Command::Scan {
            paths,
            quarantine,
            no_quarantine,
        } => match with_daemon(|client| {
            let paths: Vec<PathBuf> = paths
                .iter()
                .map(|p| kariba_core::paths::expand_tilde(p))
                .collect();
            let kind = match paths.as_slice() {
                [p] if p.as_os_str() == "/" => "full",
                _ => "custom",
            };
            let quarantine = match (quarantine, no_quarantine) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            };
            let params = ScanParams {
                paths,
                quarantine,
                kind: kind.into(),
            };
            let interactive = std::io::stdout().is_terminal();
            let value = client.call_with_notifications(
                method::SCAN_START,
                serde_json::to_value(params).unwrap_or_default(),
                |notification| print_progress(notification, interactive),
            )?;
            let result: ScanResult = serde_json::from_value(value)
                .map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))?;
            if interactive {
                println!();
            }
            println!(
                "scanned {} files in {}ms · {} threat(s) found · {} quarantined",
                result.files_scanned, result.duration_ms, result.threats_found, result.quarantined
            );
            Ok(if result.threats_found > 0 { 2 } else { 0 })
        }) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Command::Quarantine(args) => match run_quarantine(args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Command::Threats { status } => match run_threats(status) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        Command::Settings(args) => match run_settings(args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
    };
    std::process::exit(exit_code);
}

fn with_daemon<F>(action: F) -> Result<i32, kariba_ipc::RpcError>
where
    F: FnOnce(&mut Client) -> Result<i32, kariba_ipc::RpcError>,
{
    let mut client = kariba_ipc::connect_daemon().map_err(|e| {
        let tried = paths::socket_candidates()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        kariba_ipc::RpcError::new(
            -32000,
            format!("cannot reach karibad (tried {tried}): {e}. Start it first: karibad"),
        )
    })?;
    action(&mut client)
}

fn print_progress(notification: &Notification, interactive: bool) {
    if notification.method != method::SCAN_PROGRESS {
        return;
    }
    let Ok(progress) = serde_json::from_value::<ScanProgress>(notification.params.clone()) else {
        return;
    };
    if progress.files_total == 0 && progress.files_scanned == 0 {
        return;
    }
    if interactive {
        print!(
            "\r\x1b[2K  {}/{} files · {} threat(s) · {}",
            progress.files_scanned, progress.files_total, progress.threats_found, progress.current
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
    } else {
        println!(
            "  {}/{} files · {} threat(s) · {}",
            progress.files_scanned, progress.files_total, progress.threats_found, progress.current
        );
    }
}

fn run_quarantine(args: QuarantineArgs) -> Result<i32, kariba_ipc::RpcError> {
    match args.action {
        QuarantineAction::List => with_daemon(|client| {
            let value = client.call(method::QUARANTINE_LIST, Value::Null)?;
            let items: Vec<QuarantineItem> = serde_json::from_value(value)
                .map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))?;
            if items.is_empty() {
                println!("quarantine is empty");
                return Ok(0);
            }
            const HEADER: [&str; 4] = ["ID", "ENGINE", "SIGNATURE", "ORIGINAL PATH"];
            println!(
                "{:<4} {:<12} {:<24} {}",
                HEADER[0], HEADER[1], HEADER[2], HEADER[3]
            );
            for item in items {
                println!(
                    "{:<4} {:<12} {:<24} {}",
                    item.id, item.engine, item.signature, item.original_path
                );
            }
            Ok(0)
        }),
        QuarantineAction::Restore { id } => with_daemon(|client| {
            let value = client.call(
                method::QUARANTINE_RESTORE,
                serde_json::to_value(IdParams { id }).unwrap_or_default(),
            )?;
            println!("restored to {}", value.as_str().unwrap_or("?"));
            Ok(0)
        }),
        QuarantineAction::Delete { id } => with_daemon(|client| {
            client.call(
                method::QUARANTINE_DELETE,
                serde_json::to_value(IdParams { id }).unwrap_or_default(),
            )?;
            println!("deleted quarantine item {id}");
            Ok(0)
        }),
    }
}

fn run_threats(status: Option<String>) -> Result<i32, kariba_ipc::RpcError> {
    with_daemon(|client| {
        let filter = ThreatStatusFilter { status };
        let value = client.call(
            method::THREATS_LIST,
            serde_json::to_value(filter).unwrap_or_default(),
        )?;
        let items: Vec<ThreatHistoryItem> = serde_json::from_value(value)
            .map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))?;
        if items.is_empty() {
            println!("no detections recorded");
            return Ok(0);
        }
        const HEADER: [&str; 5] = ["WHEN", "VERDICT", "ENGINE", "SIGNATURE", "PATH"];
        println!(
            "{:<10} {:<12} {:<12} {:<24} {}",
            HEADER[0], HEADER[1], HEADER[2], HEADER[3], HEADER[4]
        );
        for item in items {
            println!(
                "{:<10} {:<12} {:<12} {:<24} {}",
                ago(item.detected_at),
                item.status,
                item.engine,
                item.signature,
                item.path
            );
        }
        Ok(0)
    })
}

fn ago(unix: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let delta = now.saturating_sub(unix);
    match delta {
        s if s < 60 => format!("{s}s ago"),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

fn run_settings(args: SettingsArgs) -> Result<i32, kariba_ipc::RpcError> {
    match args.action {
        None => with_daemon(|client| {
            let value = client.call(method::SETTINGS_GET, Value::Null)?;
            let settings: Settings = serde_json::from_value(value)
                .map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))?;
            print!("{}", settings.to_toml());
            Ok(0)
        }),
        Some(SettingsAction::Set { key, value }) => with_daemon(|client| {
            let mut settings = get_settings(client)?;
            apply_key(&mut settings, &key, &value)?;
            set_settings(client, settings)?;
            println!(
                "{key} updated (saved to {})",
                paths::config_path().display()
            );
            Ok(0)
        }),
        Some(SettingsAction::RestoreBuiltins) => with_daemon(|client| {
            let mut settings = get_settings(client)?;
            if settings.restore_builtins() {
                set_settings(client, settings)?;
                println!(
                    "built-in exclusions restored (saved to {})",
                    paths::config_path().display()
                );
            } else {
                println!("all built-in exclusions already present");
            }
            Ok(0)
        }),
    }
}

fn get_settings(client: &mut Client) -> Result<Settings, kariba_ipc::RpcError> {
    let value = client.call(method::SETTINGS_GET, Value::Null)?;
    serde_json::from_value(value).map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))
}

fn set_settings(client: &mut Client, settings: Settings) -> Result<(), kariba_ipc::RpcError> {
    let params = serde_json::to_value(SettingsSetParams { settings })
        .map_err(|e| kariba_ipc::RpcError::new(-32000, e.to_string()))?;
    client.call(method::SETTINGS_SET, params)?;
    Ok(())
}

fn apply_key(settings: &mut Settings, key: &str, value: &str) -> Result<(), kariba_ipc::RpcError> {
    fn parse_bool(value: &str) -> Result<bool, kariba_ipc::RpcError> {
        match value {
            "true" | "on" | "1" => Ok(true),
            "false" | "off" | "0" => Ok(false),
            _ => Err(kariba_ipc::RpcError::new(
                -32602,
                format!("expected true/false, got: {value}"),
            )),
        }
    }
    fn parse_list(value: &str) -> Vec<String> {
        value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
    match key {
        "realtime.enabled" => settings.realtime.enabled = parse_bool(value)?,
        "realtime.auto_quarantine" => settings.realtime.auto_quarantine = parse_bool(value)?,
        "scan.default_quarantine" => settings.scan.default_quarantine = parse_bool(value)?,
        "exclusions.paths" => settings.exclusions.paths = parse_list(value),
        "exclusions.extensions" => settings.exclusions.extensions = parse_list(value),
        other => {
            return Err(kariba_ipc::RpcError::new(
                -32602,
                format!(
                    "unknown key: {other}. Valid keys: realtime.enabled, \
                     realtime.auto_quarantine, scan.default_quarantine, \
                     exclusions.paths, exclusions.extensions"
                ),
            ));
        }
    }
    Ok(())
}

fn print_survey(report: &SurveyReport) {
    let p = palette();

    println!(
        "{}host:{} {} · init: {}",
        p.bold, p.reset, report.distro, report.init
    );
    println!();

    let mut current_engine = String::new();
    for check in &report.checks {
        if check.engine != current_engine {
            current_engine.clone_from(&check.engine);
            println!("{}{}{}", p.bold, check.engine, p.reset);
        }

        let (color, symbol) = match check.status {
            CheckStatus::Ok => (p.green, "●"),
            CheckStatus::Warning => (p.yellow, "▲"),
            CheckStatus::Failed => (p.red, "✕"),
        };
        println!(
            "  {}{}{} {:<20} {}{}{}",
            color, symbol, p.reset, check.component, p.dim, check.detail, p.reset
        );
        if let Some(suggestion) = &check.suggestion {
            println!("      {}↳ fix:{} {}", p.bold, p.reset, suggestion);
        }
    }

    let (ok, warn, fail) = report.counts();
    println!();
    println!(
        "{}summary:{} {}{} ok{} · {}{} warning(s){} · {}{} failure(s){}",
        p.bold, p.reset, p.green, ok, p.reset, p.yellow, warn, p.reset, p.red, fail, p.reset
    );
}

struct Palette {
    green: &'static str,
    yellow: &'static str,
    red: &'static str,
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
}

const COLOR: Palette = Palette {
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    red: "\x1b[31m",
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    reset: "\x1b[0m",
};

const PLAIN: Palette = Palette {
    green: "",
    yellow: "",
    red: "",
    bold: "",
    dim: "",
    reset: "",
};

fn palette() -> &'static Palette {
    if std::io::stdout().is_terminal() {
        &COLOR
    } else {
        &PLAIN
    }
}
