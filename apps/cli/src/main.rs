use clap::{Args, Parser, Subcommand};
use kariba_core::paths;
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, ScanParams, ScanProgress, ScanResult, StatusResult, method,
};
use kariba_ipc::{Client, Notification};
use kariba_survey::{CheckStatus, SurveyReport, run_survey};
use serde_json::Value;
use std::io::IsTerminal;
use std::path::PathBuf;

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
        /// Quarantine detected threats automatically
        #[arg(long)]
        quarantine: bool,
    },
    /// Manage quarantined files
    Quarantine(QuarantineArgs),
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
                "karibad {} · up {}s",
                status.daemon_version, status.uptime_secs
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
        Command::Scan { paths, quarantine } => match with_daemon(|client| {
            let params = ScanParams { paths, quarantine };
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
    };
    std::process::exit(exit_code);
}

fn with_daemon<F>(action: F) -> Result<i32, kariba_ipc::RpcError>
where
    F: FnOnce(&mut Client) -> Result<i32, kariba_ipc::RpcError>,
{
    let socket = paths::socket_path();
    let mut client = Client::connect(&socket).map_err(|e| {
        kariba_ipc::RpcError::new(
            -32000,
            format!(
                "cannot reach karibad at {} ({e}). Start it first: karibad",
                socket.display()
            ),
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
    if interactive {
        print!(
            "\r\x1b[2K  {} files · {} threat(s) · {}",
            progress.files_scanned, progress.threats_found, progress.current
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
    } else {
        println!(
            "  {} files · {} threat(s) · {}",
            progress.files_scanned, progress.threats_found, progress.current
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
