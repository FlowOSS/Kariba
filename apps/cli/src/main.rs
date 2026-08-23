use clap::{Parser, Subcommand};
use kariba_survey::{CheckStatus, SurveyReport, run_survey};
use std::io::IsTerminal;

#[derive(Parser)]
#[command(name = "kariba-cli", version, about = "Command-line client for Kariba")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify engines, services, and dependencies
    Survey,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Survey => {
            let report = run_survey();
            print_report(&report);
            if report.worst() == CheckStatus::Failed {
                std::process::exit(1);
            }
        }
    }
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

fn print_report(report: &SurveyReport) {
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
