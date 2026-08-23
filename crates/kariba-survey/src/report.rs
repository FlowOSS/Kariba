use kariba_core::{Distro, InitSystem};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    Ok,
    Warning,
    Failed,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warning => "warning",
            CheckStatus::Failed => "failed",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub engine: String,
    pub component: String,
    pub status: CheckStatus,
    pub detail: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SurveyReport {
    pub distro: Distro,
    pub init: InitSystem,
    pub checks: Vec<CheckResult>,
}

impl SurveyReport {
    pub fn worst(&self) -> CheckStatus {
        self.checks.iter().fold(CheckStatus::Ok, |acc, c| {
            use CheckStatus::*;
            match (acc, c.status) {
                (Failed, _) | (_, Failed) => Failed,
                (Warning, _) | (_, Warning) => Warning,
                _ => Ok,
            }
        })
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for c in &self.checks {
            match c.status {
                CheckStatus::Ok => ok += 1,
                CheckStatus::Warning => warn += 1,
                CheckStatus::Failed => fail += 1,
            }
        }
        (ok, warn, fail)
    }
}
