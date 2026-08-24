use kariba_core::config::Settings;
use kariba_ipc::client::{reader, respond};
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, RpcError, ScanHistoryItem, ScanParams, SettingsSetParams,
    StatusResult, WireMessage, error_code, method, parse_line,
};
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::db::Db;
use crate::quarantine::Quarantine;
use crate::scanner;

const HISTORY_LIMIT: u64 = 20;

pub struct Daemon {
    started_at: Instant,
    db: Mutex<Db>,
    quarantine: Quarantine,
    active_scans: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    settings: Mutex<Settings>,
    config_path: PathBuf,
}

impl Daemon {
    pub fn new(db: Db, quarantine: Quarantine, settings: Settings, config_path: PathBuf) -> Self {
        Self {
            started_at: Instant::now(),
            db: Mutex::new(db),
            quarantine,
            active_scans: Mutex::new(HashMap::new()),
            settings: Mutex::new(settings),
            config_path,
        }
    }
}

pub fn handle_connection(mut stream: UnixStream, daemon: Arc<Daemon>) {
    let Ok(buf_reader) = reader(&stream) else {
        return;
    };
    for line in buf_reader.lines() {
        let Ok(line) = line else { return };
        let message = match parse_line(&line) {
            Ok(message) => message,
            Err(_) => continue,
        };
        let WireMessage::Request(request) = message else {
            continue;
        };

        let result = dispatch(&daemon, &mut stream, &request.method, request.params);
        respond(&mut stream, request.id, result);
    }
}

fn dispatch(
    daemon: &Daemon,
    stream: &mut UnixStream,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, RpcError> {
    match method {
        method::PING => Ok(serde_json::Value::String("pong".into())),

        method::STATUS => {
            let db = lock_db(daemon)?;
            let (scans_total, threats_total, quarantined_items) = db.counts();
            let protection_enabled = lock_settings(daemon)?.realtime.enabled;
            serde_json::to_value(StatusResult {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                uptime_secs: daemon.started_at.elapsed().as_secs(),
                scans_total,
                threats_total,
                quarantined_items,
                protection_enabled,
            })
            .map_err(server_err)
        }

        method::SURVEY_RUN => {
            let report = kariba_survey::run_survey();
            serde_json::to_value(&report).map_err(server_err)
        }

        method::SCAN_START => {
            let params: ScanParams =
                serde_json::from_value(params).map_err(|e| invalid_params(e.to_string()))?;
            if params.paths.is_empty() {
                return Err(invalid_params("paths must not be empty"));
            }
            for path in &params.paths {
                if !path.exists() {
                    return Err(invalid_params(format!("{} does not exist", path.display())));
                }
            }
            let cancel = Arc::new(AtomicBool::new(false));
            let policy = {
                let settings = lock_settings(daemon)?;
                scanner::ScanPolicy {
                    auto_quarantine: params
                        .quarantine
                        .unwrap_or(settings.scan.default_quarantine),
                    exclusions: scanner::Exclusions::from_settings(&settings),
                }
            };
            let result = scanner::run_scan(
                params,
                &policy,
                stream,
                &daemon.db,
                &daemon.quarantine,
                &daemon.active_scans,
                cancel,
            )?;
            serde_json::to_value(result).map_err(server_err)
        }

        method::SCAN_CANCEL => {
            let requested: Option<IdParams> = serde_json::from_value(params).ok();
            let active = lock_active(daemon)?;
            let mut cancelled = 0u32;
            for (id, flag) in active.iter() {
                if requested.as_ref().is_some_and(|p| p.id != *id) {
                    continue;
                }
                if !flag.swap(true, Ordering::Relaxed) {
                    cancelled += 1;
                }
            }
            Ok(serde_json::json!({ "cancelled": cancelled }))
        }

        method::SCAN_HISTORY => {
            let db = lock_db(daemon)?;
            let items: Vec<ScanHistoryItem> = db
                .list_scans(HISTORY_LIMIT)
                .into_iter()
                .map(|r| ScanHistoryItem {
                    id: r.id,
                    kind: r.kind,
                    paths: r.paths,
                    started_at: r.started_at,
                    finished_at: r.finished_at,
                    files_scanned: r.files_scanned,
                    threats_found: r.threats_found,
                    status: r.status,
                })
                .collect();
            serde_json::to_value(items).map_err(server_err)
        }

        method::QUARANTINE_LIST => {
            let db = lock_db(daemon)?;
            let items: Vec<QuarantineItem> = db
                .list_quarantine()
                .into_iter()
                .map(|r| QuarantineItem {
                    id: r.id,
                    original_path: r.original_path,
                    engine: r.engine,
                    signature: r.signature,
                    size: r.size,
                    quarantined_at: r.quarantined_at,
                })
                .collect();
            serde_json::to_value(items).map_err(server_err)
        }

        method::QUARANTINE_RESTORE => {
            let params: IdParams =
                serde_json::from_value(params).map_err(|e| invalid_params(e.to_string()))?;
            let mut db = lock_db(daemon)?;
            let row = db.get_quarantine(params.id).ok_or_else(|| {
                invalid_params(format!("quarantine item {} not found", params.id))
            })?;
            daemon
                .quarantine
                .restore(
                    &PathBuf::from(&row.blob_path),
                    &PathBuf::from(&row.original_path),
                    row.original_mode,
                )
                .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))?;
            db.set_threat_status(row.threat_id, "restored");
            db.delete_quarantine(params.id);
            Ok(serde_json::to_value(row.original_path).map_err(server_err)?)
        }

        method::QUARANTINE_DELETE => {
            let params: IdParams =
                serde_json::from_value(params).map_err(|e| invalid_params(e.to_string()))?;
            let mut db = lock_db(daemon)?;
            let row = db.get_quarantine(params.id).ok_or_else(|| {
                invalid_params(format!("quarantine item {} not found", params.id))
            })?;
            daemon
                .quarantine
                .delete(&PathBuf::from(&row.blob_path))
                .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))?;
            db.set_threat_status(row.threat_id, "deleted");
            db.delete_quarantine(params.id);
            Ok(serde_json::Value::Bool(true))
        }

        method::SETTINGS_GET => {
            let settings = lock_settings(daemon)?.clone();
            serde_json::to_value(settings).map_err(server_err)
        }

        method::SETTINGS_SET => {
            let params: SettingsSetParams =
                serde_json::from_value(params).map_err(|e| invalid_params(e.to_string()))?;
            let mut settings = params.settings;
            normalize_settings(&mut settings)?;
            settings.save(&daemon.config_path).map_err(|e| {
                RpcError::new(error_code::SERVER_ERROR, format!("cannot save config: {e}"))
            })?;
            *lock_settings(daemon)? = settings.clone();
            serde_json::to_value(settings).map_err(server_err)
        }

        _ => Err(RpcError::new(
            error_code::METHOD_NOT_FOUND,
            format!("unknown method: {method}"),
        )),
    }
}

// Whole-document sets come straight from clients, so trim, dedupe, and
// reject shapes the scanner cannot apply. Persistence happens after
// validation, so a rejected set never touches the config file.
fn normalize_settings(settings: &mut Settings) -> Result<(), RpcError> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for raw in settings.exclusions.paths.drain(..) {
        let path = raw.trim().to_string();
        if path.is_empty() {
            continue;
        }
        if !(path.starts_with('/') || path.starts_with("~/")) {
            return Err(invalid_params(format!(
                "exclusion path must be absolute or start with ~/: {path}"
            )));
        }
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }
    settings.exclusions.paths = paths;

    let mut seen_ext = HashSet::new();
    let mut extensions = Vec::new();
    for raw in settings.exclusions.extensions.drain(..) {
        let ext = raw
            .trim()
            .trim_start_matches('*')
            .trim_start_matches('.')
            .to_lowercase();
        if ext.is_empty() {
            continue;
        }
        if ext.contains('/') {
            return Err(invalid_params(format!(
                "extension pattern must look like *.iso: {raw}"
            )));
        }
        if seen_ext.insert(ext.clone()) {
            extensions.push(format!("*.{ext}"));
        }
    }
    settings.exclusions.extensions = extensions;

    Ok(())
}

fn lock_db(daemon: &Daemon) -> Result<std::sync::MutexGuard<'_, Db>, RpcError> {
    daemon
        .db
        .lock()
        .map_err(|_| RpcError::new(error_code::SERVER_ERROR, "database lock poisoned"))
}

fn lock_settings(daemon: &Daemon) -> Result<std::sync::MutexGuard<'_, Settings>, RpcError> {
    daemon
        .settings
        .lock()
        .map_err(|_| RpcError::new(error_code::SERVER_ERROR, "settings lock poisoned"))
}

fn lock_active(
    daemon: &Daemon,
) -> Result<std::sync::MutexGuard<'_, HashMap<u64, Arc<AtomicBool>>>, RpcError> {
    daemon
        .active_scans
        .lock()
        .map_err(|_| RpcError::new(error_code::SERVER_ERROR, "active scan registry poisoned"))
}

fn server_err(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(error_code::SERVER_ERROR, e.to_string())
}

fn invalid_params(message: impl Into<String>) -> RpcError {
    RpcError::new(error_code::INVALID_PARAMS, message)
}
