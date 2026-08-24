use kariba_core::config::Settings;
use kariba_core::paths;
use kariba_ipc::client::{reader, respond};
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, RpcError, ScanHistoryItem, ScanParams, SettingsSetParams,
    StatusResult, ThreatHistoryItem, ThreatStatusFilter, WireMessage, error_code, method,
    parse_line,
};
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::broadcast::Broadcaster;
use crate::db::Db;
use crate::quarantine::Quarantine;
use crate::realtime;
use crate::scanner;

const HISTORY_LIMIT: u64 = 20;
const THREATS_LIMIT: u64 = 200;

pub struct Daemon {
    started_at: Instant,
    db: Arc<Mutex<Db>>,
    quarantine: Arc<Quarantine>,
    active_scans: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    settings: Arc<Mutex<Settings>>,
    config_path: PathBuf,
    broadcaster: Arc<Broadcaster>,
    realtime: Mutex<Option<realtime::Handle>>,
    realtime_detail: Mutex<String>,
}

impl Daemon {
    pub fn new(db: Db, quarantine: Quarantine, settings: Settings, config_path: PathBuf) -> Self {
        Self {
            started_at: Instant::now(),
            db: Arc::new(Mutex::new(db)),
            quarantine: Arc::new(quarantine),
            active_scans: Mutex::new(HashMap::new()),
            settings: Arc::new(Mutex::new(settings)),
            config_path,
            broadcaster: Arc::new(Broadcaster::new()),
            realtime: Mutex::new(None),
            realtime_detail: Mutex::new("not started".into()),
        }
    }

    /// Align the watcher with `realtime.enabled`. Called at startup and
    /// after every settings change (a restart re-snapshots exclusions and
    /// the auto-quarantine flag). Safe to call repeatedly.
    pub fn sync_realtime(&self) {
        let enabled = self
            .settings
            .lock()
            .map(|s| s.realtime.enabled)
            .unwrap_or(false);
        let Ok(mut slot) = self.realtime.lock() else {
            return;
        };
        let Ok(mut detail) = self.realtime_detail.lock() else {
            return;
        };

        if let Some(handle) = slot.take() {
            handle.stop();
        }

        if !enabled {
            *detail = "disabled in settings".into();
            return;
        }

        let Ok(settings) = self.settings.lock() else {
            return;
        };
        let ctx = realtime::WatcherCtx {
            db: Arc::clone(&self.db),
            quarantine: Arc::clone(&self.quarantine),
            broadcaster: Arc::clone(&self.broadcaster),
            data_dir: paths::data_dir(),
            settings: settings.clone(),
        };
        drop(settings);
        match realtime::start(ctx) {
            Ok(handle) => {
                let mount_list = handle
                    .mounts
                    .iter()
                    .map(|m| m.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                *detail = format!("watching {} mount(s): {}", handle.mounts.len(), mount_list);
                *slot = Some(handle);
            }
            Err(reason) => *detail = reason,
        }
    }

    pub fn realtime_status(&self) -> (bool, String) {
        let active = self
            .realtime
            .lock()
            .map(|slot| slot.is_some())
            .unwrap_or(false);
        let detail = self
            .realtime_detail
            .lock()
            .map(|d| d.clone())
            .unwrap_or_default();
        (active, detail)
    }
}

pub fn handle_connection(mut stream: UnixStream, daemon: Arc<Daemon>) {
    let subscription = daemon.broadcaster.register(&stream);
    let Ok(buf_reader) = reader(&stream) else {
        if let Some(id) = subscription {
            daemon.broadcaster.unregister(id);
        }
        return;
    };
    for line in buf_reader.lines() {
        let Ok(line) = line else { break };
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
    if let Some(id) = subscription {
        daemon.broadcaster.unregister(id);
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
            let (scans_total, threats_total, quarantined_items) = lock_db(daemon)?.counts();
            let protection_enabled = lock_settings(daemon)?.realtime.enabled;
            let (realtime_active, realtime_detail) = daemon.realtime_status();
            serde_json::to_value(StatusResult {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                uptime_secs: daemon.started_at.elapsed().as_secs(),
                scans_total,
                threats_total,
                quarantined_items,
                protection_enabled,
                realtime_active,
                realtime_detail,
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
                    exclusions: crate::exclusions::Exclusions::from_settings(&settings),
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

        method::THREATS_LIST => {
            let filter: ThreatStatusFilter =
                serde_json::from_value(params).unwrap_or(ThreatStatusFilter { status: None });
            let db = lock_db(daemon)?;
            let items: Vec<ThreatHistoryItem> = db
                .list_threats(filter.status.as_deref(), THREATS_LIMIT)
                .into_iter()
                .map(|r| ThreatHistoryItem {
                    id: r.id,
                    path: r.path,
                    sha256: r.sha256,
                    engine: r.engine,
                    signature: r.signature,
                    detected_at: r.detected_at,
                    status: r.status,
                    source: r.source,
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
                    source: r.source,
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
            // Realign the watcher: picks up realtime.enabled, exclusions,
            // and the auto-quarantine flag.
            daemon.sync_realtime();
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
