use kariba_ipc::client::{reader, respond};
use kariba_ipc::protocol::{
    IdParams, QuarantineItem, RpcError, ScanParams, StatusResult, WireMessage, error_code, method,
    parse_line,
};
use std::io::BufRead;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::db::Db;
use crate::quarantine::Quarantine;
use crate::scanner;

pub struct Daemon {
    started_at: Instant,
    db: Mutex<Db>,
    quarantine: Quarantine,
}

impl Daemon {
    pub fn new(db: Db, quarantine: Quarantine) -> Self {
        Self {
            started_at: Instant::now(),
            db: Mutex::new(db),
            quarantine,
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
            serde_json::to_value(StatusResult {
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                uptime_secs: daemon.started_at.elapsed().as_secs(),
                scans_total,
                threats_total,
                quarantined_items,
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
            let mut db = lock_db(daemon)?;
            let result = scanner::run_scan(params, stream, &mut db, &daemon.quarantine)?;
            serde_json::to_value(result).map_err(server_err)
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

        _ => Err(RpcError::new(
            error_code::METHOD_NOT_FOUND,
            format!("unknown method: {method}"),
        )),
    }
}

fn lock_db(daemon: &Daemon) -> Result<std::sync::MutexGuard<'_, Db>, RpcError> {
    daemon
        .db
        .lock()
        .map_err(|_| RpcError::new(error_code::SERVER_ERROR, "database lock poisoned"))
}

fn server_err(e: impl std::fmt::Display) -> RpcError {
    RpcError::new(error_code::SERVER_ERROR, e.to_string())
}

fn invalid_params(message: impl Into<String>) -> RpcError {
    RpcError::new(error_code::INVALID_PARAMS, message)
}
