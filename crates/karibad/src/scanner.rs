use kariba_engine_clamav::{ClamdClient, ScanOutcome};
use kariba_ipc::client::send;
use kariba_ipc::protocol::{
    Detection, Notification, RpcError, ScanParams, ScanProgress, ScanResult, error_code, method,
};
use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::db::Db;
use crate::quarantine::{Quarantine, sha256_file};

const PROGRESS_EVERY: u64 = 100;
const ENGINE: &str = "ClamAV";
const EXCLUDED_PREFIXES: [&str; 4] = ["/proc", "/sys", "/dev", "/run"];

fn is_excluded(path: &Path) -> bool {
    EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

pub fn run_scan(
    params: ScanParams,
    writer: &mut UnixStream,
    db: &mut Db,
    quarantine: &Quarantine,
) -> Result<ScanResult, RpcError> {
    let mut clamd = ClamdClient::connect().map_err(|e| {
        RpcError::new(
            error_code::SERVER_ERROR,
            format!("cannot connect to clamd: {e}"),
        )
    })?;

    let paths_display: Vec<String> = params
        .paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let scan_id = db.insert_scan("custom", &paths_display);
    let started = Instant::now();
    let skip = quarantine.dir().to_path_buf();

    let mut files_scanned: u64 = 0;
    let mut threats_found: u32 = 0;
    let mut quarantined: u32 = 0;
    let mut stack: Vec<PathBuf> = params.paths.clone();

    while let Some(entry) = stack.pop() {
        if entry.starts_with(&skip) || is_excluded(&entry) {
            continue;
        }
        let Ok(metadata) = entry.symlink_metadata() else {
            continue;
        };
        if metadata.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            if let Ok(read_dir) = fs::read_dir(&entry) {
                for child in read_dir.flatten() {
                    stack.push(child.path());
                }
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        match clamd.scan_path(&entry) {
            Ok(ScanOutcome::Infected { signature }) => {
                threats_found += 1;
                let _ = send(
                    writer,
                    &Notification::new(
                        method::SCAN_DETECTION,
                        serde_json::to_value(Detection {
                            path: entry.display().to_string(),
                            engine: ENGINE.into(),
                            signature: signature.clone(),
                        })
                        .unwrap_or_default(),
                    ),
                );

                let sha256 = sha256_file(&entry).unwrap_or_default();
                let threat_id = db.insert_threat(
                    scan_id,
                    &entry.display().to_string(),
                    &sha256,
                    ENGINE,
                    &signature,
                );

                if params.quarantine {
                    match quarantine.put(threat_id, &entry) {
                        Ok(q) => {
                            db.set_threat_status(threat_id, "quarantined");
                            db.insert_quarantine(
                                threat_id,
                                &entry.display().to_string(),
                                &q.blob_path.display().to_string(),
                                q.original_mode,
                                q.size,
                            );
                            quarantined += 1;
                        }
                        Err(_) => {
                            db.set_threat_status(threat_id, "detected");
                        }
                    }
                }
            }
            Ok(ScanOutcome::Clean) => {}
            Ok(ScanOutcome::Error { .. }) => {}
            Err(e) => {
                return Err(RpcError::new(
                    error_code::SERVER_ERROR,
                    format!("clamd connection lost: {e}"),
                ));
            }
        }

        files_scanned += 1;
        if files_scanned.is_multiple_of(PROGRESS_EVERY) {
            let _ = send(
                writer,
                &Notification::new(
                    method::SCAN_PROGRESS,
                    serde_json::to_value(ScanProgress {
                        scan_id,
                        files_scanned,
                        threats_found,
                        current: entry.display().to_string(),
                    })
                    .unwrap_or_default(),
                ),
            );
        }
    }

    db.finish_scan(scan_id, files_scanned, threats_found, "completed");

    Ok(ScanResult {
        scan_id,
        files_scanned,
        threats_found,
        quarantined,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}
