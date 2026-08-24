use kariba_core::config::Settings;
use kariba_core::paths;
use kariba_engine_clamav::{ClamdClient, ScanOutcome};
use kariba_ipc::client::send;
use kariba_ipc::protocol::{
    Detection, Notification, RpcError, ScanParams, ScanProgress, ScanResult, error_code, method,
};
use std::collections::HashMap;
use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use crate::db::Db;
use crate::quarantine::{Quarantine, sha256_file};

const PROGRESS_EVERY: u64 = 100;
const ENGINE: &str = "ClamAV";

// Policy resolved from Settings when a scan starts: whether detections are
// quarantined and which paths/file types are skipped.
pub struct ScanPolicy {
    pub auto_quarantine: bool,
    pub exclusions: Exclusions,
}

// User-configurable scan exclusions, snapshotted from Settings when a scan
// starts. Path entries act as prefixes; extension entries are `*.ext`
// patterns matched case-insensitively against the file extension.
pub struct Exclusions {
    prefixes: Vec<PathBuf>,
    extensions: Vec<String>,
}

impl Exclusions {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            prefixes: settings
                .exclusions
                .paths
                .iter()
                .map(|p| paths::expand_tilde(Path::new(p.trim())))
                .filter(|p| !p.as_os_str().is_empty())
                .collect(),
            extensions: settings
                .exclusions
                .extensions
                .iter()
                .filter_map(|e| e.trim().strip_prefix("*."))
                .map(str::to_lowercase)
                .collect(),
        }
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        if self.prefixes.iter().any(|prefix| path.starts_with(prefix)) {
            return true;
        }
        if self.extensions.is_empty() {
            return false;
        }
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| self.extensions.contains(&ext.to_lowercase()))
    }
}

// Depth-first walk that yields only scannable regular files, applying the
// same exclusion rules everywhere so the pre-count pass and the scan pass
// agree on what will be scanned.
struct FileWalker<'a> {
    stack: Vec<PathBuf>,
    skip: PathBuf,
    exclusions: &'a Exclusions,
}

impl<'a> FileWalker<'a> {
    fn new(roots: Vec<PathBuf>, skip: PathBuf, exclusions: &'a Exclusions) -> Self {
        Self {
            stack: roots,
            skip,
            exclusions,
        }
    }
}

impl Iterator for FileWalker<'_> {
    type Item = PathBuf;

    fn next(&mut self) -> Option<PathBuf> {
        while let Some(entry) = self.stack.pop() {
            if entry.starts_with(&self.skip) || self.exclusions.is_excluded(&entry) {
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
                        self.stack.push(child.path());
                    }
                }
                continue;
            }
            if metadata.is_file() {
                return Some(entry);
            }
        }
        None
    }
}

// The DB lock is held only for the duration of each individual operation so
// that status / quarantine handlers can run concurrently with a long scan.
fn lock_db(db: &Mutex<Db>) -> Result<MutexGuard<'_, Db>, RpcError> {
    db.lock()
        .map_err(|_| RpcError::new(error_code::SERVER_ERROR, "database lock poisoned"))
}

pub fn run_scan(
    params: ScanParams,
    policy: &ScanPolicy,
    writer: &mut UnixStream,
    db: &Mutex<Db>,
    quarantine: &Quarantine,
    active_scans: &Mutex<HashMap<u64, Arc<AtomicBool>>>,
    cancel: Arc<AtomicBool>,
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
    let scan_id = lock_db(db)?.insert_scan(&params.kind, &paths_display);
    let started = Instant::now();
    let skip = quarantine.dir().to_path_buf();
    if let Ok(mut active) = active_scans.lock() {
        active.insert(scan_id, Arc::clone(&cancel));
    }

    // Immediate notification so clients can show feedback right away; the
    // enumeration pass below can take several seconds on large trees.
    if !send_progress(writer, scan_id, 0, 0, 0, "") {
        cancel.store(true, Ordering::Relaxed);
    }

    // Fast enumeration pass so clients can render determinate progress.
    let files_total =
        FileWalker::new(params.paths.clone(), skip.clone(), &policy.exclusions).count() as u64;
    if !send_progress(writer, scan_id, 0, files_total, 0, "") {
        cancel.store(true, Ordering::Relaxed);
    }

    let mut files_scanned: u64 = 0;
    let mut threats_found: u32 = 0;
    let mut quarantined: u32 = 0;
    let mut cancelled = cancel.load(Ordering::Relaxed);

    for entry in FileWalker::new(params.paths.clone(), skip, &policy.exclusions) {
        if cancelled {
            break;
        }
        match clamd.scan_path(&entry) {
            Ok(ScanOutcome::Infected { signature }) => {
                threats_found += 1;
                // A failed send means the client went away; record the
                // threat but stop scanning (no orphaned scans).
                if send(
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
                )
                .is_err()
                {
                    cancel.store(true, Ordering::Relaxed);
                }

                let sha256 = sha256_file(&entry).unwrap_or_default();
                let threat_id = lock_db(db)?.insert_threat(
                    scan_id,
                    &entry.display().to_string(),
                    &sha256,
                    ENGINE,
                    &signature,
                );

                if policy.auto_quarantine {
                    match quarantine.put(threat_id, &entry) {
                        Ok(q) => {
                            let mut db = lock_db(db)?;
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
                            lock_db(db)?.set_threat_status(threat_id, "detected");
                        }
                    }
                }
            }
            Ok(ScanOutcome::Clean) => {}
            Ok(ScanOutcome::Error { .. }) => {}
            Err(e) => {
                if let Ok(mut active) = active_scans.lock() {
                    active.remove(&scan_id);
                }
                lock_db(db)?.finish_scan(scan_id, files_scanned, threats_found, "error");
                return Err(RpcError::new(
                    error_code::SERVER_ERROR,
                    format!("clamd connection lost: {e}"),
                ));
            }
        }

        files_scanned += 1;
        if files_scanned.is_multiple_of(PROGRESS_EVERY) || files_scanned == files_total {
            let sent = send_progress(
                writer,
                scan_id,
                files_scanned,
                files_total,
                threats_found,
                &entry.display().to_string(),
            );
            if !sent {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        cancelled = cancel.load(Ordering::Relaxed);
    }

    if let Ok(mut active) = active_scans.lock() {
        active.remove(&scan_id);
    }
    let status = if cancelled { "cancelled" } else { "completed" };
    lock_db(db)?.finish_scan(scan_id, files_scanned, threats_found, status);

    Ok(ScanResult {
        scan_id,
        files_scanned,
        threats_found,
        quarantined,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn send_progress(
    writer: &mut UnixStream,
    scan_id: u64,
    files_scanned: u64,
    files_total: u64,
    threats_found: u32,
    current: &str,
) -> bool {
    send(
        writer,
        &Notification::new(
            method::SCAN_PROGRESS,
            serde_json::to_value(ScanProgress {
                scan_id,
                files_scanned,
                files_total,
                threats_found,
                current: current.to_string(),
            })
            .unwrap_or_default(),
        ),
    )
    .is_ok()
}
