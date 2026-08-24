//! Real-time protection: mount-wide fanotify watcher with an exec gate.
//!
//! `FAN_OPEN_EXEC_PERM` events get a bounded synchronous verdict (the exec
//! gate — the security boundary); `FAN_CLOSE_WRITE` events are scanned
//! asynchronously. Verdicts fail open on timeout/engine-down and queue a
//! re-scan, per PLAN.md "Real-time Protection Design".

use kariba_engine_clamav::{ClamdClient, ScanOutcome};
use kariba_ipc::Notification;
use kariba_ipc::protocol::{RealtimeDetection, method};
use std::collections::HashMap;
use std::fs;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::broadcast::Broadcaster;
use crate::db::Db;
use crate::exclusions::Exclusions;
use crate::fanotify;
use crate::quarantine::{Quarantine, sha256_file};

const VERDICT_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_TIMEOUT_MS: i32 = 500;
const ENGINE: &str = "ClamAV";
const CACHE_CAP: usize = 10_000;

pub struct WatcherCtx {
    pub db: Arc<Mutex<Db>>,
    pub quarantine: Arc<Quarantine>,
    pub broadcaster: Arc<Broadcaster>,
    pub data_dir: PathBuf,
    // Snapshot at watcher start; the daemon restarts the watcher when
    // settings change rather than mutating a live watcher.
    pub settings: kariba_core::config::Settings,
}

pub struct Handle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    pub mounts: Vec<PathBuf>,
}

impl Handle {
    /// The thread notices the flag within one poll interval, closes the
    /// fanotify fd (releasing all marks), and exits.
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

pub fn start(ctx: WatcherCtx) -> Result<Handle, String> {
    let fan_fd = fanotify::init().map_err(friendly_init_error)?;

    let mask = fanotify::FAN_CLOSE_WRITE | fanotify::FAN_OPEN_EXEC_PERM;
    let mut marked = Vec::new();
    match kariba_core::mounts::list_mounts() {
        Ok(all) => {
            for mount in kariba_core::mounts::watchable_mounts(&all) {
                match fanotify::mark_mount(fan_fd, &mount.mount_point, mask) {
                    Ok(()) => marked.push(mount.mount_point.clone()),
                    Err(e) => {
                        eprintln!("karibad: cannot mark {}: {e}", mount.mount_point.display())
                    }
                }
            }
        }
        Err(e) => {
            fanotify::close_fd(fan_fd);
            return Err(format!("cannot enumerate mounts: {e}"));
        }
    }
    if marked.is_empty() {
        fanotify::close_fd(fan_fd);
        return Err("no watchable mounts could be marked".into());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("kariba-realtime".into())
        .spawn(move || run(fan_fd, ctx, thread_stop))
        .map_err(|e| e.to_string())?;
    Ok(Handle {
        stop,
        thread,
        mounts: marked,
    })
}

fn friendly_init_error(e: std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::EPERM) {
        "requires root (CAP_SYS_ADMIN) — run karibad as root to enable real-time protection".into()
    } else {
        format!("fanotify unavailable: {e}")
    }
}

// clamd writes temp files into TemporaryDirectory (/tmp) while scanning and
// deletes them right after; freshclam rewrites the signature databases.
// Scanning the engines' own churn is wasted work (and would race their
// cleanup), so their writes are skipped.
fn writer_is_engine(pid: i32) -> bool {
    let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
        return false;
    };
    matches!(comm.trim(), "clamd" | "freshclam" | "karibad")
}

fn run(fan_fd: RawFd, ctx: WatcherCtx, stop: Arc<AtomicBool>) {
    let mut state = WatcherState::new(&ctx);
    let mut buf = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::Relaxed) {
        match fanotify::wait_readable(fan_fd, POLL_TIMEOUT_MS) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => break,
        }
        let events = match fanotify::read_events(fan_fd, &mut buf) {
            Ok(events) => events,
            Err(_) => break,
        };
        // Permission events hold user processes' syscalls, so they are
        // processed before any queued background re-scans.
        for event in events {
            state.process(fan_fd, event, &ctx);
        }
        state.drain_rescans(&ctx);
    }
    if let Ok(mut db) = ctx.db.lock() {
        db.finish_scan(
            state.realtime_scan_id,
            state.files_scanned,
            state.detections,
            "completed",
        );
    }
    fanotify::close_fd(fan_fd);
}

#[derive(Clone, PartialEq)]
enum Verdict {
    Clean,
    Infected(String),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    path: PathBuf,
    mtime_secs: u64,
    size: u64,
}

impl CacheKey {
    fn from_path(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        let mtime_secs = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Some(Self {
            path: path.to_path_buf(),
            mtime_secs,
            size: metadata.len(),
        })
    }
}

struct WatcherState {
    exclusions: Exclusions,
    auto_quarantine: bool,
    cache: HashMap<CacheKey, Verdict>,
    pending_rescans: Vec<PathBuf>,
    scan_client: Option<ClamdClient>,
    realtime_scan_id: u64,
    files_scanned: u64,
    detections: u32,
}

impl WatcherState {
    fn new(ctx: &WatcherCtx) -> Self {
        let mut exclusions = Exclusions::from_settings(&ctx.settings);
        exclusions.add_prefix(ctx.data_dir.clone());
        exclusions.add_prefix(ctx.quarantine.dir().to_path_buf());
        // Scanning the signature databases themselves is pointless churn.
        exclusions.add_prefix(kariba_core::clamav::db_dir());
        let realtime_scan_id = ctx
            .db
            .lock()
            .map(|mut db| db.insert_scan("realtime", &["<real-time protection>".into()]))
            .unwrap_or(0);
        Self {
            exclusions,
            auto_quarantine: ctx.settings.realtime.auto_quarantine,
            cache: HashMap::new(),
            pending_rescans: Vec::new(),
            scan_client: None,
            realtime_scan_id,
            files_scanned: 0,
            detections: 0,
        }
    }

    fn process(&mut self, fan_fd: RawFd, event: fanotify::Event, ctx: &WatcherCtx) {
        if event.fd < 0 {
            return;
        }
        let is_exec_perm = event.mask & fanotify::FAN_OPEN_EXEC_PERM != 0;
        let is_close_write = event.mask & fanotify::FAN_CLOSE_WRITE != 0;
        let path = fs::read_link(format!("/proc/self/fd/{}", event.fd)).ok();

        // The kernel suffixes readlink targets of already-unlinked files;
        // nothing left to scan there.
        let vanished = path
            .as_ref()
            .is_some_and(|p| p.to_string_lossy().ends_with(" (deleted)"));

        if is_exec_perm {
            let allow = match &path {
                Some(path) if !vanished && !self.exclusions.is_excluded(path) => {
                    self.exec_verdict(path, ctx)
                }
                _ => true,
            };
            let _ = fanotify::respond(fan_fd, event.fd, allow);
        } else if is_close_write
            && !vanished
            && let Some(path) = &path
            && !self.exclusions.is_excluded(path)
            && !writer_is_engine(event.pid)
        {
            self.scan_and_handle(path, ctx);
        }

        fanotify::close_fd(event.fd);
    }

    fn exec_verdict(&mut self, path: &Path, ctx: &WatcherCtx) -> bool {
        match self.verdict(path) {
            Verdict::Clean => true,
            Verdict::Infected(signature) => {
                self.handle_detection(path, &signature, "denied", ctx);
                false
            }
        }
    }

    /// Cache lookup, then a bounded engine scan. Timeouts and engine errors
    /// fail open (allow) and queue a background re-scan.
    fn verdict(&mut self, path: &Path) -> Verdict {
        let Some(key) = CacheKey::from_path(path) else {
            return Verdict::Clean;
        };
        if let Some(verdict) = self.cache.get(&key) {
            return verdict.clone();
        }
        let outcome = self.scan_bounded(path);
        let verdict = match outcome {
            Some(ScanOutcome::Clean) => Verdict::Clean,
            Some(ScanOutcome::Infected { signature }) => Verdict::Infected(signature),
            Some(ScanOutcome::Error { message }) => {
                eprintln!(
                    "karibad: real-time verdict error for {}: {message}; allowing and queueing re-scan",
                    path.display()
                );
                self.pending_rescans.push(path.to_path_buf());
                return Verdict::Clean;
            }
            None => {
                eprintln!(
                    "karibad: real-time verdict over budget for {}, allowing and queueing re-scan",
                    path.display()
                );
                self.pending_rescans.push(path.to_path_buf());
                return Verdict::Clean;
            }
        };
        self.cache_put(key, verdict.clone());
        verdict
    }

    /// Fresh connection per verdict: a persistent verdict client accumulates
    /// idle-state failure modes (clamd reaps idle connections, keepalives
    /// consume the verdict budget). Connecting is ~0.1ms; a verdict must
    /// never inherit the previous one's connection problems.
    fn scan_bounded(&mut self, path: &Path) -> Option<ScanOutcome> {
        let started = Instant::now();
        let mut client = match ClamdClient::connect_with_read_timeout(VERDICT_TIMEOUT) {
            Ok(client) => client,
            Err(e) => {
                eprintln!(
                    "karibad: verdict connect failed for {}: {e}",
                    path.display()
                );
                return None;
            }
        };
        match client.scan_path_once(path) {
            Ok(outcome) => Some(outcome),
            Err(e) => {
                eprintln!(
                    "karibad: verdict scan failed for {} after {}ms: {e}",
                    path.display(),
                    started.elapsed().as_millis()
                );
                None
            }
        }
    }

    fn scan_async(&mut self, path: &Path) -> Result<ScanOutcome, std::io::Error> {
        if self.scan_client.is_none() {
            self.scan_client = ClamdClient::connect().ok();
        }
        let Some(client) = self.scan_client.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "clamd unavailable",
            ));
        };
        match client.scan_path(path) {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                self.scan_client = None;
                Err(e)
            }
        }
    }

    fn scan_and_handle(&mut self, path: &Path, ctx: &WatcherCtx) {
        self.files_scanned += 1;
        match self.scan_async(path) {
            Ok(ScanOutcome::Infected { signature }) => {
                if let Some(key) = CacheKey::from_path(path) {
                    self.cache_put(key, Verdict::Infected(signature.clone()));
                }
                self.handle_detection(path, &signature, "detected", ctx);
            }
            Ok(ScanOutcome::Clean) => {
                if let Some(key) = CacheKey::from_path(path) {
                    self.cache_put(key, Verdict::Clean);
                }
            }
            Ok(ScanOutcome::Error { message }) => {
                eprintln!(
                    "karibad: real-time scan error for {}: {message}",
                    path.display()
                );
            }
            // The file vanished between event and scan (writer deleted it)
            // — a harmless race, not an engine failure.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!(
                    "karibad: real-time scan unavailable ({e}) for {}",
                    path.display()
                );
            }
        }
    }

    fn drain_rescans(&mut self, ctx: &WatcherCtx) {
        if self.pending_rescans.is_empty() {
            return;
        }
        let rescans = std::mem::take(&mut self.pending_rescans);
        for path in rescans {
            if path.exists() {
                self.scan_and_handle(&path, ctx);
            }
        }
    }

    // `kind` is what triggered the detection: "denied" (exec gate) or
    // "detected" (file written). Whether the file is actually quarantined is
    // decided here from `auto_quarantine`, and both the GUI action label and
    // the daemon log spell out the outcome — detection itself always happens
    // when real-time is on; quarantine is only one possible response.
    fn handle_detection(&mut self, path: &Path, signature: &str, kind: &str, ctx: &WatcherCtx) {
        self.detections += 1;
        let sha256 = sha256_file(path).unwrap_or_default();
        let path_display = path.display().to_string();

        let threat_id = {
            let Ok(mut db) = ctx.db.lock() else {
                return;
            };
            db.insert_threat(
                self.realtime_scan_id,
                &path_display,
                &sha256,
                ENGINE,
                signature,
            )
        };

        let mut quarantined = false;
        if self.auto_quarantine
            && let Ok(q) = ctx.quarantine.put(threat_id, path)
        {
            let Ok(mut db) = ctx.db.lock() else {
                return;
            };
            db.set_threat_status(threat_id, "quarantined");
            db.insert_quarantine(
                threat_id,
                &path_display,
                &q.blob_path.display().to_string(),
                q.original_mode,
                q.size,
            );
            quarantined = true;
        }

        let action = match (kind, quarantined) {
            ("denied", true) => "denied+quarantined",
            ("denied", false) => "denied",
            (_, true) => "quarantined",
            (_, false) => "detected",
        };

        let verb = if kind == "denied" {
            "BLOCKED execution of"
        } else {
            "detected"
        };
        let outcome = if quarantined {
            "quarantined".to_string()
        } else if self.auto_quarantine {
            "quarantine FAILED, left in place".to_string()
        } else {
            "left in place (auto-quarantine is off)".to_string()
        };
        eprintln!("karibad: real-time: {verb} {path_display} ({signature}) — {outcome}");

        ctx.broadcaster.broadcast(&Notification::new(
            method::REALTIME_DETECTION,
            serde_json::to_value(RealtimeDetection {
                path: path_display,
                engine: ENGINE.into(),
                signature: signature.into(),
                action: action.to_string(),
            })
            .unwrap_or_default(),
        ));
    }

    fn cache_put(&mut self, key: CacheKey, verdict: Verdict) {
        if self.cache.len() >= CACHE_CAP {
            self.cache.clear();
        }
        self.cache.insert(key, verdict);
    }
}
