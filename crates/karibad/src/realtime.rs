//! Real-time protection: mount-wide fanotify watcher with an exec gate.
//!
//! One blocking surface, everything else async (PLAN.md, "Real-time
//! Protection Design"):
//!
//! - `FAN_OPEN_EXEC_PERM` — the exec gate, the sole synchronous path.
//!   Verdicts are bounded (L1), batch-budgeted (L2), and the response is
//!   written before any bookkeeping (L3).
//! - `FAN_CLOSE_WRITE` — detect-at-landing, queued for the worker pool.
//!
//! Safety layers against lockups: intake never does slow work; a watchdog
//! closes the fanotify fd if intake stalls (kernel auto-allows all pending
//! permission events) and restarts the watcher; shutdown closes the fd
//! FIRST, then persists the queue, then interrupts workers. The kernel
//! queue is bounded — overflow arrives as `FAN_Q_OVERFLOW` and degrades
//! visibility loudly instead of pinning unbounded kernel resources.

use kariba_engine_clamav::{ClamdClient, ScanOutcome};
use kariba_ipc::Notification;
use kariba_ipc::protocol::{RealtimeDetection, method};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::net::Shutdown;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::broadcast::Broadcaster;
use crate::db::Db;
use crate::exclusions::Exclusions;
use crate::fanotify;
use crate::quarantine::{Quarantine, sha256_file};

const VERDICT_TIMEOUT: Duration = Duration::from_secs(2);
// Workers must not sit on a wedged clamd for minutes: shutdown interrupts
// them via their socket handles, but a stale connection should also die on
// its own quickly.
const WORKER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT_MS: i32 = 500;
const ENGINE: &str = "ClamAV";
const CACHE_CAP: usize = 10_000;
const WORKERS: usize = 4;
// In-memory queue cap; beyond it paths spill to SQLite, so coverage is
// preserved without unbounded RAM.
const MEM_QUEUE_CAP: usize = 50_000;
const DB_BATCH: u64 = 200;
// Identical per-path errors repeat while a file churns (live databases);
// log the first occurrence, then stay quiet for a while.
const ERROR_SUPPRESS: Duration = Duration::from_secs(60);
// L2: total verdict-scan time allowed per event batch. Cache-miss execs
// beyond the budget are allowed and re-queued — worst-case exec latency
// stays bounded no matter how congested clamd is.
const VERDICT_BATCH_BUDGET: Duration = Duration::from_millis(1000);
// Progress log cadence for backlog drains.
const PROGRESS_STEP: u64 = 5_000;
// Backlog above this marks a "drain in progress" for the drained log line.
const BACKLOG_HIGH: u64 = 1_000;
// L4: intake heartbeat checking.
const WATCHDOG_INTERVAL: Duration = Duration::from_millis(500);
const WATCHDOG_STALL: Duration = Duration::from_secs(3);
const MAX_WATCHER_RESTARTS: u32 = 3;

#[derive(Clone)]
pub struct WatcherCtx {
    pub db: Arc<Mutex<Db>>,
    pub quarantine: Arc<Quarantine>,
    pub broadcaster: Arc<Broadcaster>,
    pub data_dir: PathBuf,
    // Snapshot at watcher start; the daemon restarts the watcher when
    // settings change rather than mutating a live watcher.
    pub settings: kariba_core::config::Settings,
}

/// Shared fanotify fd with an idempotent, cross-thread close. Closing it
/// is the universal unblock: poll/read fail in the intake thread and the
/// kernel auto-allows every pending permission event.
#[derive(Clone)]
struct FanFd(Arc<AtomicI32>);

impl FanFd {
    fn new(fd: RawFd) -> Self {
        Self(Arc::new(AtomicI32::new(fd)))
    }

    fn get(&self) -> Option<RawFd> {
        let fd = self.0.load(Ordering::Acquire);
        (fd >= 0).then_some(fd)
    }

    fn close(&self) {
        let fd = self.0.swap(-1, Ordering::AcqRel);
        if fd >= 0 {
            fanotify::close_fd(fd);
        }
    }
}

enum Task {
    Scan(PathBuf),
    // Exec gate already answered DENY; quarantine/broadcast bookkeeping
    // happens here, after the response (L3 respond-first).
    GateDetection { path: PathBuf, signature: String },
}

/// Dedup'd scan queue: memory first, async SQLite spill beyond the cap.
/// Overflow paths land in an in-memory spill buffer and a dedicated thread
/// batches them to SQLite — intake never does disk I/O, so it cannot stall
/// (a synchronous per-event spill once stalled it and tripped the watchdog).
struct ScanQueue {
    inner: Mutex<QueueInner>,
    condvar: Condvar,
    spill_buf: Mutex<Vec<PathBuf>>,
    db: Arc<Mutex<Db>>,
}

struct QueueInner {
    deque: VecDeque<Task>,
    queued: HashSet<PathBuf>,
}

impl ScanQueue {
    fn new(db: Arc<Mutex<Db>>) -> Self {
        Self {
            inner: Mutex::new(QueueInner {
                deque: VecDeque::new(),
                queued: HashSet::new(),
            }),
            condvar: Condvar::new(),
            spill_buf: Mutex::new(Vec::new()),
            db,
        }
    }

    /// Report paths spilled during a previous lifetime. They stay in the
    /// DB and are drained in batches only when the live queue is empty, so
    /// fresh events always jump ahead of stale backlog.
    fn report_pending(&self) {
        let count = self.db.lock().map(|db| db.pending_count()).unwrap_or(0);
        if count > 0 {
            eprintln!("karibad: real-time: resuming {count} queued scan(s) from previous run");
        }
    }

    /// Dedup'd push: a path already queued is skipped, and a burst beyond
    /// the memory cap overflows into the spill buffer (O(1), no I/O) for
    /// the spill thread to batch to SQLite.
    fn push_scan(&self, path: PathBuf) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.queued.insert(path.clone()) {
            return;
        }
        if inner.deque.len() >= MEM_QUEUE_CAP {
            inner.queued.remove(&path);
            drop(inner);
            self.spill_buf.lock().unwrap().push(path);
            return;
        }
        inner.deque.push_back(Task::Scan(path));
        self.condvar.notify_one();
    }

    fn take_spill_buf(&self) -> Vec<PathBuf> {
        std::mem::take(&mut self.spill_buf.lock().unwrap())
    }

    /// Front-of-line task for exec-gate bookkeeping; never dedup'd or
    /// capped (a DENY's follow-up must not be lost).
    fn push_gate_detection(&self, path: PathBuf, signature: String) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .deque
            .push_front(Task::GateDetection { path, signature });
        self.condvar.notify_one();
    }

    /// Persist a batch of unfinished paths (used on shutdown so nothing
    /// queued is lost).
    fn persist(&self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        if let Ok(mut db) = self.db.lock() {
            db.spill_pending(&paths);
        }
    }

    /// Next task: memory queue first, then spilled DB rows. Returns None
    /// once the exit flag is set (after finishing at most the scan in
    /// flight) — whatever remains is persisted by the shutdown path, not
    /// scanned, so a SIGTERM never drains a 50k backlog before exiting.
    fn pop(&self, exit: &AtomicBool, timeout: Duration) -> Option<Task> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if exit.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(task) = inner.deque.pop_front() {
                if let Task::Scan(path) = &task {
                    inner.queued.remove(path);
                }
                return Some(task);
            }
            drop(inner);
            let batch = {
                let Ok(mut db) = self.db.lock() else {
                    return None;
                };
                db.take_pending(DB_BATCH)
            };
            inner = self.inner.lock().unwrap();
            if !batch.is_empty() {
                for path in batch.into_iter().rev() {
                    if inner.queued.insert(path.clone()) {
                        inner.deque.push_front(Task::Scan(path));
                    }
                }
                continue;
            }
            let (guard, _) = self.condvar.wait_timeout(inner, timeout).unwrap();
            inner = guard;
        }
    }

    /// Drain everything still queued, returning paths to persist.
    fn drain_paths(&self) -> Vec<PathBuf> {
        let mut inner = self.inner.lock().unwrap();
        let paths = inner
            .deque
            .drain(..)
            .map(|task| match task {
                Task::Scan(path) | Task::GateDetection { path, .. } => path,
            })
            .collect();
        inner.queued.clear();
        paths
    }

    fn notify_all(&self) {
        self.condvar.notify_all();
    }

    /// Everything not yet scanned: memory queue + spill buffer + spilled
    /// DB rows. Used for progress/ETA logging.
    fn backlog_len(&self, db: &Mutex<Db>) -> u64 {
        let mem = {
            let inner = self.inner.lock().unwrap();
            inner.deque.len() as u64 + self.spill_buf.lock().unwrap().len() as u64
        };
        let pending = db.lock().map(|d| d.pending_count()).unwrap_or(0);
        mem + pending
    }
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

/// State shared between the intake thread and the scan workers.
struct Shared {
    exclusions: Exclusions,
    auto_quarantine: bool,
    cache: Mutex<HashMap<CacheKey, Verdict>>,
    recent_errors: Mutex<HashMap<PathBuf, (String, Instant)>>,
    // Clones of worker clamd sockets so shutdown can interrupt blocked
    // scans immediately.
    worker_streams: Mutex<Vec<std::os::unix::net::UnixStream>>,
    // Watcher-level note surfaced in `status` (overflow, failed-open…).
    status_note: Arc<Mutex<Option<String>>>,
    overflows: AtomicU64,
    db: Arc<Mutex<Db>>,
    quarantine: Arc<Quarantine>,
    broadcaster: Arc<Broadcaster>,
    realtime_scan_id: u64,
    files_scanned: AtomicU64,
    detections: AtomicU32,
    started: Instant,
    had_backlog: AtomicBool,
}

impl Shared {
    fn new(ctx: &WatcherCtx, status_note: Arc<Mutex<Option<String>>>) -> Self {
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
            cache: Mutex::new(HashMap::new()),
            recent_errors: Mutex::new(HashMap::new()),
            worker_streams: Mutex::new(Vec::new()),
            status_note,
            overflows: AtomicU64::new(0),
            db: Arc::clone(&ctx.db),
            quarantine: Arc::clone(&ctx.quarantine),
            broadcaster: Arc::clone(&ctx.broadcaster),
            realtime_scan_id,
            files_scanned: AtomicU64::new(0),
            detections: AtomicU32::new(0),
            started: Instant::now(),
            had_backlog: AtomicBool::new(false),
        }
    }

    /// Progress line every PROGRESS_STEP scans with backlog, rate and ETA;
    /// a one-shot "backlog drained" line when a real backlog empties out.
    fn progress_tick(&self, queue: &ScanQueue) {
        let n = self.files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
        if !n.is_multiple_of(PROGRESS_STEP) {
            return;
        }
        let backlog = queue.backlog_len(&self.db);
        if backlog > BACKLOG_HIGH {
            self.had_backlog.store(true, Ordering::Relaxed);
        }
        let secs = self.started.elapsed().as_secs().max(1);
        if backlog == 0 && self.had_backlog.swap(false, Ordering::Relaxed) {
            eprintln!("karibad: real-time: backlog drained ({n} scanned in {secs}s)");
            return;
        }
        let rate = n / secs;
        let eta = backlog.checked_div(rate).unwrap_or(backlog);
        eprintln!(
            "karibad: real-time: {n} scanned, backlog {backlog}, ~{rate}/s, ETA {}",
            fmt_eta(eta)
        );
    }

    fn cache_lookup(&self, key: &CacheKey) -> Option<Verdict> {
        self.cache.lock().unwrap().get(key).cloned()
    }

    fn cache_put(&self, key: CacheKey, verdict: Verdict) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_CAP {
            cache.clear();
        }
        cache.insert(key, verdict);
    }

    /// Exec-gate verdict (L1+L2): cache hit instant; miss = bounded engine
    /// scan; over budget, timeout, or engine error = ALLOW + re-queue.
    /// Returns true to allow execution.
    fn exec_verdict(&self, path: &Path, queue: &ScanQueue, deadline: Instant) -> bool {
        let Some(key) = CacheKey::from_path(path) else {
            return true; // can't stat → fail open
        };
        if let Some(verdict) = self.cache_lookup(&key) {
            return match verdict {
                Verdict::Clean => true,
                Verdict::Infected(signature) => {
                    queue.push_gate_detection(path.to_path_buf(), signature);
                    false
                }
            };
        }
        if Instant::now() >= deadline {
            self.note_error(
                path,
                "verdict batch budget exhausted; allowing and queueing re-scan",
            );
            queue.push_scan(path.to_path_buf());
            return true;
        }
        let started = Instant::now();
        match scan_bounded(path) {
            Some(ScanOutcome::Clean) => {
                // One line per cache-miss verdict: the moments the gate
                // actually held an exec. Re-execs hit the cache and stay
                // silent, so this doesn't spam on normal process churn.
                eprintln!(
                    "karibad: exec gate: checked {} (clean, {}ms)",
                    path.display(),
                    started.elapsed().as_millis()
                );
                self.cache_put(key, Verdict::Clean);
                true
            }
            Some(ScanOutcome::Infected { signature }) => {
                eprintln!(
                    "karibad: exec gate: DENIED {} ({}, {}ms)",
                    path.display(),
                    signature,
                    started.elapsed().as_millis()
                );
                self.cache_put(key, Verdict::Infected(signature.clone()));
                queue.push_gate_detection(path.to_path_buf(), signature);
                false
            }
            Some(ScanOutcome::Error { message }) => {
                self.note_error(path, &format!("verdict error: {message}; allowing"));
                queue.push_scan(path.to_path_buf());
                true
            }
            None => {
                self.note_error(path, "verdict over budget; allowing");
                queue.push_scan(path.to_path_buf());
                true
            }
        }
    }

    /// One async scan through a worker's persistent clamd connection.
    fn scan_one(&self, path: &Path, client: &mut Option<ClamdClient>) {
        if client.is_none() {
            *client = ClamdClient::connect_with_read_timeout(WORKER_READ_TIMEOUT).ok();
            if let Some(c) = client.as_ref()
                && let Ok(handle) = c.stream_handle()
            {
                self.worker_streams.lock().unwrap().push(handle);
            }
        }
        let Some(c) = client.as_mut() else {
            self.note_error(path, "clamd unavailable");
            return;
        };
        match c.scan_path(path) {
            Ok(ScanOutcome::Infected { signature }) => {
                if let Some(key) = CacheKey::from_path(path) {
                    self.cache_put(key, Verdict::Infected(signature.clone()));
                }
                self.handle_detection(path, &signature, "detected");
            }
            Ok(ScanOutcome::Clean) => {
                if let Some(key) = CacheKey::from_path(path) {
                    self.cache_put(key, Verdict::Clean);
                }
            }
            Ok(ScanOutcome::Error { message }) => {
                self.note_error(path, &message);
            }
            // The file vanished between queueing and scanning (writer
            // deleted it) — a harmless race, not an engine failure.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                // Force a fresh connection on the next attempt.
                *client = None;
                if e.raw_os_error() == Some(libc::EMFILE) {
                    // fd pressure: give the system a moment to recover
                    // instead of hot-spinning.
                    std::thread::sleep(Duration::from_millis(200));
                }
                self.note_error(path, &e.to_string());
            }
        }
    }

    /// Interrupt every registered worker connection so blocked reads
    /// return immediately (used by shutdown; bounded joins depend on it).
    fn interrupt_workers(&self) {
        let mut streams = self.worker_streams.lock().unwrap();
        for stream in streams.drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Per-path error suppression: live databases churn CLOSE_WRITE events
    /// constantly; logging every repeat would drown the daemon output.
    fn note_error(&self, path: &Path, message: &str) {
        let mut recent = self.recent_errors.lock().unwrap();
        let now = Instant::now();
        if let Some((last_message, at)) = recent.get(path)
            && last_message == message
            && now.duration_since(*at) < ERROR_SUPPRESS
        {
            return;
        }
        if recent.len() > CACHE_CAP {
            recent.clear();
        }
        recent.insert(path.to_path_buf(), (message.to_string(), now));
        drop(recent);
        eprintln!(
            "karibad: real-time scan error for {}: {message}",
            path.display()
        );
    }

    /// Kernel event-queue overflow: events were dropped. Visibility is
    /// degraded until a catch-up sweep (Phase B) covers the mount; say so
    /// loudly but rate-limited.
    fn note_overflow(&self) {
        let count = self.overflows.fetch_add(1, Ordering::Relaxed) + 1;
        *self.status_note.lock().unwrap() = Some(format!(
            "kernel event queue overflowed {count}×: visibility degraded until catch-up"
        ));
        let path = Path::new("<kernel queue>");
        let mut recent = self.recent_errors.lock().unwrap();
        let now = Instant::now();
        if let Some((_, at)) = recent.get(path)
            && now.duration_since(*at) < ERROR_SUPPRESS
        {
            return;
        }
        recent.insert(path.to_path_buf(), ("overflow".to_string(), now));
        drop(recent);
        eprintln!(
            "karibad: real-time: kernel event queue overflow ({count}×): events were dropped; \
             catch-up sweep pending"
        );
    }

    // `kind` is what triggered the detection: "denied" (exec gate) or
    // "detected" (file written). Whether the file is actually quarantined is
    // decided here from `auto_quarantine`, and both the GUI action label and
    // the daemon log spell out the outcome — detection itself always happens
    // when real-time is on; quarantine is only one possible response.
    fn handle_detection(&self, path: &Path, signature: &str, kind: &str) {
        self.detections.fetch_add(1, Ordering::Relaxed);
        let sha256 = sha256_file(path).unwrap_or_default();
        let path_display = path.display().to_string();

        let threat_id = {
            let Ok(mut db) = self.db.lock() else {
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
            && let Ok(q) = self.quarantine.put(threat_id, path)
        {
            let Ok(mut db) = self.db.lock() else {
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
        eprintln!("karibad: real-time: {verb} {path_display} ({signature}): {outcome}");

        self.broadcaster.broadcast(&Notification::new(
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
}

/// Fresh connection per verdict: a persistent verdict client accumulates
/// idle-state failure modes (clamd reaps idle connections, keepalives
/// consume the verdict budget). Connecting is ~0.1ms; a verdict must
/// never inherit the previous one's connection problems.
fn scan_bounded(path: &Path) -> Option<ScanOutcome> {
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

// One live watcher generation: fanotify fd + intake thread + workers.
struct WatcherInner {
    fan_fd: FanFd,
    heartbeat: Arc<Mutex<Instant>>,
    thread: JoinHandle<()>,
}

pub struct Handle {
    stop: Arc<AtomicBool>,
    inner: Arc<Mutex<Option<WatcherInner>>>,
    status_note: Arc<Mutex<Option<String>>>,
    watchdog: JoinHandle<()>,
    pub mounts: Vec<PathBuf>,
}

impl Handle {
    /// L5 bounded shutdown: close the fanotify fd FIRST (unblocks intake;
    /// kernel auto-allows pending permission events), then let intake
    /// persist the queue and interrupt+join the workers, then stop the
    /// watchdog. Nothing joins before the fd is closed.
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut slot) = self.inner.lock()
            && let Some(inner) = slot.take()
        {
            inner.fan_fd.close();
            let _ = inner.thread.join();
        }
        let _ = self.watchdog.join();
    }

    /// Extra runtime note (overflow degradation, failed-open) on top of
    /// the daemon's "watching N mounts" detail.
    pub fn status_note(&self) -> Option<String> {
        self.status_note.lock().unwrap().clone()
    }
}

pub fn start(ctx: WatcherCtx) -> Result<Handle, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let status_note: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let spawned = spawn_watcher(&ctx, Arc::clone(&stop), Arc::clone(&status_note))?;
    let mounts = spawned.mounts;
    let inner_slot = Arc::new(Mutex::new(Some(spawned.inner)));

    // L4: intake watchdog. On a stall it closes the fanotify fd (kernel
    // auto-allows every pending exec), then restarts the watcher — a
    // stalled karibad becomes a fail-open karibad, never a frozen machine.
    let watchdog_inner = Arc::clone(&inner_slot);
    let watchdog_stop = Arc::clone(&stop);
    let watchdog_ctx = ctx.clone();
    let watchdog_note = Arc::clone(&status_note);
    let watchdog = std::thread::Builder::new()
        .name("kariba-rt-watchdog".into())
        .spawn(move || {
            let mut restarts = 0u32;
            let mut healthy_streak = 0u32;
            loop {
                std::thread::sleep(WATCHDOG_INTERVAL);
                if watchdog_stop.load(Ordering::Relaxed) {
                    break;
                }
                let stalled = {
                    let Ok(slot) = watchdog_inner.lock() else {
                        break;
                    };
                    slot.as_ref().is_some_and(|inner| {
                        inner
                            .heartbeat
                            .lock()
                            .map(|hb| hb.elapsed() > WATCHDOG_STALL)
                            .unwrap_or(true)
                    })
                };
                if !stalled {
                    // Clear a stale "restarted" note once the watcher has
                    // proven healthy again (overflow/failed-open notes stay).
                    healthy_streak += 1;
                    if healthy_streak > 20
                        && watchdog_note.lock().unwrap().as_deref()
                            == Some("watcher restarted after stall")
                    {
                        *watchdog_note.lock().unwrap() = None;
                    }
                    continue;
                }
                healthy_streak = 0;
                restarts += 1;
                if restarts > MAX_WATCHER_RESTARTS {
                    eprintln!(
                        "karibad: real-time: watcher stalled repeatedly: FAILED OPEN, \
                         real-time protection disabled until restart or settings change"
                    );
                    *watchdog_note.lock().unwrap() = Some(
                        "watcher stalled repeatedly, failed open; restart karibad or toggle real-time"
                            .into(),
                    );
                    let _ = watchdog_inner.lock().map(|mut slot| slot.take());
                    break;
                }
                eprintln!(
                    "karibad: real-time: intake stalled >{}s: closing fanotify fd \
                     (pending permission events auto-allowed) and restarting watcher",
                    WATCHDOG_STALL.as_secs()
                );
                let old = watchdog_inner.lock().ok().and_then(|mut slot| slot.take());
                if let Some(old) = old {
                    old.fan_fd.close();
                    let _ = old.thread.join();
                }
                match spawn_watcher(&watchdog_ctx, Arc::clone(&watchdog_stop), Arc::clone(&watchdog_note))
                {
                    Ok(fresh) => {
                        *watchdog_note.lock().unwrap() =
                            Some("watcher restarted after stall".into());
                        if let Ok(mut slot) = watchdog_inner.lock() {
                            *slot = Some(fresh.inner);
                        }
                    }
                    Err(e) => {
                        eprintln!("karibad: real-time: watcher restart failed ({e}): FAILED OPEN");
                        *watchdog_note.lock().unwrap() =
                            Some(format!("watcher restart failed ({e}), failed open"));
                        break;
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(Handle {
        stop,
        inner: inner_slot,
        status_note,
        watchdog,
        mounts,
    })
}

struct SpawnedWatcher {
    inner: WatcherInner,
    mounts: Vec<PathBuf>,
}

fn spawn_watcher(
    ctx: &WatcherCtx,
    stop: Arc<AtomicBool>,
    status_note: Arc<Mutex<Option<String>>>,
) -> Result<SpawnedWatcher, String> {
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

    let fan = FanFd::new(fan_fd);
    let shared = Arc::new(Shared::new(ctx, status_note));
    let queue = Arc::new(ScanQueue::new(Arc::clone(&shared.db)));
    queue.report_pending();

    // Per-generation exit flag: on shutdown (SIGTERM or watchdog restart)
    // workers stop after their current scan and the remainder is persisted,
    // never scanned-then-exit.
    let exit = Arc::new(AtomicBool::new(false));

    let mut workers = Vec::new();
    for _ in 0..WORKERS {
        let shared = Arc::clone(&shared);
        let queue = Arc::clone(&queue);
        let exit = Arc::clone(&exit);
        if let Ok(worker) = std::thread::Builder::new()
            .name("kariba-rt-worker".into())
            .spawn(move || {
                let mut client: Option<ClamdClient> = None;
                while let Some(task) = queue.pop(&exit, Duration::from_millis(250)) {
                    match task {
                        Task::Scan(path) => {
                            if path.exists() {
                                shared.scan_one(&path, &mut client);
                                shared.progress_tick(&queue);
                            }
                        }
                        Task::GateDetection { path, signature } => {
                            shared.handle_detection(&path, &signature, "denied");
                        }
                    }
                }
            })
        {
            workers.push(worker);
        }
    }

    // Spill thread: batches overflow paths from the spill buffer into
    // SQLite. Intake only ever appends to the buffer, so it stays fast.
    let spill_queue = Arc::clone(&queue);
    let spill_exit = Arc::clone(&exit);
    let spill_thread = std::thread::Builder::new()
        .name("kariba-rt-spill".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                if spill_exit.load(Ordering::Relaxed) {
                    break;
                }
                let batch = spill_queue.take_spill_buf();
                if !batch.is_empty()
                    && let Ok(mut db) = spill_queue.db.lock()
                {
                    db.spill_pending(&batch);
                }
            }
        })
        .map_err(|e| e.to_string())?;

    let heartbeat = Arc::new(Mutex::new(Instant::now()));
    let run_fan = fan.clone();
    let run_shared = Arc::clone(&shared);
    let run_queue = Arc::clone(&queue);
    let run_heartbeat = Arc::clone(&heartbeat);
    let run_stop = Arc::clone(&stop);
    let run_exit = Arc::clone(&exit);
    let thread = std::thread::Builder::new()
        .name("kariba-realtime".into())
        .spawn(move || {
            run(
                run_fan,
                run_shared,
                run_queue,
                workers,
                spill_thread,
                run_stop,
                run_exit,
                run_heartbeat,
            )
        })
        .map_err(|e| e.to_string())?;

    Ok(SpawnedWatcher {
        inner: WatcherInner {
            fan_fd: fan,
            heartbeat,
            thread,
        },
        mounts: marked,
    })
}

fn fmt_eta(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}m{:02}s", secs / 60, secs % 60)
    }
}

fn friendly_init_error(e: std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::EPERM) {
        "requires root (CAP_SYS_ADMIN): run karibad as root to enable real-time protection".into()
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

#[allow(clippy::too_many_arguments)]
fn run(
    fan: FanFd,
    shared: Arc<Shared>,
    queue: Arc<ScanQueue>,
    workers: Vec<JoinHandle<()>>,
    spill_thread: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    exit: Arc<AtomicBool>,
    heartbeat: Arc<Mutex<Instant>>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let beat = || {
        *heartbeat.lock().unwrap() = Instant::now();
    };
    while !stop.load(Ordering::Relaxed) {
        let Some(fd) = fan.get() else {
            break;
        };
        beat();
        match fanotify::wait_readable(fd, POLL_TIMEOUT_MS) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => break,
        }
        let events = match fanotify::read_events(fd, &mut buf) {
            Ok(events) => events,
            Err(_) => break,
        };
        beat();
        // L2: one budget per batch. Permission events are answered before
        // any close-write queueing happens.
        let deadline = Instant::now() + VERDICT_BATCH_BUDGET;
        for event in events {
            intake_event(&shared, &queue, fd, event, deadline);
        }
        beat();
    }

    // L5 shutdown order: fd first (already closed if watchdog/stop did it —
    // close is idempotent), then signal workers + spill thread to exit,
    // then persist whatever is still queued, interrupt blocked scans, and
    // join. The remainder is rescanned by the next lifetime, never here.
    fan.close();
    exit.store(true, Ordering::Relaxed);
    let _ = spill_thread.join();
    let mut paths = queue.take_spill_buf();
    paths.extend(queue.drain_paths());
    queue.persist(paths);
    shared.interrupt_workers();
    queue.notify_all();
    for worker in workers {
        let _ = worker.join();
    }

    if let Ok(mut db) = shared.db.lock() {
        db.finish_scan(
            shared.realtime_scan_id,
            shared.files_scanned.load(Ordering::Relaxed),
            shared.detections.load(Ordering::Relaxed),
            "completed",
        );
    }
}

/// Resolve one event, answer permission events synchronously, queue
/// close-write paths for the workers. The event fd is closed before
/// returning, so kernel-held fds never accumulate.
fn intake_event(
    shared: &Shared,
    queue: &ScanQueue,
    fan_fd: RawFd,
    event: fanotify::Event,
    deadline: Instant,
) {
    // Kernel queue overflow: no fd, events were dropped.
    if event.mask & fanotify::FAN_Q_OVERFLOW != 0 {
        shared.note_overflow();
        return;
    }
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
            Some(path) if !vanished && !shared.exclusions.is_excluded(path) => {
                shared.exec_verdict(path, queue, deadline)
            }
            _ => true,
        };
        // L3: the response goes out before any bookkeeping (detection
        // handling was queued, not run inline).
        let _ = fanotify::respond(fan_fd, event.fd, allow);
    } else if is_close_write
        && !vanished
        && let Some(path) = &path
        && !shared.exclusions.is_excluded(path)
        && !writer_is_engine(event.pid)
    {
        queue.push_scan(path.clone());
    }

    fanotify::close_fd(event.fd);
}
