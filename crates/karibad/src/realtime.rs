//! Real-time protection: mount-wide fanotify watcher with an exec gate.
//!
//! One blocking surface, everything else async (PLAN.md, "Real-time
//! Protection Design"):
//!
//! - `FAN_OPEN_EXEC_PERM` — the exec gate, the sole synchronous path.
//!   Verdicts are bounded (L1), batch-budgeted (L2), and the response is
//!   written before any bookkeeping (L3). Gate exclusions (default
//!   `/usr`, `/boot`) skip verdicts entirely for system paths.
//! - `FAN_CLOSE_WRITE` — detect-at-landing, queued into triage lanes.
//! - `FAN_OPEN` — cache-first read checks (toggle `scan_on_open`): clean
//!   unchanged files cost a hashmap lookup; misses queue an async scan.
//!
//! Triage lanes drain in priority order EXEC → DATA → MEDIA; churn files
//! (live databases, logs) get a per-path cooldown; backlog and catch-up
//! sweep paths sit behind all live traffic.
//!
//! Safety layers against lockups: intake never does slow work; a watchdog
//! closes the fanotify fd if intake stalls (kernel auto-allows all pending
//! permission events) and restarts the watcher; shutdown closes the fd
//! FIRST, then persists the queue, then interrupts workers. The kernel
//! queue is bounded — overflow arrives as `FAN_Q_OVERFLOW`, is logged, and
//! triggers a low-priority catch-up sweep of the watched mounts.

use kariba_engine_clamav::{ClamdClient, ScanOutcome};
use kariba_ipc::Notification;
use kariba_ipc::protocol::{RealtimeDetection, method};
use serde::{Deserialize, Serialize};
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
const CACHE_CAP: usize = 100_000;
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
// Churn cooldown: live databases rewrite constantly; re-scan them at most
// this often, latest-wins.
const CHURN_COOLDOWN: Duration = Duration::from_secs(5);
// Cache persistence cadence and location.
const CACHE_SAVE_INTERVAL: Duration = Duration::from_secs(30);
const CACHE_FILE: &str = "rtcache.json";
// Catch-up sweep pacing: only feed paths while the live queue is shallow.
const SWEEP_YIELD_AT: usize = 1_000;
const SWEEP_FLUSH_BATCH: usize = 500;

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

/// File metadata from fstat (event fd) or stat (path). dev+ino identify
/// the file object across renames; mtime+size detect content changes.
#[derive(Debug, Clone, Copy)]
struct FileMeta {
    dev: u64,
    ino: u64,
    mtime_secs: u64,
    size: u64,
    mode: u32,
    is_dir: bool,
}

fn fstat_meta(fd: RawFd) -> Option<FileMeta> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return None;
    }
    Some(FileMeta {
        dev: stat.st_dev as u64,
        ino: stat.st_ino as u64,
        mtime_secs: stat.st_mtime as u64,
        size: stat.st_size as u64,
        mode: stat.st_mode as u32,
        is_dir: stat.st_mode & libc::S_IFMT == libc::S_IFDIR,
    })
}

fn stat_meta(path: &Path) -> Option<FileMeta> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path).ok()?;
    let mtime_secs = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(FileMeta {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mtime_secs,
        size: metadata.len(),
        mode: metadata.mode(),
        is_dir: metadata.is_dir(),
    })
}

/// Triage lanes: a scheduling decision, not a security one. Every lane is
/// still scanned; lanes only decide the order (and what yields first when
/// the queue overflows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Exec,
    Data,
    Media,
    Churn,
}

const MEDIA_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tif", "tiff", "avif", "ttf", "otf", "woff",
    "woff2", "mp3", "mp4", "wav", "flac", "ogg", "oga", "opus", "mkv", "avi", "webm", "mov", "m4a",
    "aac",
];

/// Zero-I/O classification (path + mode come from the event's fstat).
fn classify(path: &Path, mode: u32) -> Lane {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Churn first: live databases and logs, even in odd locations.
    if name.ends_with("-wal")
        || name.ends_with("-journal")
        || name.ends_with(".sqlite")
        || name.ends_with(".sqlite3")
        || name.ends_with(".bdb")
        || name.ends_with(".db")
        || name.ends_with(".log")
    {
        return Lane::Churn;
    }
    // Executables: any exec bit, shared libraries, AppImages, bin dirs.
    if mode & 0o111 != 0 {
        return Lane::Exec;
    }
    if name.ends_with(".so") || name.contains(".so.") || name.ends_with(".appimage") {
        return Lane::Exec;
    }
    if let Some(parent) = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        && matches!(parent, "bin" | "sbin" | "libexec")
    {
        return Lane::Exec;
    }
    // Media: inert content formats.
    if let Some(ext) = path.extension().and_then(|e| e.to_str())
        && MEDIA_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
    {
        return Lane::Media;
    }
    Lane::Data
}

enum Task {
    Scan(PathBuf),
    // Exec gate already answered DENY; quarantine/broadcast bookkeeping
    // happens here, after the response (L3 respond-first).
    GateDetection { path: PathBuf, signature: String },
}

/// Dedup'd priority scan queue: EXEC → DATA → MEDIA for live traffic,
/// backlog (spilled + catch-up paths) behind all of it, gate bookkeeping
/// ahead of everything. Overflow spills to SQLite via an async buffer —
/// intake never does disk I/O, so it cannot stall.
struct ScanQueue {
    inner: Mutex<QueueInner>,
    condvar: Condvar,
    spill_buf: Mutex<Vec<PathBuf>>,
    db: Arc<Mutex<Db>>,
}

struct QueueInner {
    gate: VecDeque<Task>,
    exec: VecDeque<PathBuf>,
    data: VecDeque<PathBuf>,
    media: VecDeque<PathBuf>,
    backlog: VecDeque<PathBuf>,
    queued: HashSet<PathBuf>,
}

impl ScanQueue {
    fn new(db: Arc<Mutex<Db>>) -> Self {
        Self {
            inner: Mutex::new(QueueInner {
                gate: VecDeque::new(),
                exec: VecDeque::new(),
                data: VecDeque::new(),
                media: VecDeque::new(),
                backlog: VecDeque::new(),
                queued: HashSet::new(),
            }),
            condvar: Condvar::new(),
            spill_buf: Mutex::new(Vec::new()),
            db,
        }
    }

    /// Report paths spilled during a previous lifetime. They stay in the
    /// DB and are drained only when every live lane is empty, so fresh
    /// events always jump ahead of stale backlog.
    fn report_pending(&self) {
        let count = self.db.lock().map(|db| db.pending_count()).unwrap_or(0);
        if count > 0 {
            eprintln!("karibad: real-time: resuming {count} queued scan(s) from previous run");
        }
    }

    /// Live-queue depth across all lanes (not backlog, not DB).
    fn depth(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.exec.len() + inner.data.len() + inner.media.len()
    }

    /// Dedup'd push into a triage lane. Beyond the memory cap, the
    /// lowest-priority entry spills to the SQLite buffer (O(1), no I/O) so
    /// the new path can be queued — media yields first, then data, then
    /// exec; nothing is ever dropped.
    fn push_scan(&self, path: PathBuf, lane: Lane) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.queued.insert(path.clone()) {
            return;
        }
        let total = inner.exec.len() + inner.data.len() + inner.media.len();
        if total >= MEM_QUEUE_CAP {
            let victim = inner
                .media
                .pop_back()
                .or_else(|| inner.data.pop_back())
                .or_else(|| inner.exec.pop_back());
            if let Some(victim) = victim {
                inner.queued.remove(&victim);
                drop(inner);
                self.spill_buf.lock().unwrap().push(victim);
                self.push_scan(path, lane);
                return;
            }
            // All lanes empty yet over cap cannot happen; spill the new
            // path to stay safe.
            inner.queued.remove(&path);
            drop(inner);
            self.spill_buf.lock().unwrap().push(path);
            return;
        }
        match lane {
            Lane::Exec => inner.exec.push_back(path),
            Lane::Data | Lane::Churn => inner.data.push_back(path),
            Lane::Media => inner.media.push_back(path),
        }
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
            .gate
            .push_back(Task::GateDetection { path, signature });
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

    /// Next task: gate → exec → data → media → backlog → spilled DB rows.
    /// Returns None once the exit flag is set (after finishing at most the
    /// scan in flight) — whatever remains is persisted by the shutdown
    /// path, never scanned, so a SIGTERM never drains a backlog first.
    fn pop(&self, exit: &AtomicBool, timeout: Duration) -> Option<Task> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if exit.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(task) = inner.gate.pop_front() {
                return Some(task);
            }
            let scan = inner
                .exec
                .pop_front()
                .or_else(|| inner.data.pop_front())
                .or_else(|| inner.media.pop_front())
                .or_else(|| inner.backlog.pop_front());
            if let Some(path) = scan {
                inner.queued.remove(&path);
                return Some(Task::Scan(path));
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
                        inner.backlog.push_front(path);
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
        let mut paths: Vec<PathBuf> = inner
            .gate
            .drain(..)
            .map(|task| match task {
                Task::Scan(path) | Task::GateDetection { path, .. } => path,
            })
            .collect();
        paths.extend(inner.exec.drain(..));
        paths.extend(inner.data.drain(..));
        paths.extend(inner.media.drain(..));
        paths.extend(inner.backlog.drain(..));
        inner.queued.clear();
        paths
    }

    fn notify_all(&self) {
        self.condvar.notify_all();
    }

    /// Everything not yet scanned: lanes + backlog + spill buffer + spilled
    /// DB rows. Used for progress/ETA logging.
    fn backlog_len(&self, db: &Mutex<Db>) -> u64 {
        let mem = {
            let inner = self.inner.lock().unwrap();
            (inner.exec.len() + inner.data.len() + inner.media.len() + inner.backlog.len()) as u64
                + self.spill_buf.lock().unwrap().len() as u64
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

/// Inode-keyed verdict cache entry: rename-proof, and "unchanged" is
/// answered without hashing.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct CacheKey {
    dev: u64,
    ino: u64,
    mtime_secs: u64,
    size: u64,
}

impl CacheKey {
    fn from_meta(meta: &FileMeta) -> Self {
        Self {
            dev: meta.dev,
            ino: meta.ino,
            mtime_secs: meta.mtime_secs,
            size: meta.size,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CacheFileEntry {
    dev: u64,
    ino: u64,
    mtime_secs: u64,
    size: u64,
    // None = clean; Some(signature) = infected.
    infected: Option<String>,
}

fn cache_file_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CACHE_FILE)
}

fn load_cache(data_dir: &Path) -> HashMap<CacheKey, Verdict> {
    let Ok(raw) = fs::read_to_string(cache_file_path(data_dir)) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_str::<Vec<CacheFileEntry>>(&raw) else {
        return HashMap::new();
    };
    entries
        .into_iter()
        .map(|e| {
            (
                CacheKey {
                    dev: e.dev,
                    ino: e.ino,
                    mtime_secs: e.mtime_secs,
                    size: e.size,
                },
                match e.infected {
                    Some(signature) => Verdict::Infected(signature),
                    None => Verdict::Clean,
                },
            )
        })
        .collect()
}

/// Per-path churn state: when it was last queued for scanning, and
/// whether it changed again during cooldown (needs one more scan once the
/// cooldown elapses).
struct ChurnEntry {
    last_queued: Instant,
    dirty: bool,
}

/// Drain-rate measurement window: starts when the backlog goes high, so
/// ETA reflects actual drain throughput instead of the lifetime average
/// (which is dominated by idle trickle periods and wildly overestimates).
struct RateWindow {
    since: Instant,
    scans_at_start: u64,
}

/// State shared between the intake thread and the scan workers.
struct Shared {
    exclusions: Exclusions,
    auto_quarantine: bool,
    scan_on_open: bool,
    auto_catchup: bool,
    data_dir: PathBuf,
    mounts: Vec<PathBuf>,
    cache: Mutex<HashMap<CacheKey, Verdict>>,
    cache_dirty: AtomicBool,
    last_cache_save: Mutex<Instant>,
    churn: Mutex<HashMap<PathBuf, ChurnEntry>>,
    recent_errors: Mutex<HashMap<PathBuf, (String, Instant)>>,
    // Clones of worker clamd sockets so shutdown can interrupt blocked
    // scans immediately.
    worker_streams: Mutex<Vec<std::os::unix::net::UnixStream>>,
    // Watcher-level note surfaced in `status` (overflow, failed-open…).
    status_note: Arc<Mutex<Option<String>>>,
    // Set on kernel queue overflow; the catch-up thread consumes it.
    catchup_requested: AtomicBool,
    overflows: AtomicU64,
    db: Arc<Mutex<Db>>,
    quarantine: Arc<Quarantine>,
    broadcaster: Arc<Broadcaster>,
    realtime_scan_id: u64,
    files_scanned: AtomicU64,
    detections: AtomicU32,
    started: Instant,
    had_backlog: AtomicBool,
    rate_window: Mutex<Option<RateWindow>>,
}

impl Shared {
    fn new(
        ctx: &WatcherCtx,
        status_note: Arc<Mutex<Option<String>>>,
        mounts: Vec<PathBuf>,
    ) -> Self {
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
        let cache = load_cache(&ctx.data_dir);
        let loaded = cache.len();
        if loaded > 0 {
            eprintln!("karibad: real-time: loaded {loaded} cached verdict(s) from disk");
        }
        Self {
            exclusions,
            auto_quarantine: ctx.settings.realtime.auto_quarantine,
            scan_on_open: ctx.settings.realtime.scan_on_open,
            auto_catchup: ctx.settings.realtime.auto_catchup,
            data_dir: ctx.data_dir.clone(),
            mounts,
            cache: Mutex::new(cache),
            cache_dirty: AtomicBool::new(false),
            last_cache_save: Mutex::new(Instant::now()),
            churn: Mutex::new(HashMap::new()),
            recent_errors: Mutex::new(HashMap::new()),
            worker_streams: Mutex::new(Vec::new()),
            status_note,
            catchup_requested: AtomicBool::new(false),
            overflows: AtomicU64::new(0),
            db: Arc::clone(&ctx.db),
            quarantine: Arc::clone(&ctx.quarantine),
            broadcaster: Arc::clone(&ctx.broadcaster),
            realtime_scan_id,
            files_scanned: AtomicU64::new(0),
            detections: AtomicU32::new(0),
            started: Instant::now(),
            had_backlog: AtomicBool::new(false),
            rate_window: Mutex::new(None),
        }
    }

    /// Progress line every PROGRESS_STEP scans with backlog, rate and ETA.
    /// ETA uses the busy-window drain rate (clock starts when the backlog
    /// goes high): the lifetime average is misleading because idle trickle
    /// periods measure arrival rate (~files/s the system opens), not scan
    /// capacity. A one-shot "backlog drained" line closes each episode.
    fn progress_tick(&self, queue: &ScanQueue) {
        let n = self.files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
        if !n.is_multiple_of(PROGRESS_STEP) {
            return;
        }
        let backlog = queue.backlog_len(&self.db);
        if backlog > BACKLOG_HIGH {
            self.had_backlog.store(true, Ordering::Relaxed);
        }
        let mut window = self.rate_window.lock().unwrap();
        if backlog == 0 && self.had_backlog.swap(false, Ordering::Relaxed) {
            let secs = self.started.elapsed().as_secs().max(1);
            *window = None;
            eprintln!("karibad: real-time: backlog drained ({n} scanned in {secs}s)");
            return;
        }
        if backlog >= BACKLOG_HIGH {
            let w = window.get_or_insert(RateWindow {
                since: Instant::now(),
                scans_at_start: n,
            });
            let elapsed = w.since.elapsed().as_secs();
            if elapsed >= 2 && n > w.scans_at_start {
                let rate = ((n - w.scans_at_start) / elapsed).max(1);
                let eta = backlog / rate;
                eprintln!(
                    "karibad: real-time: {n} scanned, backlog {backlog}, ~{rate}/s, ETA {}",
                    fmt_eta(eta)
                );
            } else {
                eprintln!(
                    "karibad: real-time: {n} scanned, backlog {backlog}, measuring drain rate"
                );
            }
        } else {
            // Trickle: small backlog, no meaningful ETA; lifetime rate is
            // fine as an "activity" number here.
            *window = None;
            let secs = self.started.elapsed().as_secs().max(1);
            let rate = n / secs;
            eprintln!("karibad: real-time: {n} scanned, backlog {backlog}, ~{rate}/s");
        }
    }

    fn cache_lookup(&self, key: &CacheKey) -> Option<Verdict> {
        self.cache.lock().unwrap().get(key).cloned()
    }

    fn cache_put(&self, key: CacheKey, verdict: Verdict) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_CAP {
            // Evict an arbitrary half, never the whole cache: a full clear
            // causes system-wide re-check waves (seen live: waybar scripts
            // re-scanned after read-check verdicts crossed the cap).
            let excess = cache.len() - CACHE_CAP / 2;
            let victims: Vec<CacheKey> = cache.keys().take(excess).cloned().collect();
            for key in victims {
                cache.remove(&key);
            }
        }
        cache.insert(key, verdict);
        drop(cache);
        self.cache_dirty.store(true, Ordering::Relaxed);
    }

    /// Atomic write of the verdict cache so warm verdicts survive daemon
    /// restarts (no re-check wave on the next start).
    fn save_cache(&self) {
        if !self.cache_dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let entries: Vec<CacheFileEntry> = self
            .cache
            .lock()
            .unwrap()
            .iter()
            .map(|(key, verdict)| CacheFileEntry {
                dev: key.dev,
                ino: key.ino,
                mtime_secs: key.mtime_secs,
                size: key.size,
                infected: match verdict {
                    Verdict::Clean => None,
                    Verdict::Infected(signature) => Some(signature.clone()),
                },
            })
            .collect();
        let Ok(raw) = serde_json::to_string(&entries) else {
            return;
        };
        let path = cache_file_path(&self.data_dir);
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, raw).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
        *self.last_cache_save.lock().unwrap() = Instant::now();
    }

    /// Churn gate: enqueue at most once per cooldown; changes during the
    /// cooldown mark the path dirty so one final scan happens afterwards
    /// (latest-wins). Returns true when the path should be enqueued now.
    fn churn_try_queue(&self, path: &Path) -> bool {
        let mut churn = self.churn.lock().unwrap();
        if churn.len() > CACHE_CAP {
            churn.clear();
        }
        let now = Instant::now();
        match churn.get_mut(path) {
            Some(entry) if now.duration_since(entry.last_queued) < CHURN_COOLDOWN => {
                entry.dirty = true;
                false
            }
            Some(entry) => {
                entry.last_queued = now;
                entry.dirty = false;
                true
            }
            None => {
                churn.insert(
                    path.to_path_buf(),
                    ChurnEntry {
                        last_queued: now,
                        dirty: false,
                    },
                );
                true
            }
        }
    }

    /// Re-enqueue churn paths that changed during their cooldown and whose
    /// cooldown has now elapsed (called from the housekeeping thread).
    fn churn_flush(&self, queue: &ScanQueue) {
        let now = Instant::now();
        let due: Vec<PathBuf> = {
            let mut churn = self.churn.lock().unwrap();
            let due: Vec<PathBuf> = churn
                .iter()
                .filter(|(_, entry)| {
                    entry.dirty && now.duration_since(entry.last_queued) >= CHURN_COOLDOWN
                })
                .map(|(path, _)| path.clone())
                .collect();
            for path in &due {
                if let Some(entry) = churn.get_mut(path) {
                    entry.last_queued = now;
                    entry.dirty = false;
                }
            }
            due
        };
        for path in due {
            queue.push_scan(path, Lane::Churn);
        }
    }

    /// Exec-gate verdict (L1+L2): cache hit instant; miss = bounded engine
    /// scan; over budget, timeout, or engine error = ALLOW + re-queue.
    /// Returns true to allow execution.
    fn exec_verdict(
        &self,
        path: &Path,
        meta: Option<FileMeta>,
        queue: &ScanQueue,
        deadline: Instant,
    ) -> bool {
        let key = match meta {
            Some(meta) => CacheKey::from_meta(&meta),
            None => {
                let Some(m) = stat_meta(path) else {
                    return true; // can't stat → fail open
                };
                CacheKey::from_meta(&m)
            }
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
            queue.push_scan(path.to_path_buf(), Lane::Exec);
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
                queue.push_scan(path.to_path_buf(), Lane::Exec);
                true
            }
            None => {
                self.note_error(path, "verdict over budget; allowing");
                queue.push_scan(path.to_path_buf(), Lane::Exec);
                true
            }
        }
    }

    /// One async scan through a worker's persistent clamd connection.
    fn scan_one(&self, path: &Path, client: &mut Option<ClamdClient>) {
        // Pre-scan metadata: the cache key for the content about to be
        // scanned (a rewrite mid-scan invalidates itself via a new key on
        // the next event).
        let Some(meta) = stat_meta(path) else {
            return; // vanished between queueing and scanning
        };
        let key = CacheKey::from_meta(&meta);
        // Verdicts already cached (e.g. catch-up sweep over scanned files)
        // cost nothing here.
        if self.cache_lookup(&key).is_some() {
            return;
        }
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
                // Check-and-set dedup: concurrent scans of the same file
                // version (e.g. open-check + close-write racing) must
                // produce exactly one detection. First one wins.
                {
                    let mut cache = self.cache.lock().unwrap();
                    if matches!(cache.get(&key), Some(Verdict::Infected(_))) {
                        return;
                    }
                    cache.insert(key, Verdict::Infected(signature.clone()));
                }
                self.cache_dirty.store(true, Ordering::Relaxed);
                self.handle_detection(path, &signature, "detected");
            }
            Ok(ScanOutcome::Clean) => {
                self.cache_put(key, Verdict::Clean);
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

    /// Kernel event-queue overflow: events were dropped. Request a
    /// catch-up sweep and say so loudly but rate-limited.
    fn note_overflow(&self) {
        let count = self.overflows.fetch_add(1, Ordering::Relaxed) + 1;
        *self.status_note.lock().unwrap() = Some(format!(
            "kernel event queue overflowed {count}×: catch-up sweep pending"
        ));
        self.catchup_requested.store(true, Ordering::Relaxed);
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
        // Gone by the time we act: already handled by a racing scan or
        // deleted by the writer. Nothing to record or quarantine.
        if fs::metadata(path).is_err() {
            return;
        }
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
        if self.auto_quarantine {
            match self.quarantine.put(threat_id, path) {
                Ok(q) => {
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
                Err(e) => {
                    eprintln!(
                        "karibad: real-time: quarantine failed for {}: {e}",
                        path_display
                    );
                }
            }
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

    let mut mask = fanotify::FAN_CLOSE_WRITE | fanotify::FAN_OPEN_EXEC_PERM;
    if ctx.settings.realtime.scan_on_open {
        mask |= fanotify::FAN_OPEN;
    }
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
    let shared = Arc::new(Shared::new(ctx, status_note, marked.clone()));
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
                            shared.scan_one(&path, &mut client);
                            shared.progress_tick(&queue);
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

    // Housekeeping thread: batches overflow paths from the spill buffer
    // into SQLite, flushes churn re-scans whose cooldown elapsed, and
    // persists the verdict cache periodically. Intake only ever appends
    // to buffers, so it stays fast.
    let hk_shared = Arc::clone(&shared);
    let hk_queue = Arc::clone(&queue);
    let hk_exit = Arc::clone(&exit);
    let housekeeping_thread = std::thread::Builder::new()
        .name("kariba-rt-housekeeping".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(250));
                if hk_exit.load(Ordering::Relaxed) {
                    break;
                }
                let batch = hk_queue.take_spill_buf();
                if !batch.is_empty()
                    && let Ok(mut db) = hk_queue.db.lock()
                {
                    db.spill_pending(&batch);
                }
                hk_shared.churn_flush(&hk_queue);
                let save_due = hk_shared
                    .last_cache_save
                    .lock()
                    .map(|t| t.elapsed() >= CACHE_SAVE_INTERVAL)
                    .unwrap_or(false);
                if save_due {
                    hk_shared.save_cache();
                }
            }
        })
        .map_err(|e| e.to_string())?;

    // Catch-up sweep thread: after a kernel queue overflow, walk the
    // watched mounts and feed paths into pending_scans (lowest priority),
    // yielding whenever live traffic is pending. Gated by auto_catchup.
    let sweep_shared = Arc::clone(&shared);
    let sweep_queue = Arc::clone(&queue);
    let sweep_exit = Arc::clone(&exit);
    let sweep_thread = std::thread::Builder::new()
        .name("kariba-rt-catchup".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                if sweep_exit.load(Ordering::Relaxed) {
                    break;
                }
                if !sweep_shared.auto_catchup
                    || !sweep_shared
                        .catchup_requested
                        .swap(false, Ordering::Relaxed)
                {
                    continue;
                }
                sweep_shared.run_catchup(&sweep_queue, &sweep_exit);
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
                housekeeping_thread,
                sweep_thread,
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

impl Shared {
    /// Catch-up sweep: walk the watched mounts and spill paths into
    /// pending_scans, which workers drain only when all live traffic is
    //  done — recovery never competes with protection.
    fn run_catchup(&self, queue: &ScanQueue, exit: &AtomicBool) {
        let mounts: Vec<PathBuf> = self.mounts.clone();
        let mount_strings: Vec<String> = mounts.iter().map(|m| m.display().to_string()).collect();
        let mount_list = mount_strings.join(", ");
        let scan_id = self
            .db
            .lock()
            .map(|mut db| db.insert_scan("catchup", &mount_strings))
            .unwrap_or(0);
        eprintln!(
            "karibad: real-time: catch-up sweep starting ({})",
            if mounts.len() == 1 {
                mount_list.clone()
            } else {
                format!("{} mounts", mounts.len())
            }
        );
        let mut walked = 0u64;
        let mut batch: Vec<PathBuf> = Vec::with_capacity(SWEEP_FLUSH_BATCH);
        let flush = |batch: &mut Vec<PathBuf>| {
            if batch.is_empty() {
                return;
            }
            if let Ok(mut db) = self.db.lock() {
                db.spill_pending(batch);
            }
            batch.clear();
        };
        'outer: for mount in &mounts {
            let mut stack = vec![mount.clone()];
            while let Some(dir) = stack.pop() {
                if exit.load(Ordering::Relaxed) {
                    break 'outer;
                }
                // Yield to live traffic before walking on.
                while queue.depth() >= SWEEP_YIELD_AT {
                    if exit.load(Ordering::Relaxed) {
                        break 'outer;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                let Ok(entries) = fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if self.exclusions.is_excluded(&path) {
                        continue;
                    }
                    let file_type = entry.file_type().ok();
                    if file_type.as_ref().is_some_and(|t| t.is_dir()) {
                        stack.push(path);
                        continue;
                    }
                    if !file_type.as_ref().is_some_and(|t| t.is_file()) {
                        continue; // symlinks, sockets, devices: skip
                    }
                    batch.push(path);
                    walked += 1;
                    if batch.len() >= SWEEP_FLUSH_BATCH {
                        flush(&mut batch);
                    }
                    if walked.is_multiple_of(50_000) {
                        eprintln!("karibad: real-time: catch-up sweep: {walked} paths queued");
                    }
                }
            }
        }
        flush(&mut batch);
        if let Ok(mut db) = self.db.lock() {
            db.finish_scan(scan_id, walked, 0, "completed");
        }
        if exit.load(Ordering::Relaxed) {
            eprintln!("karibad: real-time: catch-up sweep interrupted (shutdown)");
        } else {
            eprintln!(
                "karibad: real-time: catch-up sweep done ({walked} paths queued for idle scanning)"
            );
            *self.status_note.lock().unwrap() = None;
        }
    }
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
    housekeeping_thread: JoinHandle<()>,
    sweep_thread: JoinHandle<()>,
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
    // close is idempotent), then signal workers + helper threads to exit,
    // then persist whatever is still queued, interrupt blocked scans, and
    // join. The remainder is rescanned by the next lifetime, never here.
    fan.close();
    exit.store(true, Ordering::Relaxed);
    let _ = housekeeping_thread.join();
    let _ = sweep_thread.join();
    let mut paths = queue.take_spill_buf();
    paths.extend(queue.drain_paths());
    queue.persist(paths);
    shared.interrupt_workers();
    queue.notify_all();
    for worker in workers {
        let _ = worker.join();
    }
    shared.save_cache();

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
/// close-write/open paths for the workers. The event fd is closed before
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
    let is_open = event.mask & fanotify::FAN_OPEN != 0;
    let path = fs::read_link(format!("/proc/self/fd/{}", event.fd)).ok();

    // The kernel suffixes readlink targets of already-unlinked files;
    // nothing left to scan there.
    let vanished = path
        .as_ref()
        .is_some_and(|p| p.to_string_lossy().ends_with(" (deleted)"));

    if is_exec_perm {
        let allow = match &path {
            // Gate exclusions (default /usr, /boot) pass without a verdict;
            // full exclusions pass too. Async scanning still covers both.
            Some(path)
                if !vanished
                    && !shared.exclusions.is_excluded(path)
                    && !shared.exclusions.is_gate_excluded(path) =>
            {
                shared.exec_verdict(path, fstat_meta(event.fd), queue, deadline)
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
        let meta = fstat_meta(event.fd);
        let mode = meta.map(|m| m.mode).unwrap_or(0);
        match classify(path, mode) {
            // Churn gate: live databases get at most one scan per cooldown,
            // plus one final scan of the settled content.
            Lane::Churn => {
                if shared.churn_try_queue(path) {
                    queue.push_scan(path.clone(), Lane::Churn);
                }
            }
            lane => queue.push_scan(path.clone(), lane),
        }
    } else if is_open
        && shared.scan_on_open
        && !vanished
        && let Some(path) = &path
        && !shared.exclusions.is_excluded(path)
        && !writer_is_engine(event.pid)
        && let Some(meta) = fstat_meta(event.fd)
        && !meta.is_dir
    {
        // Cache-first read check: clean-and-unchanged files cost a hashmap
        // lookup and nothing else; misses queue an async scan. Infected
        // hits are left alone here (soft boundary; re-quarantining a
        // deliberately restored file on read would fight the user).
        let key = CacheKey::from_meta(&meta);
        if shared.cache_lookup(&key).is_none() {
            let lane = classify(path, meta.mode);
            if lane != Lane::Churn || shared.churn_try_queue(path) {
                queue.push_scan(path.clone(), lane);
            }
        }
    }

    fanotify::close_fd(event.fd);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_lanes() {
        // Exec bit wins.
        assert_eq!(classify(Path::new("/tmp/tool"), 0o755), Lane::Exec);
        // Shared libraries and AppImages without an exec bit.
        assert_eq!(classify(Path::new("/usr/lib/libfoo.so"), 0o644), Lane::Exec);
        assert_eq!(
            classify(Path::new("/opt/game/libbar.so.1"), 0o644),
            Lane::Exec
        );
        assert_eq!(
            classify(Path::new("/opt/Kariba.AppImage"), 0o644),
            Lane::Exec
        );
        // Bin-like directories.
        assert_eq!(
            classify(Path::new("/opt/app/bin/runner"), 0o644),
            Lane::Exec
        );
        // Churn: live databases and logs, checked before everything else.
        assert_eq!(classify(Path::new("/home/me/app.db"), 0o644), Lane::Churn);
        assert_eq!(
            classify(Path::new("/home/me/app.db-wal"), 0o644),
            Lane::Churn
        );
        assert_eq!(
            classify(Path::new("/home/me/data.sqlite"), 0o644),
            Lane::Churn
        );
        assert_eq!(classify(Path::new("/var/log/foo.log"), 0o644), Lane::Churn);
        // Media.
        assert_eq!(classify(Path::new("/tmp/texture.PNG"), 0o644), Lane::Media);
        assert_eq!(classify(Path::new("/tmp/song.mp3"), 0o644), Lane::Media);
        // Everything else is data.
        assert_eq!(classify(Path::new("/tmp/notes.txt"), 0o644), Lane::Data);
        assert_eq!(classify(Path::new("/tmp/archive.zip"), 0o644), Lane::Data);
    }

    #[test]
    fn queue_drains_in_priority_order() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        let queue = ScanQueue::new(Arc::new(Mutex::new(db)));
        let exit = Arc::new(AtomicBool::new(false));

        queue.push_scan(PathBuf::from("/m/1.png"), Lane::Media);
        queue.push_scan(PathBuf::from("/d/1.txt"), Lane::Data);
        queue.push_scan(PathBuf::from("/e/1.bin"), Lane::Exec);
        queue.push_scan(PathBuf::from("/c/1.db"), Lane::Churn);
        queue.push_gate_detection(PathBuf::from("/g/1.bin"), "Sig".into());

        let mut order = Vec::new();
        for _ in 0..5 {
            let Some(task) = queue.pop(&exit, Duration::from_millis(10)) else {
                break;
            };
            match task {
                Task::GateDetection { path, .. } => order.push(path),
                Task::Scan(path) => order.push(path),
            }
        }
        assert_eq!(
            order,
            vec![
                PathBuf::from("/g/1.bin"), // gate bookkeeping first
                PathBuf::from("/e/1.bin"), // exec lane
                PathBuf::from("/d/1.txt"), // data lane
                PathBuf::from("/c/1.db"),  // churn rides with data, FIFO
                PathBuf::from("/m/1.png"), // media last
            ]
        );
    }

    #[test]
    fn queue_dedups_paths() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        let queue = ScanQueue::new(Arc::new(Mutex::new(db)));
        let exit = Arc::new(AtomicBool::new(false));

        queue.push_scan(PathBuf::from("/a/file"), Lane::Data);
        queue.push_scan(PathBuf::from("/a/file"), Lane::Data);
        queue.push_scan(PathBuf::from("/a/file"), Lane::Exec);

        assert!(queue.pop(&exit, Duration::from_millis(10)).is_some());
        // Nothing else was queued: depth is back to zero.
        assert_eq!(queue.depth(), 0);
    }

    #[test]
    fn churn_gate_blocks_rapid_requeue() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        let shared_db = Arc::new(Mutex::new(db));
        let status_note = Arc::new(Mutex::new(None));
        let ctx = WatcherCtx {
            db: Arc::clone(&shared_db),
            quarantine: Arc::new(Quarantine::new(dir.path().join("q")).unwrap()),
            broadcaster: Arc::new(Broadcaster::new()),
            data_dir: dir.path().to_path_buf(),
            settings: kariba_core::config::Settings::default(),
        };
        let shared = Shared::new(&ctx, status_note, Vec::new());

        let path = Path::new("/home/me/app.db");
        assert!(shared.churn_try_queue(path)); // first write: scan now
        assert!(!shared.churn_try_queue(path)); // immediate rewrite: cooldown
        assert!(!shared.churn_try_queue(path)); // still cooling down
    }
}
