use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,
    paths         TEXT NOT NULL,
    started_at    INTEGER NOT NULL,
    finished_at   INTEGER,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    engine      TEXT NOT NULL,
    signature   TEXT NOT NULL,
    detected_at INTEGER NOT NULL,
    status      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id      INTEGER NOT NULL REFERENCES threats(id),
    original_path  TEXT NOT NULL,
    blob_path      TEXT NOT NULL,
    original_mode  INTEGER NOT NULL,
    size           INTEGER NOT NULL,
    quarantined_at INTEGER NOT NULL
);
-- Real-time scan queue overflow. Close-write events beyond the in-memory
-- queue cap spill here so coverage survives bursts and daemon restarts;
-- the watcher drains this table after the in-memory queue.
CREATE TABLE IF NOT EXISTS pending_scans (
    path      TEXT PRIMARY KEY,
    queued_at INTEGER NOT NULL
);
";

pub struct QuarantineRow {
    pub id: u64,
    pub threat_id: u64,
    pub original_path: String,
    pub blob_path: String,
    pub original_mode: u32,
    pub size: u64,
    pub quarantined_at: u64,
    pub engine: String,
    pub signature: String,
    // "scan" | "realtime"
    pub source: String,
}

pub struct ThreatRow {
    pub id: u64,
    pub path: String,
    pub sha256: String,
    pub engine: String,
    pub signature: String,
    pub detected_at: u64,
    // detected | quarantined | restored | deleted
    pub status: String,
    // "scan" | "realtime"
    pub source: String,
}

pub struct ScanRow {
    pub id: u64,
    pub kind: String,
    pub paths: Vec<String>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub status: String,
}

pub struct Db {
    conn: Connection,
}

/// Detections are grouped under their scan row; real-time catches live under
/// the sentinel "realtime" scan (see realtime.rs).
fn source_from_kind(kind: &str) -> String {
    if kind == "realtime" {
        "realtime".into()
    } else {
        "scan".into()
    }
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn insert_scan(&mut self, kind: &str, paths: &[String]) -> u64 {
        let paths_json = serde_json::to_string(paths).unwrap_or_else(|_| "[]".into());
        let _ = self.conn.execute(
            "INSERT INTO scans (kind, paths, started_at, status) VALUES (?1, ?2, ?3, 'running')",
            params![kind, paths_json, Self::now() as i64],
        );
        self.conn.last_insert_rowid() as u64
    }

    pub fn finish_scan(&mut self, id: u64, files_scanned: u64, threats_found: u32, status: &str) {
        let _ = self.conn.execute(
            "UPDATE scans SET finished_at = ?1, files_scanned = ?2, threats_found = ?3, status = ?4 WHERE id = ?5",
            params![Self::now() as i64, files_scanned as i64, threats_found as i64, status, id as i64],
        );
    }

    pub fn insert_threat(
        &mut self,
        scan_id: u64,
        path: &str,
        sha256: &str,
        engine: &str,
        signature: &str,
    ) -> u64 {
        let _ = self.conn.execute(
            "INSERT INTO threats (scan_id, path, sha256, engine, signature, detected_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'detected')",
            params![
                scan_id as i64,
                path,
                sha256,
                engine,
                signature,
                Self::now() as i64
            ],
        );
        self.conn.last_insert_rowid() as u64
    }

    pub fn set_threat_status(&mut self, id: u64, status: &str) {
        let _ = self.conn.execute(
            "UPDATE threats SET status = ?1 WHERE id = ?2",
            params![status, id as i64],
        );
    }

    pub fn insert_quarantine(
        &mut self,
        threat_id: u64,
        original_path: &str,
        blob_path: &str,
        original_mode: u32,
        size: u64,
    ) -> u64 {
        let _ = self.conn.execute(
            "INSERT INTO quarantine (threat_id, original_path, blob_path, original_mode, size, quarantined_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![threat_id as i64, original_path, blob_path, original_mode as i64, size as i64, Self::now() as i64],
        );
        self.conn.last_insert_rowid() as u64
    }

    pub fn list_quarantine(&self) -> Vec<QuarantineRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT q.id, q.threat_id, q.original_path, q.blob_path, q.original_mode,
                        q.size, q.quarantined_at, t.engine, t.signature, s.kind
                 FROM quarantine q
                 JOIN threats t ON t.id = q.threat_id
                 JOIN scans s ON s.id = t.scan_id
                 ORDER BY q.id",
            )
            .expect("quarantine list query is valid");
        stmt.query_map([], |row| {
            let kind: String = row.get(9)?;
            Ok(QuarantineRow {
                id: row.get::<_, i64>(0)? as u64,
                threat_id: row.get::<_, i64>(1)? as u64,
                original_path: row.get(2)?,
                blob_path: row.get(3)?,
                original_mode: row.get::<_, i64>(4)? as u32,
                size: row.get::<_, i64>(5)? as u64,
                quarantined_at: row.get::<_, i64>(6)? as u64,
                engine: row.get(7)?,
                signature: row.get(8)?,
                source: source_from_kind(&kind),
            })
        })
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    }

    pub fn get_quarantine(&self, id: u64) -> Option<QuarantineRow> {
        self.list_quarantine().into_iter().find(|r| r.id == id)
    }

    pub fn delete_quarantine(&mut self, id: u64) {
        let _ = self
            .conn
            .execute("DELETE FROM quarantine WHERE id = ?1", params![id as i64]);
    }

    /// Spill queued scan paths to disk. `INSERT OR IGNORE` keeps the dedup
    /// guarantee across restarts: one pending row per path. Batched in a
    /// transaction — per-statement autocommit would fsync once per path.
    pub fn spill_pending(&mut self, paths: &[PathBuf]) {
        if paths.is_empty() {
            return;
        }
        let Ok(tx) = self.conn.transaction() else {
            return;
        };
        let now = Self::now() as i64;
        {
            let mut stmt = tx
                .prepare("INSERT OR IGNORE INTO pending_scans (path, queued_at) VALUES (?1, ?2)")
                .expect("pending insert is valid");
            for path in paths {
                let _ = stmt.execute(params![path.display().to_string(), now]);
            }
        }
        let _ = tx.commit();
    }

    /// Take up to `limit` pending paths for scanning and remove them.
    pub fn take_pending(&mut self, limit: u64) -> Vec<PathBuf> {
        let paths: Vec<PathBuf> = self
            .conn
            .prepare("SELECT path FROM pending_scans ORDER BY queued_at LIMIT ?1")
            .expect("pending select is valid")
            .query_map(params![limit as i64], |row| {
                let path: String = row.get(0)?;
                Ok(PathBuf::from(path))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default();
        if !paths.is_empty() {
            let _ = self.conn.execute(
                "DELETE FROM pending_scans WHERE path IN (SELECT path FROM pending_scans ORDER BY queued_at LIMIT ?1)",
                params![limit as i64],
            );
        }
        paths
    }

    #[allow(dead_code)] // exercised by tests; future status surface
    pub fn pending_count(&self) -> u64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM pending_scans", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64
    }

    pub fn counts(&self) -> (u64, u64, u64) {
        let count = |table: &str| -> u64 {
            self.conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap_or(0) as u64
        };
        (count("scans"), count("threats"), count("quarantine"))
    }

    /// Threat history. The threats table is append-only — one row per
    /// detection event, so identical files detected repeatedly yield one row
    /// each; restore/delete only flip `status`, never remove rows.
    pub fn list_threats(&self, status: Option<&str>, limit: u64) -> Vec<ThreatRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT t.id, t.path, t.sha256, t.engine, t.signature, t.detected_at,
                        t.status, s.kind
                 FROM threats t
                 JOIN scans s ON s.id = t.scan_id
                 WHERE (?1 IS NULL OR t.status = ?1)
                 ORDER BY t.id DESC LIMIT ?2",
            )
            .expect("threat history query is valid");
        stmt.query_map(params![status, limit as i64], |row| {
            let kind: String = row.get(7)?;
            Ok(ThreatRow {
                id: row.get::<_, i64>(0)? as u64,
                path: row.get(1)?,
                sha256: row.get(2)?,
                engine: row.get(3)?,
                signature: row.get(4)?,
                detected_at: row.get::<_, i64>(5)? as u64,
                status: row.get(6)?,
                source: source_from_kind(&kind),
            })
        })
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    }

    pub fn list_scans(&self, limit: u64) -> Vec<ScanRow> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, paths, started_at, finished_at, files_scanned,
                        threats_found, status
                 FROM scans ORDER BY id DESC LIMIT ?1",
            )
            .expect("scan history query is valid");
        stmt.query_map(params![limit as i64], |row| {
            let paths_json: String = row.get(2)?;
            Ok(ScanRow {
                id: row.get::<_, i64>(0)? as u64,
                kind: row.get(1)?,
                paths: serde_json::from_str(&paths_json).unwrap_or_default(),
                started_at: row.get::<_, i64>(3)? as u64,
                finished_at: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                files_scanned: row.get::<_, i64>(5)? as u64,
                threats_found: row.get::<_, i64>(6)? as u32,
                status: row.get(7)?,
            })
        })
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open(&dir.path().join("test.db")).unwrap();

        let scan_id = db.insert_scan("custom", &["/tmp".into()]);
        assert!(scan_id > 0);

        let threat_id = db.insert_threat(scan_id, "/tmp/x", "abc", "ClamAV", "Test.Sig");
        db.set_threat_status(threat_id, "quarantined");

        let q_id = db.insert_quarantine(threat_id, "/tmp/x", "/q/1.quar", 0o644, 42);
        let rows = db.list_quarantine();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, q_id);
        assert_eq!(rows[0].signature, "Test.Sig");
        assert_eq!(rows[0].original_mode, 0o644);

        let (scans, threats, quarantined) = db.counts();
        assert_eq!((scans, threats, quarantined), (1, 1, 1));

        db.delete_quarantine(q_id);
        assert!(db.list_quarantine().is_empty());

        db.finish_scan(scan_id, 100, 1, "completed");
    }

    #[test]
    fn threat_history_preserves_duplicates_and_status_transitions() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open(&dir.path().join("test.db")).unwrap();

        let scan_id = db.insert_scan("custom", &["/tmp".into()]);
        // Same file detected twice: two distinct history rows, never deduped.
        let first = db.insert_threat(scan_id, "/tmp/x", "abc", "ClamAV", "Test.Sig");
        let second = db.insert_threat(scan_id, "/tmp/x", "abc", "ClamAV", "Test.Sig");
        assert_ne!(first, second);
        assert_eq!(db.list_threats(None, 50).len(), 2);

        // Lifecycle: quarantined -> restored. The row survives resolution.
        db.set_threat_status(first, "quarantined");
        db.set_threat_status(first, "restored");
        db.set_threat_status(second, "quarantined");
        db.set_threat_status(second, "deleted");

        let all = db.list_threats(None, 50);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].status, "deleted"); // newest first
        assert_eq!(all[1].status, "restored");
        assert!(all.iter().all(|t| t.source == "scan"));

        let restored = db.list_threats(Some("restored"), 50);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].id, first);

        assert!(db.list_threats(Some("detected"), 50).is_empty());

        // Real-time catches sit under the sentinel "realtime" scan row and
        // are marked as such in history.
        let rt_scan = db.insert_scan("realtime", &["<real-time protection>".into()]);
        let rt_threat = db.insert_threat(rt_scan, "/tmp/dropped", "abc", "ClamAV", "Test.Sig");
        db.insert_quarantine(rt_threat, "/tmp/dropped", "/q/9.quar", 0o644, 3);
        let rt = db.list_threats(None, 50);
        assert_eq!(rt[0].id, rt_threat);
        assert_eq!(rt[0].source, "realtime");
        let q_rows = db.list_quarantine();
        assert_eq!(q_rows.len(), 1);
        assert_eq!(q_rows[0].source, "realtime");
    }

    #[test]
    fn pending_queue_spills_dedupes_and_drains() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Db::open(&dir.path().join("test.db")).unwrap();

        let paths = vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")];
        db.spill_pending(&paths);
        // Re-spilling the same paths must not duplicate rows.
        db.spill_pending(&[PathBuf::from("/tmp/b"), PathBuf::from("/tmp/c")]);
        assert_eq!(db.pending_count(), 3);

        let taken = db.take_pending(2);
        assert_eq!(taken.len(), 2);
        assert_eq!(db.pending_count(), 1);
        let rest = db.take_pending(10);
        assert_eq!(rest, vec![PathBuf::from("/tmp/c")]);
        assert!(db.take_pending(10).is_empty());
    }
}
