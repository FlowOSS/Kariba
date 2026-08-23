use rusqlite::{Connection, params};
use std::path::Path;
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
                        q.size, q.quarantined_at, t.engine, t.signature
                 FROM quarantine q JOIN threats t ON t.id = q.threat_id
                 ORDER BY q.id",
            )
            .expect("quarantine list query is valid");
        stmt.query_map([], |row| {
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
}
