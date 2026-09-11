//! The catalog: devices, runs, snapshots. Nothing else.
//!
//! Per CLAUDE.md: "Keep it small. It tracks devices, runs and snapshots —
//! not file-level deltas." `archives` and `destinations` join this schema
//! in M3, once there's an archive layer to populate them — adding empty,
//! unused tables now would be working ahead of what this milestone needs.
//!
//! Secrets never live here. `devices.credential_ref` is a name to look up
//! in the macOS Keychain (Windows DPAPI later), never a secret value
//! itself — nothing populates it yet, since nothing in Cradle needs a
//! stored secret before M5's crypto layer.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::CradleError;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS devices (
    udid            TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    product_type    TEXT NOT NULL,
    ios_version     TEXT NOT NULL,
    last_seen       INTEGER NOT NULL,
    encrypted       INTEGER NOT NULL,
    credential_ref  TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    udid        TEXT NOT NULL REFERENCES devices(udid),
    kind        TEXT NOT NULL,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    status      TEXT NOT NULL,
    bytes       INTEGER,
    files       INTEGER,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    udid         TEXT NOT NULL REFERENCES devices(udid),
    run_id       INTEGER NOT NULL REFERENCES runs(id),
    taken_at     INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    ios_version  TEXT NOT NULL,
    verified_at  INTEGER
);

CREATE INDEX IF NOT EXISTS runs_udid ON runs(udid);
CREATE INDEX IF NOT EXISTS snapshots_udid ON snapshots(udid);
";

/// Handle to the catalog database. One per process is plenty — this is
/// small, local, and only ever touched briefly before/after a transfer,
/// never during one.
pub struct Catalog {
    conn: Connection,
}

/// What kind of operation a [`runs`] row records. Only `Backup` exists
/// until M4 adds restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    Backup,
}

impl RunKind {
    fn as_str(self) -> &'static str {
        match self {
            RunKind::Backup => "backup",
        }
    }
}

/// How a run ended, or that it hasn't yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Running,
    Succeeded,
    Failed,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Succeeded => "succeeded",
            RunStatus::Failed => "failed",
        }
    }
}

/// A device as last seen, for the `devices` table.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub udid: String,
    pub name: String,
    pub product_type: String,
    pub ios_version: String,
    pub encrypted: bool,
}

/// One row from `runs`.
#[derive(Debug, Clone)]
pub struct RunRecord {
    pub id: i64,
    pub udid: String,
    pub kind: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: String,
    pub bytes: Option<i64>,
    pub files: Option<i64>,
    pub error: Option<String>,
}

/// One row from `snapshots`.
#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub id: i64,
    pub udid: String,
    pub run_id: i64,
    pub taken_at: i64,
    pub size: i64,
    pub ios_version: String,
    pub verified_at: Option<i64>,
}

/// Current time as Unix seconds — every timestamp column in this schema
/// uses this, so a human inspecting the database with `sqlite3` can read
/// them via `datetime(started_at, 'unixepoch')`.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Catalog {
    /// Opens (creating if needed) the catalog database at `path`,
    /// including its parent directory.
    pub fn open(path: &Path) -> Result<Self, CradleError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// The default catalog location: the platform data directory (e.g.
    /// `~/Library/Application Support` on macOS) under `Cradle/catalog.db`.
    pub fn default_path() -> Result<PathBuf, CradleError> {
        let base = dirs::data_dir()
            .ok_or_else(|| CradleError::Other("could not determine a data directory for this platform".into()))?;
        Ok(base.join("Cradle").join("catalog.db"))
    }

    /// Inserts or updates a device's row, bumping `last_seen` to now.
    pub fn upsert_device(&self, device: &DeviceRecord) -> Result<(), CradleError> {
        self.conn.execute(
            "INSERT INTO devices (udid, name, product_type, ios_version, last_seen, encrypted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(udid) DO UPDATE SET
                name = excluded.name,
                product_type = excluded.product_type,
                ios_version = excluded.ios_version,
                last_seen = excluded.last_seen,
                encrypted = excluded.encrypted",
            params![
                device.udid,
                device.name,
                device.product_type,
                device.ios_version,
                now(),
                device.encrypted as i64,
            ],
        )?;
        Ok(())
    }

    /// Opens a new run row with `status = 'running'` and returns its id.
    pub fn start_run(&self, udid: &str, kind: RunKind) -> Result<i64, CradleError> {
        self.conn.execute(
            "INSERT INTO runs (udid, kind, started_at, status) VALUES (?1, ?2, ?3, ?4)",
            params![udid, kind.as_str(), now(), RunStatus::Running.as_str()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Closes out a run: final status, byte/file counts, and an error
    /// message if it failed. Always call this — a run left `"running"`
    /// forever is as much a bug as one recorded with the wrong outcome.
    pub fn finish_run(
        &self,
        run_id: i64,
        status: RunStatus,
        bytes: u64,
        files: u64,
        error: Option<&str>,
    ) -> Result<(), CradleError> {
        self.conn.execute(
            "UPDATE runs SET ended_at = ?1, status = ?2, bytes = ?3, files = ?4, error = ?5
             WHERE id = ?6",
            params![now(), status.as_str(), bytes as i64, files as i64, error, run_id],
        )?;
        Ok(())
    }

    /// Records a snapshot produced by `run_id`. `verified` should reflect
    /// whether [`crate::verify::Report::passed`] returned true — per
    /// CLAUDE.md, an unverified run must never look like a trustworthy
    /// snapshot, so callers must not call this for a run that failed the
    /// gate.
    pub fn record_snapshot(
        &self,
        udid: &str,
        run_id: i64,
        size: u64,
        ios_version: &str,
        verified: bool,
    ) -> Result<i64, CradleError> {
        self.conn.execute(
            "INSERT INTO snapshots (udid, run_id, taken_at, size, ios_version, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                udid,
                run_id,
                now(),
                size as i64,
                ios_version,
                verified.then(now),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Runs for `udid`, most recent first.
    pub fn list_runs(&self, udid: &str) -> Result<Vec<RunRecord>, CradleError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, udid, kind, started_at, ended_at, status, bytes, files, error
             FROM runs WHERE udid = ?1 ORDER BY started_at DESC",
        )?;
        let rows = stmt
            .query_map(params![udid], |row| {
                Ok(RunRecord {
                    id: row.get(0)?,
                    udid: row.get(1)?,
                    kind: row.get(2)?,
                    started_at: row.get(3)?,
                    ended_at: row.get(4)?,
                    status: row.get(5)?,
                    bytes: row.get(6)?,
                    files: row.get(7)?,
                    error: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Snapshots for `udid`, most recent first.
    pub fn list_snapshots(&self, udid: &str) -> Result<Vec<SnapshotRecord>, CradleError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, udid, run_id, taken_at, size, ios_version, verified_at
             FROM snapshots WHERE udid = ?1 ORDER BY taken_at DESC",
        )?;
        let rows = stmt
            .query_map(params![udid], |row| {
                Ok(SnapshotRecord {
                    id: row.get(0)?,
                    udid: row.get(1)?,
                    run_id: row.get(2)?,
                    taken_at: row.get(3)?,
                    size: row.get(4)?,
                    ios_version: row.get(5)?,
                    verified_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The most recent run for `udid`, if any.
    pub fn latest_run(&self, udid: &str) -> Result<Option<RunRecord>, CradleError> {
        self.conn
            .query_row(
                "SELECT id, udid, kind, started_at, ended_at, status, bytes, files, error
                 FROM runs WHERE udid = ?1 ORDER BY started_at DESC LIMIT 1",
                params![udid],
                |row| {
                    Ok(RunRecord {
                        id: row.get(0)?,
                        udid: row.get(1)?,
                        kind: row.get(2)?,
                        started_at: row.get(3)?,
                        ended_at: row.get(4)?,
                        status: row.get(5)?,
                        bytes: row.get(6)?,
                        files: row.get(7)?,
                        error: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(CradleError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> Catalog {
        // In-memory: no cleanup needed, and rusqlite/SQLite support it
        // directly rather than needing a temp-file dance.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        Catalog { conn }
    }

    fn device(udid: &str) -> DeviceRecord {
        DeviceRecord {
            udid: udid.to_string(),
            name: "Test Device".to_string(),
            product_type: "iPhone18,3".to_string(),
            ios_version: "26.6.1".to_string(),
            encrypted: true,
        }
    }

    #[test]
    fn run_lifecycle_round_trips() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();

        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();
        let latest = cat.latest_run("udid-1").unwrap().unwrap();
        assert_eq!(latest.status, "running");
        assert_eq!(latest.ended_at, None);

        cat.finish_run(run_id, RunStatus::Succeeded, 12_345, 42, None)
            .unwrap();
        let latest = cat.latest_run("udid-1").unwrap().unwrap();
        assert_eq!(latest.status, "succeeded");
        assert_eq!(latest.bytes, Some(12_345));
        assert_eq!(latest.files, Some(42));
        assert!(latest.ended_at.is_some());
    }

    #[test]
    fn failed_run_keeps_its_error() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();

        cat.finish_run(run_id, RunStatus::Failed, 0, 0, Some("device locked"))
            .unwrap();

        let latest = cat.latest_run("udid-1").unwrap().unwrap();
        assert_eq!(latest.status, "failed");
        assert_eq!(latest.error.as_deref(), Some("device locked"));
    }

    #[test]
    fn verified_snapshot_records_verified_at() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();

        let snap_id = cat
            .record_snapshot("udid-1", run_id, 1_000_000, "26.6.1", true)
            .unwrap();
        let snapshots = cat.list_snapshots("udid-1").unwrap();
        let snap = snapshots.iter().find(|s| s.id == snap_id).unwrap();
        assert!(snap.verified_at.is_some());
    }

    #[test]
    fn unverified_snapshot_leaves_verified_at_null() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();

        cat.record_snapshot("udid-1", run_id, 1_000_000, "26.6.1", false)
            .unwrap();
        let snapshots = cat.list_snapshots("udid-1").unwrap();
        assert_eq!(snapshots[0].verified_at, None);
    }

    #[test]
    fn upsert_device_updates_rather_than_duplicates() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let mut updated = device("udid-1");
        updated.name = "Renamed".to_string();
        cat.upsert_device(&updated).unwrap();

        let count: i64 = cat
            .conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
