//! The catalog: devices, runs, snapshots, destinations, archives.
//!
//! Kept small: it tracks devices, runs and snapshots — not file-level
//! deltas. `destinations` and `archives` joined this schema once there was
//! an archive layer to populate them.
//!
//! Secrets never live here. `devices.credential_ref` and
//! `destinations.credential_ref` are names to look up in the macOS
//! Keychain (Windows DPAPI later) — see [`crate::keychain`] — never a
//! secret value itself. `devices.credential_ref` still isn't populated by
//! anything; nothing needs a per-device stored secret before the crypto
//! layer. `destinations.credential_ref` is populated once an archive
//! destination exists: every restic repository needs a password, and
//! restic — not Cradle — is the thing that encrypts archived data (Cradle
//! doesn't build its own archive encryption).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

CREATE TABLE IF NOT EXISTS destinations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,
    uri             TEXT NOT NULL,
    credential_ref  TEXT NOT NULL,
    retention_json  TEXT
);

CREATE TABLE IF NOT EXISTS archives (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    destination_id  INTEGER NOT NULL REFERENCES destinations(id),
    restic_id       TEXT,
    state           TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    verified_at     INTEGER,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS runs_udid ON runs(udid);
CREATE INDEX IF NOT EXISTS snapshots_udid ON snapshots(udid);
CREATE INDEX IF NOT EXISTS archives_snapshot ON archives(snapshot_id);
CREATE INDEX IF NOT EXISTS archives_destination ON archives(destination_id);
";

/// Handle to the catalog database. One per process is plenty — this is
/// small, local, and only ever touched briefly before/after a transfer,
/// never during one.
///
/// The connection is `Mutex`-wrapped so `Catalog` is `Sync`, not just
/// `Send`: `workflow.rs` holds a `Catalog` across `.await` points
/// alongside other operations, and a plain `rusqlite::Connection` is
/// `Send` but not `Sync` — a `&Catalog` held across an await would make
/// the enclosing future un-`Send`, which Tauri's command futures must be.
/// Actual contention is essentially nonexistent in practice (this is a
/// small local database touched briefly around a transfer, not during
/// one), so a plain `Mutex` costs nothing worth measuring.
pub struct Catalog {
    conn: Mutex<Connection>,
}

/// What kind of operation a [`runs`] row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    Backup,
    Restore,
}

impl RunKind {
    fn as_str(self) -> &'static str {
        match self {
            RunKind::Backup => "backup",
            RunKind::Restore => "restore",
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
#[derive(Debug, Clone, serde::Serialize)]
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapshotRecord {
    pub id: i64,
    pub udid: String,
    pub run_id: i64,
    pub taken_at: i64,
    pub size: i64,
    pub ios_version: String,
    pub verified_at: Option<i64>,
}

/// A configured archive target, for the `destinations` table. `kind` is
/// informational (`"local"` / `"nas"` / `"s3"` / `"b2"`, ...) — restic's own
/// backend abstraction is what actually interprets `uri`; nothing in
/// Cradle branches on `kind` to talk to a backend differently. See
/// `archive.rs`.
#[derive(Debug, Clone)]
pub struct DestinationRecord {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub uri: String,
    /// Keychain account — see [`crate::keychain::new_destination_account`].
    /// Never the password itself.
    pub credential_ref: String,
    pub retention_json: Option<String>,
}

/// Whether an archive attempt is in flight or how it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveState {
    Pending,
    Succeeded,
    Failed,
}

impl ArchiveState {
    fn as_str(self) -> &'static str {
        match self {
            ArchiveState::Pending => "pending",
            ArchiveState::Succeeded => "succeeded",
            ArchiveState::Failed => "failed",
        }
    }
}

/// One row from `archives`. Tied to a local `snapshot_id`, not a `run_id`
/// — archiving is its own operation against an already-verified snapshot,
/// not a kind of run.
#[derive(Debug, Clone)]
pub struct ArchiveRecord {
    pub id: i64,
    pub snapshot_id: i64,
    pub destination_id: i64,
    pub restic_id: Option<String>,
    pub state: String,
    pub created_at: i64,
    pub verified_at: Option<i64>,
    pub error: Option<String>,
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
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Locks the connection. A poisoned lock (only possible if a prior
    /// call panicked mid-statement) still yields the connection rather
    /// than poisoning every future call forever — the data underneath is
    /// exactly as valid as it was before the panic; SQLite's own
    /// transaction semantics are what actually protect it.
    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
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
        self.conn().execute(
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

    /// Every device Cradle has ever backed up, most recently seen first.
    /// Used to offer a cross-device restore source that isn't the device
    /// currently attached — the whole point of `source_udid` in
    /// [`crate::restore::run`] is that the backup being restored can come
    /// from a device that's no longer around.
    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>, CradleError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT udid, name, product_type, ios_version, encrypted
             FROM devices ORDER BY last_seen DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DeviceRecord {
                    udid: row.get(0)?,
                    name: row.get(1)?,
                    product_type: row.get(2)?,
                    ios_version: row.get(3)?,
                    encrypted: row.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Opens a new run row with `status = 'running'` and returns its id.
    pub fn start_run(&self, udid: &str, kind: RunKind) -> Result<i64, CradleError> {
        // One guard for both calls: `last_insert_rowid` reflects whatever
        // this connection inserted most recently, so another operation
        // squeezing in an insert between `execute` and this would return
        // the wrong id.
        let conn = self.conn();
        conn.execute(
            "INSERT INTO runs (udid, kind, started_at, status) VALUES (?1, ?2, ?3, ?4)",
            params![udid, kind.as_str(), now(), RunStatus::Running.as_str()],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Marks every `running` row for `udid` as `failed` — for a caller
    /// that just acquired [`crate::lock::WorkingSetLock`] for this device
    /// and can therefore be certain nothing else is actually running
    /// against it: any `running` row it finds must be left over from a
    /// process that exited without calling [`Catalog::finish_run`] (a
    /// crash, a kill, a forced quit), not a real concurrent operation.
    /// Returns how many rows it closed out, purely for logging — zero is
    /// the ordinary case.
    pub fn fail_abandoned_runs(&self, udid: &str) -> Result<u64, CradleError> {
        let changed = self.conn().execute(
            "UPDATE runs SET ended_at = ?1, status = ?2, error = ?3
             WHERE udid = ?4 AND status = ?5",
            params![
                now(),
                RunStatus::Failed.as_str(),
                "abandoned: process exited without finishing this run",
                udid,
                RunStatus::Running.as_str(),
            ],
        )?;
        Ok(changed as u64)
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
        self.conn().execute(
            "UPDATE runs SET ended_at = ?1, status = ?2, bytes = ?3, files = ?4, error = ?5
             WHERE id = ?6",
            params![now(), status.as_str(), bytes as i64, files as i64, error, run_id],
        )?;
        Ok(())
    }

    /// Atomically closes out a successful backup run and records the
    /// snapshot it produced — one transaction, not the two separate
    /// statements [`Catalog::finish_run`] plus [`Catalog::record_snapshot`]
    /// would be. CODEBASE_ANALYSIS.md: "SQLite completion and snapshot
    /// creation are separate statements; failed bookkeeping can disagree
    /// with completed data operations." Without this, a crash between the
    /// two writes could leave a run marked `succeeded` with no snapshot
    /// row to show for it — the backup actually completed, but nothing in
    /// the catalog would know it produced anything restorable.
    #[allow(clippy::too_many_arguments)] // one field per column across the two rows this writes atomically
    pub fn finish_run_with_snapshot(
        &self,
        run_id: i64,
        bytes: u64,
        files: u64,
        udid: &str,
        size: u64,
        ios_version: &str,
        verified: bool,
    ) -> Result<i64, CradleError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE runs SET ended_at = ?1, status = ?2, bytes = ?3, files = ?4, error = NULL
             WHERE id = ?5",
            params![now(), RunStatus::Succeeded.as_str(), bytes as i64, files as i64, run_id],
        )?;
        tx.execute(
            "INSERT INTO snapshots (udid, run_id, taken_at, size, ios_version, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![udid, run_id, now(), size as i64, ios_version, verified.then(now)],
        )?;
        let snapshot_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(snapshot_id)
    }

    /// Records a snapshot produced by `run_id`. `verified` should reflect
    /// whether [`crate::verify::Report::passed`] returned true — an
    /// unverified run must never look like a trustworthy snapshot, so
    /// callers must not call this for a run that failed the
    /// gate.
    pub fn record_snapshot(
        &self,
        udid: &str,
        run_id: i64,
        size: u64,
        ios_version: &str,
        verified: bool,
    ) -> Result<i64, CradleError> {
        // See `start_run` for why this is one guard, not two.
        let conn = self.conn();
        conn.execute(
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
        Ok(conn.last_insert_rowid())
    }

    /// Runs for `udid`, most recent first.
    pub fn list_runs(&self, udid: &str) -> Result<Vec<RunRecord>, CradleError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
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
        let conn = self.conn();
        let mut stmt = conn.prepare(
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
        self.conn()
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

    /// The most recently taken *verified* snapshot for `udid`, if any.
    /// What `cradle archive` looks for — a partial backup must never
    /// become a snapshot, so archiving must never pick up one that hasn't
    /// passed the verification gate.
    pub fn latest_verified_snapshot(
        &self,
        udid: &str,
    ) -> Result<Option<SnapshotRecord>, CradleError> {
        self.conn()
            .query_row(
                "SELECT id, udid, run_id, taken_at, size, ios_version, verified_at
                 FROM snapshots
                 WHERE udid = ?1 AND verified_at IS NOT NULL
                 ORDER BY taken_at DESC LIMIT 1",
                params![udid],
                |row| {
                    Ok(SnapshotRecord {
                        id: row.get(0)?,
                        udid: row.get(1)?,
                        run_id: row.get(2)?,
                        taken_at: row.get(3)?,
                        size: row.get(4)?,
                        ios_version: row.get(5)?,
                        verified_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(CradleError::from)
    }

    /// The most recently taken snapshot for `udid`, verified or not — used
    /// to find the snapshot a just-supplied password should be checked
    /// against, without caring yet whether it already passed.
    pub fn latest_snapshot(&self, udid: &str) -> Result<Option<SnapshotRecord>, CradleError> {
        self.conn()
            .query_row(
                "SELECT id, udid, run_id, taken_at, size, ios_version, verified_at
                 FROM snapshots WHERE udid = ?1 ORDER BY taken_at DESC LIMIT 1",
                params![udid],
                |row| {
                    Ok(SnapshotRecord {
                        id: row.get(0)?,
                        udid: row.get(1)?,
                        run_id: row.get(2)?,
                        taken_at: row.get(3)?,
                        size: row.get(4)?,
                        ios_version: row.get(5)?,
                        verified_at: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(CradleError::from)
    }

    /// Marks an existing snapshot verified after the fact — for a snapshot
    /// recorded as `NeedsPassword` whose password Cradle has since been
    /// given, letting the already-downloaded `Manifest.db` be re-checked
    /// without a repeat device transfer. A no-op if already verified.
    pub fn mark_snapshot_verified(&self, snapshot_id: i64) -> Result<(), CradleError> {
        self.conn().execute(
            "UPDATE snapshots SET verified_at = ?1 WHERE id = ?2 AND verified_at IS NULL",
            params![now(), snapshot_id],
        )?;
        Ok(())
    }

    /// Registers a new archive destination. `credential_ref` is a Keychain
    /// account name (see [`crate::keychain::new_destination_account`]), not a
    /// secret.
    pub fn create_destination(
        &self,
        name: &str,
        kind: &str,
        uri: &str,
        credential_ref: &str,
    ) -> Result<i64, CradleError> {
        // See `start_run` for why this is one guard, not two.
        let conn = self.conn();
        conn.execute(
            "INSERT INTO destinations (name, kind, uri, credential_ref) VALUES (?1, ?2, ?3, ?4)",
            params![name, kind, uri, credential_ref],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Looks up a destination by its unique name (what the CLI addresses
    /// destinations by — ids are catalog-internal).
    pub fn destination_by_name(
        &self,
        name: &str,
    ) -> Result<Option<DestinationRecord>, CradleError> {
        self.conn()
            .query_row(
                "SELECT id, name, kind, uri, credential_ref, retention_json
                 FROM destinations WHERE name = ?1",
                params![name],
                Self::map_destination,
            )
            .optional()
            .map_err(CradleError::from)
    }

    /// Removes a destination's catalog row. Does *not* touch the restic
    /// repository itself — the actual backed-up data at `uri` is
    /// untouched, only Cradle's record of the destination goes away.
    /// Callers are expected to also delete the Keychain-stored password
    /// (this doesn't do that itself, since credential deletion goes
    /// through `keychain.rs`, not the catalog).
    ///
    /// Also removes this destination's own `archives` rows first, in the
    /// same transaction — every real destination has archived at least one
    /// snapshot to it by the time anyone wants to remove it, and
    /// `archives.destination_id` is a foreign key with no `ON DELETE`
    /// clause, so deleting the destination alone fails outright ("FOREIGN
    /// KEY constraint failed") rather than removing it. Those rows are
    /// only Cradle's local record of *which* snapshot went where and under
    /// what restic id — not the archived data itself, which this doesn't
    /// touch — so dropping them is exactly as harmless as the doc above
    /// already promises the destination row's own removal is.
    pub fn delete_destination(&self, id: i64) -> Result<(), CradleError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM archives WHERE destination_id = ?1", params![id])?;
        tx.execute("DELETE FROM destinations WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(())
    }

    /// All configured destinations.
    pub fn list_destinations(&self) -> Result<Vec<DestinationRecord>, CradleError> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT id, name, kind, uri, credential_ref, retention_json FROM destinations ORDER BY name")?;
        let rows = stmt
            .query_map([], Self::map_destination)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Records the retention policy most recently used to prune a
    /// destination, for audit — this does not itself apply retention; see
    /// `archive::prune`.
    pub fn set_destination_retention(
        &self,
        destination_id: i64,
        retention_json: &str,
    ) -> Result<(), CradleError> {
        self.conn().execute(
            "UPDATE destinations SET retention_json = ?1 WHERE id = ?2",
            params![retention_json, destination_id],
        )?;
        Ok(())
    }

    fn map_destination(row: &rusqlite::Row) -> rusqlite::Result<DestinationRecord> {
        Ok(DestinationRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            kind: row.get(2)?,
            uri: row.get(3)?,
            credential_ref: row.get(4)?,
            retention_json: row.get(5)?,
        })
    }

    /// Opens a `pending` archive row for `snapshot_id` at `destination_id`.
    pub fn start_archive(
        &self,
        snapshot_id: i64,
        destination_id: i64,
    ) -> Result<i64, CradleError> {
        // See `start_run` for why this is one guard, not two.
        let conn = self.conn();
        conn.execute(
            "INSERT INTO archives (snapshot_id, destination_id, state, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                snapshot_id,
                destination_id,
                ArchiveState::Pending.as_str(),
                now()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Same idea as [`Catalog::fail_abandoned_runs`], for archive attempts
    /// against `snapshot_id` — a caller holding the working-set lock for
    /// the device that snapshot belongs to can be sure any `pending`
    /// archive row it finds was abandoned, not concurrent.
    pub fn fail_abandoned_archives(&self, snapshot_id: i64) -> Result<u64, CradleError> {
        let changed = self.conn().execute(
            "UPDATE archives SET state = ?1, error = ?2
             WHERE snapshot_id = ?3 AND state = ?4",
            params![
                ArchiveState::Failed.as_str(),
                "abandoned: process exited without finishing this archive",
                snapshot_id,
                ArchiveState::Pending.as_str(),
            ],
        )?;
        Ok(changed as u64)
    }

    /// Closes out an archive attempt. A successful restic backup is taken
    /// as verified immediately — restic content-addresses and checksums
    /// every blob it writes as part of the backup itself, which is a
    /// stronger integrity guarantee than what M1's own gate can currently
    /// give `Manifest.db` (see `verify.rs`'s doc comment). `restic check`
    /// against the whole repo remains available as a separate, heavier
    /// periodic audit — see `archive::check`.
    pub fn finish_archive(
        &self,
        archive_id: i64,
        state: ArchiveState,
        restic_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), CradleError> {
        let verified_at = (state == ArchiveState::Succeeded).then(now);
        self.conn().execute(
            "UPDATE archives SET state = ?1, restic_id = ?2, verified_at = ?3, error = ?4
             WHERE id = ?5",
            params![state.as_str(), restic_id, verified_at, error, archive_id],
        )?;
        Ok(())
    }

    /// Archive attempts for `snapshot_id`, most recent first.
    pub fn list_archives_for_snapshot(
        &self,
        snapshot_id: i64,
    ) -> Result<Vec<ArchiveRecord>, CradleError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, snapshot_id, destination_id, restic_id, state, created_at, verified_at, error
             FROM archives WHERE snapshot_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map(params![snapshot_id], |row| {
                Ok(ArchiveRecord {
                    id: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    destination_id: row.get(2)?,
                    restic_id: row.get(3)?,
                    state: row.get(4)?,
                    created_at: row.get(5)?,
                    verified_at: row.get(6)?,
                    error: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
        Catalog { conn: Mutex::new(conn) }
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
    fn fail_abandoned_runs_closes_out_a_stuck_running_row() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();
        // Simulates a process that crashed mid-run: never calls finish_run.

        let changed = cat.fail_abandoned_runs("udid-1").unwrap();
        assert_eq!(changed, 1);

        let latest = cat.latest_run("udid-1").unwrap().unwrap();
        assert_eq!(latest.id, run_id);
        assert_eq!(latest.status, "failed");
        assert!(latest.error.as_deref().unwrap().contains("abandoned"));
    }

    #[test]
    fn fail_abandoned_runs_leaves_a_completed_run_alone() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();
        cat.finish_run(run_id, RunStatus::Succeeded, 100, 5, None).unwrap();

        let changed = cat.fail_abandoned_runs("udid-1").unwrap();
        assert_eq!(changed, 0);

        let latest = cat.latest_run("udid-1").unwrap().unwrap();
        assert_eq!(latest.status, "succeeded");
    }

    #[test]
    fn finish_run_with_snapshot_updates_both_in_one_call() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();

        let snap_id = cat
            .finish_run_with_snapshot(run_id, 500, 10, "udid-1", 1_000_000, "26.6.1", true)
            .unwrap();

        let run = cat.latest_run("udid-1").unwrap().unwrap();
        assert_eq!(run.status, "succeeded");
        assert_eq!(run.bytes, Some(500));
        assert_eq!(run.files, Some(10));

        let snapshots = cat.list_snapshots("udid-1").unwrap();
        let snap = snapshots.iter().find(|s| s.id == snap_id).unwrap();
        assert_eq!(snap.run_id, run_id);
        assert!(snap.verified_at.is_some());
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
            .conn()
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn list_devices_returns_every_device_seen() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        cat.upsert_device(&device("udid-2")).unwrap();

        let udids: Vec<String> = cat.list_devices().unwrap().into_iter().map(|d| d.udid).collect();
        assert_eq!(udids.len(), 2);
        assert!(udids.contains(&"udid-1".to_string()));
        assert!(udids.contains(&"udid-2".to_string()));
    }

    #[test]
    fn delete_destination_removes_it() {
        let cat = open_temp();
        let id = cat.create_destination("nas", "nas", "/tmp/repo", "cradle-destination-nas").unwrap();
        assert!(cat.destination_by_name("nas").unwrap().is_some());

        cat.delete_destination(id).unwrap();

        assert!(cat.destination_by_name("nas").unwrap().is_none());
        assert!(cat.list_destinations().unwrap().is_empty());
    }

    /// Real bug: every destination that's actually been used has at least
    /// one `archives` row referencing it, and that foreign key has no `ON
    /// DELETE` clause — deleting the destination alone failed outright
    /// with "FOREIGN KEY constraint failed" instead of removing it.
    #[test]
    fn delete_destination_with_archived_snapshots_still_succeeds() {
        let cat = open_temp();
        cat.upsert_device(&device("udid-1")).unwrap();
        let run_id = cat.start_run("udid-1", RunKind::Backup).unwrap();
        let snap_id = cat
            .record_snapshot("udid-1", run_id, 1_000_000, "26.6.1", true)
            .unwrap();
        let dest_id = cat.create_destination("nas", "nas", "/tmp/repo", "cradle-destination-nas").unwrap();
        let archive_id = cat.start_archive(snap_id, dest_id).unwrap();
        cat.finish_archive(archive_id, ArchiveState::Succeeded, Some("abc123"), None).unwrap();

        cat.delete_destination(dest_id).unwrap();

        assert!(cat.destination_by_name("nas").unwrap().is_none());
        assert!(cat.list_archives_for_snapshot(snap_id).unwrap().is_empty());
    }
}
