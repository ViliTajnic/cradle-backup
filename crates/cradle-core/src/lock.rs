//! Serializes operations against one working set (`working_root/<UDID>/`).
//!
//! `working/<UDID>/` is canonical, and mobilebackup2 computes incrementals
//! by inspecting exactly the state that directory is in right now. Two
//! operations touching it at once — a second backup starting
//! while the first is still writing, or an archive reading it mid-backup —
//! don't just race, they can hand a real device transfer stale or
//! half-written state. [`WorkingSetLock::acquire`] must be held across
//! backup, verification, an archive's read of the directory, and restore
//! staging out of it.
//!
//! Two processes can point at the same working root just as easily as two
//! calls within one (the CLI and the Tauri app run separately; the app
//! could also get two commands in flight in the same process). Neither
//! alone is enough:
//!
//! - An in-process registry catches two calls in the same process, but a
//!   separate process has its own copy of that registry and would see
//!   nothing.
//! - An OS-level advisory lock (`flock`) catches separate processes, but
//!   on every platform this project has checked, two descriptors opened by
//!   *the same* process are independent for `flock` purposes — one call
//!   locking, then a second call in that same process locking again,
//!   would both "succeed".
//!
//! So both are checked, in that order (the cheap, always-available
//! in-process check first). Never blocks: a stuck lock means some other
//! operation is genuinely running, not something worth an indefinite wait
//! against a transfer that might take an hour.

use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::CradleError;

fn in_process_locks() -> &'static Mutex<HashSet<PathBuf>> {
    static LOCKS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Held for the lifetime of one backup, verification pass, pre-archive
/// read, or restore staging copy. Dropping it (including via a panic
/// unwind) releases both the in-process and the cross-process lock.
#[derive(Debug)]
pub struct WorkingSetLock {
    key: PathBuf,
    _cross_process: File,
}

impl WorkingSetLock {
    /// Locks `working_root/<udid>` for exclusive use by the calling
    /// operation. Fails immediately, naming what's blocking it, rather
    /// than waiting.
    pub fn acquire(working_root: &Path, udid: &str) -> Result<Self, CradleError> {
        let key = working_root.join(udid);
        std::fs::create_dir_all(working_root)?;

        {
            let mut held = in_process_locks().lock().unwrap_or_else(|e| e.into_inner());
            if !held.insert(key.clone()) {
                return Err(CradleError::Other(format!(
                    "another Cradle operation is already running against {} — wait for it to finish first",
                    key.display()
                )));
            }
        }

        // A sidecar file next to the UDID directory, not inside it: restore
        // staging and a fresh full backup both have reason to recreate that
        // directory outright, which must not silently drop the lock file
        // out from under an fd that already has it open and locked.
        let lock_path = working_root.join(format!(".{udid}.lock"));
        let file = match File::options().create(true).truncate(false).write(true).open(&lock_path) {
            Ok(file) => file,
            Err(e) => {
                in_process_locks().lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                return Err(e.into());
            }
        };
        if let Err(e) = try_lock_exclusive(&file) {
            in_process_locks().lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
            return Err(CradleError::Other(format!(
                "another Cradle process is already running against {} ({e}) — if it crashed \
                 rather than actually being busy, no cleanup is needed: this lock releases \
                 automatically once that process exits",
                key.display()
            )));
        }

        Ok(Self {
            key,
            _cross_process: file,
        })
    }
}

impl Drop for WorkingSetLock {
    fn drop(&mut self) {
        in_process_locks().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.key);
        // `_cross_process`'s own `Drop` closes the fd, which releases the
        // OS-level flock — no explicit unlock call needed or possible to
        // forget.
    }
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file`'s fd is valid for the duration of this call and
    // outlives it (owned by the caller); `flock` takes no pointer
    // arguments that could be misused.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> std::io::Result<()> {
    // Windows isn't a supported Cradle target yet — only the in-process
    // guard applies there for now, rather than a hard failure that would
    // block running the rest of this workspace's tests on it.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cradle-lock-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn second_acquire_in_process_fails_while_first_is_held() {
        let root = temp_root("in-process");
        let first = WorkingSetLock::acquire(&root, "udid-1").unwrap();

        let err = WorkingSetLock::acquire(&root, "udid-1").unwrap_err();
        assert!(err.to_string().contains("already running"));

        drop(first);
        // Released: a third acquire now succeeds.
        let _third = WorkingSetLock::acquire(&root, "udid-1").unwrap();

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn different_udids_do_not_contend() {
        let root = temp_root("distinct-udids");
        let _a = WorkingSetLock::acquire(&root, "udid-a").unwrap();
        let _b = WorkingSetLock::acquire(&root, "udid-b").unwrap();

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dropping_releases_it_for_a_later_acquire() {
        let root = temp_root("release");
        {
            let _lock = WorkingSetLock::acquire(&root, "udid-1").unwrap();
        }
        let _lock_again = WorkingSetLock::acquire(&root, "udid-1").unwrap();

        let _ = std::fs::remove_dir_all(&root);
    }
}
