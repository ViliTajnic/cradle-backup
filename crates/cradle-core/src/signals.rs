//! Propagates a termination signal Cradle itself received to its whole
//! process group, so a child subprocess (`idevicebackup2`, `restic`)
//! doesn't survive as an orphan when something kills only Cradle's own
//! PID — Activity Monitor's Force Quit, or a script/supervisor doing
//! `kill <pid>` — rather than the whole group, which is what an
//! interactive terminal's Ctrl-C already does by itself.
//!
//! Real bug, not hypothetical: killing just the `cradle` process mid-backup
//! left `idevicebackup2` running, still writing into `working/<UDID>/`,
//! with [`crate::lock::WorkingSetLock`] already released by the parent's
//! exit — exactly the "operations can overlap" hazard that lock exists to
//! prevent. Child processes are spawned without their own process group
//! (the default), so a signal delivered to the whole group reaches both;
//! this only covers the gap where a signal reaches Cradle alone.
//!
//! Deliberately does no catalog cleanup itself — the next `cradle`
//! invocation's [`crate::catalog::Catalog::fail_abandoned_runs`] (run once
//! it holds the working-set lock, so it can be sure of what it's looking
//! at) already closes out whatever this left `running`.

/// Waits for SIGTERM or Ctrl-C, then re-sends whichever one arrived to
/// this process's own group and exits. Race this against an operation
/// with `tokio::select!`; it never returns.
#[cfg(unix)]
pub async fn wait_and_propagate_termination() -> ! {
    use tokio::signal::unix::{SignalKind, signal};

    let sig = match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => libc::SIGTERM,
                _ = tokio::signal::ctrl_c() => libc::SIGINT,
            }
        }
        Err(_) => {
            // No SIGTERM handler available for some reason — Ctrl-C alone
            // is still worth covering rather than propagating nothing.
            let _ = tokio::signal::ctrl_c().await;
            libc::SIGINT
        }
    };

    // SAFETY: `killpg` with a pgrp of 0 targets the caller's own process
    // group; this has no memory-safety preconditions. Cradle's own
    // still-installed handler for this signal (the `signal`/`ctrl_c`
    // listener above) means receiving it again here is harmless — this
    // process is exiting immediately regardless.
    unsafe {
        libc::killpg(0, sig);
    }

    // A graceful SIGTERM/SIGINT alone isn't enough: confirmed against a
    // real `idevicebackup2` process, which stayed alive after `killpg`
    // reported success sending it SIGTERM — it doesn't exit promptly on
    // that signal alone. Give the group a bounded moment to exit on its
    // own, then force it — CODEBASE_ANALYSIS.md's "graceful subprocess
    // termination with a bounded forced-kill fallback."
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    unsafe {
        libc::killpg(0, libc::SIGKILL);
    }
    std::process::exit(128 + sig);
}

#[cfg(not(unix))]
pub async fn wait_and_propagate_termination() -> ! {
    // Windows isn't a supported Cradle target yet (CLAUDE.md) — block
    // forever rather than exiting immediately, so a `tokio::select!`
    // racing this against real work never picks this branch by accident.
    std::future::pending().await
}
