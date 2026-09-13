//! Subprocess wrappers around `libimobiledevice`'s CLI tools (`idevice_id`,
//! `ideviceinfo`, `idevicepair`, `idevicebackup2`) — Cradle's entire device
//! protocol layer.
//!
//! Replaces the `idevice` Rust crate everywhere in Cradle. `idevice`
//! (pinned `=0.1.65`) reliably failed a real backup with `MBErrorDomain
//! 104` at a fixed point (~94%, ~19,000 files) on a real device,
//! reproducing regardless of working directory history or destination
//! volume. `idevicebackup2`, run directly against the same device with the
//! same live data, completed cleanly — isolating the bug to `idevice`
//! itself rather than the device, the data, or the environment. See
//! `CLAUDE.md`'s Stack section for the full story.
//!
//! These tools are a runtime *subprocess* dependency, the same footing as
//! `restic`/`rclone` elsewhere in Cradle — not a linked library, so this
//! doesn't reintroduce the LGPL-linking concern the old `idevice`-only
//! stack avoided. Install with `brew install libimobiledevice`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{info, warn};

use crate::CradleError;
use crate::backup::ProgressSink;

/// Extra places to look for these tools beyond `PATH` — Homebrew's default
/// prefixes on Apple Silicon and Intel Macs. A GUI app launched from
/// Finder/Dock (unlike a shell) doesn't always inherit Homebrew's `PATH`
/// entry.
const EXTRA_TOOL_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];

fn tool_path(name: &'static str) -> Result<PathBuf, CradleError> {
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for dir in EXTRA_TOOL_DIRS {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CradleError::ToolNotFound(name))
}

/// Runs a short-lived tool to completion and captures its output — for the
/// quick, one-shot queries (`idevice_id`, `ideviceinfo`, `idevicepair`), not
/// the long-running `idevicebackup2` transfer (see [`run_idevicebackup2`]).
async fn run_capture(tool: &'static str, args: &[&str]) -> Result<(bool, String, String), CradleError> {
    let path = tool_path(tool)?;
    let output = Command::new(path)
        .args(args)
        .output()
        .await
        .map_err(CradleError::Io)?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}

/// How a device is currently attached — `idevice_id` only answers "USB
/// devices" or "network devices" as separate queries, never both at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Usb,
    Network,
}

/// A device `usbmuxd` currently sees, before any session work has happened.
#[derive(Debug, Clone)]
pub struct AttachedDevice {
    pub udid: String,
    pub transport: Transport,
}

/// Lists every device `usbmuxd` currently sees, USB or Wi-Fi sync. A device
/// on both (rare) is reported once, as USB — the more likely one to matter
/// for a wired backup.
pub async fn list_devices() -> Result<Vec<AttachedDevice>, CradleError> {
    let (_, usb_stdout, _) = run_capture("idevice_id", &["-l"]).await?;
    let (_, net_stdout, _) = run_capture("idevice_id", &["-n"]).await?;

    let mut devices: Vec<AttachedDevice> = usb_stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|udid| AttachedDevice {
            udid: udid.to_string(),
            transport: Transport::Usb,
        })
        .collect();
    let known: std::collections::HashSet<String> = devices.iter().map(|d| d.udid.clone()).collect();
    for udid in net_stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if !known.contains(udid) {
            devices.push(AttachedDevice {
                udid: udid.to_string(),
                transport: Transport::Network,
            });
        }
    }
    Ok(devices)
}

/// Reads one lockdown value for a device, optionally scoped to a specific
/// domain (`None` for the root domain). `ideviceinfo` prints just the raw
/// value for a single `-k` query and exits 0 with empty output when the key
/// doesn't exist in that domain — so `Ok(None)` means "not present", not an
/// error; the caller decides what that should default to.
pub async fn info_value(udid: &str, domain: Option<&str>, key: &str) -> Result<Option<String>, CradleError> {
    let mut args = vec!["-u", udid];
    if let Some(domain) = domain {
        args.push("-q");
        args.push(domain);
    }
    args.push("-k");
    args.push(key);
    let (ok, stdout, stderr) = run_capture("ideviceinfo", &args).await?;
    if !ok {
        return Err(CradleError::ToolFailed(if stderr.is_empty() { stdout } else { stderr }));
    }
    Ok(if stdout.is_empty() { None } else { Some(stdout) })
}

async fn info_bool(udid: &str, domain: &str, key: &str, default: bool) -> bool {
    info_value(udid, Some(domain), key)
        .await
        .ok()
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(default)
}

/// Display metadata read from lockdownd — mirrors `crate::device::DeviceInfo`.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
    pub product_type: String,
    pub ios_version: String,
}

/// Reads the handful of lockdown values Cradle needs to identify and
/// display a device. A hard error here (unlike [`info_bool`]'s soft
/// default) means the device genuinely isn't reachable.
pub async fn device_info(udid: &str) -> Result<DeviceInfo, CradleError> {
    let name = info_value(udid, None, "DeviceName").await?.unwrap_or_default();
    let product_type = info_value(udid, None, "ProductType").await?.unwrap_or_default();
    let ios_version = info_value(udid, None, "ProductVersion").await?.unwrap_or_default();
    Ok(DeviceInfo {
        udid: udid.to_string(),
        name,
        product_type,
        ios_version,
    })
}

/// Backup-encryption state, read from the `com.apple.mobile.backup` domain.
pub async fn will_encrypt(udid: &str) -> bool {
    info_bool(udid, "com.apple.mobile.backup", "WillEncrypt", false).await
}

/// Whether Find My is linked to an Apple ID on the device, read from the
/// undocumented `com.apple.fmip` domain. Defaults to the *stricter*
/// assumption (associated) on failure, matching the old `idevice`-backed
/// precheck's reasoning: a false "off" here risks a bricked restore attempt
/// on a Find My-locked device.
pub async fn find_my_associated(udid: &str) -> bool {
    info_bool(udid, "com.apple.fmip", "IsAssociated", true).await
}

/// Result of `idevicepair validate`.
pub struct PairingCheck {
    pub valid: bool,
    /// Set only when `valid` is `false` — the tool's own diagnostic text.
    pub message: Option<String>,
}

/// Checks whether this Mac has a valid pairing record for `udid`, per
/// CLAUDE.md: "stale pairing is the most common failure; surface 'tap
/// Trust on the device' as a UI state, not an error."
pub async fn check_pairing(udid: &str) -> Result<PairingCheck, CradleError> {
    let (ok, stdout, stderr) = run_capture("idevicepair", &["-u", udid, "validate"]).await?;
    if ok {
        Ok(PairingCheck { valid: true, message: None })
    } else {
        let detail = if stderr.is_empty() { stdout } else { stderr };
        Ok(PairingCheck {
            valid: false,
            message: Some(format!(
                "No valid pairing record for this device — open it once with Finder or Xcode, \
                 unlock the device, and tap Trust. ({detail})"
            )),
        })
    }
}

/// Tracks when [`run_idevicebackup2`]'s subprocess last printed *anything*,
/// so a stall watchdog can tell "still working, just slow" apart from "the
/// process stopped responding and nothing will ever come back" — the same
/// problem and the same fix as the old `idevice`-backed `run`'s
/// `ActivityMonitor`, just watching a subprocess's stdout instead of
/// in-process delegate callbacks.
struct ActivityMonitor(Mutex<Instant>);

impl ActivityMonitor {
    fn new() -> Self {
        Self(Mutex::new(Instant::now()))
    }

    fn touch(&self) {
        *self.0.lock().unwrap() = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.0.lock().unwrap().elapsed()
    }
}

/// How long [`run_idevicebackup2`] tolerates its subprocess printing
/// nothing at all before giving up on it as stalled and killing it. Same
/// value and same reasoning as the old `idevice` backend's stall watchdog:
/// generous enough not to false-positive on a real lull, short enough not
/// to sit on a truly dead process for the rest of the run.
const STALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const STALL_POLL_INTERVAL: Duration = Duration::from_secs(15);

async fn watch_for_stall(activity: Arc<ActivityMonitor>) {
    loop {
        tokio::time::sleep(STALL_POLL_INTERVAL).await;
        if activity.idle_for() >= STALL_TIMEOUT {
            return;
        }
    }
}

/// Reads `reader` byte-by-byte-buffered, calling `on_line` for each logical
/// line — splitting on `\r` *or* `\n`, since `idevicebackup2` redraws its
/// progress bar with bare `\r`, not `\n`. A plain `.lines()` reader would
/// simply never see most of this tool's output.
async fn stream_lines<R: tokio::io::AsyncRead + Unpin>(mut reader: R, mut on_line: impl FnMut(&str)) {
    let mut buf = [0u8; 4096];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &b in &buf[..n] {
            if b == b'\r' || b == b'\n' {
                if !acc.is_empty() {
                    on_line(&String::from_utf8_lossy(&acc));
                    acc.clear();
                }
            } else {
                acc.push(b);
            }
        }
    }
    if !acc.is_empty() {
        on_line(&String::from_utf8_lossy(&acc));
    }
}

/// Parses a `"NN% Finished"` *overall* progress line into a percentage.
/// Distinguished from the per-file byte-progress lines (see
/// [`parse_file_bytes`]) by the literal word "Finished", which only ever
/// appears on the aggregate line.
fn parse_overall_percent(line: &str) -> Option<f64> {
    if !line.contains("Finished") {
        return None;
    }
    line.split_whitespace().find_map(|tok| tok.strip_suffix('%')?.parse().ok())
}

/// Parses a per-file progress line's `(done/total)` byte fraction, e.g.
/// `"[===   ]  42% (1.2 MB/3.4 MB)"`.
fn parse_file_bytes(line: &str) -> Option<(u64, u64)> {
    let start = line.rfind('(')?;
    let end = line.rfind(')')?;
    if end <= start {
        return None;
    }
    let (done, total) = line[start + 1..end].split_once('/')?;
    Some((parse_human_bytes(done.trim())?, parse_human_bytes(total.trim())?))
}

fn parse_human_bytes(s: &str) -> Option<u64> {
    let (num, unit) = s.split_once(' ')?;
    let value: f64 = num.parse().ok()?;
    let mult = match unit {
        "Bytes" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * mult) as u64)
}

/// Best-effort classification of an `idevicebackup2` failure message into
/// the same retryable [`CradleError`] variants the old `idevice` backend
/// used, by looking for the `MBErrorDomain` code the tool's own
/// `"ErrorCode %d: %s"` text prints. Falls back to
/// [`CradleError::ToolFailed`] for anything else — still a real message
/// naming the tool's own diagnosis, per CLAUDE.md's "name the fix, not the
/// symptom" rule, just not one of the two Cradle retries automatically.
fn classify_error(message: &str) -> CradleError {
    let has_code = |code: &str| {
        message
            .split(|c: char| !c.is_ascii_digit())
            .any(|tok| tok == code)
    };
    if has_code("208") {
        CradleError::DeviceLocked
    } else if has_code("104") {
        CradleError::HostIoError
    } else {
        CradleError::ToolFailed(message.to_string())
    }
}

/// What a subprocess-driven backup/restore attempt ended with — on success
/// or failure alike, since a failed attempt's partial counts matter just as
/// much as a successful one's (the catalog records real partial progress
/// either way; see `backup::BackupError`'s own doc for why that mattered on
/// a real run).
pub(crate) struct RunResult {
    pub outcome: Result<(), CradleError>,
    pub files_received: u64,
    pub bytes_transferred: u64,
}

#[derive(Default, Clone)]
struct ParserState {
    saw_success: bool,
    files_received: u64,
    bytes_done: u64,
    last_error: Option<String>,
}

/// Parses `idevicebackup2`'s live output into [`ProgressSink`] calls,
/// writing its running totals into a shared `state` after *every* line —
/// not just once at the end — so a stalled attempt that gets killed mid-run
/// still leaves real partial counts behind instead of all-zeros.
struct ProgressParser {
    progress: Arc<dyn ProgressSink>,
    state: Arc<Mutex<ParserState>>,
    files: u32,
    bytes_done: u64,
    last_file_bytes: u64,
    last_file_complete: bool,
    waiting_for_passcode: bool,
    received_final: Option<u64>,
}

impl ProgressParser {
    fn new(progress: Arc<dyn ProgressSink>, state: Arc<Mutex<ParserState>>) -> Self {
        Self {
            progress,
            state,
            files: 0,
            bytes_done: 0,
            last_file_bytes: 0,
            last_file_complete: false,
            waiting_for_passcode: false,
            received_final: None,
        }
    }

    fn on_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }

        if line.contains("Waiting for passcode") {
            if !self.waiting_for_passcode {
                self.waiting_for_passcode = true;
                // Timestamped deliberately: correlating this against a
                // HostIoError log line below is how we tell a real
                // host-side fault apart from the device just timing out
                // its own passcode/Face ID wait.
                info!("device presented auth prompt (passcode/Face ID)");
                self.progress.on_attention_needed(true);
            }
            return;
        }
        // `idevicebackup2` never prints an explicit "dismissed" message of
        // its own (unlike the notification-proxy event the old `idevice`
        // backend watched directly) — any further output after the prompt
        // means it was resolved one way or another.
        if self.waiting_for_passcode {
            self.waiting_for_passcode = false;
            info!("device dismissed auth prompt");
            self.progress.on_attention_needed(false);
        }

        if let Some(pct) = parse_overall_percent(line) {
            self.progress.on_progress(self.bytes_done, 0, pct);
            return;
        }

        if let Some((done, total)) = parse_file_bytes(line) {
            let delta = done.saturating_sub(self.last_file_bytes);
            self.bytes_done += delta;
            self.last_file_bytes = done;
            let is_complete = total > 0 && done >= total;
            if is_complete && !self.last_file_complete {
                self.files += 1;
                self.progress.on_file(line, self.files);
                self.last_file_bytes = 0;
            }
            self.last_file_complete = is_complete;
            self.sync_state();
            return;
        }

        if let Some(rest) = line.strip_prefix("Received ")
            && let Some(n) = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok())
        {
            self.received_final = Some(n);
            self.sync_state();
            return;
        }

        if line.ends_with("Successful.") {
            self.state.lock().unwrap().saw_success = true;
            return;
        }

        if line.starts_with("ERROR") || line.contains("Failed") || line.contains("Aborted") {
            self.state.lock().unwrap().last_error = Some(line.to_string());
        }
    }

    fn sync_state(&self) {
        let mut state = self.state.lock().unwrap();
        state.files_received = self.received_final.unwrap_or(self.files as u64);
        state.bytes_done = self.bytes_done;
    }
}

/// Drives `idevicebackup2 <args>` (a full argument list — `-u`/`-s`,
/// subcommand, subcommand options, and the target directory, in whatever
/// order that subcommand needs) for a backup, restore, or password change,
/// forwarding progress to `progress` through the same [`ProgressSink`]
/// every backend feeds, and mapping the exit code / printed messages to a
/// [`CradleError`] — including the same [`CradleError::Stalled`] a hung
/// attempt produced under the old `idevice` backend, since a stuck
/// subprocess is exactly as silent a failure mode as a stuck in-process
/// future was.
///
/// `env` carries extra environment variables (e.g. `BACKUP_PASSWORD`) —
/// never passed as CLI arguments, so a password never shows up in `ps` or
/// shell history, per the tool's own security note.
pub(crate) async fn run_idevicebackup2(args: &[&str], env: &[(&str, &str)], progress: Arc<dyn ProgressSink>) -> RunResult {
    let no_progress = |source: CradleError| RunResult {
        outcome: Err(source),
        files_received: 0,
        bytes_transferred: 0,
    };

    let path = match tool_path("idevicebackup2") {
        Ok(path) => path,
        Err(e) => return no_progress(e),
    };
    let mut cmd = Command::new(path);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return no_progress(CradleError::Io(e)),
    };
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let activity = Arc::new(ActivityMonitor::new());
    let state = Arc::new(Mutex::new(ParserState::default()));

    let stdout_activity = activity.clone();
    let stdout_state = state.clone();
    let stdout_task = tokio::spawn(async move {
        let mut parser = ProgressParser::new(progress, stdout_state);
        stream_lines(stdout, |line| {
            stdout_activity.touch();
            parser.on_line(line);
        })
        .await;
    });

    let stderr_task = tokio::spawn(async move {
        let mut lines = Vec::new();
        stream_lines(stderr, |line| lines.push(line.to_string())).await;
        lines
    });

    enum Resolution {
        Exited(std::io::Result<std::process::ExitStatus>),
        Stalled,
    }
    let resolution = tokio::select! {
        status = child.wait() => Resolution::Exited(status),
        _ = watch_for_stall(activity) => Resolution::Stalled,
    };

    let status = match resolution {
        Resolution::Exited(Ok(status)) => status,
        Resolution::Exited(Err(e)) => {
            let partial = state.lock().unwrap().clone();
            return RunResult {
                outcome: Err(CradleError::Io(e)),
                files_received: partial.files_received,
                bytes_transferred: partial.bytes_done,
            };
        }
        Resolution::Stalled => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            let partial = state.lock().unwrap().clone();
            return RunResult {
                outcome: Err(CradleError::Stalled),
                files_received: partial.files_received,
                bytes_transferred: partial.bytes_done,
            };
        }
    };

    let _ = stdout_task.await;
    let stderr_lines = stderr_task.await.unwrap_or_default();
    let parsed = state.lock().unwrap().clone();

    let outcome = if status.success() && parsed.saw_success {
        Ok(())
    } else {
        let message = parsed
            .last_error
            .clone()
            .or_else(|| stderr_lines.into_iter().rev().find(|l| !l.trim().is_empty()))
            .unwrap_or_else(|| format!("idevicebackup2 exited with status {status}"));
        warn!(
            bytes_transferred = parsed.bytes_done,
            files_received = parsed.files_received,
            "idevicebackup2 reported a failure: {message}"
        );
        Err(classify_error(&message))
    };

    RunResult {
        outcome,
        files_received: parsed.files_received,
        bytes_transferred: parsed.bytes_done,
    }
}
