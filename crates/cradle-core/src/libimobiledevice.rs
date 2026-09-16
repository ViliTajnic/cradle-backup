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
//! itself rather than the device, the data, or the environment.
//!
//! These tools are a runtime *subprocess* dependency, the same footing as
//! `restic`/`rclone` elsewhere in Cradle — not a linked library, so this
//! doesn't reintroduce the LGPL-linking concern the old `idevice`-only
//! stack avoided. Install with `brew install libimobiledevice`.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{info, warn};

use crate::CradleError;
use crate::backup::ProgressSink;


/// Runs a short-lived tool to completion and captures its output — for the
/// quick, one-shot queries (`idevice_id`, `ideviceinfo`, `idevicepair`), not
/// the long-running `idevicebackup2` transfer (see [`run_idevicebackup2`]).
async fn run_capture(tool: &'static str, args: &[&str]) -> Result<(bool, String, String), CradleError> {
    let path = crate::tools::resolve(tool)
        .map_err(|e| CradleError::Other(format!("{e} — install libimobiledevice with `brew install libimobiledevice`")))?;
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

/// Display metadata read from lockdownd — mirrors `crate::libimobiledevice::DeviceInfo`.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub udid: String,
    pub name: String,
    pub product_type: String,
    pub ios_version: String,
}

/// Reads every root-domain lockdown value in one `ideviceinfo` call
/// instead of one call per key — [`device_info`] used to run three
/// separate queries (`DeviceName`, `ProductType`, `ProductVersion`),
/// which is three subprocess round trips' worth of latency (mostly USB
/// protocol overhead, not CPU) to answer what's really one question.
/// `ideviceinfo` with no `-k` prints the whole domain as `Key: Value`
/// lines — some values span multiple indented lines (nested plist dicts),
/// but every key this module actually reads is always a plain one-line
/// string, so scanning for an exact `"<key>: "` line prefix is enough;
/// this never needs to parse the nested cases.
async fn info_domain(udid: &str) -> Result<String, CradleError> {
    let (ok, stdout, stderr) = run_capture("ideviceinfo", &["-u", udid]).await?;
    if !ok {
        return Err(CradleError::ToolFailed(if stderr.is_empty() { stdout } else { stderr }));
    }
    Ok(stdout)
}

fn domain_value<'a>(domain: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}: ");
    domain.lines().find_map(|line| line.strip_prefix(prefix.as_str()))
}

/// Reads the handful of lockdown values Cradle needs to identify and
/// display a device. A hard error here (unlike [`info_bool`]'s soft
/// default) means the device genuinely isn't reachable.
pub async fn device_info(udid: &str) -> Result<DeviceInfo, CradleError> {
    let domain = info_domain(udid).await?;
    Ok(DeviceInfo {
        udid: udid.to_string(),
        name: domain_value(&domain, "DeviceName").unwrap_or_default().to_string(),
        product_type: domain_value(&domain, "ProductType").unwrap_or_default().to_string(),
        ios_version: domain_value(&domain, "ProductVersion").unwrap_or_default().to_string(),
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

/// Bytes free on the device's own data volume, read from the
/// `com.apple.disk_usage` domain's `AmountDataAvailable` — the restore
/// precheck's equivalent of `precheck::free_disk_space` for the *target
/// device* rather than this Mac's disk. `None` when it can't be read
/// (older iOS, transient query failure); the caller treats that as
/// "unknown," never as "assume plenty," same reasoning as the host-side
/// check.
pub async fn available_disk_space(udid: &str) -> Option<u64> {
    info_value(udid, Some("com.apple.disk_usage"), "AmountDataAvailable")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
}

/// Result of `idevicepair validate`.
pub struct PairingCheck {
    pub valid: bool,
    /// Set only when `valid` is `false` — the tool's own diagnostic text.
    pub message: Option<String>,
}

/// Checks whether this Mac has a valid pairing record for `udid` — a
/// stale pairing is the most common failure, surfaced as a "tap Trust on
/// the device" UI state, not an error.
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
/// `"[===   ]  42% (1.2 MB/3.4 MB)"` — the shape `idevicebackup2 backup`
/// prints per file as it *receives* one.
fn parse_file_bytes(line: &str) -> Option<(u64, u64)> {
    let start = line.rfind('(')?;
    let end = line.rfind(')')?;
    if end <= start {
        return None;
    }
    let (done, total) = line[start + 1..end].split_once('/')?;
    Some((parse_human_bytes(done.trim())?, parse_human_bytes(total.trim())?))
}

/// Parses a restore's own per-file announcement, e.g.
/// `"Sending 'ab/cd1234...' (1.2 MB)"` — confirmed via `strings` on the
/// installed `idevicebackup2` binary that restore's send loop uses this
/// single-size format, not backup's `(done/total)` fraction, so
/// [`parse_file_bytes`] never matches a single line of it. Before this,
/// every restore's FILES and RATE readouts sat at 0 for the entire
/// on-device transfer — only the shared overall-percent line (see
/// [`parse_overall_percent`]) ever moved — because nothing recognized
/// this format at all.
fn parse_sending_file(line: &str) -> Option<u64> {
    let rest = line.strip_prefix("Sending '")?;
    let (_name, rest) = rest.split_once("' (")?;
    let size = rest.strip_suffix(')')?;
    parse_human_bytes(size.trim())
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
/// naming the tool's own diagnosis (error messages should name the fix,
/// not the symptom), just not one of the two Cradle retries automatically.
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
    } else if has_code("207") {
        CradleError::WrongBackupPassword
    } else if message.contains("Could not start service com.apple.mobilebackup2") {
        CradleError::DeviceNotReadyForBackupService
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

        if let Some(size) = parse_sending_file(line) {
            self.bytes_done += size;
            self.files += 1;
            self.progress.on_file(line, self.files);
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

    let path = match crate::tools::resolve("idevicebackup2") {
        Ok(path) => path,
        Err(e) => {
            return no_progress(CradleError::Other(format!(
                "{e} — install libimobiledevice with `brew install libimobiledevice`"
            )));
        }
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

    // Bounded to the last few lines rather than collected wholesale: only
    // the single most recent non-empty line is ever read back out (below),
    // so an unbounded `Vec` here would just be memory an unusually chatty
    // or long-running `idevicebackup2` process never needed to cost us.
    const STDERR_TAIL_LINES: usize = 50;
    let stderr_task = tokio::spawn(async move {
        let mut lines = std::collections::VecDeque::with_capacity(STDERR_TAIL_LINES);
        stream_lines(stderr, |line| {
            if lines.len() == STDERR_TAIL_LINES {
                lines.pop_front();
            }
            lines.push_back(line.to_string());
        })
        .await;
        Vec::from(lines)
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
        // A bare "exited with status 255 (or similar) and printed nothing at
        // all" has shown up on a real device with an otherwise-healthy
        // pairing — every other failure mode this code knows about prints
        // *something* (an ErrorCode line, "Aborted", a lockdownd error).
        // Confirmed via direct manual `idevicebackup2` runs against the
        // same device that this is consistent with a dropped USB/network
        // connection to the device mid-connect, not a Cradle-side bug —
        // so this names the fix even though the tool gave nothing to
        // classify.
        let message = parsed.last_error.clone().or_else(|| stderr_lines.into_iter().rev().find(|l| !l.trim().is_empty())).unwrap_or_else(|| {
            format!(
                "idevicebackup2 exited unexpectedly ({status}) without printing an error — this \
                 usually means the connection to the device dropped before the backup protocol \
                 could even start. Check the cable/USB connection, make sure the device is \
                 unlocked and still shows as trusted, and try again."
            )
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Real (anonymized) `ideviceinfo` root-domain output shape, nested
    /// multi-line value included — `domain_value` must skip past that
    /// without getting confused, since it's real output shape, not a
    /// simplified fixture.
    const SAMPLE_DOMAIN: &str = "\
ActivationState: Activated
BasebandKeyHashInformation: AKeyStatus: 2
 SKeyHash: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
 SKeyStatus: 0
DeviceName: Backup iPhone
ProductType: iPhone14,7
ProductVersion: 26.5.2";

    #[test]
    fn reads_simple_string_keys_around_a_nested_multiline_one() {
        assert_eq!(domain_value(SAMPLE_DOMAIN, "DeviceName"), Some("Backup iPhone"));
        assert_eq!(domain_value(SAMPLE_DOMAIN, "ProductType"), Some("iPhone14,7"));
        assert_eq!(domain_value(SAMPLE_DOMAIN, "ProductVersion"), Some("26.5.2"));
    }

    #[test]
    fn missing_key_is_none() {
        assert_eq!(domain_value(SAMPLE_DOMAIN, "NoSuchKey"), None);
    }

    #[test]
    fn a_value_containing_a_colon_is_read_in_full() {
        let domain = "DeviceName: Vili's: iPhone";
        assert_eq!(domain_value(domain, "DeviceName"), Some("Vili's: iPhone"));
    }

    /// `idevicebackup2`'s own fallback for a code it doesn't recognize
    /// either ("Restore Failed (Error Code 207)." — confirmed via `strings`
    /// on the installed binary, which only special-cases a handful of
    /// codes) — found on a real cross-device restore where the override
    /// password was wrong, and the error shown carried no more information
    /// than the bare number until this classification existed.
    #[test]
    fn error_code_207_is_classified_as_a_wrong_backup_password() {
        assert!(matches!(
            classify_error("Restore Failed (Error Code 207)."),
            CradleError::WrongBackupPassword
        ));
    }

    /// Confirmed on a real device mid-Setup Assistant: pairing/Trust can
    /// succeed before iOS enables `com.apple.mobilebackup2`, so this shows
    /// up as its own distinct failure — not a pairing problem, and not one
    /// of the numbered `ErrorCode` failures at all.
    #[test]
    fn mobilebackup2_service_unavailable_is_classified_as_device_not_ready() {
        assert!(matches!(
            classify_error("ERROR: Could not start service com.apple.mobilebackup2: Invalid service"),
            CradleError::DeviceNotReadyForBackupService
        ));
    }

    #[test]
    fn parses_a_restore_send_line_size() {
        assert_eq!(parse_sending_file("Sending 'ab/cd1234567890' (1.2 MB)"), Some(1_258_291));
    }

    #[test]
    fn a_backup_receive_fraction_line_is_not_mistaken_for_a_restore_send_line() {
        // Same message family, different shape — must not cross-match.
        assert_eq!(parse_sending_file("[===   ]  42% (1.2 MB/3.4 MB)"), None);
        assert!(parse_file_bytes("Sending 'ab/cd1234567890' (1.2 MB)").is_none());
    }
}
