//! A system-level alert for moments that need a human's attention *right
//! now* — not a progress update, an interrupt.
//!
//! Exists specifically for [`crate::backup::ProgressSink::on_attention_needed`]:
//! iOS's own passcode/Face ID prompt for protected-data access during a
//! backup has a short timeout, and an in-app banner or a terminal line is
//! easy to miss if the user has switched windows or walked away — which
//! real usage shows happens constantly, not rarely. Confirmed against a
//! real device: the same backup restarted as a full transfer multiple
//! times in a row because the prompt kept timing out unanswered, each
//! restart costing the better part of an hour. Telling users to disable
//! their device's Auto-Lock isn't a fix — nobody backing up a phone in
//! normal use is going to change a device setting for it — so this is the
//! actual fix: make the moment impossible to miss instead of asking
//! people to prevent it from ever occurring.
//!
//! macOS only for now (Windows is M9), via `osascript` — same "wrap, don't
//! reimplement" reasoning as [`crate::power::SleepGuard`]'s use of
//! `caffeinate`: Notification Center is exactly the user-facing surface
//! this needs, and shelling out to the OS's own scripting bridge is
//! simpler and more robust than binding UserNotifications.framework
//! directly for a two-line alert.

/// Best-effort: posts `title`/`message` to Notification Center (with its
/// default sound). Never fails the caller's actual operation over this —
/// a missing `osascript` or a user who's denied Cradle's notification
/// permission means the alert silently doesn't show, exactly as today,
/// not a broken backup.
#[cfg(target_os = "macos")]
pub fn alert(title: &str, message: &str) {
    let script = format!(
        "display notification {} with title {}",
        applescript_string_literal(message),
        applescript_string_literal(title),
    );
    let _ = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .spawn();
}

#[cfg(not(target_os = "macos"))]
pub fn alert(_title: &str, _message: &str) {}

/// Quotes `s` as an AppleScript string literal. `title`/`message` are
/// always our own static wording, never attacker-controlled input, but
/// correct escaping is what keeps a stray `"` from producing a broken
/// script instead of a shown notification.
#[cfg(target_os = "macos")]
fn applescript_string_literal(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
