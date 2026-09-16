//! The `--json` output envelope: one object per invocation, printed once
//! to stdout, so a script gets exactly one thing to parse regardless of
//! whether the command succeeded. Progress and interstitial status lines
//! stay on stderr either way (`progress.rs`, and each command's own
//! `--json` branch below skips its normal `println!`s) — mixing a
//! streaming progress line into the one JSON value on stdout would make
//! it unparseable.
//!
//! `category` is deliberately a small, stable set of machine-checkable
//! strings a script can match on (`"precheck"`, `"locked"`, ...) — see
//! each call site for what it actually means there — rather than
//! `Display`-formatted prose, which is free to reword itself and would
//! break a script depending on its exact text.

use serde::Serialize;

#[derive(Serialize)]
struct Envelope<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorPayload>,
}

#[derive(Serialize)]
struct ErrorPayload {
    category: String,
    message: String,
}

/// Prints a successful result as the one JSON object on stdout.
pub fn print_ok<T: Serialize>(data: T) {
    let envelope = Envelope { ok: true, data: Some(data), error: None };
    println!("{}", serde_json::to_string(&envelope).expect("Envelope<T> is always representable as JSON"));
}

/// Prints a failure as the one JSON object on stdout. `category` is a
/// stable, lowercase, `snake_case` identifier — see this module's own doc.
pub fn print_err(category: &str, message: impl std::fmt::Display) {
    let envelope: Envelope<()> = Envelope {
        ok: false,
        data: None,
        error: Some(ErrorPayload {
            category: category.to_string(),
            message: message.to_string(),
        }),
    };
    println!("{}", serde_json::to_string(&envelope).expect("Envelope<()> is always representable as JSON"));
}

/// `print_err`, then builds the `anyhow::Error` a caller's own `?`/`return
/// Err` still needs for its normal (non-JSON) exit-code and stderr
/// behavior. Meant for a command function's own early, well-known failure
/// points (a bad destination name, a catalog that won't open) — the ones
/// most likely to be hit by an automated caller, so worth a specific
/// `category` rather than falling through to whatever generic error
/// bubbles up from deep inside a library call.
pub fn bail(json: bool, category: &str, message: impl std::fmt::Display) -> anyhow::Error {
    if json {
        print_err(category, &message);
    }
    anyhow::anyhow!("{message}")
}
