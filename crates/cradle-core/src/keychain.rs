//! macOS Keychain access for restic repository passwords.
//!
//! Secrets go in the macOS Keychain / Windows DPAPI, referenced by
//! `credential_ref` — never stored in the database itself. Windows DPAPI
//! support is a future project; this module is macOS-only for now.
//!
//! Deliberately goes through `security-framework` (native `Security.framework`
//! bindings) rather than shelling out to the `security` CLI: a `security
//! add-generic-password -w <password>` invocation would put the plaintext
//! password in this process's own argv, visible to any local user via `ps`
//! for as long as the process runs.
//!
//! `archive.rs` reads a destination's password via [`read`] and hands it
//! to `restic` as `RESTIC_PASSWORD` on the child process's own
//! environment, rather than letting restic fetch it itself via
//! `--password-command "security find-generic-password ..."`. That looked
//! more careful — the secret would never touch Cradle's env at all — but
//! broke in practice: an item created via `SecItemAdd` (what
//! `set_generic_password` below calls) gets an access-control list scoped
//! to the *creating* application, and `/usr/bin/security`, run as restic's
//! child rather than Cradle's, is a different application as far as that
//! ACL is concerned. It triggered a macOS Keychain authorization prompt —
//! a GUI dialog with nothing to answer it from a terminal, so the whole
//! pipeline hung. Confirmed against a real repository, not a hypothetical.
//! Reading the password here, in the same process that created the
//! Keychain item, stays inside that ACL and never prompts.

use rand::RngExt;
use security_framework::passwords::{
    PasswordOptions, delete_generic_password, generic_password, set_generic_password,
};

use crate::CradleError;

/// Keychain service name every Cradle-managed restic repository password is
/// stored under. Individual destinations are distinguished by `account`
/// (see [`new_destination_account`]), not by service.
pub const SERVICE: &str = "com.cradle.restic-repo-password";

/// A fresh, unique Keychain `account` for a new destination's password.
/// Whatever this returns becomes `destinations.credential_ref` in the
/// catalog — a lookup key, never the secret itself — and every later
/// lookup reads that stored value back rather than recomputing this
/// function, so nothing needs it to be deterministic.
///
/// Deliberately *not* derived only from `destination_name`: two
/// independent catalogs on the same Mac naming a destination the same
/// thing (a reinstall, a second `--catalog` file, ...) would otherwise
/// share one Keychain slot — CODEBASE_ANALYSIS.md flagged exactly this.
/// The random suffix is generated before the destination's catalog
/// `INSERT` (whose row id doesn't exist yet), so a half-created
/// destination never gets recorded with no matching Keychain item, but
/// two destinations can never collide regardless of what they're named.
pub fn new_destination_account(destination_name: &str) -> String {
    let mut suffix = [0u8; 8];
    rand::rng().fill(&mut suffix);
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    format!("cradle-destination-{destination_name}-{suffix}")
}

/// The Keychain `account` a device's *backup* password lives under —
/// different secret from a destination's repository password (this is the
/// password the user set on-device/in Finder for encrypted backups, not
/// one Cradle generated), but the same storage mechanism.
pub fn device_account(udid: &str) -> String {
    format!("cradle-device-backup-{udid}")
}

/// Generates a new random repository password and stores it in the
/// Keychain under `account`. Returns the password so the caller can hand
/// it straight to `restic init` without a second Keychain round trip.
pub fn generate_and_store(account: &str) -> Result<String, CradleError> {
    let password = generate_password();
    store(account, &password)?;
    Ok(password)
}

/// Stores a password the caller already has — e.g. a device's backup
/// password the user typed in, as opposed to [`generate_and_store`]'s
/// randomly generated ones.
pub fn store(account: &str, password: &str) -> Result<(), CradleError> {
    set_generic_password(SERVICE, account, password.as_bytes())
        .map_err(|e| CradleError::Other(format!("could not store Keychain entry: {e}")))
}

/// Reads a previously stored password back out of the Keychain. Only
/// needed by Cradle's own code (e.g. a future `cradle destination show`);
/// the restic subprocess reads it independently via `--password-command`.
pub fn read(account: &str) -> Result<String, CradleError> {
    let bytes = generic_password(PasswordOptions::new_generic_password(SERVICE, account))
        .map_err(|e| CradleError::Other(format!("could not read Keychain entry: {e}")))?;
    String::from_utf8(bytes)
        .map_err(|_| CradleError::Other("Keychain entry was not valid UTF-8".into()))
}

/// Like [`read`], but a missing entry is `Ok(None)` rather than an error —
/// for callers like verify.rs's real Manifest.db check, where "no stored
/// backup password yet" is an expected, common case to fall back from, not
/// a failure to report.
pub fn try_read(account: &str) -> Result<Option<String>, CradleError> {
    match generic_password(PasswordOptions::new_generic_password(SERVICE, account)) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| CradleError::Other("Keychain entry was not valid UTF-8".into())),
        Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(None),
        Err(e) => Err(CradleError::Other(format!("could not read Keychain entry: {e}"))),
    }
}

/// Removes a destination's stored password. Used when a destination is
/// deleted.
pub fn delete(account: &str) -> Result<(), CradleError> {
    delete_generic_password(SERVICE, account)
        .map_err(|e| CradleError::Other(format!("could not delete Keychain entry: {e}")))
}

/// 32 bytes of CSPRNG entropy, hex-encoded. restic treats a repository
/// password as an opaque passphrase, so there's no charset requirement to
/// satisfy beyond "long and random."
fn generate_password() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real macOS Keychain — `#[ignore]`d so a routine `cargo
    /// test` never risks a GUI access prompt in a non-interactive run. Run
    /// explicitly with `cargo test -- --ignored` when you want to confirm
    /// this for real.
    #[test]
    #[ignore]
    fn round_trip_against_real_keychain() {
        let account = format!("cradle-test-{}", std::process::id());

        let password = generate_and_store(&account).unwrap();
        assert_eq!(password.len(), 64, "32 bytes hex-encoded");

        let read_back = read(&account).unwrap();
        assert_eq!(read_back, password);

        delete(&account).unwrap();
        assert!(read(&account).is_err(), "deleted entry should no longer read back");
    }
}
