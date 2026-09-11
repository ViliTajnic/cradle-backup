//! macOS Keychain access for restic repository passwords.
//!
//! Per CLAUDE.md: "Secrets go in the macOS Keychain / Windows DPAPI,
//! referenced by `credential_ref`. Never store a secret in the database."
//! Windows DPAPI support lands with M9; this module is macOS-only for now.
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
/// (see [`destination_account`]), not by service.
pub const SERVICE: &str = "com.cradle.restic-repo-password";

/// The Keychain `account` a destination's password lives under. This is
/// exactly what `destinations.credential_ref` holds in the catalog — a
/// lookup key, never the secret itself.
///
/// Keyed by the destination's (unique) *name* rather than its catalog id:
/// the id doesn't exist until after `INSERT`, and generating the Keychain
/// entry before that insert — so a half-created destination is never
/// recorded — needs a key that doesn't depend on it.
pub fn destination_account(destination_name: &str) -> String {
    format!("cradle-destination-{destination_name}")
}

/// Generates a new random repository password and stores it in the
/// Keychain under `account`. Returns the password so the caller can hand
/// it straight to `restic init` without a second Keychain round trip.
pub fn generate_and_store(account: &str) -> Result<String, CradleError> {
    let password = generate_password();
    set_generic_password(SERVICE, account, password.as_bytes())
        .map_err(|e| CradleError::Other(format!("could not store Keychain entry: {e}")))?;
    Ok(password)
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
