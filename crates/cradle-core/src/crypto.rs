//! Backup decryption: parses a device's `BackupKeyBag`, recovers whichever
//! protection-class keys are unlockable from the backup password, and uses
//! them to decrypt `Manifest.db` and individual file payloads.
//!
//! This implements the on-disk key-bag format Apple documents at a
//! protocol level in its Platform Security Guide — data-protection
//! classes, per-class AES key wrapping, and the post-iOS-10.2 two-stage
//! PBKDF2 stretch. The field layout (TLV tags, wrap-flag bits, the
//! little-endian class prefix on a file's wrapped key) is a fixed
//! property of the device's own backup format, not a design choice of any
//! particular codebase, and this module is written independently against
//! that documentation rather than ported from another implementation.
//!
//! Needed to give the verification gate a real `PRAGMA integrity_check`
//! on `Manifest.db` and to support raw file extraction. Manifest
//! *browsing* (listing files by domain/path) additionally needs an
//! NSKeyedArchiver decoder for the `Files` table's `file` BLOB column —
//! deliberately not built in this pass; see `ROADMAP.md`'s M5 section.

use std::collections::HashMap;
use std::path::Path;

use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use aes_kw::{KeyInit, KwAes256};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;

use crate::CradleError;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// RFC 3394 key wrap always adds a fixed 8-byte integrity block, so
/// wrapping a 32-byte AES-256 key produces exactly 40 bytes.
const WRAPPED_KEY_LEN: usize = 40;

/// Bit set in a class's `WRAP` value when that class's key is (also)
/// wrapped by the backup password, and therefore recoverable offline.
/// Classes wrapped only under the device's own UID key never set this bit
/// and cannot be recovered this way.
const WRAP_BY_PASSWORD: u32 = 0x2;

/// One `tag(4) + length(4, big-endian) + value(length)` record from the
/// key-bag's TLV byte stream.
#[derive(Debug)]
struct TlvField {
    tag: [u8; 4],
    value: Vec<u8>,
}

fn read_fields(raw: &[u8]) -> Result<Vec<TlvField>, CradleError> {
    let mut fields = Vec::new();
    let mut cursor = 0usize;

    while cursor < raw.len() {
        let header = raw.get(cursor..cursor + 8).ok_or_else(|| {
            CradleError::Other("BackupKeyBag ends mid-field (short header)".into())
        })?;
        let tag: [u8; 4] = header[0..4].try_into().unwrap();
        let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        cursor += 8;

        let value = raw
            .get(cursor..cursor + len)
            .ok_or_else(|| CradleError::Other("BackupKeyBag field runs past end of blob".into()))?
            .to_vec();
        cursor += len;

        fields.push(TlvField { tag, value });
    }

    Ok(fields)
}

fn field_u32(fields: &[TlvField], tag: &[u8; 4]) -> Option<u32> {
    field_bytes(fields, tag).and_then(|b| Some(u32::from_be_bytes(b.try_into().ok()?)))
}

fn field_bytes<'a>(fields: &'a [TlvField], tag: &[u8; 4]) -> Option<&'a [u8]> {
    fields.iter().find(|f| &f.tag == tag).map(|f| f.value.as_slice())
}

/// Splits the flat field list into the root section (backup-wide salt,
/// iteration counts, ...) and one slice per protection class. Classes are
/// delimited by their own `CLAS` tags rather than assumed to be a fixed
/// number of fields wide — real key bags vary the field count per class
/// (an asymmetric class carries extra key material a symmetric one
/// doesn't), and this also means a truncated or single stray `CLAS` entry
/// simply yields a short, unusable group instead of an arithmetic
/// under/overflow.
fn root_and_classes(fields: &[TlvField]) -> Result<(&[TlvField], Vec<&[TlvField]>), CradleError> {
    let class_starts: Vec<usize> = fields
        .iter()
        .enumerate()
        .filter(|(_, f)| &f.tag == b"CLAS")
        .map(|(i, _)| i)
        .collect();
    let Some(&first) = class_starts.first() else {
        return Err(CradleError::Other("BackupKeyBag has no protection classes".into()));
    };

    let classes = class_starts
        .iter()
        .enumerate()
        .map(|(i, &start)| {
            let end = class_starts.get(i + 1).copied().unwrap_or(fields.len());
            &fields[start..end]
        })
        .collect();

    Ok((&fields[..first], classes))
}

/// Turns the backup password into the key that unwraps whichever
/// protection classes were wrapped for it.
///
/// Backups from iOS 10.2 onward stretch the password through an extra
/// PBKDF2-HMAC-SHA256 pass (salted by `DPSL`, iterated `DPIC` times)
/// before the classic PBKDF2-HMAC-SHA1 pass over `SALT`/`ITER`; older
/// backups skip straight to the SHA1 pass. Branching on whether `DPSL`/
/// `DPIC` are actually present, rather than on the backup's recorded iOS
/// version, means this function only needs the key-bag bytes it already
/// has — no `Manifest.plist` version field required.
fn derive_root_key(root: &[TlvField], password: &[u8]) -> Result<[u8; 32], CradleError> {
    let salt = field_bytes(root, b"SALT")
        .ok_or_else(|| CradleError::Other("BackupKeyBag root is missing SALT".into()))?;
    let iterations = field_u32(root, b"ITER")
        .ok_or_else(|| CradleError::Other("BackupKeyBag root is missing ITER".into()))?;

    let stretched;
    let password_material: &[u8] = match (field_bytes(root, b"DPSL"), field_u32(root, b"DPIC")) {
        (Some(dpsl), Some(dpic)) => {
            let mut out = [0u8; 32];
            pbkdf2_hmac::<Sha256>(password, dpsl, dpic, &mut out);
            stretched = out;
            &stretched
        }
        _ => password,
    };

    let mut root_key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(password_material, salt, iterations, &mut root_key);
    Ok(root_key)
}

/// Unwraps every protection-class key reachable from `root_key`, keyed by
/// class number. Classes without a `WRAP_BY_PASSWORD` bit, or with a
/// wrapped-key blob of the wrong length, are silently skipped rather than
/// treated as errors — most, but never all, of a backup's classes are
/// recoverable from the password alone.
///
/// A wrong password shows up here, not in [`derive_root_key`]: RFC 3394
/// key unwrap carries its own integrity check, so an incorrect
/// key-encryption key reliably fails to unwrap instead of quietly
/// producing garbage.
fn recover_class_keys(
    classes: &[&[TlvField]],
    root_key: &[u8; 32],
) -> Result<HashMap<u32, [u8; 32]>, CradleError> {
    let unwrapper = KwAes256::new(root_key.into());
    let mut recovered = HashMap::new();

    for class_fields in classes {
        let (Some(class_id), Some(wrap_flags), Some(wrapped)) = (
            field_u32(class_fields, b"CLAS"),
            field_u32(class_fields, b"WRAP"),
            field_bytes(class_fields, b"WPKY"),
        ) else {
            continue;
        };
        if wrap_flags & WRAP_BY_PASSWORD == 0 || wrapped.len() != WRAPPED_KEY_LEN {
            continue;
        }

        let mut key = [0u8; 32];
        unwrapper.unwrap_key(wrapped, &mut key).map_err(|_| {
            CradleError::Other(format!(
                "could not unwrap protection class {class_id} — wrong backup password?"
            ))
        })?;
        recovered.insert(class_id, key);
    }

    Ok(recovered)
}

/// A backup's unlocked key bag: every protection-class key recoverable
/// from the backup password, ready to decrypt `Manifest.db` and
/// individual files.
#[derive(Debug)]
pub struct Keybag {
    classes: HashMap<u32, [u8; 32]>,
}

impl Keybag {
    /// Parses and unlocks a `BackupKeyBag` (the raw bytes of
    /// `Manifest.plist`'s `BackupKeyBag` entry) with `password` — the
    /// password the user set when enabling encrypted backups.
    pub fn unlock(raw_keybag: &[u8], password: &str) -> Result<Self, CradleError> {
        let fields = read_fields(raw_keybag)?;
        let (root, classes) = root_and_classes(&fields)?;
        let root_key = derive_root_key(root, password.as_bytes())?;
        let classes = recover_class_keys(&classes, &root_key)?;

        if classes.is_empty() {
            return Err(CradleError::Other(
                "no protection class keys could be unwrapped — wrong backup password?".into(),
            ));
        }
        Ok(Self { classes })
    }

    /// Reads `backup_dir`'s `Manifest.plist`, pulls out its `BackupKeyBag`,
    /// and unlocks it with `password` — the common case, so callers
    /// (`verify.rs`, the CLI's `decrypt` command) don't each re-implement
    /// "go find the keybag bytes."
    pub fn unlock_from_backup_dir(backup_dir: &Path, password: &str) -> Result<Self, CradleError> {
        let manifest_plist = plist::Value::from_file(backup_dir.join("Manifest.plist"))
            .map_err(|e| CradleError::Other(format!("could not read Manifest.plist: {e}")))?;
        let keybag_raw = manifest_plist
            .as_dictionary()
            .and_then(|d| d.get("BackupKeyBag"))
            .and_then(|v| v.as_data())
            .ok_or_else(|| CradleError::Other("Manifest.plist has no BackupKeyBag".into()))?;
        Self::unlock(keybag_raw, password)
    }

    /// Decrypts `data` in place using the wrapped-key blob `wrapped_key` —
    /// as found in `Manifest.plist`'s `ManifestKey`, or a `Manifest.db`
    /// `Files` row's `EncryptionKey`. Both are `class(4, little-endian) +
    /// wrapped-key(40)`; the little-endian class id here is the opposite
    /// byte order from every integer field inside the key-bag TLV itself,
    /// a real quirk of the format worth flagging since it's easy to get
    /// backwards.
    ///
    /// Takes `data` by unique reference and overwrites it with the
    /// plaintext, rather than returning a second, separately allocated
    /// buffer — for a large extracted file, a caller already holding the
    /// whole ciphertext in memory has no reason to also hold a
    /// same-sized plaintext copy at the same time; AES-CBC decryption is
    /// naturally an in-place operation once you have the key. `data` is
    /// left as the plaintext on success and in an unspecified state on
    /// failure — the block cipher may have written partial output before
    /// hitting an error, so callers must not read `data` after a `Err`.
    ///
    /// Content is AES-256-CBC with a zero IV — Apple's own convention,
    /// safe here only because every file/manifest gets its own one-time
    /// key. There is no standard block padding to strip: `data` keeps its
    /// original length and may run past the item's true size, which
    /// general file extraction must instead take from the corresponding
    /// `Manifest.db` row. `Manifest.db` itself is SQLite, which tolerates
    /// trailing bytes past the real page data.
    pub fn decrypt(&self, data: &mut [u8], wrapped_key: &[u8]) -> Result<(), CradleError> {
        if wrapped_key.len() != 4 + WRAPPED_KEY_LEN {
            return Err(CradleError::Other(format!(
                "unexpected wrapped key length: {} bytes",
                wrapped_key.len()
            )));
        }
        let class_id = u32::from_le_bytes(wrapped_key[..4].try_into().unwrap());
        let wrapped_file_key = &wrapped_key[4..];

        let class_key = self.classes.get(&class_id).ok_or_else(|| {
            CradleError::Other(format!(
                "no usable key for protection class {class_id} — this item isn't recoverable \
                 from the backup password alone"
            ))
        })?;

        let mut file_key = [0u8; 32];
        KwAes256::new(class_key.into())
            .unwrap_key(wrapped_file_key, &mut file_key)
            .map_err(|_| CradleError::Other("could not unwrap file encryption key".into()))?;

        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(CradleError::Other(
                "ciphertext is not AES-block-aligned — truncated or corrupt".into(),
            ));
        }
        Aes256CbcDec::new(&file_key.into(), &[0u8; 16].into())
            .decrypt_padded::<NoPadding>(data)
            .map_err(|_| CradleError::Other("AES-CBC decryption failed".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt;
    use aes_kw::KwAes256 as TestWrap;

    /// Appends one `tag(4) + length(4, big-endian) + value` field to a raw
    /// key-bag byte buffer under construction.
    fn put_field(buf: &mut Vec<u8>, tag: &[u8; 4], value: &[u8]) {
        buf.extend_from_slice(tag);
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value);
    }

    /// Builds a one-class synthetic key bag (a stretched-password root
    /// plus a single password-wrapped class) so derivation and unwrap can
    /// be tested without a real device backup, which this environment
    /// doesn't have.
    fn synthetic_keybag(password: &str, class_id: u32) -> (Vec<u8>, [u8; 32]) {
        let salt = *b"backup-salt-000012345"; // arbitrary, fixed length not required
        let iterations: u32 = 500;
        let stretch_salt = *b"stretch-salt-abcdefgh";
        let stretch_iterations: u32 = 500;

        let mut intermediate = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &stretch_salt, stretch_iterations, &mut intermediate);
        let mut root_key = [0u8; 32];
        pbkdf2_hmac::<Sha1>(&intermediate, &salt, iterations, &mut root_key);

        let class_key = [0x5Au8; 32];
        let mut wrapped_class_key = [0u8; WRAPPED_KEY_LEN];
        TestWrap::new((&root_key).into())
            .wrap_key(&class_key, &mut wrapped_class_key)
            .unwrap();

        let mut raw = Vec::new();
        put_field(&mut raw, b"SALT", &salt);
        put_field(&mut raw, b"ITER", &iterations.to_be_bytes());
        put_field(&mut raw, b"DPSL", &stretch_salt);
        put_field(&mut raw, b"DPIC", &stretch_iterations.to_be_bytes());
        put_field(&mut raw, b"CLAS", &class_id.to_be_bytes());
        put_field(&mut raw, b"WRAP", &WRAP_BY_PASSWORD.to_be_bytes());
        put_field(&mut raw, b"WPKY", &wrapped_class_key);

        (raw, class_key)
    }

    fn wrap_item_key(class_id: u32, class_key: &[u8; 32], item_key: &[u8; 32]) -> Vec<u8> {
        let mut wrapped = [0u8; WRAPPED_KEY_LEN];
        TestWrap::new(class_key.into()).wrap_key(item_key, &mut wrapped).unwrap();

        let mut blob = class_id.to_le_bytes().to_vec();
        blob.extend_from_slice(&wrapped);
        blob
    }

    #[test]
    fn correct_password_unlocks_wrong_password_does_not() {
        let (raw, class_key) = synthetic_keybag("correct horse battery staple", 6);

        let keybag = Keybag::unlock(&raw, "correct horse battery staple").unwrap();
        assert_eq!(keybag.classes.get(&6), Some(&class_key));

        let err = Keybag::unlock(&raw, "wrong password").unwrap_err();
        assert!(err.to_string().contains("wrong backup password"));
    }

    #[test]
    fn decrypts_content_wrapped_under_a_recovered_class() {
        let (raw, class_key) = synthetic_keybag("hunter2", 3);
        let keybag = Keybag::unlock(&raw, "hunter2").unwrap();

        let item_key = [0x11u8; 32];
        let wrapped_item_key = wrap_item_key(3, &class_key, &item_key);

        let plaintext: &[u8] = b"exactly two whole AES blocks!!!!";
        assert_eq!(plaintext.len(), 32);
        let mut ciphertext = plaintext.to_vec();
        cbc::Encryptor::<Aes256>::new(&item_key.into(), &[0u8; 16].into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, plaintext.len())
            .unwrap();

        keybag.decrypt(&mut ciphertext, &wrapped_item_key).unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn rejects_non_block_aligned_ciphertext() {
        let (raw, class_key) = synthetic_keybag("pw", 1);
        let keybag = Keybag::unlock(&raw, "pw").unwrap();
        let wrapped_item_key = wrap_item_key(1, &class_key, &[0x22; 32]);

        let err = keybag.decrypt(&mut [0u8; 17], &wrapped_item_key).unwrap_err();
        assert!(err.to_string().contains("block-aligned"));
    }

    #[test]
    fn unrecoverable_class_reports_missing_key_not_a_crash() {
        let (raw, _class_key) = synthetic_keybag("pw", 1);
        let keybag = Keybag::unlock(&raw, "pw").unwrap();

        // Class 99 was never present in the synthetic key bag at all.
        let bogus_key = wrap_item_key(99, &[0u8; 32], &[0u8; 32]);
        let err = keybag.decrypt(&mut [0u8; 16], &bogus_key).unwrap_err();
        assert!(err.to_string().contains("no usable key for protection class 99"));
    }

    #[test]
    fn a_lone_class_marker_with_no_key_material_is_not_a_crash() {
        let mut raw = Vec::new();
        put_field(&mut raw, b"SALT", b"0123456789012345678\x00");
        put_field(&mut raw, b"ITER", &1000u32.to_be_bytes());
        put_field(&mut raw, b"CLAS", &7u32.to_be_bytes()); // no WRAP/WPKY follow

        let err = Keybag::unlock(&raw, "anything").unwrap_err();
        assert!(err.to_string().contains("no protection class keys"));
    }

    #[test]
    fn a_keybag_with_no_class_entries_is_a_clear_error() {
        let mut raw = Vec::new();
        put_field(&mut raw, b"SALT", b"0123456789012345678\x00");
        put_field(&mut raw, b"ITER", &1000u32.to_be_bytes());

        let err = Keybag::unlock(&raw, "anything").unwrap_err();
        assert!(err.to_string().contains("no protection classes"));
    }

    #[test]
    fn a_field_claiming_more_bytes_than_remain_is_a_clear_error() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"SALT");
        raw.extend_from_slice(&500u32.to_be_bytes()); // claims 500 bytes, none follow
        raw.extend_from_slice(b"short");

        let err = Keybag::unlock(&raw, "anything").unwrap_err();
        assert!(err.to_string().contains("runs past end"));
    }

    #[test]
    fn trailing_bytes_shorter_than_a_field_header_are_a_clear_error() {
        let mut raw = Vec::new();
        put_field(&mut raw, b"CLAS", &1u32.to_be_bytes());
        raw.extend_from_slice(b"AB"); // 2 stray trailing bytes, not a full header

        let err = read_fields(&raw).unwrap_err();
        assert!(err.to_string().contains("short header"));
    }
}
