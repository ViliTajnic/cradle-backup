//! Backup decryption: `BackupKeyBag` parsing, PBKDF2 key derivation, class
//! key unwrapping, and per-file/per-manifest AES-256-CBC decryption.
//!
//! Ported faithfully from [doronz88/pyiosbackup's
//! `keybag.py`](https://github.com/doronz88/pyiosbackup) — a proven,
//! working implementation used by `pymobiledevice3` — rather than
//! reconstructed from blog posts. Every TLV tag, byte order, and the
//! two-stage PBKDF2 detail below is a direct translation, checked against
//! that source, not a guess.
//!
//! Needed to give M1's verification gate a real `PRAGMA integrity_check`
//! on `Manifest.db` (see `verify.rs`'s `# M5` markers) and to unlock raw
//! file extraction. Manifest *browsing* (listing files by domain/path)
//! additionally needs an NSKeyedArchiver decoder for the `Files` table's
//! `file` BLOB column — deliberately not built in this pass; see
//! `ROADMAP.md`'s M5 section for that gap.

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

/// How many consecutive TLV entries make up one protection class
/// (`CLAS`, `WRAP`, `KTYP`, `WRAP` again in some layouts, `WPKY`) — taken
/// directly from `pyiosbackup`'s `CLASS_ELEMENTS_COUNT`, not derived.
const CLASS_ELEMENTS_COUNT: usize = 5;

/// RFC 3394 AES key wrap adds a fixed 8-byte integrity block, so wrapping
/// a 32-byte AES-256 key always produces exactly 40 bytes.
const WRAPPED_256_LEN: usize = 40;

struct KeybagEntry {
    tag: [u8; 4],
    data: Vec<u8>,
}

/// Parses the raw TLV stream: `tag(4 bytes) + size(4 bytes, big-endian) +
/// data(size bytes)`, repeated to the end of the blob. Numeric fields
/// (`ITER`, `DPIC`, `CLAS`, `WRAP`) are 4-byte entries interpreted as
/// big-endian integers by the caller via [`u32_be`] — this parser always
/// stores raw bytes and leaves that interpretation to whoever reads a
/// specific tag, since only some tags are numeric.
fn parse_tlv(bytes: &[u8]) -> Result<Vec<KeybagEntry>, CradleError> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&bytes[i..i + 4]);
        let size = u32::from_be_bytes(bytes[i + 4..i + 8].try_into().unwrap()) as usize;
        i += 8;
        if i + size > bytes.len() {
            return Err(CradleError::Other("truncated BackupKeyBag entry".into()));
        }
        entries.push(KeybagEntry {
            tag,
            data: bytes[i..i + size].to_vec(),
        });
        i += size;
    }
    Ok(entries)
}

fn u32_be(data: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(data.try_into().ok()?))
}

/// Root section runs from the start of the keybag up to where the
/// repeating per-class groups begin. Found by locating the *first* `CLAS`
/// tag and working out how many full 5-element class groups fit from
/// there to the end — not just "everything before the first CLAS", since
/// that's what `pyiosbackup` does and a naive cutoff can misalign if a
/// class group's own layout varies.
fn class_section_start(entries: &[KeybagEntry]) -> Result<usize, CradleError> {
    let first_class_index = entries
        .iter()
        .position(|e| &e.tag == b"CLAS")
        .ok_or_else(|| CradleError::Other("BackupKeyBag has no class entries".into()))?;
    let class_count = (entries.len() - first_class_index).div_ceil(CLASS_ELEMENTS_COUNT);
    Ok(entries.len() - CLASS_ELEMENTS_COUNT * class_count)
}

fn find_tag<'a>(entries: &'a [KeybagEntry], tag: &[u8; 4]) -> Option<&'a [u8]> {
    entries.iter().find(|e| &e.tag == tag).map(|e| e.data.as_slice())
}

/// Derives the keybag's root decryption key from the backup password.
///
/// Two-stage when `DPSL`/`DPIC` are present (PBKDF2-HMAC-SHA256 over the
/// raw password, then PBKDF2-HMAC-SHA1 over *that* result) — every backup
/// this project will ever see has these (iOS > 10.2; `pyiosbackup` gates
/// on the backup's recorded iOS version, but checking for the fields'
/// presence directly means this function doesn't need to know anything
/// about `Manifest.plist` at all, only the keybag bytes it's already
/// given).
fn derive_decryption_key(password: &[u8], root: &[KeybagEntry]) -> Result<[u8; 32], CradleError> {
    let salt = find_tag(root, b"SALT")
        .ok_or_else(|| CradleError::Other("BackupKeyBag is missing SALT".into()))?;
    let iterations = find_tag(root, b"ITER")
        .and_then(u32_be)
        .ok_or_else(|| CradleError::Other("BackupKeyBag is missing a valid ITER".into()))?;

    let stage1_password: Vec<u8> = match (find_tag(root, b"DPSL"), find_tag(root, b"DPIC").and_then(u32_be)) {
        (Some(dpsl), Some(dpic)) => {
            let mut intermediate = [0u8; 32];
            pbkdf2_hmac::<Sha256>(password, dpsl, dpic, &mut intermediate);
            intermediate.to_vec()
        }
        _ => password.to_vec(),
    };

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(&stage1_password, salt, iterations, &mut key);
    Ok(key)
}

/// Unwraps every protection class key that's actually derivable from the
/// backup password (`WRAP & 2` — bit 1 means "wrapped by passcode/backup
/// key"; classes wrapped only by the device's own UID key are not
/// recoverable this way, and are silently skipped rather than treated as
/// an error, since most backup file classes still are).
///
/// A wrong password surfaces here: RFC 3394 AES key unwrap carries its own
/// integrity check, so an incorrect key-encryption-key reliably fails to
/// unwrap rather than silently producing garbage.
fn unwrap_class_keys(
    entries: &[KeybagEntry],
    class_section_start: usize,
    decryption_key: &[u8; 32],
) -> Result<HashMap<u32, [u8; 32]>, CradleError> {
    let kek = KwAes256::new(decryption_key.into());
    let mut classes = HashMap::new();

    for group in entries[class_section_start..].chunks(CLASS_ELEMENTS_COUNT) {
        let class = group.iter().find(|e| &e.tag == b"CLAS").and_then(|e| u32_be(&e.data));
        let wrap = group.iter().find(|e| &e.tag == b"WRAP").and_then(|e| u32_be(&e.data));
        let wpky = group.iter().find(|e| &e.tag == b"WPKY").map(|e| e.data.as_slice());

        let (Some(class), Some(wrap), Some(wpky)) = (class, wrap, wpky) else {
            continue;
        };
        if wrap & 2 == 0 || wpky.len() != WRAPPED_256_LEN {
            continue;
        }

        let mut unwrapped = [0u8; 32];
        kek.unwrap_key(wpky, &mut unwrapped).map_err(|_| {
            CradleError::Other(format!(
                "could not unwrap protection class {class} key — wrong backup password?"
            ))
        })?;
        classes.insert(class, unwrapped);
    }

    Ok(classes)
}

/// A backup's decrypted keybag: every protection-class key recoverable
/// from the backup password, ready to decrypt `Manifest.db` and
/// individual files' content.
pub struct Keybag {
    classes: HashMap<u32, [u8; 32]>,
}

impl Keybag {
    /// Parses and unlocks a `BackupKeyBag` (the raw bytes of
    /// `Manifest.plist`'s `BackupKeyBag` entry) with `password` — the
    /// same password the user set when enabling encrypted backups.
    pub fn unlock(raw_keybag: &[u8], password: &str) -> Result<Self, CradleError> {
        let entries = parse_tlv(raw_keybag)?;
        let boundary = class_section_start(&entries)?;
        let decryption_key = derive_decryption_key(password.as_bytes(), &entries[..boundary])?;
        let classes = unwrap_class_keys(&entries, boundary, &decryption_key)?;
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

    /// Decrypts `data` using the wrapped-key blob `wrapped_key` — as found
    /// in `Manifest.plist`'s `ManifestKey`, or a `Manifest.db` `Files` row's
    /// `EncryptionKey`. AES-256-CBC with a zero IV, matching Apple's own
    /// convention.
    ///
    /// The returned plaintext may have trailing bytes past the true
    /// content size (CBC operates in whole 16-byte blocks; Apple does not
    /// use standard PKCS7 padding for backup file content). SQLite
    /// tolerates this for `Manifest.db` — confirmed against `pyiosbackup`,
    /// which writes this output straight to a `.sqlite3` file with no
    /// truncation. General file extraction should truncate to the size
    /// recorded in the corresponding `Manifest.db` row instead of trying
    /// to unpad.
    pub fn decrypt(&self, data: &[u8], wrapped_key: &[u8]) -> Result<Vec<u8>, CradleError> {
        if wrapped_key.len() != 4 + WRAPPED_256_LEN {
            return Err(CradleError::Other(format!(
                "unexpected wrapped key length: {} bytes",
                wrapped_key.len()
            )));
        }
        // The class id prefixing a *file's* wrapped key is little-endian —
        // unlike every integer field inside the keybag TLV itself, which
        // is big-endian. Confirmed against pyiosbackup's `encryption_key_struct`
        // (`Int32ul`, vs. the keybag's `Int32ub`) — easy to get backwards.
        let class = u32::from_le_bytes(wrapped_key[0..4].try_into().unwrap());
        let wrapped_file_key = &wrapped_key[4..];

        let class_key = self.classes.get(&class).ok_or_else(|| {
            CradleError::Other(format!(
                "no usable key for protection class {class} — this item isn't recoverable from \
                 the backup password alone"
            ))
        })?;

        let kek = KwAes256::new(class_key.into());
        let mut file_key = [0u8; 32];
        kek.unwrap_key(wrapped_file_key, &mut file_key)
            .map_err(|_| CradleError::Other("could not unwrap file encryption key".into()))?;

        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(CradleError::Other(
                "ciphertext is not AES-block-aligned — truncated or corrupt".into(),
            ));
        }
        let mut buf = data.to_vec();
        let decrypted_len = Aes256CbcDec::new(&file_key.into(), &[0u8; 16].into())
            .decrypt_padded::<NoPadding>(&mut buf)
            .map_err(|_| CradleError::Other("AES-CBC decryption failed".into()))?
            .len();
        buf.truncate(decrypted_len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockModeEncrypt;
    use aes_kw::KwAes256 as TestKw;

    /// Builds a synthetic single-class keybag (SALT/ITER/DPSL/DPIC root +
    /// one WRAP-by-password class) so the parsing and key-derivation
    /// chain can be tested deterministically without a real device
    /// backup, which this environment doesn't have.
    fn build_test_keybag(password: &str, class_id: u32) -> (Vec<u8>, [u8; 32]) {
        let salt = *b"0123456789012345678\x00"; // 20 bytes, arbitrary
        let iter: u32 = 1000;
        let dpsl = *b"abcdefghijklmnopqrst"; // 20 bytes, arbitrary
        let dpic: u32 = 1000;

        let mut intermediate = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &dpsl, dpic, &mut intermediate);
        let mut decryption_key = [0u8; 32];
        pbkdf2_hmac::<Sha1>(&intermediate, &salt, iter, &mut decryption_key);

        let class_key = [0x42u8; 32];
        let kek = TestKw::new((&decryption_key).into());
        let mut wpky = [0u8; WRAPPED_256_LEN];
        kek.wrap_key(&class_key, &mut wpky).unwrap();

        let mut buf = Vec::new();
        let mut push = |tag: &[u8; 4], data: &[u8]| {
            buf.extend_from_slice(tag);
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
        };
        push(b"SALT", &salt);
        push(b"ITER", &iter.to_be_bytes());
        push(b"DPSL", &dpsl);
        push(b"DPIC", &dpic.to_be_bytes());
        push(b"CLAS", &class_id.to_be_bytes());
        push(b"WRAP", &2u32.to_be_bytes());
        push(b"KTYP", &0u32.to_be_bytes());
        push(b"PBKY", &[0u8; 65]); // unrelated filler tag, ignored by the parser
        push(b"WPKY", &wpky);

        (buf, class_key)
    }

    #[test]
    fn unlocks_with_correct_password_and_wrong_password_fails() {
        let (raw, class_key) = build_test_keybag("correct horse battery staple", 6);

        let keybag = Keybag::unlock(&raw, "correct horse battery staple").unwrap();
        assert_eq!(keybag.classes.get(&6), Some(&class_key));

        match Keybag::unlock(&raw, "wrong password") {
            Err(e) => assert!(e.to_string().contains("wrong backup password")),
            Ok(_) => panic!("wrong password should not unlock the keybag"),
        }
    }

    /// Wraps `file_key` under `class_key` and builds the little-endian
    /// `class + wrapped key` blob format [`Keybag::decrypt`] expects as
    /// its `wrapped_key` argument.
    fn wrap_file_key(class: u32, class_key: &[u8; 32], file_key: &[u8; 32]) -> Vec<u8> {
        let kek = TestKw::new(class_key.into());
        let mut wrapped_file_key = [0u8; WRAPPED_256_LEN];
        kek.wrap_key(file_key, &mut wrapped_file_key).unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(&class.to_le_bytes());
        blob.extend_from_slice(&wrapped_file_key);
        blob
    }

    #[test]
    fn decrypts_data_wrapped_under_a_known_class() {
        let (raw, class_key) = build_test_keybag("hunter2", 3);
        let keybag = Keybag::unlock(&raw, "hunter2").unwrap();

        let file_key = [0x99u8; 32];
        let wrapped_key_blob = wrap_file_key(3, &class_key, &file_key);

        let plaintext: &[u8] = &[0x41; 32]; // 2 AES blocks, no ambiguity about padding
        let mut ciphertext = plaintext.to_vec();
        cbc::Encryptor::<Aes256>::new(&file_key.into(), &[0u8; 16].into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, plaintext.len())
            .unwrap();

        let decrypted = keybag.decrypt(&ciphertext, &wrapped_key_blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_a_non_block_aligned_ciphertext() {
        let (raw, class_key) = build_test_keybag("pw", 1);
        let keybag = Keybag::unlock(&raw, "pw").unwrap();
        let wrapped_key_blob = wrap_file_key(1, &class_key, &[0x77; 32]);

        let err = keybag.decrypt(&[0u8; 15], &wrapped_key_blob).unwrap_err();
        assert!(err.to_string().contains("block-aligned"));
    }
}
