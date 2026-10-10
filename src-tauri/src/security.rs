//! Master password handling, temporary directories and serial numbers.

use std::path::{Path, PathBuf};

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use tempfile::TempDir;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

pub const MIN_PASSWORD_LEN: usize = 8;

/// Secret kept in memory while the database is unlocked. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Bytes for an openssl `stdin` password line.
    pub fn stdin_line(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Vec::with_capacity(self.0.len() + 1);
        v.extend_from_slice(self.0.as_bytes());
        v.push(b'\n');
        Zeroizing::new(v)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Rejects passwords openssl cannot read from a single stdin line.
pub fn validate_password(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::validation("password_too_short"));
    }
    if pw.contains(['\n', '\r', '\0']) {
        return Err(Error::validation("password_invalid_chars"));
    }
    Ok(())
}

pub fn hash_password(pw: &Secret) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.expose().as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| Error::Internal(format!("argon2: {e}")))
}

pub fn verify_password(pw: &Secret, stored_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(stored_hash).map_err(|e| Error::Internal(format!("argon2: {e}")))?;
    Ok(Argon2::default()
        .verify_password(pw.expose().as_bytes(), &parsed)
        .is_ok())
}

/// Private working directory for one operation (mode 0700). Removed on drop,
/// including on error paths.
pub struct WorkDir {
    dir: TempDir,
}

impl WorkDir {
    pub fn new(base: &Path) -> Result<Self> {
        std::fs::create_dir_all(base)?;
        let dir = tempfile::Builder::new().prefix("pqlab-").tempdir_in(base)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Writes public material or an already encrypted key into the directory.
    pub fn write(&self, name: &str, contents: &str) -> Result<PathBuf> {
        debug_assert!(!contains_plain_private_key(contents));
        let p = self.dir.path().join(name);
        std::fs::write(&p, contents)?;
        Ok(p)
    }
}

/// True if `text` contains an unencrypted private key PEM block.
pub fn contains_plain_private_key(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("-----BEGIN") && l.contains("PRIVATE KEY") && !l.contains("ENCRYPTED")
    })
}

/// 16 random bytes with the top bit cleared, as `0x<hex>` for `-set_serial`.
pub fn random_serial() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 0x01;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!("0x{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_is_positive_16_bytes() {
        for _ in 0..100 {
            let s = random_serial();
            assert_eq!(s.len(), 34);
            let first = u8::from_str_radix(&s[2..4], 16).unwrap();
            assert!(first & 0x80 == 0 && first != 0);
        }
    }

    #[test]
    fn hash_and_verify() {
        let pw = Secret::new("correct horse");
        let h = hash_password(&pw).unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&pw, &h).unwrap());
        assert!(!verify_password(&Secret::new("wrong horse"), &h).unwrap());
    }

    #[test]
    fn detects_plain_keys() {
        assert!(contains_plain_private_key("-----BEGIN PRIVATE KEY-----\n"));
        assert!(contains_plain_private_key("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(!contains_plain_private_key(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        ));
    }
}
