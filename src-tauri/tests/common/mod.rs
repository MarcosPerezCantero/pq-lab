//! Shared helpers for integration tests. Every test runs the real OpenSSL
//! binary (sidecar or `PQLAB_OPENSSL`) and checks results independently.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::openssl::OpenSsl;
use pqlab_lib::pki::{IssueRequest, Issued, Pki, Validity};
use pqlab_lib::profile::{preset, CertProfile};
use pqlab_lib::security::Secret;
use pqlab_lib::validation::SubjectInput;
use tempfile::TempDir;

pub const MASTER: &str = "master-pass-123";

pub fn openssl() -> OpenSsl {
    OpenSsl::locate().expect("openssl sidecar not found: run scripts/build-openssl.sh")
}

/// An unlocked lab with its own data and temporary directories.
pub struct Lab {
    pub dir: TempDir,
    pub pki: Pki,
}

impl Lab {
    pub fn new() -> Self {
        Self::with_tmp("tmp")
    }

    /// A lab whose temporary directories live under `tmp` (a name relative
    /// to the lab directory), to test unusual paths.
    pub fn with_tmp(tmp: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        let o = openssl().with_log(dir.path().join("data").join("pqlab.log"));
        let mut pki = Pki::new(o, dir.path().join(tmp));
        pki.create_database(&dir.path().join("data").join("lab.db"), Secret::new(MASTER))
            .unwrap();
        Self { dir, pki }
    }

    pub fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    pub fn tmp_root(&self) -> PathBuf {
        self.pki.tmp_root().to_path_buf()
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir().join("lab.db")
    }

    pub fn key(&self, name: &str, alg: Algorithm) -> i64 {
        self.pki.generate_key(name, alg).unwrap()
    }

    /// Issues a certificate for a fresh key of `alg` using a built-in preset.
    pub fn cert(&self, name: &str, alg: Algorithm, issuer: Option<i64>, preset_id: &str) -> Issued {
        let mut profile = preset(preset_id).unwrap().profile;
        if profile.ext_key_usage.iter().any(|e| e == "serverAuth") {
            profile.san = vec![name.into()];
        }
        self.cert_with(name, alg, issuer, profile)
    }

    pub fn cert_with(&self, name: &str, alg: Algorithm, issuer: Option<i64>, profile: CertProfile) -> Issued {
        let key_id = self.key(&format!("{name}-key"), alg);
        self.issue(name, key_id, issuer, profile).unwrap()
    }

    pub fn issue(
        &self,
        name: &str,
        key_id: i64,
        issuer_id: Option<i64>,
        profile: CertProfile,
    ) -> pqlab_lib::error::Result<Issued> {
        self.pki.issue_certificate(&IssueRequest {
            name: name.into(),
            key_id,
            issuer_id,
            subject: SubjectInput::cn(name),
            profile,
            validity: Validity::default(),
            template: "custom".into(),
        })
    }

    pub fn root(&self, name: &str, alg: Algorithm) -> Issued {
        self.cert(name, alg, None, "root")
    }

    pub fn intermediate(&self, name: &str, alg: Algorithm, issuer_id: i64) -> Issued {
        self.cert(name, alg, Some(issuer_id), "intermediate")
    }

    pub fn pem(&self, id: i64) -> String {
        String::from_utf8(
            self.pki
                .export_certificate(id, pqlab_lib::pki::CertFormat::Pem)
                .unwrap(),
        )
        .unwrap()
    }

    /// Asserts the temporary root holds no leftover operation directory.
    pub fn assert_tmp_clean(&self) {
        let root = self.tmp_root();
        if root.exists() {
            let left: Vec<_> = std::fs::read_dir(&root).unwrap().collect();
            assert!(left.is_empty(), "temporary directories left behind: {left:?}");
        }
    }
}

/// Runs openssl in `dir` and returns (success, stdout+stderr).
pub fn run_in(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(openssl().path())
        .args(args)
        .env("OPENSSL_CONF", pqlab_lib::openssl::NULL_CONFIG)
        .current_dir(dir)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Independent `openssl verify` of `leaf` against `root` (+ intermediates),
/// from a fresh directory containing only public files.
pub fn external_verify(root: &str, intermediates: &[String], leaf: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("root.pem"), root).unwrap();
    std::fs::write(dir.path().join("leaf.pem"), leaf).unwrap();
    let mut args = vec!["verify", "-CAfile", "root.pem"];
    if !intermediates.is_empty() {
        std::fs::write(dir.path().join("inter.pem"), intermediates.concat()).unwrap();
        args.extend(["-untrusted", "inter.pem"]);
    }
    args.push("leaf.pem");
    run_in(dir.path(), &args)
}

/// `openssl x509 -noout -text` of a PEM certificate.
pub fn cert_text(pem: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("c.pem"), pem).unwrap();
    let (ok, out) = run_in(dir.path(), &["x509", "-in", "c.pem", "-noout", "-text"]);
    assert!(ok, "{out}");
    out
}

/// Recursively searches `dir` for unencrypted private key PEM headers.
pub fn find_plain_private_keys(dir: &Path) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    if !dir.exists() {
        return hits;
    }
    for entry in walk(dir) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        if text.contains("BEGIN PRIVATE KEY")
            || text.contains("BEGIN RSA PRIVATE KEY")
            || text.contains("BEGIN EC PRIVATE KEY")
        {
            hits.push(entry);
        }
    }
    hits
}

pub fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

pub fn has_warning(issued: &Issued, code: &str) -> bool {
    issued.warnings.iter().any(|w| w.code == code)
}
