//! High-level PKI operations. Orchestrates validation, temporary files, the
//! database and OpenSSL invocations. Contains no cryptography.

mod certs;
mod pkcs12;
mod revocation;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::algorithms::Algorithm;
use crate::db::{CsrRow, Db, KeyRow, TemplateRow};
use crate::error::{Error, Result};
use crate::inspect::{self, CsrInfo};
use crate::openssl::{OpenSsl, OpenSslError};
use crate::profile::{self, CertProfile, Preset, Usage};
use crate::security::{self, Secret, WorkDir};
use crate::validation::{self, SubjectInput, WARN_VALIDITY_CLIPPED};

pub use certs::{CertFormat, CertView, IssueRequest, SignCsrRequest, VerifyResult};
pub use pkcs12::Pkcs12Import;
pub use revocation::{CrlView, REVOCATION_REASONS};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Warning {
    pub code: &'static str,
    pub params: BTreeMap<&'static str, String>,
}

impl Warning {
    fn with(code: &'static str, k: &'static str, v: String) -> Self {
        Self {
            code,
            params: [(k, v)].into_iter().collect(),
        }
    }
}

/// Result of an operation that creates a certificate.
#[derive(Debug, Serialize)]
pub struct Issued {
    pub id: i64,
    pub warnings: Vec<Warning>,
}

/// Validity requested in the UI: a number of days, or exact dates
/// (`YYYY-MM-DD` or RFC 3339). Missing values fall back to defaults.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Validity {
    pub days: Option<u32>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl Validity {
    pub fn days(days: u32) -> Self {
        Self {
            days: Some(days),
            ..Default::default()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CsrRequest {
    pub name: String,
    pub key_id: i64,
    pub subject: SubjectInput,
    /// Extensions requested in the CSR (optional).
    #[serde(default)]
    pub profile: Option<CertProfile>,
}

#[derive(Debug, Serialize)]
pub struct CsrView {
    pub row: CsrRow,
    pub info: CsrInfo,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct Templates {
    pub presets: Vec<Preset>,
    pub user: Vec<TemplateRow>,
}

pub(crate) struct Session {
    pub(crate) db: Db,
    pub(crate) password: Secret,
    path: PathBuf,
}

pub struct Pki {
    openssl: OpenSsl,
    tmp_root: PathBuf,
    session: Option<Session>,
}

impl Pki {
    pub fn new(openssl: OpenSsl, tmp_root: PathBuf) -> Self {
        Self {
            openssl,
            tmp_root,
            session: None,
        }
    }

    pub fn openssl(&self) -> &OpenSsl {
        &self.openssl
    }

    // ---- database lifecycle -----------------------------------------------

    pub fn create_database(&mut self, path: &Path, password: Secret) -> Result<()> {
        security::validate_password(password.expose())?;
        self.lock();
        let hash = security::hash_password(&password)?;
        let db = Db::create(path, &hash)?;
        self.session = Some(Session {
            db,
            password,
            path: path.to_path_buf(),
        });
        Ok(())
    }

    pub fn open_database(&mut self, path: &Path, password: Secret) -> Result<()> {
        self.lock();
        let db = Db::open(path)?;
        let hash = db
            .get_meta("master_hash")?
            .ok_or_else(|| Error::validation("db_invalid"))?;
        if !security::verify_password(&password, &hash)? {
            return Err(Error::WrongPassword);
        }
        self.session = Some(Session {
            db,
            password,
            path: path.to_path_buf(),
        });
        Ok(())
    }

    /// Closes the database and wipes the master password from memory.
    pub fn lock(&mut self) {
        self.session = None;
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.session.as_ref().map(|s| s.path.as_path())
    }

    pub(crate) fn session(&self) -> Result<&Session> {
        self.session.as_ref().ok_or(Error::Locked)
    }

    fn session_mut(&mut self) -> Result<&mut Session> {
        self.session.as_mut().ok_or(Error::Locked)
    }

    pub fn tmp_root(&self) -> &Path {
        &self.tmp_root
    }

    pub(crate) fn workdir(&self) -> Result<WorkDir> {
        WorkDir::new(&self.tmp_root)
    }

    // ---- keys ---------------------------------------------------------------

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        self.session()?.db.list_keys()
    }

    pub fn generate_key(&self, name: &str, algorithm: Algorithm) -> Result<i64> {
        let s = self.session()?;
        let name = validation::validate_name(name)?;
        let args = [
            "genpkey",
            "-algorithm",
            algorithm.openssl_name(),
            "-aes-256-cbc",
            "-pass",
            "stdin",
        ];
        let private_enc = self
            .openssl
            .run(&args, Some(&s.password.stdin_line()))?
            .stdout_text();
        let public = self.public_from_private(s, &private_enc)?;
        s.db.insert_key(&name, algorithm.id(), &public, Some(&private_enc))
    }

    fn public_from_private(&self, s: &Session, private_enc: &str) -> Result<String> {
        let work = self.workdir()?;
        let key = work.write("key.pem", private_enc)?;
        let out = self.openssl.run(
            &["pkey", "-in", path_str(&key)?, "-passin", "stdin", "-pubout"],
            Some(&s.password.stdin_line()),
        )?;
        Ok(out.stdout_text())
    }

    /// Imports a PEM key. Private keys (clear or encrypted with
    /// `import_password`) are re-encrypted with the master password without
    /// ever being written to disk; the PEM travels through openssl's stdin.
    pub fn import_key(&self, name: &str, pem: &str, import_password: Option<Secret>) -> Result<i64> {
        let s = self.session()?;
        let name = validation::validate_name(name)?;
        let is_private = pem.contains("PRIVATE KEY-----");
        let is_public = pem.contains("-----BEGIN PUBLIC KEY-----");
        let work = self.workdir()?;
        let (public, private_enc) = if is_private {
            let encrypted = pem.contains("ENCRYPTED");
            let mut input: Vec<u8> = Vec::new();
            let mut args = vec!["pkey"];
            if encrypted {
                let pw = import_password
                    .as_ref()
                    .filter(|p| !p.expose().is_empty())
                    .ok_or_else(|| Error::validation("import_password_required"))?;
                args.extend(["-passin", "stdin"]);
                input.extend_from_slice(&pw.stdin_line());
            } else {
                // A dummy passin keeps openssl from prompting on a tty.
                args.extend(["-passin", "pass:"]);
            }
            args.extend(["-passout", "stdin", "-aes-256-cbc"]);
            input.extend_from_slice(&s.password.stdin_line());
            input.extend_from_slice(pem.as_bytes());
            let input = zeroize::Zeroizing::new(input);
            let enc = self
                .openssl
                .run(&args, Some(&input))
                .map_err(|e| import_error(e, "import_key_failed"))?
                .stdout_text();
            if security::contains_plain_private_key(&enc) || !enc.contains("ENCRYPTED PRIVATE KEY") {
                return Err(Error::Internal("unexpected key output".into()));
            }
            (self.public_from_private(s, &enc)?, Some(enc))
        } else if is_public {
            let p = work.write("in.pem", pem)?;
            let out = self
                .openssl
                .run(&["pkey", "-pubin", "-in", path_str(&p)?, "-pubout"], None)
                .map_err(|e| import_error(e, "import_key_failed"))?;
            (out.stdout_text(), None)
        } else {
            return Err(Error::validation("import_not_pem_key"));
        };
        let pub_path = work.write("pub.pem", &public)?;
        let algorithm = inspect::public_key_algorithm(&self.openssl, path_str(&pub_path)?)?
            .ok_or_else(|| Error::validation("algorithm_unsupported"))?;
        if let Some(existing) = s.db.find_key_by_public(&public)? {
            if existing.private_pem_enc.is_none() {
                if let Some(enc) = &private_enc {
                    s.db.set_key_private(existing.id, enc)?;
                    return Ok(existing.id);
                }
            }
            return Err(Error::validation_with("key_exists", &[("name", existing.name)]));
        }
        s.db.insert_key(&name, algorithm.id(), &public, private_enc.as_deref())
    }

    pub fn rename_key(&self, id: i64, name: &str) -> Result<()> {
        let name = validation::validate_name(name)?;
        self.session()?.db.rename_key(id, &name)
    }

    pub fn delete_key(&mut self, id: i64) -> Result<()> {
        self.session_mut()?.db.delete_key(id)
    }

    pub fn export_public_key(&self, id: i64) -> Result<String> {
        Ok(self.session()?.db.get_key(id)?.public_pem)
    }

    /// Exports the private key encrypted with `export_password`.
    pub fn export_private_key(&self, id: i64, export_password: &Secret) -> Result<String> {
        security::validate_password(export_password.expose())?;
        let s = self.session()?;
        let key = s.db.get_key(id)?;
        let enc = key
            .private_pem_enc
            .ok_or_else(|| Error::validation("key_no_private"))?;
        let work = self.workdir()?;
        let p = work.write("key.pem", &enc)?;
        let mut input = s.password.stdin_line();
        input.extend_from_slice(&export_password.stdin_line());
        let out = self.openssl.run(
            &[
                "pkey",
                "-in",
                path_str(&p)?,
                "-passin",
                "stdin",
                "-passout",
                "stdin",
                "-aes-256-cbc",
            ],
            Some(&input),
        )?;
        let text = out.stdout_text();
        if !text.contains("ENCRYPTED PRIVATE KEY") {
            return Err(Error::Internal("unexpected key output".into()));
        }
        Ok(text)
    }

    pub(crate) fn key_with_algorithm(&self, s: &Session, key_id: i64) -> Result<(KeyRow, Algorithm)> {
        let key = s.db.get_key(key_id)?;
        let alg =
            Algorithm::from_id(&key.algorithm).ok_or_else(|| Error::validation("algorithm_unsupported"))?;
        Ok((key, alg))
    }

    // ---- templates ------------------------------------------------------------

    pub fn list_templates(&self) -> Result<Templates> {
        Ok(Templates {
            presets: profile::presets(),
            user: self.session()?.db.list_templates()?,
        })
    }

    pub fn save_template(&self, id: Option<i64>, name: &str, profile: &CertProfile) -> Result<i64> {
        let name = validation::validate_name(name)?;
        profile.validate(Usage {
            key: None,
            self_signed: false,
            template: true,
        })?;
        let json = serde_json::to_string(profile).map_err(|e| Error::Internal(e.to_string()))?;
        self.session()?.db.save_template(id, &name, &json)
    }

    pub fn delete_template(&self, id: i64) -> Result<()> {
        self.session()?.db.delete_template(id)
    }

    // ---- CSRs -----------------------------------------------------------------

    pub fn list_csrs(&self) -> Result<Vec<CsrRow>> {
        self.session()?.db.list_csrs()
    }

    pub fn delete_csr(&self, id: i64) -> Result<()> {
        self.session()?.db.delete_csr(id)
    }

    /// `openssl req -new` with an encrypted private key; returns the CSR PEM.
    /// `config` optionally carries requested extensions in section `ext`.
    fn make_csr(
        &self,
        s: &Session,
        work: &WorkDir,
        private_enc: &str,
        subj: &str,
        config: Option<&str>,
    ) -> Result<String> {
        let key_path = work.write("csr.key", private_enc)?;
        let cnf = work.write(
            "csr.cnf",
            config.unwrap_or("[req]\ndistinguished_name = req_dn\nprompt = no\n[req_dn]\n"),
        )?;
        let mut args = vec![
            "req",
            "-new",
            "-utf8",
            "-key",
            path_str(&key_path)?,
            "-passin",
            "stdin",
            "-subj",
            subj,
            "-config",
            path_str(&cnf)?,
        ];
        if config.is_some() {
            args.extend(["-reqexts", "ext"]);
        }
        Ok(self
            .openssl
            .run(&args, Some(&s.password.stdin_line()))?
            .stdout_text())
    }

    pub fn generate_csr(&self, req: &CsrRequest) -> Result<i64> {
        let s = self.session()?;
        let name = validation::validate_name(&req.name)?;
        let (key, alg) = self.key_with_algorithm(s, req.key_id)?;
        if !alg.can_sign() {
            return Err(Error::validation("kem_no_csr"));
        }
        let private = key
            .private_pem_enc
            .as_deref()
            .ok_or_else(|| Error::validation("key_no_private"))?;
        let config = match &req.profile {
            Some(p) => Some(
                p.validate(Usage {
                    key: Some(alg),
                    self_signed: false,
                    template: false,
                })?
                .render_request("ext"),
            ),
            None => None,
        };
        let work = self.workdir()?;
        let pem = self.make_csr(
            s,
            &work,
            private,
            &req.subject.to_openssl(false)?,
            config.as_deref(),
        )?;
        let p = work.write("new.csr", &pem)?;
        let info = inspect::csr_info(&self.openssl, path_str(&p)?)?;
        s.db.insert_csr(&name, Some(key.id), &info.subject, alg.id(), &pem)
    }

    /// Imports an external CSR after checking its self-signature.
    pub fn import_csr(&self, name: &str, pem: &str) -> Result<i64> {
        let s = self.session()?;
        let name = validation::validate_name(name)?;
        if !pem.contains("CERTIFICATE REQUEST-----") {
            return Err(Error::validation("import_not_pem_csr"));
        }
        let work = self.workdir()?;
        let raw = work.write("raw.csr", pem)?;
        let normalized = self
            .openssl
            .run(&["req", "-in", path_str(&raw)?], None)
            .map_err(|e| import_error(e, "import_csr_failed"))?
            .stdout_text();
        let p = work.write("in.csr", &normalized)?;
        self.verify_csr_signature(&p)?;
        let info = inspect::csr_info(&self.openssl, path_str(&p)?)?;
        if Algorithm::from_id(&info.key_algorithm).is_none() {
            return Err(Error::validation("algorithm_unsupported"));
        }
        let public = self
            .openssl
            .run(&["req", "-in", path_str(&p)?, "-noout", "-pubkey"], None)?
            .stdout_text();
        let key_id = s.db.find_key_by_public(&public)?.map(|k| k.id);
        s.db.insert_csr(&name, key_id, &info.subject, &info.key_algorithm, &normalized)
    }

    fn verify_csr_signature(&self, csr: &Path) -> Result<()> {
        match self
            .openssl
            .run(&["req", "-in", path_str(csr)?, "-noout", "-verify"], None)
        {
            Ok(o) if !o.stderr.to_ascii_lowercase().contains("fail") => Ok(()),
            Ok(_) | Err(OpenSslError::Failed { .. }) => Err(Error::validation("csr_bad_signature")),
            Err(e) => Err(e.into()),
        }
    }

    pub fn view_csr(&self, id: i64) -> Result<CsrView> {
        let s = self.session()?;
        let row = s.db.get_csr(id)?;
        let work = self.workdir()?;
        let p = work.write("view.csr", &row.pem)?;
        let info = inspect::csr_info(&self.openssl, path_str(&p)?)?;
        let text = inspect::csr_text(&self.openssl, path_str(&p)?)?;
        Ok(CsrView { row, info, text })
    }

    pub fn export_csr(&self, id: i64) -> Result<String> {
        Ok(self.session()?.db.get_csr(id)?.pem)
    }
}

/// Resolves a validity request to explicit `-not_before`/`-not_after` dates,
/// clipping it to the issuer's notAfter when needed.
pub(crate) fn resolve_validity(
    v: &Validity,
    default_days: u32,
    issuer_not_after: Option<DateTime<Utc>>,
    warnings: &mut Vec<Warning>,
) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let now = Utc::now();
    let not_before = match v.not_before.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => parse_date(s, false)?,
        None => now,
    };
    let mut not_after = match v.not_after.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => parse_date(s, true)?,
        None => {
            let days = v.days.unwrap_or(default_days);
            if days == 0 || days > 36500 {
                return Err(Error::validation("days_invalid"));
            }
            not_before + Duration::days(days as i64)
        }
    };
    if not_after <= not_before {
        return Err(Error::validation("validity_invalid"));
    }
    if let Some(limit) = issuer_not_after {
        if limit <= now {
            return Err(Error::validation("issuer_expired"));
        }
        if not_before >= limit {
            return Err(Error::validation("validity_after_issuer"));
        }
        if not_after > limit {
            warnings.push(Warning::with(
                WARN_VALIDITY_CLIPPED,
                "not_after",
                inspect::to_rfc3339(limit),
            ));
            not_after = limit;
        }
    }
    Ok((not_before, not_after))
}

fn parse_date(s: &str, end_of_day: bool) -> Result<DateTime<Utc>> {
    if let Ok(d) = inspect::parse_rfc3339(s) {
        return Ok(d);
    }
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| Error::validation("validity_invalid"))?;
    let t = if end_of_day {
        date.and_hms_opt(23, 59, 59)
    } else {
        date.and_hms_opt(0, 0, 0)
    };
    Ok(t.expect("valid time").and_utc())
}

/// OpenSSL `-not_before`/`-not_after` argument format.
pub(crate) fn openssl_time(d: DateTime<Utc>) -> String {
    d.format("%Y%m%d%H%M%SZ").to_string()
}

pub(crate) fn path_str(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| Error::Internal("non UTF-8 temporary path".into()))
}

pub(crate) fn import_error(e: OpenSslError, code: &'static str) -> Error {
    match e {
        OpenSslError::Failed { .. } => Error::validation(code),
        other => other.into(),
    }
}
