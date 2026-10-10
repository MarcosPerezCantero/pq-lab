//! Tauri commands exposed to the frontend. Thin wrappers over `Pki`.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

use crate::algorithms::{self, Algorithm, AlgorithmInfo};
use crate::db::{CertRow, CrlRow, CsrRow, KeyRow};
use crate::error::{Error, ErrorPayload, Result};
use crate::openssl::OpenSsl;
use crate::pki::{
    CertFormat, CertView, CrlView, CsrRequest, CsrView, IssueRequest, Issued, Pkcs12Import, Pki,
    SignCsrRequest, Templates, Validity, VerifyResult, REVOCATION_REASONS,
};
use crate::profile::{CertProfile, KNOWN_EKUS};
use crate::security::Secret;

pub struct AppState {
    pki: Option<Pki>,
    openssl_version: std::result::Result<String, ErrorPayload>,
    default_db_path: PathBuf,
    log_path: PathBuf,
}

impl AppState {
    pub fn new(data_dir: PathBuf) -> Self {
        let log_path = data_dir.join("pqlab.log");
        let located = OpenSsl::locate()
            .map(|o| o.with_log(log_path.clone()))
            .map_err(Error::from)
            .and_then(|o| o.check_version().map(|v| (o, v)).map_err(Error::from));
        let (pki, openssl_version) = match located {
            Ok((o, v)) => (Some(Pki::new(o, std::env::temp_dir())), Ok(v)),
            Err(e) => (None, Err(ErrorPayload::from(&e))),
        };
        Self {
            pki,
            openssl_version,
            default_db_path: data_dir.join("pqlab.db"),
            log_path,
        }
    }

    fn pki(&mut self) -> Result<&mut Pki> {
        self.pki
            .as_mut()
            .ok_or(Error::OpenSsl(crate::openssl::OpenSslError::NotFound))
    }
}

type AppMutex<'a> = State<'a, Mutex<AppState>>;

fn with<T>(state: &AppMutex, f: impl FnOnce(&mut Pki) -> Result<T>) -> Result<T> {
    let mut guard = state
        .lock()
        .map_err(|_| Error::Internal("state poisoned".into()))?;
    f(guard.pki()?)
}

#[derive(Serialize)]
pub struct Status {
    openssl_version: Option<String>,
    openssl_error: Option<ErrorPayload>,
    openssl_path: Option<String>,
    default_db_path: String,
    default_db_exists: bool,
    unlocked: bool,
    db_path: Option<String>,
    log_path: String,
}

#[tauri::command]
pub fn app_status(state: AppMutex) -> Status {
    let st = state.lock().expect("state poisoned");
    let (openssl_version, openssl_error) = match &st.openssl_version {
        Ok(v) => (Some(v.clone()), None),
        Err(e) => (
            None,
            Some(ErrorPayload {
                code: e.code,
                params: e.params.clone(),
                detail: e.detail.clone(),
            }),
        ),
    };
    Status {
        openssl_version,
        openssl_error,
        openssl_path: st.pki.as_ref().map(|p| p.openssl().path().display().to_string()),
        default_db_path: st.default_db_path.display().to_string(),
        default_db_exists: st.default_db_path.is_file(),
        unlocked: st.pki.as_ref().and_then(|p| p.db_path()).is_some(),
        db_path: st
            .pki
            .as_ref()
            .and_then(|p| p.db_path())
            .map(|p| p.display().to_string()),
        log_path: st.log_path.display().to_string(),
    }
}

#[derive(Serialize)]
pub struct Catalog {
    algorithms: Vec<AlgorithmInfo>,
    ext_key_usages: &'static [&'static str],
    revocation_reasons: &'static [&'static str],
}

#[tauri::command]
pub fn catalog() -> Catalog {
    Catalog {
        algorithms: algorithms::catalog(),
        ext_key_usages: KNOWN_EKUS,
        revocation_reasons: REVOCATION_REASONS,
    }
}

#[tauri::command(async)]
pub fn create_database(state: AppMutex, path: String, password: String) -> Result<()> {
    with(&state, |p| {
        p.create_database(&PathBuf::from(path), Secret::new(password))
    })
}

#[tauri::command(async)]
pub fn open_database(state: AppMutex, path: String, password: String) -> Result<()> {
    with(&state, |p| {
        p.open_database(&PathBuf::from(path), Secret::new(password))
    })
}

#[tauri::command]
pub fn lock_database(state: AppMutex) -> Result<()> {
    with(&state, |p| {
        p.lock();
        Ok(())
    })
}

// ---- keys -------------------------------------------------------------------

#[tauri::command]
pub fn list_keys(state: AppMutex) -> Result<Vec<KeyRow>> {
    with(&state, |p| p.list_keys())
}

#[tauri::command(async)]
pub fn generate_key(state: AppMutex, name: String, algorithm: Algorithm) -> Result<i64> {
    with(&state, |p| p.generate_key(&name, algorithm))
}

#[tauri::command(async)]
pub fn import_key(state: AppMutex, name: String, pem: String, password: Option<String>) -> Result<i64> {
    with(&state, |p| p.import_key(&name, &pem, password.map(Secret::new)))
}

#[tauri::command]
pub fn rename_key(state: AppMutex, id: i64, name: String) -> Result<()> {
    with(&state, |p| p.rename_key(id, &name))
}

#[tauri::command]
pub fn delete_key(state: AppMutex, id: i64) -> Result<()> {
    with(&state, |p| p.delete_key(id))
}

#[tauri::command(async)]
pub fn export_public_key(state: AppMutex, id: i64, path: String) -> Result<()> {
    let pem = with(&state, |p| p.export_public_key(id))?;
    write_file(&path, pem.as_bytes())
}

#[tauri::command(async)]
pub fn export_private_key(state: AppMutex, id: i64, path: String, password: String) -> Result<()> {
    let pem = with(&state, |p| p.export_private_key(id, &Secret::new(password)))?;
    write_file(&path, pem.as_bytes())
}

// ---- certificates -------------------------------------------------------------

#[tauri::command]
pub fn list_certificates(state: AppMutex) -> Result<Vec<CertRow>> {
    with(&state, |p| p.list_certs())
}

#[tauri::command(async)]
pub fn issue_certificate(state: AppMutex, req: IssueRequest) -> Result<Issued> {
    with(&state, |p| p.issue_certificate(&req))
}

#[tauri::command(async)]
pub fn renew_certificate(state: AppMutex, id: i64, validity: Validity) -> Result<Issued> {
    with(&state, |p| p.renew_certificate(id, &validity))
}

#[tauri::command]
pub fn revoke_certificate(state: AppMutex, id: i64, reason: String) -> Result<()> {
    with(&state, |p| p.revoke_certificate(id, &reason))
}

#[tauri::command]
pub fn unrevoke_certificate(state: AppMutex, id: i64) -> Result<()> {
    with(&state, |p| p.unrevoke_certificate(id))
}

#[tauri::command(async)]
pub fn export_pkcs12(state: AppMutex, id: i64, path: String, password: String, chain: bool) -> Result<()> {
    let bytes = with(&state, |p| p.export_pkcs12(id, &Secret::new(password), chain))?;
    write_file(&path, &bytes)
}

#[tauri::command(async)]
pub fn import_pkcs12(state: AppMutex, name: String, path: String, password: String) -> Result<Pkcs12Import> {
    let meta = std::fs::metadata(&path)?;
    if meta.len() > 1024 * 1024 {
        return Err(Error::validation("file_too_large"));
    }
    let data = std::fs::read(&path)?;
    with(&state, |p| p.import_pkcs12(&name, &data, &Secret::new(password)))
}

// ---- templates ------------------------------------------------------------------

#[tauri::command]
pub fn list_templates(state: AppMutex) -> Result<Templates> {
    with(&state, |p| p.list_templates())
}

#[tauri::command]
pub fn save_template(state: AppMutex, id: Option<i64>, name: String, profile: CertProfile) -> Result<i64> {
    with(&state, |p| p.save_template(id, &name, &profile))
}

#[tauri::command]
pub fn delete_template(state: AppMutex, id: i64) -> Result<()> {
    with(&state, |p| p.delete_template(id))
}

// ---- CRLs -----------------------------------------------------------------------

#[tauri::command]
pub fn list_crls(state: AppMutex) -> Result<Vec<CrlRow>> {
    with(&state, |p| p.list_crls())
}

#[tauri::command(async)]
pub fn generate_crl(state: AppMutex, issuer_id: i64, days: u32) -> Result<i64> {
    with(&state, |p| p.generate_crl(issuer_id, days))
}

#[tauri::command(async)]
pub fn view_crl(state: AppMutex, id: i64) -> Result<CrlView> {
    with(&state, |p| p.view_crl(id))
}

#[tauri::command(async)]
pub fn export_crl(state: AppMutex, id: i64, format: CertFormat, path: String) -> Result<()> {
    let bytes = with(&state, |p| p.export_crl(id, format == CertFormat::Der))?;
    write_file(&path, &bytes)
}

#[tauri::command]
pub fn delete_crl(state: AppMutex, id: i64) -> Result<()> {
    with(&state, |p| p.delete_crl(id))
}

#[tauri::command(async)]
pub fn import_certificate(state: AppMutex, name: String, pem: String) -> Result<Issued> {
    with(&state, |p| p.import_certificate(&name, &pem))
}

#[tauri::command]
pub fn delete_certificate(state: AppMutex, id: i64) -> Result<()> {
    with(&state, |p| p.delete_cert(id))
}

#[tauri::command(async)]
pub fn view_certificate(state: AppMutex, id: i64) -> Result<CertView> {
    with(&state, |p| p.view_certificate(id))
}

#[tauri::command(async)]
pub fn verify_chain(state: AppMutex, id: i64) -> Result<VerifyResult> {
    with(&state, |p| p.verify_chain(id))
}

#[tauri::command(async)]
pub fn export_certificate(state: AppMutex, id: i64, format: CertFormat, path: String) -> Result<()> {
    let bytes = with(&state, |p| p.export_certificate(id, format))?;
    write_file(&path, &bytes)
}

#[tauri::command(async)]
pub fn export_chain(state: AppMutex, id: i64, path: String) -> Result<()> {
    let pem = with(&state, |p| p.export_chain(id))?;
    write_file(&path, pem.as_bytes())
}

// ---- CSRs ---------------------------------------------------------------------

#[tauri::command]
pub fn list_csrs(state: AppMutex) -> Result<Vec<CsrRow>> {
    with(&state, |p| p.list_csrs())
}

#[tauri::command(async)]
pub fn generate_csr(state: AppMutex, req: CsrRequest) -> Result<i64> {
    with(&state, |p| p.generate_csr(&req))
}

#[tauri::command(async)]
pub fn import_csr(state: AppMutex, name: String, pem: String) -> Result<i64> {
    with(&state, |p| p.import_csr(&name, &pem))
}

#[tauri::command(async)]
pub fn sign_csr(state: AppMutex, req: SignCsrRequest) -> Result<Issued> {
    with(&state, |p| p.sign_csr(&req))
}

#[tauri::command]
pub fn delete_csr(state: AppMutex, id: i64) -> Result<()> {
    with(&state, |p| p.delete_csr(id))
}

#[tauri::command(async)]
pub fn view_csr(state: AppMutex, id: i64) -> Result<CsrView> {
    with(&state, |p| p.view_csr(id))
}

#[tauri::command(async)]
pub fn export_csr(state: AppMutex, id: i64, path: String) -> Result<()> {
    let pem = with(&state, |p| p.export_csr(id))?;
    write_file(&path, pem.as_bytes())
}

// ---- files ----------------------------------------------------------------------

/// Reads a PEM file chosen by the user in an open dialog (max 1 MiB).
#[tauri::command(async)]
pub fn read_pem_file(path: String) -> Result<String> {
    let meta = std::fs::metadata(&path)?;
    if meta.len() > 1024 * 1024 {
        return Err(Error::validation("file_too_large"));
    }
    let bytes = std::fs::read(&path)?;
    String::from_utf8(bytes).map_err(|_| Error::validation("file_not_pem"))
}

fn write_file(path: &str, bytes: &[u8]) -> Result<()> {
    if path.trim().is_empty() {
        return Err(Error::validation("path_required"));
    }
    std::fs::write(path, bytes)?;
    Ok(())
}
