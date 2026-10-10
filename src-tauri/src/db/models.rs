use serde::Serialize;

use crate::profile::CertProfile;

#[derive(Clone, Debug, Serialize)]
pub struct KeyRow {
    pub id: i64,
    pub name: String,
    pub algorithm: String,
    pub public_pem: String,
    /// Never serialized to the frontend.
    #[serde(skip)]
    pub private_pem_enc: Option<String>,
    pub has_private: bool,
    pub created_at: String,
    /// Number of certificates referencing this key.
    pub cert_count: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertRow {
    pub id: i64,
    pub name: String,
    pub key_id: Option<i64>,
    pub issuer_id: Option<i64>,
    pub template: String,
    pub is_ca: bool,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub sig_algorithm: String,
    pub key_algorithm: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub pem: String,
    pub created_at: String,
    /// Profile the certificate was issued with (None for imported ones).
    pub profile: Option<CertProfile>,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
}

/// Values for inserting a certificate.
pub struct NewCert {
    pub name: String,
    pub key_id: Option<i64>,
    pub issuer_id: Option<i64>,
    pub template: String,
    pub is_ca: bool,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub sig_algorithm: String,
    pub key_algorithm: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub pem: String,
    pub profile: Option<CertProfile>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsrRow {
    pub id: i64,
    pub name: String,
    pub key_id: Option<i64>,
    pub subject: String,
    pub key_algorithm: String,
    pub pem: String,
    pub signed_cert_id: Option<i64>,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TemplateRow {
    pub id: i64,
    pub name: String,
    pub profile: CertProfile,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CrlRow {
    pub id: i64,
    pub issuer_id: i64,
    pub number: i64,
    pub this_update: String,
    pub next_update: String,
    pub revoked_count: i64,
    pub pem: String,
    pub created_at: String,
}

/// One entry of a CA's CRL: a revoked certificate that may since have been
/// deleted from the database.
#[derive(Clone, Debug)]
pub struct RevocationEntry {
    pub serial: String,
    pub not_after: String,
    pub revoked_at: String,
    pub reason: String,
}
