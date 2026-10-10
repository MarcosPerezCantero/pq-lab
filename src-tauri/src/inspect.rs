//! Parsing of OpenSSL's text output into structured summaries.

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Serialize;

use crate::algorithms::Algorithm;
use crate::error::{Error, Result};
use crate::openssl::OpenSsl;

/// `-nameopt` used everywhere: RFC 2253 order with raw UTF-8.
pub const NAMEOPT: &str = "RFC2253,-esc_msb";

#[derive(Clone, Debug, Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub sig_algorithm: String,
    pub key_algorithm: String,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub sans: Vec<String>,
    pub key_usage: Option<String>,
    pub ext_key_usage: Option<String>,
    pub self_signed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsrInfo {
    pub subject: String,
    pub key_algorithm: String,
    pub sig_algorithm: String,
    pub sans: Vec<String>,
}

/// True for ML-DSA / SLH-DSA signature algorithm names.
pub fn is_pq_signature(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.starts_with("ML-DSA") || n.starts_with("SLH-DSA")
}

/// Converts OpenSSL's `-dateopt iso_8601` output ("2036-10-08 12:00:00Z") to RFC 3339.
pub fn parse_openssl_date(s: &str) -> Result<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%SZ")
        .map(|d| d.and_utc())
        .map_err(|_| Error::Internal(format!("unexpected date format: {s}")))
}

pub fn to_rfc3339(d: DateTime<Utc>) -> String {
    d.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn parse_rfc3339(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| Error::Internal(format!("unexpected date: {s}")))
}

fn field<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(prefix))
        .map(str::trim)
}

/// Value on the line following a header such as "X509v3 Key Usage: critical".
fn ext_value(text: &str, header: &str) -> Option<String> {
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l.trim().starts_with(header) {
            return lines.next().map(|v| v.trim().to_string());
        }
    }
    None
}

fn parse_sans(text: &str) -> Vec<String> {
    ext_value(text, "X509v3 Subject Alternative Name")
        .map(|v| {
            v.split(", ")
                .map(|e| {
                    e.trim_start_matches("DNS:")
                        .trim_start_matches("IP Address:")
                        .trim_start_matches("email:")
                        .trim_start_matches("URI:")
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Algorithm id when recognised, otherwise OpenSSL's own name.
fn key_algorithm(text: &str) -> String {
    Algorithm::detect_from_key_text(text)
        .map(|a| a.id().to_string())
        .or_else(|| field(text, "Public Key Algorithm:").map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

pub fn cert_text(openssl: &OpenSsl, pem_path: &str) -> Result<String> {
    Ok(openssl
        .run(
            &["x509", "-in", pem_path, "-noout", "-text", "-nameopt", NAMEOPT],
            None,
        )?
        .stdout_text())
}

pub fn cert_info(openssl: &OpenSsl, pem_path: &str) -> Result<CertInfo> {
    let fields = openssl
        .run(
            &[
                "x509",
                "-in",
                pem_path,
                "-noout",
                "-subject",
                "-issuer",
                "-serial",
                "-startdate",
                "-enddate",
                "-fingerprint",
                "-sha256",
                "-nameopt",
                NAMEOPT,
                "-dateopt",
                "iso_8601",
            ],
            None,
        )?
        .stdout_text();
    let text = cert_text(openssl, pem_path)?;
    let get = |p: &str| {
        field(&fields, p)
            .map(str::to_string)
            .ok_or_else(|| Error::Internal(format!("missing {p}")))
    };
    let subject = get("subject=")?;
    let issuer = get("issuer=")?;
    let basic = ext_value(&text, "X509v3 Basic Constraints").unwrap_or_default();
    let path_len = basic
        .split(',')
        .find_map(|p| p.trim().strip_prefix("pathlen:"))
        .and_then(|n| n.parse().ok());
    Ok(CertInfo {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: get("serial=")?,
        not_before: to_rfc3339(parse_openssl_date(&get("notBefore=")?)?),
        not_after: to_rfc3339(parse_openssl_date(&get("notAfter=")?)?),
        fingerprint_sha256: fields
            .lines()
            .find_map(|l| l.split_once("Fingerprint=").map(|(_, v)| v.trim().to_string()))
            .ok_or_else(|| Error::Internal("missing fingerprint".into()))?,
        sig_algorithm: field(&text, "Signature Algorithm:")
            .unwrap_or("unknown")
            .to_string(),
        key_algorithm: key_algorithm(&text),
        is_ca: basic.contains("CA:TRUE"),
        path_len,
        sans: parse_sans(&text),
        key_usage: ext_value(&text, "X509v3 Key Usage"),
        ext_key_usage: ext_value(&text, "X509v3 Extended Key Usage"),
    })
}

pub fn csr_text(openssl: &OpenSsl, pem_path: &str) -> Result<String> {
    Ok(openssl
        .run(
            &["req", "-in", pem_path, "-noout", "-text", "-nameopt", NAMEOPT],
            None,
        )?
        .stdout_text())
}

pub fn csr_info(openssl: &OpenSsl, pem_path: &str) -> Result<CsrInfo> {
    let subject = openssl
        .run(
            &["req", "-in", pem_path, "-noout", "-subject", "-nameopt", NAMEOPT],
            None,
        )?
        .stdout_text();
    let text = csr_text(openssl, pem_path)?;
    Ok(CsrInfo {
        subject: field(&subject, "subject=").unwrap_or_default().to_string(),
        key_algorithm: key_algorithm(&text),
        sig_algorithm: field(&text, "Signature Algorithm:")
            .unwrap_or("unknown")
            .to_string(),
        sans: parse_sans(&text),
    })
}

/// Algorithm of a public key PEM file.
pub fn public_key_algorithm(openssl: &OpenSsl, pub_path: &str) -> Result<Option<Algorithm>> {
    let text = openssl
        .run(&["pkey", "-pubin", "-in", pub_path, "-noout", "-text"], None)?
        .stdout_text();
    Ok(Algorithm::detect_from_key_text(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        let d = parse_openssl_date("2036-10-08 12:00:01Z").unwrap();
        assert_eq!(to_rfc3339(d), "2036-10-08T12:00:01Z");
        assert_eq!(parse_rfc3339("2036-10-08T12:00:01Z").unwrap(), d);
    }

    #[test]
    fn sans_from_text() {
        let t = "            X509v3 Subject Alternative Name: \n                DNS:a.lab, IP Address:10.0.0.1, email:x@y.lab\n";
        assert_eq!(parse_sans(t), vec!["a.lab", "10.0.0.1", "x@y.lab"]);
    }
}
