//! Revocation and CRLs. CRLs are signed by `openssl ca -gencrl` from an
//! `index.txt` rebuilt from the database for each generation.

use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;

use super::{path_str, Pki};
use crate::db::CrlRow;
use crate::error::{Error, Result};
use crate::inspect;

/// Reason codes accepted by OpenSSL's `ca` index (RFC 5280 CRLReason).
pub const REVOCATION_REASONS: &[&str] = &[
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "privilegeWithdrawn",
    "AACompromise",
];

#[derive(Debug, Serialize)]
pub struct CrlView {
    pub row: CrlRow,
    pub issuer_name: String,
    pub text: String,
}

/// ASN.1 time as written in an OpenSSL `index.txt`.
fn index_time(d: DateTime<Utc>) -> String {
    if d.year() < 2050 {
        d.format("%y%m%d%H%M%SZ").to_string()
    } else {
        d.format("%Y%m%d%H%M%SZ").to_string()
    }
}

/// Escapes a value for an OpenSSL configuration file, where `\` starts an
/// escape, `$` a variable, `#` a comment and quotes are stripped. Windows
/// paths (`C:\Users\...\Temp`) would otherwise be mangled.
pub(crate) fn conf_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        if matches!(c, '\\' | '$' | '#' | '"' | '\'') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl Pki {
    pub fn revoke_certificate(&self, id: i64, reason: &str) -> Result<()> {
        let s = self.session()?;
        if !REVOCATION_REASONS.contains(&reason) {
            return Err(Error::validation("revocation_reason_invalid"));
        }
        let cert = s.db.get_cert(id)?;
        if cert.issuer_id.is_none() {
            return Err(Error::validation("revoke_no_issuer"));
        }
        if cert.revoked_at.is_some() {
            return Err(Error::validation("already_revoked"));
        }
        let now = inspect::to_rfc3339(Utc::now());
        s.db.set_revocation(id, Some((&now, reason)))
    }

    pub fn unrevoke_certificate(&self, id: i64) -> Result<()> {
        self.session()?.db.set_revocation(id, None)
    }

    pub fn list_crls(&self) -> Result<Vec<CrlRow>> {
        self.session()?.db.list_crls()
    }

    pub fn delete_crl(&self, id: i64) -> Result<()> {
        self.session()?.db.delete_crl(id)
    }

    /// Generates and stores a new CRL for `issuer_id`, valid for `days`.
    pub fn generate_crl(&self, issuer_id: i64, days: u32) -> Result<i64> {
        let s = self.session()?;
        if days == 0 || days > 3650 {
            return Err(Error::validation("days_invalid"));
        }
        let ca = s.db.get_cert(issuer_id)?;
        if !ca.is_ca {
            return Err(Error::validation("issuer_not_ca"));
        }
        let key_id = ca.key_id.ok_or_else(|| Error::validation("issuer_no_private"))?;
        let (key, _) = self.key_with_algorithm(s, key_id)?;
        let private = key
            .private_pem_enc
            .as_deref()
            .ok_or_else(|| Error::validation("issuer_no_private"))?;
        let work = self.workdir()?;
        let ca_path = work.write("ca.pem", &ca.pem)?;
        let info = inspect::cert_info(self.openssl(), path_str(&ca_path)?)?;
        if !info.key_usage.as_deref().unwrap_or_default().contains("CRL Sign") {
            return Err(Error::validation("issuer_no_crlsign"));
        }

        let revoked = s.db.revocation_entries(issuer_id)?;
        let mut index = String::new();
        for c in &revoked {
            let expiry = inspect::parse_rfc3339(&c.not_after)?;
            let at = inspect::parse_rfc3339(&c.revoked_at)?;
            let mut serial = c.serial.to_ascii_uppercase();
            if serial.len() % 2 == 1 {
                serial.insert(0, '0');
            }
            index.push_str(&format!(
                "R\t{}\t{},{}\t{}\tunknown\t/CN=revoked\n",
                index_time(expiry),
                index_time(at),
                c.reason,
                serial
            ));
        }
        let number = s.db.next_crl_number(issuer_id)?;
        let mut number_hex = format!("{number:X}");
        if number_hex.len() % 2 == 1 {
            number_hex.insert(0, '0');
        }
        let index_path = work.write("index.txt", &index)?;
        let number_path = work.write("crlnumber", &format!("{number_hex}\n"))?;
        let cnf = work.write(
            "ca.cnf",
            &format!(
                "[ca]\ndefault_ca = lab\n\n[lab]\ndatabase = {}\ncrlnumber = {}\ndefault_md = default\n\
                 crl_extensions = crl_ext\n\n[crl_ext]\nauthorityKeyIdentifier = keyid:always\n",
                conf_value(path_str(&index_path)?),
                conf_value(path_str(&number_path)?)
            ),
        )?;
        let key_path = work.write("ca.key", private)?;
        let days_s = days.to_string();
        let pem = self
            .openssl()
            .run(
                &[
                    "ca",
                    "-gencrl",
                    "-config",
                    path_str(&cnf)?,
                    "-cert",
                    path_str(&ca_path)?,
                    "-keyfile",
                    path_str(&key_path)?,
                    "-passin",
                    "stdin",
                    "-crldays",
                    &days_s,
                ],
                Some(&s.password.stdin_line()),
            )?
            .stdout_text();
        let crl_path = work.write("new.crl", &pem)?;
        // Independent check of the signature before storing it.
        self.openssl().run(
            &[
                "crl",
                "-in",
                path_str(&crl_path)?,
                "-CAfile",
                path_str(&ca_path)?,
                "-noout",
                "-verify",
            ],
            None,
        )?;
        let dates = self
            .openssl()
            .run(
                &[
                    "crl",
                    "-in",
                    path_str(&crl_path)?,
                    "-noout",
                    "-lastupdate",
                    "-nextupdate",
                    "-dateopt",
                    "iso_8601",
                ],
                None,
            )?
            .stdout_text();
        let get = |prefix: &str| -> Result<String> {
            let v = dates
                .lines()
                .find_map(|l| l.trim().strip_prefix(prefix))
                .ok_or_else(|| Error::Internal(format!("missing {prefix}")))?;
            Ok(inspect::to_rfc3339(inspect::parse_openssl_date(v)?))
        };
        s.db.insert_crl(
            issuer_id,
            number,
            &get("lastUpdate=")?,
            &get("nextUpdate=")?,
            revoked.len() as i64,
            &pem,
        )
    }

    pub fn view_crl(&self, id: i64) -> Result<CrlView> {
        let s = self.session()?;
        let row = s.db.get_crl(id)?;
        let issuer_name = s.db.get_cert(row.issuer_id)?.name;
        let work = self.workdir()?;
        let p = work.write("view.crl", &row.pem)?;
        let text = self
            .openssl()
            .run(
                &[
                    "crl",
                    "-in",
                    path_str(&p)?,
                    "-noout",
                    "-text",
                    "-nameopt",
                    inspect::NAMEOPT,
                ],
                None,
            )?
            .stdout_text();
        Ok(CrlView {
            row,
            issuer_name,
            text,
        })
    }

    pub fn export_crl(&self, id: i64, der: bool) -> Result<Vec<u8>> {
        let s = self.session()?;
        let row = s.db.get_crl(id)?;
        if !der {
            return Ok(row.pem.into_bytes());
        }
        let work = self.workdir()?;
        let p = work.write("export.crl", &row.pem)?;
        Ok(self
            .openssl()
            .run(&["crl", "-in", path_str(&p)?, "-outform", "DER"], None)?
            .stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::conf_value;

    #[test]
    fn conf_value_escapes_config_syntax() {
        assert_eq!(
            conf_value(r"C:\Users\me\AppData\Local\Temp\pqlab-x\index.txt"),
            r"C:\\Users\\me\\AppData\\Local\\Temp\\pqlab-x\\index.txt"
        );
        assert_eq!(conf_value("/tmp/a $b #c 'd\""), r#"/tmp/a \$b \#c \'d\""#);
        assert_eq!(conf_value("/plain/path with spaces"), "/plain/path with spaces");
    }
}
