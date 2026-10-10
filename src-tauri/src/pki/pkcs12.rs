//! PKCS#12 export and import. The private key never appears in clear: on
//! export openssl reads the master-encrypted key and writes the container
//! encrypted with the export password; on import it decrypts the container
//! and re-encrypts the key with the master password in a single process.

use serde::Serialize;

use super::{path_str, Pki};
use crate::error::{Error, Result};
use crate::inspect;
use crate::openssl::OpenSslError;
use crate::security::{self, Secret};
use crate::validation;

#[derive(Debug, Serialize)]
pub struct Pkcs12Import {
    pub key_id: Option<i64>,
    /// Certificates added to the database (already present ones are skipped).
    pub cert_ids: Vec<i64>,
}

impl Pki {
    /// PKCS#12 with the certificate, its private key and optionally its chain,
    /// protected with `password`.
    pub fn export_pkcs12(&self, cert_id: i64, password: &Secret, include_chain: bool) -> Result<Vec<u8>> {
        security::validate_password(password.expose())?;
        let s = self.session()?;
        let cert = s.db.get_cert(cert_id)?;
        let key_id = cert.key_id.ok_or_else(|| Error::validation("key_no_private"))?;
        let key = s.db.get_key(key_id)?;
        let private = key
            .private_pem_enc
            .as_deref()
            .ok_or_else(|| Error::validation("key_no_private"))?;
        let work = self.workdir()?;
        let key_path = work.write("p12.key", private)?;
        let cert_path = work.write("p12.pem", &cert.pem)?;
        let mut args = vec![
            "pkcs12".to_string(),
            "-export".into(),
            "-inkey".into(),
            path_str(&key_path)?.into(),
            "-in".into(),
            path_str(&cert_path)?.into(),
            "-name".into(),
            cert.name.clone(),
            "-passin".into(),
            "stdin".into(),
            "-passout".into(),
            "stdin".into(),
        ];
        if include_chain {
            let chain: String = self
                .chain_rows(s, &cert)?
                .iter()
                .skip(1)
                .map(|c| c.pem.as_str())
                .collect();
            if !chain.is_empty() {
                let p = work.write("chain.pem", &chain)?;
                args.push("-certfile".into());
                args.push(path_str(&p)?.into());
            }
        }
        let mut input = s.password.stdin_line();
        input.extend_from_slice(&password.stdin_line());
        Ok(self.openssl().run(&args, Some(&input))?.stdout)
    }

    /// Imports the key and certificates of a PKCS#12 container.
    pub fn import_pkcs12(&self, name: &str, data: &[u8], password: &Secret) -> Result<Pkcs12Import> {
        let name = validation::validate_name(name)?;
        let s = self.session()?;
        let work = self.workdir()?;
        // The container is encrypted, so it may sit in the private work dir.
        let p12 = work.path().join("in.p12");
        std::fs::write(&p12, data)?;
        let mut input = password.stdin_line();
        input.extend_from_slice(&s.password.stdin_line());
        let out = self
            .openssl()
            .run(
                &[
                    "pkcs12",
                    "-in",
                    path_str(&p12)?,
                    "-passin",
                    "stdin",
                    "-passout",
                    "stdin",
                ],
                Some(&input),
            )
            .map_err(|e| match e {
                OpenSslError::Failed { .. } => Error::validation("import_p12_failed"),
                other => other.into(),
            })?
            .stdout_text();
        if security::contains_plain_private_key(&out) {
            return Err(Error::Internal("unexpected clear key in pkcs12 output".into()));
        }

        let mut key_pem = None;
        let mut certs = Vec::new();
        let mut current: Option<String> = None;
        for line in out.lines() {
            if line.starts_with("-----BEGIN ") {
                current = Some(String::new());
            }
            if let Some(block) = current.as_mut() {
                block.push_str(line);
                block.push('\n');
            }
            if line.starts_with("-----END ") {
                let block = current.take().unwrap_or_default();
                if line.contains("ENCRYPTED PRIVATE KEY") {
                    key_pem = Some(block);
                } else if line.contains("CERTIFICATE") {
                    certs.push(block);
                }
            }
        }
        if key_pem.is_none() && certs.is_empty() {
            return Err(Error::validation("import_p12_failed"));
        }

        // All or nothing: a rejected certificate leaves no imported key.
        s.db.atomic(|| {
            let key_id = match &key_pem {
                Some(k) => Some(
                    match self.import_key(&format!("{name} (clave)"), k, Some(s.password.clone())) {
                        Ok(id) => id,
                        Err(Error::Validation {
                            code: "key_exists", ..
                        }) => {
                            let pubkey = self.public_from_private(s, k)?;
                            s.db.find_key_by_public(&pubkey)?
                                .map(|k| k.id)
                                .ok_or_else(|| Error::Internal("key vanished".into()))?
                        }
                        Err(e) => return Err(e),
                    },
                ),
                None => None,
            };

            // CA certificates first so the leaf links to its issuer.
            let mut infos = Vec::new();
            for pem in certs {
                let p = work.write("bag.pem", &pem)?;
                infos.push((inspect::cert_info(self.openssl(), path_str(&p)?)?, pem));
            }
            infos.sort_by_key(|(info, _)| !info.is_ca);
            let mut cert_ids = Vec::new();
            for (info, pem) in infos {
                let cert_name = if info.is_ca {
                    cn_of(&info.subject).unwrap_or_else(|| info.subject.clone())
                } else {
                    name.clone()
                };
                match self.import_certificate(&cert_name, &pem) {
                    Ok(issued) => cert_ids.push(issued.id),
                    Err(Error::Validation {
                        code: "cert_exists", ..
                    }) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(Pkcs12Import { key_id, cert_ids })
        })
    }
}

fn cn_of(dn: &str) -> Option<String> {
    dn.split(',')
        .find_map(|p| p.trim().strip_prefix("CN="))
        .map(str::to_string)
}
