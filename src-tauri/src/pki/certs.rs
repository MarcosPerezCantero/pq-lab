//! Certificates: issuance (self-signed or by a CA), CSR signing, renewal,
//! import, viewing, chain verification and export.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    import_error, openssl_time, path_str, resolve_validity, Issued, Pki, Session, Validity, Warning,
};
use crate::algorithms::Algorithm;
use crate::db::{CertRow, NewCert};
use crate::error::{Error, Result};
use crate::inspect::{self, CertInfo};
use crate::openssl::OpenSslError;
use crate::profile::{CertProfile, Usage};
use crate::security::{self, WorkDir};
use crate::validation::{self, SubjectInput, WARN_PATHLEN_CLIPPED};

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    pub name: String,
    /// Key certified by the new certificate.
    pub key_id: i64,
    /// Signing CA; `None` makes the certificate self-signed.
    pub issuer_id: Option<i64>,
    pub subject: SubjectInput,
    pub profile: CertProfile,
    #[serde(default)]
    pub validity: Validity,
    /// Label shown in the list: preset id, user template name or "custom".
    #[serde(default = "custom")]
    pub template: String,
}

#[derive(Debug, Deserialize)]
pub struct SignCsrRequest {
    pub csr_id: i64,
    pub issuer_id: i64,
    pub name: String,
    pub profile: CertProfile,
    #[serde(default)]
    pub validity: Validity,
    #[serde(default = "custom")]
    pub template: String,
}

fn custom() -> String {
    "custom".into()
}

#[derive(Debug, Serialize)]
pub struct CertView {
    pub row: CertRow,
    pub info: CertInfo,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResult {
    /// The chain verifies and no certificate in it is revoked.
    pub ok: bool,
    pub output: String,
    /// Certificate names from the leaf up to the root.
    pub chain: Vec<String>,
    pub warnings: Vec<Warning>,
    /// Whether at least one CRL was used for the check.
    pub crl_checked: bool,
    /// Whether every issuer in the chain had a CRL, so the whole chain was
    /// checked against CRLs (`-crl_check_all`).
    pub crl_complete: bool,
    /// The certificate itself is revoked in the database.
    pub revoked: bool,
    /// Names of the certificates in the chain (leaf included) that are
    /// revoked in the database, whether or not a CRL says so yet.
    pub revoked_chain: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CertFormat {
    Pem,
    Der,
}

/// How the subject public key reaches `openssl`.
enum Source<'a> {
    /// A CSR (own or external); the subject comes from the CSR.
    Csr(&'a Path),
    /// A bare public key (ML-KEM), with an explicit subject.
    PublicKey { pub_path: &'a Path, subj: String },
    /// An existing certificate re-signed on renewal (subject and key kept).
    Certificate(&'a Path),
}

struct Spec<'a> {
    name: String,
    key_id: Option<i64>,
    key_alg: Option<Algorithm>,
    template: String,
    profile: &'a CertProfile,
    validity: &'a Validity,
}

impl Pki {
    pub fn list_certs(&self) -> Result<Vec<CertRow>> {
        self.session()?.db.list_certs()
    }

    pub fn delete_cert(&mut self, id: i64) -> Result<()> {
        self.session_mut()?.db.delete_cert(id)
    }

    /// Issues a certificate for one of our keys, self-signed or by a CA.
    pub fn issue_certificate(&self, req: &IssueRequest) -> Result<Issued> {
        let s = self.session()?;
        let name = validation::validate_name(&req.name)?;
        let template = validation::validate_name(&req.template)?;
        let (key, alg) = self.key_with_algorithm(s, req.key_id)?;
        let valid = req.profile.validate(Usage {
            key: Some(alg),
            self_signed: req.issuer_id.is_none(),
            template: false,
        })?;
        let work = self.workdir()?;
        let spec = Spec {
            name,
            key_id: Some(key.id),
            key_alg: Some(alg),
            template,
            profile: &req.profile,
            validity: &req.validity,
        };
        match req.issuer_id {
            None => {
                let private = key
                    .private_pem_enc
                    .as_deref()
                    .ok_or_else(|| Error::validation("key_no_private"))?;
                let mut warnings = Vec::new();
                let (nb, na) =
                    resolve_validity(&req.validity, default_days(&req.profile), None, &mut warnings)?;
                let key_path = work.write("self.key", private)?;
                let cnf = work.write("ext.cnf", &valid.render("ext"))?;
                let subj = req.subject.to_openssl(false)?;
                let serial = security::random_serial();
                let (nb, na) = (openssl_time(nb), openssl_time(na));
                let args = [
                    "req",
                    "-x509",
                    "-new",
                    "-utf8",
                    "-key",
                    path_str(&key_path)?,
                    "-passin",
                    "stdin",
                    "-subj",
                    &subj,
                    "-set_serial",
                    &serial,
                    "-not_before",
                    &nb,
                    "-not_after",
                    &na,
                    "-config",
                    path_str(&cnf)?,
                    "-extensions",
                    "ext",
                ];
                let pem = self
                    .openssl
                    .run(&args, Some(&s.password.stdin_line()))?
                    .stdout_text();
                self.store_cert(s, &work, &spec, None, &pem, warnings)
            }
            Some(issuer_id) => {
                if !alg.can_sign() {
                    let subj = req.subject.to_openssl(true)?;
                    let pub_path = work.write("kem_pub.pem", &key.public_pem)?;
                    self.issue(
                        s,
                        &work,
                        spec,
                        issuer_id,
                        Source::PublicKey {
                            pub_path: &pub_path,
                            subj,
                        },
                    )
                } else {
                    let private = key
                        .private_pem_enc
                        .as_deref()
                        .ok_or_else(|| Error::validation("key_no_private"))?;
                    let csr = self.make_csr(s, &work, private, &req.subject.to_openssl(false)?, None)?;
                    let csr_path = work.write("req.csr", &csr)?;
                    self.issue(s, &work, spec, issuer_id, Source::Csr(&csr_path))
                }
            }
        }
    }

    /// Signs a stored CSR with a CA. Extensions come from the profile; the
    /// CSR's requested extensions are not copied.
    pub fn sign_csr(&self, req: &SignCsrRequest) -> Result<Issued> {
        let s = self.session()?;
        let name = validation::validate_name(&req.name)?;
        let template = validation::validate_name(&req.template)?;
        let csr = s.db.get_csr(req.csr_id)?;
        let key_alg = Algorithm::from_id(&csr.key_algorithm)
            .ok_or_else(|| Error::validation("algorithm_unsupported"))?;
        req.profile.validate(Usage {
            key: Some(key_alg),
            self_signed: false,
            template: false,
        })?;
        let work = self.workdir()?;
        let p = work.write("sign.csr", &csr.pem)?;
        self.verify_csr_signature(&p)?;
        let issued = self.issue(
            s,
            &work,
            Spec {
                name,
                key_id: csr.key_id,
                key_alg: Some(key_alg),
                template,
                profile: &req.profile,
                validity: &req.validity,
            },
            req.issuer_id,
            Source::Csr(&p),
        )?;
        s.db.set_csr_signed(csr.id, issued.id)?;
        Ok(issued)
    }

    /// Re-issues a certificate with a new serial and validity, keeping its
    /// subject, key, issuer and extensions.
    pub fn renew_certificate(&self, id: i64, validity: &Validity) -> Result<Issued> {
        let s = self.session()?;
        let old = s.db.get_cert(id)?;
        let profile = old
            .profile
            .clone()
            .ok_or_else(|| Error::validation("renew_no_profile"))?;
        let key_alg = Algorithm::from_id(&old.key_algorithm);
        let valid = profile.validate(Usage {
            key: key_alg,
            self_signed: old.issuer_id.is_none(),
            template: false,
        })?;
        let mut validity = validity.clone();
        if validity.days.is_none() && validity.not_after.is_none() {
            let span = inspect::parse_rfc3339(&old.not_after)? - inspect::parse_rfc3339(&old.not_before)?;
            validity.days = Some(span.num_days().max(1) as u32);
        }
        let work = self.workdir()?;
        let old_path = work.write("old.pem", &old.pem)?;
        let spec = Spec {
            name: old.name.clone(),
            key_id: old.key_id,
            key_alg,
            template: old.template.clone(),
            profile: &profile,
            validity: &validity,
        };
        match old.issuer_id {
            Some(issuer_id) => self.issue(s, &work, spec, issuer_id, Source::Certificate(&old_path)),
            None => {
                if old.subject != old.issuer {
                    return Err(Error::validation("issuer_not_in_db"));
                }
                let key_id = old.key_id.ok_or_else(|| Error::validation("key_no_private"))?;
                let key = s.db.get_key(key_id)?;
                let private = key
                    .private_pem_enc
                    .as_deref()
                    .ok_or_else(|| Error::validation("key_no_private"))?;
                let mut warnings = Vec::new();
                let (nb, na) = resolve_validity(&validity, 365, None, &mut warnings)?;
                let key_path = work.write("self.key", private)?;
                let cnf = work.write("ext.cnf", &valid.render("ext"))?;
                let serial = security::random_serial();
                let (nb, na) = (openssl_time(nb), openssl_time(na));
                let args = [
                    "x509",
                    "-in",
                    path_str(&old_path)?,
                    "-key",
                    path_str(&key_path)?,
                    "-passin",
                    "stdin",
                    "-set_serial",
                    &serial,
                    "-not_before",
                    &nb,
                    "-not_after",
                    &na,
                    "-clrext",
                    "-extfile",
                    path_str(&cnf)?,
                    "-extensions",
                    "ext",
                ];
                let pem = self
                    .openssl
                    .run(&args, Some(&s.password.stdin_line()))?
                    .stdout_text();
                self.store_cert(s, &work, &spec, None, &pem, warnings)
            }
        }
    }

    /// Signs a subject (CSR, bare public key or old certificate) with a CA.
    fn issue(
        &self,
        s: &Session,
        work: &WorkDir,
        spec: Spec,
        issuer_id: i64,
        source: Source,
    ) -> Result<Issued> {
        let mut warnings = Vec::new();
        let ca = s.db.get_cert(issuer_id)?;
        if !ca.is_ca {
            return Err(Error::validation("issuer_not_ca"));
        }
        if ca.revoked_at.is_some() {
            return Err(Error::validation("issuer_revoked"));
        }
        let ca_key_id = ca.key_id.ok_or_else(|| Error::validation("issuer_no_private"))?;
        let (ca_key, ca_alg) = self.key_with_algorithm(s, ca_key_id)?;
        if !ca_alg.can_sign() {
            return Err(Error::validation("issuer_cannot_sign"));
        }
        let ca_private = ca_key
            .private_pem_enc
            .as_deref()
            .ok_or_else(|| Error::validation("issuer_no_private"))?;

        // pathLenConstraint of every CA above a new CA certificate.
        let mut profile = spec.profile.clone();
        if profile.ca {
            let mut ancestors = Vec::new();
            for c in self.chain_rows(s, &ca)? {
                let p = work.write("anc.pem", &c.pem)?;
                ancestors.push(inspect::cert_info(&self.openssl, path_str(&p)?)?.path_len);
            }
            if let Some(max) = validation::check_path_len(&ancestors)? {
                if profile.path_len.is_none_or(|n| n > max) {
                    warnings.push(Warning::with(WARN_PATHLEN_CLIPPED, "path_len", max.to_string()));
                    profile.path_len = Some(max);
                }
            }
        }
        let valid = profile.validate(Usage {
            key: spec.key_alg,
            self_signed: false,
            template: false,
        })?;

        let (nb, na) = resolve_validity(
            spec.validity,
            default_days(&profile),
            Some(inspect::parse_rfc3339(&ca.not_after)?),
            &mut warnings,
        )?;
        let ca_pem = work.write("issuer.pem", &ca.pem)?;
        let ca_key_path = work.write("issuer.key", ca_private)?;
        let cnf = work.write("ext.cnf", &valid.render("ext"))?;
        let serial = security::random_serial();
        let mut args: Vec<String> = match &source {
            Source::Csr(csr) => vec!["x509".into(), "-req".into(), "-in".into(), path_str(csr)?.into()],
            Source::PublicKey { pub_path, subj } => vec![
                "x509".into(),
                "-new".into(),
                "-subj".into(),
                subj.clone(),
                "-force_pubkey".into(),
                path_str(pub_path)?.into(),
            ],
            Source::Certificate(old) => {
                vec![
                    "x509".into(),
                    "-in".into(),
                    path_str(old)?.into(),
                    "-clrext".into(),
                ]
            }
        };
        args.extend(
            [
                "-CA",
                path_str(&ca_pem)?,
                "-CAkey",
                path_str(&ca_key_path)?,
                "-passin",
                "stdin",
                "-set_serial",
                &serial,
                "-not_before",
                &openssl_time(nb),
                "-not_after",
                &openssl_time(na),
                "-extfile",
                path_str(&cnf)?,
                "-extensions",
                "ext",
            ]
            .map(String::from),
        );
        let pem = self
            .openssl
            .run(&args, Some(&s.password.stdin_line()))?
            .stdout_text();
        let spec = Spec {
            profile: &profile,
            ..spec
        };
        self.store_cert(s, work, &spec, Some(ca.id), &pem, warnings)
    }

    fn store_cert(
        &self,
        s: &Session,
        work: &WorkDir,
        spec: &Spec,
        issuer_id: Option<i64>,
        pem: &str,
        warnings: Vec<Warning>,
    ) -> Result<Issued> {
        let p = work.write("new.pem", pem)?;
        let info = inspect::cert_info(&self.openssl, path_str(&p)?)?;
        let id = s.db.insert_cert(&new_cert(
            &spec.name,
            spec.key_id,
            issuer_id,
            &spec.template,
            pem,
            &info,
            Some(spec.profile.clone()),
        ))?;
        Ok(Issued { id, warnings })
    }

    /// Imports an external certificate, linking it to its issuer and key
    /// when they are in the database.
    pub fn import_certificate(&self, name: &str, pem: &str) -> Result<Issued> {
        let s = self.session()?;
        let name = validation::validate_name(name)?;
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(Error::validation("import_not_pem_cert"));
        }
        let work = self.workdir()?;
        let raw = work.write("raw.pem", pem)?;
        let normalized = self
            .openssl
            .run(&["x509", "-in", path_str(&raw)?], None)
            .map_err(|e| import_error(e, "import_cert_failed"))?
            .stdout_text();
        let p = work.write("cert.pem", &normalized)?;
        let info = inspect::cert_info(&self.openssl, path_str(&p)?)?;
        if Algorithm::from_id(&info.key_algorithm).is_none()
            || !crate::inspect::is_pq_signature(&info.sig_algorithm)
        {
            return Err(Error::validation("algorithm_unsupported"));
        }
        let public = self
            .openssl
            .run(&["x509", "-in", path_str(&p)?, "-noout", "-pubkey"], None)?
            .stdout_text();
        let key_id = s.db.find_key_by_public(&public)?.map(|k| k.id);
        let all = s.db.list_certs()?;
        let issuer_id = if info.self_signed {
            None
        } else {
            self.find_issuer(&work, &all, &info, &p)?
        };
        let id = s.db.insert_cert(&new_cert(
            &name,
            key_id,
            issuer_id,
            "imported",
            &normalized,
            &info,
            None,
        ))?;
        // Link existing orphans that this certificate issued.
        if info.is_ca {
            for c in all
                .iter()
                .filter(|c| c.issuer_id.is_none() && c.issuer == info.subject && c.subject != c.issuer)
            {
                let child = work.write("child.pem", &c.pem)?;
                if self.signed_by(&p, &child)? {
                    s.db.set_cert_issuer(c.id, id)?;
                }
            }
        }
        Ok(Issued {
            id,
            warnings: Vec::new(),
        })
    }

    fn find_issuer(
        &self,
        work: &WorkDir,
        all: &[CertRow],
        info: &CertInfo,
        cert: &Path,
    ) -> Result<Option<i64>> {
        for c in all.iter().filter(|c| c.is_ca && c.subject == info.issuer) {
            let ca = work.write("cand.pem", &c.pem)?;
            if self.signed_by(&ca, cert)? {
                return Ok(Some(c.id));
            }
        }
        Ok(None)
    }

    /// True if `cert` carries a valid signature from `ca`.
    fn signed_by(&self, ca: &Path, cert: &Path) -> Result<bool> {
        let r = self.openssl.run(
            &[
                "verify",
                "-partial_chain",
                "-no_check_time",
                "-CAfile",
                path_str(ca)?,
                path_str(cert)?,
            ],
            None,
        );
        match r {
            Ok(_) => Ok(true),
            Err(OpenSslError::Failed { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn view_certificate(&self, id: i64) -> Result<CertView> {
        let s = self.session()?;
        let row = s.db.get_cert(id)?;
        let work = self.workdir()?;
        let p = work.write("cert.pem", &row.pem)?;
        let info = inspect::cert_info(&self.openssl, path_str(&p)?)?;
        let text = inspect::cert_text(&self.openssl, path_str(&p)?)?;
        Ok(CertView { row, info, text })
    }

    /// Certificates from `start` up to the top of its known chain.
    pub(crate) fn chain_rows(&self, s: &Session, start: &CertRow) -> Result<Vec<CertRow>> {
        let mut chain = vec![start.clone()];
        let mut current = start.clone();
        while let Some(parent) = current.issuer_id {
            if chain.len() > 32 || chain.iter().any(|c| c.id == parent) {
                return Err(Error::Internal("certificate chain loop".into()));
            }
            current = s.db.get_cert(parent)?;
            chain.push(current.clone());
        }
        Ok(chain)
    }

    /// Verifies a certificate up to its root with `openssl verify`, using the
    /// latest CRL of every issuer in the chain that has one. Revocations the
    /// database knows about fail the check even before they are published in
    /// a CRL.
    pub fn verify_chain(&self, id: i64) -> Result<VerifyResult> {
        let s = self.session()?;
        let row = s.db.get_cert(id)?;
        let chain = self.chain_rows(s, &row)?;
        let names = chain.iter().map(|c| c.name.clone()).collect();
        let root = chain.last().expect("chain has at least one element");
        let revoked_chain: Vec<String> = chain
            .iter()
            .filter(|c| c.revoked_at.is_some())
            .map(|c| c.name.clone())
            .collect();
        let revoked = row.revoked_at.is_some();
        if root.subject != root.issuer {
            return Ok(VerifyResult {
                ok: false,
                output: String::new(),
                chain: names,
                warnings: vec![Warning {
                    code: "chain_incomplete",
                    params: Default::default(),
                }],
                crl_checked: false,
                crl_complete: false,
                revoked,
                revoked_chain,
            });
        }

        // Latest CRL of the issuer of each non-root certificate.
        let mut warnings = Vec::new();
        let mut crls = Vec::new();
        for cert in &chain[..chain.len() - 1] {
            let issuer = cert.issuer_id.expect("non-root chain member has an issuer");
            let crl = s.db.latest_crl(issuer)?;
            if let Some(at) = &cert.revoked_at {
                let published = crl
                    .as_ref()
                    .is_some_and(|c| c.this_update.as_str() >= at.as_str());
                if !published {
                    warnings.push(Warning::with("revocation_unpublished", "name", cert.name.clone()));
                }
            }
            crls.push(crl);
        }
        let crl_complete = !crls.is_empty() && crls.iter().all(Option::is_some);
        let crl_pems: String = crls.iter().flatten().map(|c| c.pem.as_str()).collect();
        if !crl_pems.is_empty() && !crl_complete {
            warnings.push(Warning {
                code: "crl_partial",
                params: Default::default(),
            });
        }

        let work = self.workdir()?;
        let root_path = work.write("root.pem", &root.pem)?;
        let leaf_path = work.write("leaf.pem", &row.pem)?;
        let intermediates: String = if chain.len() > 2 {
            chain[1..chain.len() - 1].iter().map(|c| c.pem.as_str()).collect()
        } else {
            String::new()
        };
        let mut args: Vec<String> = vec!["verify".into(), "-CAfile".into(), path_str(&root_path)?.into()];
        if !intermediates.is_empty() {
            let p = work.write("untrusted.pem", &intermediates)?;
            args.push("-untrusted".into());
            args.push(path_str(&p)?.into());
        }
        // -crl_check_all needs a CRL for every level. Otherwise OpenSSL can
        // only check the leaf (-crl_check), if its issuer has a CRL.
        let crl_flag = if crl_complete {
            Some("-crl_check_all")
        } else if matches!(crls.first(), Some(Some(_))) {
            Some("-crl_check")
        } else {
            None
        };
        if let Some(flag) = crl_flag {
            let p = work.write("crls.pem", &crl_pems)?;
            args.extend([flag.into(), "-CRLfile".into(), path_str(&p)?.into()]);
        }
        args.push(path_str(&leaf_path)?.into());
        let (openssl_ok, output) = match self.openssl.run(&args, None) {
            Ok(o) => (true, format!("{}{}", o.stdout_text(), o.stderr)),
            Err(OpenSslError::Failed { stderr, .. }) => (false, stderr),
            Err(e) => return Err(e.into()),
        };
        let output = output.replace(path_str(&leaf_path)?, &row.name);
        Ok(VerifyResult {
            ok: openssl_ok && revoked_chain.is_empty(),
            output: output.trim().to_string(),
            chain: names,
            warnings,
            crl_checked: crl_flag.is_some(),
            crl_complete,
            revoked,
            revoked_chain,
        })
    }

    pub fn export_certificate(&self, id: i64, format: CertFormat) -> Result<Vec<u8>> {
        let s = self.session()?;
        let row = s.db.get_cert(id)?;
        match format {
            CertFormat::Pem => Ok(row.pem.into_bytes()),
            CertFormat::Der => {
                let work = self.workdir()?;
                let p = work.write("cert.pem", &row.pem)?;
                Ok(self
                    .openssl
                    .run(&["x509", "-in", path_str(&p)?, "-outform", "DER"], None)?
                    .stdout)
            }
        }
    }

    /// Full chain as PEM, from the certificate up to the root.
    pub fn export_chain(&self, id: i64) -> Result<String> {
        let s = self.session()?;
        let row = s.db.get_cert(id)?;
        Ok(self.chain_rows(s, &row)?.iter().map(|c| c.pem.as_str()).collect())
    }
}

/// Default validity: 10 years for a CA without pathlen limit on top, 5 for
/// other CAs, 1 year for end entities.
fn default_days(p: &CertProfile) -> u32 {
    match (p.ca, p.aki) {
        (true, false) => 3650,
        (true, true) => 1825,
        _ => 365,
    }
}

pub(crate) fn new_cert(
    name: &str,
    key_id: Option<i64>,
    issuer_id: Option<i64>,
    template: &str,
    pem: &str,
    info: &CertInfo,
    profile: Option<CertProfile>,
) -> NewCert {
    NewCert {
        name: name.to_string(),
        key_id,
        issuer_id,
        template: template.to_string(),
        is_ca: info.is_ca,
        subject: info.subject.clone(),
        issuer: info.issuer.clone(),
        serial: info.serial.clone(),
        sig_algorithm: info.sig_algorithm.clone(),
        key_algorithm: info.key_algorithm.clone(),
        not_before: info.not_before.clone(),
        not_after: info.not_after.clone(),
        fingerprint_sha256: info.fingerprint_sha256.clone(),
        pem: pem.to_string(),
        profile,
    }
}
