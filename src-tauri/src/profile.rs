//! Certificate profiles: the X.509 extensions of a certificate, as edited in the
//! UI (XCA-style), their validation for post-quantum keys and their rendering
//! into a temporary OpenSSL configuration file.
//!
//! Every user value is validated against a strict character whitelist before
//! it reaches the configuration file, so it cannot inject configuration syntax
//! (`$` expansion, `#` comments, new lines, section headers...).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::algorithms::{Algorithm, Family};
use crate::error::{Error, Result};
use crate::validation::parse_san;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyUsage {
    #[serde(rename = "digitalSignature")]
    DigitalSignature,
    #[serde(rename = "nonRepudiation")]
    NonRepudiation,
    #[serde(rename = "keyEncipherment")]
    KeyEncipherment,
    #[serde(rename = "dataEncipherment")]
    DataEncipherment,
    #[serde(rename = "keyAgreement")]
    KeyAgreement,
    #[serde(rename = "keyCertSign")]
    KeyCertSign,
    #[serde(rename = "cRLSign")]
    CrlSign,
    #[serde(rename = "encipherOnly")]
    EncipherOnly,
    #[serde(rename = "decipherOnly")]
    DecipherOnly,
}

impl KeyUsage {
    pub fn openssl_name(self) -> &'static str {
        match self {
            KeyUsage::DigitalSignature => "digitalSignature",
            KeyUsage::NonRepudiation => "nonRepudiation",
            KeyUsage::KeyEncipherment => "keyEncipherment",
            KeyUsage::DataEncipherment => "dataEncipherment",
            KeyUsage::KeyAgreement => "keyAgreement",
            KeyUsage::KeyCertSign => "keyCertSign",
            KeyUsage::CrlSign => "cRLSign",
            KeyUsage::EncipherOnly => "encipherOnly",
            KeyUsage::DecipherOnly => "decipherOnly",
        }
    }

    /// keyUsage bits allowed for a key algorithm: RFC 9881 (ML-DSA), RFC 9909
    /// (SLH-DSA) and the ML-KEM certificate profile (keyEncipherment only).
    pub fn allowed_for(alg: Algorithm) -> &'static [KeyUsage] {
        match alg.family() {
            Family::MlDsa | Family::SlhDsa => &[
                KeyUsage::DigitalSignature,
                KeyUsage::NonRepudiation,
                KeyUsage::KeyCertSign,
                KeyUsage::CrlSign,
            ],
            Family::MlKem => &[KeyUsage::KeyEncipherment],
        }
    }
}

/// Extended key usages offered by name (OpenSSL short names). Any dotted OID
/// is accepted too.
pub const KNOWN_EKUS: &[&str] = &[
    "serverAuth",
    "clientAuth",
    "codeSigning",
    "emailProtection",
    "timeStamping",
    "OCSPSigning",
    "ipsecIKE",
    "msCodeInd",
    "msCodeCom",
    "msCTLSign",
    "msEFS",
    "msSmartcardLogin",
    "anyExtendedKeyUsage",
];

/// X.509v3 extensions of a certificate, as edited in the UI.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CertProfile {
    pub ca: bool,
    pub path_len: Option<u32>,
    pub bc_critical: bool,
    pub key_usage: Vec<KeyUsage>,
    pub ku_critical: bool,
    pub ext_key_usage: Vec<String>,
    pub eku_critical: bool,
    pub ski: bool,
    pub aki: bool,
    pub san: Vec<String>,
    pub san_critical: bool,
    pub policies: Vec<String>,
    pub crl_dp: Vec<String>,
    pub ocsp: Vec<String>,
    pub ca_issuers: Vec<String>,
    pub nc_permitted: Vec<String>,
    pub nc_excluded: Vec<String>,
}

/// A name constraint subtree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subtree {
    Dns(String),
    Ip { addr: IpAddr, mask: IpAddr },
    Email(String),
}

/// A profile whose values have all been checked and parsed.
#[derive(Clone, Debug)]
pub struct ValidProfile {
    pub profile: CertProfile,
    pub sans: Vec<crate::validation::San>,
    pub permitted: Vec<Subtree>,
    pub excluded: Vec<Subtree>,
}

/// Context in which a profile is used.
#[derive(Clone, Copy, Debug)]
pub struct Usage {
    /// Algorithm of the certified key, when known.
    pub key: Option<Algorithm>,
    pub self_signed: bool,
    /// Saving a template: per-certificate values (SAN) may still be missing.
    pub template: bool,
}

impl CertProfile {
    pub fn validate(&self, usage: Usage) -> Result<ValidProfile> {
        let p = self;
        let is_kem = usage.key.is_some_and(|k| !k.can_sign());
        if is_kem && p.ca {
            return Err(Error::validation("kem_cannot_be_ca"));
        }
        if is_kem && usage.self_signed {
            return Err(Error::validation("kem_cannot_self_sign"));
        }
        if let Some(alg) = usage.key {
            let allowed = KeyUsage::allowed_for(alg);
            if let Some(bad) = p.key_usage.iter().find(|u| !allowed.contains(u)) {
                return Err(Error::validation_with(
                    "ku_not_allowed",
                    &[
                        ("usage", bad.openssl_name().to_string()),
                        ("algorithm", alg.id().to_string()),
                    ],
                ));
            }
        }
        let cert_sign = p.key_usage.contains(&KeyUsage::KeyCertSign);
        if p.ca && !cert_sign {
            return Err(Error::validation("ca_requires_keycertsign"));
        }
        if !p.ca && cert_sign {
            return Err(Error::validation("keycertsign_requires_ca"));
        }
        if !p.ca && p.path_len.is_some() {
            return Err(Error::validation("pathlen_requires_ca"));
        }
        if p.path_len.is_some_and(|n| n > 32) {
            return Err(Error::validation("pathlen_invalid"));
        }
        for e in &p.ext_key_usage {
            if !(KNOWN_EKUS.contains(&e.as_str()) || is_oid(e)) {
                return Err(Error::validation_with("eku_invalid", &[("value", e.clone())]));
            }
        }
        let sans = p
            .san
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| parse_san(s))
            .collect::<Result<Vec<_>>>()?;
        if !usage.template
            && p.ext_key_usage.iter().any(|e| e == "serverAuth")
            && !sans
                .iter()
                .any(|s| matches!(s, crate::validation::San::Dns(_) | crate::validation::San::Ip(_)))
        {
            return Err(Error::validation("server_requires_san"));
        }
        for oid in &p.policies {
            if !(oid == "anyPolicy" || is_oid(oid)) {
                return Err(Error::validation_with(
                    "policy_invalid",
                    &[("value", oid.clone())],
                ));
            }
        }
        for uri in p.crl_dp.iter().chain(&p.ocsp).chain(&p.ca_issuers) {
            if !is_safe_uri(uri) {
                return Err(Error::validation_with("uri_invalid", &[("value", uri.clone())]));
            }
        }
        if (!p.nc_permitted.is_empty() || !p.nc_excluded.is_empty()) && !p.ca {
            return Err(Error::validation("nc_requires_ca"));
        }
        let parse_all = |v: &[String]| {
            v.iter()
                .filter(|s| !s.trim().is_empty())
                .map(|s| parse_subtree(s))
                .collect::<Result<Vec<_>>>()
        };
        Ok(ValidProfile {
            permitted: parse_all(&p.nc_permitted)?,
            excluded: parse_all(&p.nc_excluded)?,
            sans,
            profile: p.clone(),
        })
    }
}

fn is_oid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && matches!(parts[0], "0" | "1" | "2")
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.chars().all(|c| c.is_ascii_digit()))
}

/// http(s)/ldap URIs without characters that are special in OpenSSL configs.
pub fn is_safe_uri(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ldap://"))
        && s.len() <= 512
        && s.len() > 8
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~:/?&=%+@!*'()[]".contains(c))
}

fn parse_subtree(raw: &str) -> Result<Subtree> {
    let v = raw.trim();
    let invalid = || Error::validation_with("nc_invalid", &[("value", v.to_string())]);
    if let Some((addr, len)) = v.split_once('/') {
        let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
        let len: u32 = len.parse().map_err(|_| invalid())?;
        let mask = match addr {
            IpAddr::V4(_) if len <= 32 => {
                IpAddr::V4(u32::MAX.checked_shl(32 - len).unwrap_or(0).to_be_bytes().into())
            }
            IpAddr::V6(_) if len <= 128 => {
                IpAddr::V6(u128::MAX.checked_shl(128 - len).unwrap_or(0).to_be_bytes().into())
            }
            _ => return Err(invalid()),
        };
        return Ok(Subtree::Ip { addr, mask });
    }
    if let Some(domain) = v.strip_prefix('@') {
        return match parse_san(&format!("x@{domain}")) {
            Ok(_) => Ok(Subtree::Email(domain.to_ascii_lowercase())),
            Err(_) => Err(invalid()),
        };
    }
    if v.contains('@') {
        return match parse_san(v) {
            Ok(_) => Ok(Subtree::Email(v.to_string())),
            Err(_) => Err(invalid()),
        };
    }
    let host = v.strip_prefix('.').unwrap_or(v);
    match parse_san(host) {
        Ok(crate::validation::San::Dns(d)) => {
            Ok(Subtree::Dns(if v.starts_with('.') { format!(".{d}") } else { d }))
        }
        _ => Err(invalid()),
    }
}

impl ValidProfile {
    /// Renders `[req]` defaults plus the extension section `section`.
    pub fn render(&self, section: &str) -> String {
        self.render_inner(section, false)
    }

    /// Like `render`, for the requested extensions of a CSR: there is no
    /// issuer yet, so authorityKeyIdentifier is left out.
    pub fn render_request(&self, section: &str) -> String {
        self.render_inner(section, true)
    }

    fn render_inner(&self, section: &str, request: bool) -> String {
        let p = &self.profile;
        let crit = |c: bool| if c { "critical, " } else { "" };
        let mut s = String::from("[req]\ndistinguished_name = req_dn\nprompt = no\n\n[req_dn]\n\n");
        s.push_str(&format!("[{section}]\n"));
        let mut bc = format!(
            "basicConstraints = {}CA:{}",
            crit(p.bc_critical),
            if p.ca { "TRUE" } else { "FALSE" }
        );
        if let (true, Some(n)) = (p.ca, p.path_len) {
            bc.push_str(&format!(", pathlen:{n}"));
        }
        s.push_str(&bc);
        s.push('\n');
        if !p.key_usage.is_empty() {
            let list: Vec<&str> = p.key_usage.iter().map(|k| k.openssl_name()).collect();
            s.push_str(&format!(
                "keyUsage = {}{}\n",
                crit(p.ku_critical),
                list.join(", ")
            ));
        }
        if !p.ext_key_usage.is_empty() {
            s.push_str(&format!(
                "extendedKeyUsage = {}{}\n",
                crit(p.eku_critical),
                p.ext_key_usage.join(", ")
            ));
        }
        if p.ski {
            s.push_str("subjectKeyIdentifier = hash\n");
        }
        if p.aki && !request {
            s.push_str("authorityKeyIdentifier = keyid:always\n");
        }
        if !self.sans.is_empty() {
            s.push_str(&format!("subjectAltName = {}@alt_names\n", crit(p.san_critical)));
        }
        if !p.policies.is_empty() {
            let list: Vec<&str> = p
                .policies
                .iter()
                .map(|o| {
                    if o == "anyPolicy" {
                        "2.5.29.32.0"
                    } else {
                        o.as_str()
                    }
                })
                .collect();
            s.push_str(&format!("certificatePolicies = {}\n", list.join(", ")));
        }
        if !p.crl_dp.is_empty() {
            s.push_str("crlDistributionPoints = @crl_dp\n");
        }
        if !p.ocsp.is_empty() || !p.ca_issuers.is_empty() {
            s.push_str("authorityInfoAccess = @aia\n");
        }
        if !self.permitted.is_empty() || !self.excluded.is_empty() {
            s.push_str("nameConstraints = critical, @name_constraints\n");
        }

        if !self.sans.is_empty() {
            s.push_str("\n[alt_names]\n");
            for (i, san) in self.sans.iter().enumerate() {
                let n = i + 1;
                s.push_str(&match san {
                    crate::validation::San::Dns(v) => format!("DNS.{n} = {v}\n"),
                    crate::validation::San::Ip(v) => format!("IP.{n} = {v}\n"),
                    crate::validation::San::Email(v) => format!("email.{n} = {v}\n"),
                    crate::validation::San::Uri(v) => format!("URI.{n} = {v}\n"),
                });
            }
        }
        if !p.crl_dp.is_empty() {
            s.push_str("\n[crl_dp]\n");
            for (i, u) in p.crl_dp.iter().enumerate() {
                s.push_str(&format!("URI.{} = {u}\n", i + 1));
            }
        }
        if !p.ocsp.is_empty() || !p.ca_issuers.is_empty() {
            s.push_str("\n[aia]\n");
            let mut n = 0;
            for u in &p.ocsp {
                n += 1;
                s.push_str(&format!("OCSP;URI.{n} = {u}\n"));
            }
            for u in &p.ca_issuers {
                n += 1;
                s.push_str(&format!("caIssuers;URI.{n} = {u}\n"));
            }
        }
        if !self.permitted.is_empty() || !self.excluded.is_empty() {
            s.push_str("\n[name_constraints]\n");
            let mut n = 0;
            for (kind, list) in [("permitted", &self.permitted), ("excluded", &self.excluded)] {
                for t in list {
                    n += 1;
                    s.push_str(&match t {
                        Subtree::Dns(d) => format!("{kind};DNS.{n} = {d}\n"),
                        Subtree::Ip { addr, mask } => format!("{kind};IP.{n} = {addr}/{mask}\n"),
                        Subtree::Email(e) => format!("{kind};email.{n} = {e}\n"),
                    });
                }
            }
        }
        s
    }
}

// ---- built-in templates ----------------------------------------------------------

/// Built-in template: id (translated in the UI as `preset.<id>`) and profile.
#[derive(Clone, Debug, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub profile: CertProfile,
    pub default_days: u32,
    /// Only ML-KEM keys (true) or only signature keys (false).
    pub kem: bool,
}

fn base(ca: bool, ku: &[KeyUsage], eku: &[&str]) -> CertProfile {
    CertProfile {
        ca,
        path_len: None,
        bc_critical: true,
        key_usage: ku.to_vec(),
        ku_critical: true,
        ext_key_usage: eku.iter().map(|s| s.to_string()).collect(),
        eku_critical: false,
        ski: true,
        aki: !ca,
        ..Default::default()
    }
}

pub fn presets() -> Vec<Preset> {
    use KeyUsage::*;
    let leaf = |id, ku: &[KeyUsage], eku: &[&str]| Preset {
        id,
        profile: base(false, ku, eku),
        default_days: 365,
        kem: false,
    };
    let mut intermediate = base(true, &[KeyCertSign, CrlSign], &[]);
    intermediate.path_len = Some(0);
    intermediate.aki = true;
    let mut tsa = base(false, &[DigitalSignature, NonRepudiation], &["timeStamping"]);
    tsa.eku_critical = true;
    vec![
        Preset {
            id: "root",
            profile: base(true, &[KeyCertSign, CrlSign], &[]),
            default_days: 3650,
            kem: false,
        },
        Preset {
            id: "intermediate",
            profile: intermediate,
            default_days: 1825,
            kem: false,
        },
        leaf("server", &[DigitalSignature], &["serverAuth"]),
        leaf("client", &[DigitalSignature], &["clientAuth"]),
        leaf(
            "server_client",
            &[DigitalSignature],
            &["serverAuth", "clientAuth"],
        ),
        leaf("code_signing", &[DigitalSignature], &["codeSigning"]),
        leaf("smime", &[DigitalSignature, NonRepudiation], &["emailProtection"]),
        Preset {
            id: "timestamping",
            profile: tsa,
            default_days: 365,
            kem: false,
        },
        leaf("ocsp", &[DigitalSignature], &["OCSPSigning"]),
        Preset {
            id: "kem",
            profile: base(false, &[KeyEncipherment], &[]),
            default_days: 365,
            kem: true,
        },
    ]
}

pub fn preset(id: &str) -> Option<Preset> {
    presets().into_iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(alg: Algorithm) -> Usage {
        Usage {
            key: Some(alg),
            self_signed: false,
            template: false,
        }
    }

    #[test]
    fn presets_are_valid_for_their_keys() {
        for p in presets() {
            let alg = if p.kem {
                Algorithm::MlKem768
            } else {
                Algorithm::MlDsa65
            };
            let mut prof = p.profile.clone();
            if prof.ext_key_usage.contains(&"serverAuth".to_string()) {
                prof.san = vec!["a.lab".into()];
            }
            prof.validate(usage(alg))
                .unwrap_or_else(|e| panic!("{}: {e:?}", p.id));
        }
    }

    #[test]
    fn key_usage_rules() {
        let mut p = preset("server").unwrap().profile;
        p.san = vec!["a.lab".into()];
        p.key_usage.push(KeyUsage::KeyEncipherment);
        assert_eq!(
            p.validate(usage(Algorithm::MlDsa44)).unwrap_err().code(),
            "ku_not_allowed"
        );
        let mut k = preset("kem").unwrap().profile;
        k.key_usage = vec![KeyUsage::DigitalSignature];
        assert_eq!(
            k.validate(usage(Algorithm::MlKem512)).unwrap_err().code(),
            "ku_not_allowed"
        );
        let mut c = preset("client").unwrap().profile;
        c.key_usage.push(KeyUsage::KeyCertSign);
        assert_eq!(
            c.validate(usage(Algorithm::MlDsa44)).unwrap_err().code(),
            "keycertsign_requires_ca"
        );
        let mut r = preset("root").unwrap().profile;
        r.key_usage = vec![KeyUsage::CrlSign];
        assert_eq!(
            r.validate(usage(Algorithm::MlDsa44)).unwrap_err().code(),
            "ca_requires_keycertsign"
        );
    }

    #[test]
    fn rejects_injection() {
        let mut p = preset("client").unwrap().profile;
        p.crl_dp = vec!["http://x.lab/a.crl\n[evil]".into()];
        assert_eq!(
            p.validate(usage(Algorithm::MlDsa44)).unwrap_err().code(),
            "uri_invalid"
        );
        p.crl_dp = vec!["http://x.lab/$ENV::HOME".into()];
        assert_eq!(
            p.validate(usage(Algorithm::MlDsa44)).unwrap_err().code(),
            "uri_invalid"
        );
        p.crl_dp = vec![];
        p.ext_key_usage = vec!["serverAuth, critical".into()];
        assert_eq!(
            p.validate(usage(Algorithm::MlDsa44)).unwrap_err().code(),
            "eku_invalid"
        );
        p.ext_key_usage = vec!["1.3.6.1.5.5.7.3.9".into()];
        p.policies = vec!["1.2.3.4".into(), "anyPolicy".into()];
        assert!(p.validate(usage(Algorithm::MlDsa44)).is_ok());
    }

    #[test]
    fn renders_everything() {
        let mut p = preset("intermediate").unwrap().profile;
        p.path_len = Some(2);
        p.policies = vec!["anyPolicy".into()];
        p.crl_dp = vec!["http://crl.lab/root.crl".into()];
        p.ocsp = vec!["http://ocsp.lab".into()];
        p.ca_issuers = vec!["http://ca.lab/root.cer".into()];
        p.nc_permitted = vec![".pq.lab".into(), "10.0.0.0/8".into(), "@pq.lab".into()];
        p.nc_excluded = vec!["bad.pq.lab".into()];
        let cfg = p.validate(usage(Algorithm::MlDsa65)).unwrap().render("ext");
        assert!(cfg.contains("basicConstraints = critical, CA:TRUE, pathlen:2"));
        assert!(cfg.contains("certificatePolicies = 2.5.29.32.0"));
        assert!(cfg.contains("URI.1 = http://crl.lab/root.crl"));
        assert!(cfg.contains("OCSP;URI.1 = http://ocsp.lab"));
        assert!(cfg.contains("caIssuers;URI.2 = http://ca.lab/root.cer"));
        assert!(cfg.contains("permitted;DNS.1 = .pq.lab"));
        assert!(cfg.contains("permitted;IP.2 = 10.0.0.0/255.0.0.0"));
        assert!(cfg.contains("permitted;email.3 = pq.lab"));
        assert!(cfg.contains("excluded;DNS.4 = bad.pq.lab"));
    }

    #[test]
    fn kem_rules() {
        let k = preset("kem").unwrap().profile;
        assert_eq!(
            k.validate(Usage {
                key: Some(Algorithm::MlKem768),
                self_signed: true,
                template: false,
            })
            .unwrap_err()
            .code(),
            "kem_cannot_self_sign"
        );
        let r = preset("root").unwrap().profile;
        assert_eq!(
            r.validate(usage(Algorithm::MlKem768)).unwrap_err().code(),
            "kem_cannot_be_ca"
        );
    }
}
