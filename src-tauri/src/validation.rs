//! Validation rules applied before calling OpenSSL.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A validated subjectAltName entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum San {
    Dns(String),
    Ip(IpAddr),
    Email(String),
    Uri(String),
}

/// Distinguished name fields accepted from the UI.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SubjectInput {
    pub cn: String,
    #[serde(default)]
    pub o: String,
    #[serde(default)]
    pub ou: String,
    #[serde(default)]
    pub c: String,
    #[serde(default)]
    pub st: String,
    #[serde(default)]
    pub l: String,
}

impl SubjectInput {
    pub fn cn(cn: &str) -> Self {
        Self {
            cn: cn.to_string(),
            ..Default::default()
        }
    }

    /// Builds the `-subj` argument, escaping OpenSSL's separators.
    /// `ascii_only` is required by `openssl x509 -new`, which has no `-utf8`.
    pub fn to_openssl(&self, ascii_only: bool) -> Result<String> {
        let fields = [
            ("C", &self.c),
            ("ST", &self.st),
            ("L", &self.l),
            ("O", &self.o),
            ("OU", &self.ou),
            ("CN", &self.cn),
        ];
        if self.cn.trim().is_empty() {
            return Err(Error::validation("subject_cn_required"));
        }
        let c = self.c.trim();
        if !c.is_empty() && (c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic())) {
            return Err(Error::validation("subject_country_invalid"));
        }
        let mut out = String::new();
        for (key, value) in fields {
            let v = value.trim();
            if v.is_empty() {
                continue;
            }
            if v.chars().count() > 64 {
                return Err(Error::validation_with(
                    "subject_field_too_long",
                    &[("field", key.to_string())],
                ));
            }
            if v.chars().any(char::is_control) {
                return Err(Error::validation_with(
                    "subject_field_invalid",
                    &[("field", key.to_string())],
                ));
            }
            if ascii_only && !v.is_ascii() {
                return Err(Error::validation("subject_ascii_only"));
            }
            out.push('/');
            out.push_str(key);
            out.push('=');
            for ch in v.chars() {
                if matches!(ch, '\\' | '/' | '+' | '=') {
                    out.push('\\');
                }
                out.push(ch);
            }
        }
        Ok(out)
    }
}

/// Object names (keys, certificates, CSRs) shown in the UI.
pub fn validate_name(name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() {
        return Err(Error::validation("name_required"));
    }
    if n.chars().count() > 128 || n.chars().any(char::is_control) {
        return Err(Error::validation("name_invalid"));
    }
    Ok(n.to_string())
}

/// Parses a SAN entry typed by the user: an IP address, a URI, an e-mail
/// address or a DNS name (optionally a leading wildcard label).
pub fn parse_san(raw: &str) -> Result<San> {
    let v = raw.trim();
    let invalid = || Error::validation_with("san_invalid", &[("value", v.to_string())]);
    if v.is_empty() {
        return Err(invalid());
    }
    if v.contains("://") {
        return if crate::profile::is_safe_uri(v) {
            Ok(San::Uri(v.to_string()))
        } else {
            Err(invalid())
        };
    }
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Ok(San::Ip(ip));
    }
    if let Some((local, domain)) = v.split_once('@') {
        let local_ok = !local.is_empty()
            && local.len() <= 64
            && local
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c));
        if local_ok && is_dns_name(domain, false) {
            return Ok(San::Email(v.to_string()));
        }
        return Err(invalid());
    }
    if is_dns_name(v, true) {
        return Ok(San::Dns(v.to_ascii_lowercase()));
    }
    Err(invalid())
}

fn is_dns_name(name: &str, allow_wildcard: bool) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.iter().enumerate().all(|(i, label)| {
        if i == 0 && allow_wildcard && *label == "*" && labels.len() > 2 {
            return true;
        }
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// Checks `pathLenConstraint` of every CA above a new intermediate.
/// `ancestors` goes from the direct issuer upwards with each CA's pathlen.
/// Returns the maximum pathlen the new intermediate may carry.
pub fn check_path_len(ancestors: &[Option<u32>]) -> Result<Option<u32>> {
    let mut max_allowed: Option<u32> = None;
    for (distance, p) in ancestors.iter().enumerate() {
        let k = distance as u32 + 1;
        if let Some(p) = p {
            if *p < k {
                return Err(Error::validation("pathlen_violation"));
            }
            let room = p - k;
            max_allowed = Some(max_allowed.map_or(room, |m| m.min(room)));
        }
    }
    Ok(max_allowed)
}

/// Warning raised when the requested validity was clipped to the issuer's.
pub const WARN_VALIDITY_CLIPPED: &str = "validity_clipped";
/// Warning raised when the requested pathlen was reduced.
pub const WARN_PATHLEN_CLIPPED: &str = "pathlen_clipped";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_escaping() {
        let s = SubjectInput {
            cn: "a/b+c".into(),
            o: "pq lab".into(),
            ..Default::default()
        };
        assert_eq!(s.to_openssl(true).unwrap(), "/O=pq lab/CN=a\\/b\\+c");
        assert!(SubjectInput::cn("Año").to_openssl(true).is_err());
        assert!(SubjectInput::cn("Año").to_openssl(false).is_ok());
        assert!(SubjectInput::cn(" ").to_openssl(false).is_err());
    }

    #[test]
    fn sans() {
        assert_eq!(
            parse_san("WWW.Lab.Test").unwrap(),
            San::Dns("www.lab.test".into())
        );
        assert!(matches!(parse_san("10.0.0.1").unwrap(), San::Ip(_)));
        assert!(matches!(parse_san("::1").unwrap(), San::Ip(_)));
        assert!(matches!(parse_san("a@b.lab").unwrap(), San::Email(_)));
        assert!(matches!(parse_san("*.lab.test").unwrap(), San::Dns(_)));
        assert!(matches!(parse_san("https://pq.lab/id").unwrap(), San::Uri(_)));
        assert!(parse_san("https://pq.lab/a b").is_err());
        for bad in ["-a.lab", "a..lab", "a b", "x\nDNS.2 = evil", "*.com", "a@", "a,b"] {
            assert!(parse_san(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn path_len_rules() {
        assert_eq!(check_path_len(&[None]).unwrap(), None);
        assert!(check_path_len(&[Some(0)]).is_err());
        assert_eq!(check_path_len(&[Some(2)]).unwrap(), Some(1));
        assert!(check_path_len(&[Some(3), Some(1)]).is_err());
        assert_eq!(check_path_len(&[None, Some(3)]).unwrap(), Some(1));
    }
}
