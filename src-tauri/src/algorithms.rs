//! Supported post-quantum key algorithms and their capabilities.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Family {
    MlDsa,
    SlhDsa,
    MlKem,
}

macro_rules! algorithms {
    ($($variant:ident => $name:literal, $family:ident;)+) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Algorithm {
            $($variant,)+
        }

        impl Algorithm {
            pub const ALL: &'static [Algorithm] = &[$(Algorithm::$variant,)+];

            /// Identifier stored in the database; also the `-algorithm` name.
            pub fn id(self) -> &'static str {
                match self {
                    $(Algorithm::$variant => $name,)+
                }
            }

            pub fn family(self) -> Family {
                match self {
                    $(Algorithm::$variant => Family::$family,)+
                }
            }

            pub fn from_id(id: &str) -> Option<Self> {
                match id {
                    $($name => Some(Algorithm::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

algorithms! {
    MlDsa44 => "ML-DSA-44", MlDsa;
    MlDsa65 => "ML-DSA-65", MlDsa;
    MlDsa87 => "ML-DSA-87", MlDsa;
    SlhDsaSha2_128s => "SLH-DSA-SHA2-128s", SlhDsa;
    SlhDsaSha2_128f => "SLH-DSA-SHA2-128f", SlhDsa;
    SlhDsaSha2_192s => "SLH-DSA-SHA2-192s", SlhDsa;
    SlhDsaSha2_192f => "SLH-DSA-SHA2-192f", SlhDsa;
    SlhDsaSha2_256s => "SLH-DSA-SHA2-256s", SlhDsa;
    SlhDsaSha2_256f => "SLH-DSA-SHA2-256f", SlhDsa;
    SlhDsaShake128s => "SLH-DSA-SHAKE-128s", SlhDsa;
    SlhDsaShake128f => "SLH-DSA-SHAKE-128f", SlhDsa;
    SlhDsaShake192s => "SLH-DSA-SHAKE-192s", SlhDsa;
    SlhDsaShake192f => "SLH-DSA-SHAKE-192f", SlhDsa;
    SlhDsaShake256s => "SLH-DSA-SHAKE-256s", SlhDsa;
    SlhDsaShake256f => "SLH-DSA-SHAKE-256f", SlhDsa;
    MlKem512 => "ML-KEM-512", MlKem;
    MlKem768 => "ML-KEM-768", MlKem;
    MlKem1024 => "ML-KEM-1024", MlKem;
}

impl Algorithm {
    /// Value for `openssl genpkey -algorithm`.
    pub fn openssl_name(self) -> &'static str {
        self.id()
    }

    pub fn can_sign(self) -> bool {
        self.family() != Family::MlKem
    }

    pub fn can_be_ca(self) -> bool {
        self.can_sign()
    }

    /// ML-DSA and SLH-DSA sign without a separate `-<digest>` option.
    pub fn uses_digest(self) -> bool {
        false
    }

    /// Detects the algorithm from the output of `openssl pkey -pubin -noout -text`
    /// (or the public key section of `x509 -text` / `req -text`).
    pub fn detect_from_key_text(text: &str) -> Option<Self> {
        text.lines()
            .map(str::trim)
            .filter_map(|l| l.strip_suffix(" Public-Key:"))
            .find_map(Self::from_id)
    }
}

impl Serialize for Algorithm {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.id())
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Algorithm::from_id(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown algorithm {s}")))
    }
}

#[derive(Serialize)]
pub struct AlgorithmInfo {
    pub id: &'static str,
    pub family: Family,
    pub can_sign: bool,
    pub can_be_ca: bool,
    /// keyUsage bits allowed for this algorithm (RFC 9881, RFC 9909).
    pub key_usages: Vec<crate::profile::KeyUsage>,
}

pub fn catalog() -> Vec<AlgorithmInfo> {
    Algorithm::ALL
        .iter()
        .map(|&a| AlgorithmInfo {
            id: a.id(),
            family: a.family(),
            can_sign: a.can_sign(),
            can_be_ca: a.can_be_ca(),
            key_usages: crate::profile::KeyUsage::allowed_for(a).to_vec(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        for &a in Algorithm::ALL {
            assert_eq!(Algorithm::from_id(a.id()), Some(a));
        }
        assert_eq!(Algorithm::from_id("RSA-3072"), None);
    }

    #[test]
    fn capabilities() {
        assert!(!Algorithm::MlKem768.can_sign());
        assert!(!Algorithm::MlKem768.can_be_ca());
        assert!(Algorithm::MlDsa65.can_be_ca());
        assert!(Algorithm::SlhDsaShake256f.can_be_ca());
        assert!(!Algorithm::MlDsa65.uses_digest());
    }

    #[test]
    fn detects_from_text() {
        assert_eq!(
            Algorithm::detect_from_key_text("ML-KEM-768 Public-Key:\nek:"),
            Some(Algorithm::MlKem768)
        );
        assert_eq!(
            Algorithm::detect_from_key_text("SLH-DSA-SHA2-128s Public-Key:\npub:"),
            Some(Algorithm::SlhDsaSha2_128s)
        );
        assert_eq!(
            Algorithm::detect_from_key_text("Public-Key: (3072 bit)\nModulus:\n"),
            None
        );
    }
}
