//! Error type shared by the backend. Every user-facing error carries a stable
//! `code` that the frontend translates (src/i18n), plus optional parameters and
//! a technical detail (filtered OpenSSL stderr) shown in a collapsible panel.

use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;

use crate::openssl::OpenSslError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("validation error: {code}")]
    Validation {
        code: &'static str,
        params: BTreeMap<&'static str, String>,
    },
    #[error("database is locked")]
    Locked,
    #[error("wrong master password")]
    WrongPassword,
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error(transparent)]
    OpenSsl(#[from] OpenSslError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn validation(code: &'static str) -> Self {
        Error::Validation {
            code,
            params: BTreeMap::new(),
        }
    }

    pub fn validation_with(code: &'static str, params: &[(&'static str, String)]) -> Self {
        Error::Validation {
            code,
            params: params.iter().cloned().collect(),
        }
    }

    /// Stable code used by tests and by the frontend translations.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Validation { code, .. } => code,
            Error::Locked => "locked",
            Error::WrongPassword => "wrong_password",
            Error::NotFound(_) => "not_found",
            Error::OpenSsl(OpenSslError::NotFound) => "openssl_not_found",
            Error::OpenSsl(OpenSslError::VersionTooOld(_)) => "openssl_too_old",
            Error::OpenSsl(OpenSslError::Timeout(_)) => "openssl_timeout",
            Error::OpenSsl(_) => "openssl_failed",
            Error::Db(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                "duplicate"
            }
            Error::Db(_) => "db_error",
            Error::Io(_) => "io_error",
            Error::Internal(_) => "internal",
        }
    }
}

/// Serialized form sent to the frontend.
#[derive(Serialize)]
pub struct ErrorPayload {
    pub code: &'static str,
    pub params: BTreeMap<&'static str, String>,
    pub detail: Option<String>,
}

impl From<&Error> for ErrorPayload {
    fn from(e: &Error) -> Self {
        let params = match e {
            Error::Validation { params, .. } => params.clone(),
            Error::NotFound(what) => [("what", what.to_string())].into_iter().collect(),
            _ => BTreeMap::new(),
        };
        let detail = match e {
            Error::Validation { .. } | Error::Locked | Error::WrongPassword => None,
            Error::OpenSsl(OpenSslError::Failed { stderr, .. }) => Some(stderr.clone()),
            other => Some(other.to_string()),
        };
        ErrorPayload {
            code: e.code(),
            params,
            detail,
        }
    }
}

impl Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        ErrorPayload::from(self).serialize(s)
    }
}
