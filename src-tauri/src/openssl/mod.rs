//! Execution of the `openssl` binary. This module never performs cryptography:
//! it locates the binary, runs it with stdin input, captures output and maps
//! failures to typed errors.

mod runner;

pub use runner::{filter_stderr, OpenSsl, OpenSslError, Output, NULL_CONFIG};

/// Minimum supported OpenSSL version (major, minor, patch).
pub const MIN_VERSION: (u32, u32, u32) = (3, 5, 0);

/// Parses the output of `openssl version` ("OpenSSL 3.5.9 29 Sep 2026 ...").
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let token = text.split_whitespace().nth(1)?;
    let mut parts = token
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(
            parse_version("OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)"),
            Some((3, 5, 9))
        );
        assert_eq!(parse_version("OpenSSL 3.6.0-dev"), Some((3, 6, 0)));
        assert_eq!(parse_version("LibreSSL 3.3.6"), Some((3, 3, 6)));
        assert_eq!(parse_version("garbage"), None);
    }
}
