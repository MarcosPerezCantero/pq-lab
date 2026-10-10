use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use zeroize::Zeroizing;

use super::{parse_version, MIN_VERSION};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum OpenSslError {
    #[error("openssl binary not found")]
    NotFound,
    #[error("could not start openssl: {0}")]
    Spawn(String),
    #[error("openssl timed out after {0:?}")]
    Timeout(Duration),
    #[error("openssl failed (exit code {code:?}): {stderr}")]
    Failed { code: Option<i32>, stderr: String },
    #[error("unsupported openssl version: {0}")]
    VersionTooOld(String),
    #[error("i/o error talking to openssl: {0}")]
    Io(String),
}

#[derive(Debug)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Output {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Handle to an `openssl` executable.
#[derive(Clone, Debug)]
pub struct OpenSsl {
    path: PathBuf,
    timeout: Duration,
    log: Option<Arc<Mutex<PathBuf>>>,
}

impl OpenSsl {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            timeout: DEFAULT_TIMEOUT,
            log: None,
        }
    }

    /// Resolves the binary: `PQLAB_OPENSSL`, then the sidecar next to the
    /// executable, then the development sidecar in `src-tauri/binaries`.
    pub fn locate() -> Result<Self, OpenSslError> {
        if let Some(p) = std::env::var_os("PQLAB_OPENSSL") {
            let p = PathBuf::from(p);
            return if p.is_file() {
                Ok(Self::new(p))
            } else {
                Err(OpenSslError::NotFound)
            };
        }
        let exe_name = if cfg!(windows) { "openssl.exe" } else { "openssl" };
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                // Tauri strips the target triple from sidecars when bundling.
                let candidate = dir.join(exe_name);
                if candidate.is_file() {
                    return Ok(Self::new(candidate));
                }
            }
        }
        let dev = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(sidecar_file_name());
        if dev.is_file() {
            return Ok(Self::new(dev));
        }
        Err(OpenSslError::NotFound)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Appends every invocation's argv (never stdin) to `path`.
    pub fn with_log(mut self, path: PathBuf) -> Self {
        self.log = Some(Arc::new(Mutex::new(path)));
        self
    }

    /// Runs `openssl version` and checks it is >= 3.5.0.
    pub fn check_version(&self) -> Result<String, OpenSslError> {
        let out = self.run(&["version"], None)?;
        let text = out.stdout_text().trim().to_string();
        let ok = text.starts_with("OpenSSL ") && parse_version(&text).is_some_and(|v| v >= MIN_VERSION);
        if ok {
            Ok(text)
        } else {
            Err(OpenSslError::VersionTooOld(text))
        }
    }

    /// Runs openssl with `args`, writing `stdin` (typically passwords followed
    /// by PEM data) to the child's standard input.
    pub fn run<S: AsRef<str>>(&self, args: &[S], stdin: Option<&[u8]>) -> Result<Output, OpenSslError> {
        self.log_args(args);
        let mut child = Command::new(&self.path)
            .args(args.iter().map(|a| a.as_ref()))
            .env("OPENSSL_CONF", NULL_CONFIG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    OpenSslError::NotFound
                } else {
                    OpenSslError::Spawn(e.to_string())
                }
            })?;

        let input: Zeroizing<Vec<u8>> = Zeroizing::new(stdin.map(<[u8]>::to_vec).unwrap_or_default());
        let mut child_stdin = child.stdin.take().expect("stdin piped");
        let writer = thread::spawn(move || {
            // Ignore broken pipes: openssl may exit before reading everything.
            let _ = child_stdin.write_all(&input);
            drop(child_stdin);
        });
        let mut out_pipe = child.stdout.take().expect("stdout piped");
        let out_reader = thread::spawn(move || {
            let mut buf = Vec::new();
            out_pipe.read_to_end(&mut buf).map(|_| buf)
        });
        let mut err_pipe = child.stderr.take().expect("stderr piped");
        let err_reader = thread::spawn(move || {
            let mut buf = Vec::new();
            err_pipe.read_to_end(&mut buf).map(|_| buf)
        });

        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() > self.timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(OpenSslError::Timeout(self.timeout));
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(OpenSslError::Io(e.to_string())),
            }
        };
        let _ = writer.join();
        let stdout = out_reader
            .join()
            .map_err(|_| OpenSslError::Io("stdout reader panicked".into()))?
            .map_err(|e| OpenSslError::Io(e.to_string()))?;
        let stderr_raw = err_reader
            .join()
            .map_err(|_| OpenSslError::Io("stderr reader panicked".into()))?
            .map_err(|e| OpenSslError::Io(e.to_string()))?;
        let stderr = filter_stderr(&String::from_utf8_lossy(&stderr_raw));

        if status.success() {
            Ok(Output { stdout, stderr })
        } else {
            Err(OpenSslError::Failed {
                code: status.code(),
                stderr,
            })
        }
    }

    fn log_args<S: AsRef<str>>(&self, args: &[S]) {
        let Some(log) = &self.log else { return };
        let Ok(path) = log.lock() else { return };
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&*path) {
            let line: Vec<&str> = args.iter().map(|a| a.as_ref()).collect();
            let _ = writeln!(
                f,
                "{} openssl {}",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                line.join(" ")
            );
        }
    }
}

/// Every invocation gets an empty default configuration: the sidecar has no
/// `openssl.cnf`, and the user's system configuration must not alter results.
pub const NULL_CONFIG: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

/// Name of the development sidecar for the current target.
fn sidecar_file_name() -> String {
    let triple = env!("PQLAB_TARGET_TRIPLE");
    if cfg!(windows) {
        format!("openssl-{triple}.exe")
    } else {
        format!("openssl-{triple}")
    }
}

/// Removes stderr lines that could carry sensitive material (PEM blocks,
/// base64 payloads, anything mentioning passwords) before it is shown.
pub fn filter_stderr(stderr: &str) -> String {
    let mut in_pem = false;
    stderr
        .lines()
        .filter(|line| {
            let l = line.trim();
            if l.starts_with("-----BEGIN") {
                in_pem = true;
                return false;
            }
            if l.starts_with("-----END") {
                in_pem = false;
                return false;
            }
            if in_pem {
                return false;
            }
            let lower = l.to_ascii_lowercase();
            if lower.contains("pass")
                && !lower.contains("bad decrypt")
                && !lower.contains("maybe wrong password")
            {
                return false;
            }
            let looks_base64 = l.len() >= 40
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
            !looks_base64
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::filter_stderr;

    #[test]
    fn filters_pem_and_base64() {
        let input = "error one\n-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA\n-----END PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nerror two";
        assert_eq!(filter_stderr(input), "error one\nerror two");
    }

    #[test]
    fn keeps_wrong_password_hint_but_drops_other_pass_lines() {
        let input = "Enter pass phrase for x:\nmaybe wrong password\nok";
        assert_eq!(filter_stderr(input), "maybe wrong password\nok");
    }
}
