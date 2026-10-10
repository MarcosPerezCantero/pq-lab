//! SQLite storage: schema, migrations and repositories.

mod models;
mod repo;

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

pub use models::{CertRow, CrlRow, CsrRow, KeyRow, NewCert, RevocationEntry, TemplateRow};

use crate::error::{Error, Result};

pub const SCHEMA_VERSION: i64 = 3;

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    CREATE TABLE meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE keys (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      algorithm TEXT NOT NULL,
      public_pem TEXT NOT NULL,
      private_pem_enc TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE certificates (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      key_id INTEGER REFERENCES keys(id),
      issuer_id INTEGER REFERENCES certificates(id),
      template TEXT NOT NULL,
      is_ca INTEGER NOT NULL,
      subject TEXT NOT NULL,
      issuer TEXT NOT NULL,
      serial TEXT NOT NULL,
      sig_algorithm TEXT NOT NULL,
      key_algorithm TEXT NOT NULL,
      not_before TEXT NOT NULL,
      not_after TEXT NOT NULL,
      fingerprint_sha256 TEXT NOT NULL UNIQUE,
      pem TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE csrs (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      key_id INTEGER REFERENCES keys(id),
      subject TEXT NOT NULL,
      key_algorithm TEXT NOT NULL,
      pem TEXT NOT NULL,
      signed_cert_id INTEGER REFERENCES certificates(id),
      created_at TEXT NOT NULL
    );
    "#,
    // v2: profiles, revocation, user templates and CRLs
    r#"
    ALTER TABLE certificates ADD COLUMN profile_json TEXT;
    ALTER TABLE certificates ADD COLUMN revoked_at TEXT;
    ALTER TABLE certificates ADD COLUMN revocation_reason TEXT;
    CREATE TABLE templates (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      profile_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE crls (
      id INTEGER PRIMARY KEY,
      issuer_id INTEGER NOT NULL REFERENCES certificates(id),
      number INTEGER NOT NULL,
      this_update TEXT NOT NULL,
      next_update TEXT NOT NULL,
      revoked_count INTEGER NOT NULL,
      pem TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    "#,
    // v3: revocations outlive deleted certificates; CRL numbers never repeat
    r#"
    CREATE TABLE revocation_archive (
      id INTEGER PRIMARY KEY,
      issuer_id INTEGER NOT NULL REFERENCES certificates(id),
      serial TEXT NOT NULL,
      not_after TEXT NOT NULL,
      revoked_at TEXT NOT NULL,
      reason TEXT NOT NULL,
      archived_at TEXT NOT NULL
    );
    CREATE TABLE crl_counters (
      issuer_id INTEGER PRIMARY KEY REFERENCES certificates(id),
      last_number INTEGER NOT NULL
    );
    INSERT INTO crl_counters(issuer_id, last_number)
      SELECT issuer_id, MAX(number) FROM crls GROUP BY issuer_id;
    "#,
];

pub struct Db {
    pub(crate) conn: Connection,
}

impl Db {
    /// Creates a new database file. Fails if the file already exists.
    pub fn create(path: &Path, master_hash: &str) -> Result<Self> {
        if path.exists() {
            return Err(Error::validation("db_already_exists"));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let mut db = Self::configure(conn)?;
        db.migrate()?;
        db.set_meta("master_hash", master_hash)?;
        Ok(db)
    }

    /// Opens an existing database file without creating it.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Err(Error::validation("db_not_found"));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut db = Self::configure(conn)?;
        let has_meta: bool = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n == 1)
            .map_err(|_| Error::validation("db_invalid"))?;
        if !has_meta {
            return Err(Error::validation("db_invalid"));
        }
        db.migrate()?;
        Ok(db)
    }

    fn configure(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        Ok(Self { conn })
    }

    fn schema_version(&self) -> Result<i64> {
        let exists: i64 = self.conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |r| r.get(0),
        )?;
        if exists == 0 {
            return Ok(0);
        }
        Ok(self
            .get_meta("schema_version")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    fn migrate(&mut self) -> Result<()> {
        let current = self.schema_version()?;
        if current > SCHEMA_VERSION {
            return Err(Error::validation("db_newer_version"));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(i as i64 + 1).to_string()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Runs `f` inside a savepoint: what it wrote is undone if it fails.
    pub fn atomic<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.conn.execute_batch("SAVEPOINT atomic")?;
        match f() {
            Ok(v) => {
                self.conn.execute_batch("RELEASE atomic")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK TO atomic; RELEASE atomic");
                Err(e)
            }
        }
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }
}

pub(crate) fn now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
