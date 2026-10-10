use rusqlite::{params, OptionalExtension, Row};

use super::models::{CertRow, CrlRow, CsrRow, KeyRow, NewCert, RevocationEntry, TemplateRow};
use super::{now, Db};
use crate::error::{Error, Result};

const KEY_COLS: &str = "k.id, k.name, k.algorithm, k.public_pem, k.private_pem_enc, k.created_at,
    (SELECT count(*) FROM certificates c WHERE c.key_id = k.id)";
const CERT_COLS: &str = "id, name, key_id, issuer_id, template, is_ca, subject, issuer, serial,
    sig_algorithm, key_algorithm, not_before, not_after, fingerprint_sha256, pem, created_at,
    profile_json, revoked_at, revocation_reason";
const CRL_COLS: &str = "id, issuer_id, number, this_update, next_update, revoked_count, pem, created_at";
const CSR_COLS: &str = "id, name, key_id, subject, key_algorithm, pem, signed_cert_id, created_at";

fn key_row(r: &Row) -> rusqlite::Result<KeyRow> {
    let private_pem_enc: Option<String> = r.get(4)?;
    Ok(KeyRow {
        id: r.get(0)?,
        name: r.get(1)?,
        algorithm: r.get(2)?,
        public_pem: r.get(3)?,
        has_private: private_pem_enc.is_some(),
        private_pem_enc,
        created_at: r.get(5)?,
        cert_count: r.get(6)?,
    })
}

fn cert_row(r: &Row) -> rusqlite::Result<CertRow> {
    Ok(CertRow {
        id: r.get(0)?,
        name: r.get(1)?,
        key_id: r.get(2)?,
        issuer_id: r.get(3)?,
        template: r.get(4)?,
        is_ca: r.get::<_, i64>(5)? != 0,
        subject: r.get(6)?,
        issuer: r.get(7)?,
        serial: r.get(8)?,
        sig_algorithm: r.get(9)?,
        key_algorithm: r.get(10)?,
        not_before: r.get(11)?,
        not_after: r.get(12)?,
        fingerprint_sha256: r.get(13)?,
        pem: r.get(14)?,
        created_at: r.get(15)?,
        profile: r
            .get::<_, Option<String>>(16)?
            .and_then(|j| serde_json::from_str(&j).ok()),
        revoked_at: r.get(17)?,
        revocation_reason: r.get(18)?,
    })
}

fn crl_row(r: &Row) -> rusqlite::Result<CrlRow> {
    Ok(CrlRow {
        id: r.get(0)?,
        issuer_id: r.get(1)?,
        number: r.get(2)?,
        this_update: r.get(3)?,
        next_update: r.get(4)?,
        revoked_count: r.get(5)?,
        pem: r.get(6)?,
        created_at: r.get(7)?,
    })
}

fn template_row(r: &Row) -> rusqlite::Result<TemplateRow> {
    let json: String = r.get(2)?;
    Ok(TemplateRow {
        id: r.get(0)?,
        name: r.get(1)?,
        profile: serde_json::from_str(&json).unwrap_or_default(),
        created_at: r.get(3)?,
    })
}

fn csr_row(r: &Row) -> rusqlite::Result<CsrRow> {
    Ok(CsrRow {
        id: r.get(0)?,
        name: r.get(1)?,
        key_id: r.get(2)?,
        subject: r.get(3)?,
        key_algorithm: r.get(4)?,
        pem: r.get(5)?,
        signed_cert_id: r.get(6)?,
        created_at: r.get(7)?,
    })
}

impl Db {
    // ---- keys -------------------------------------------------------------

    pub fn insert_key(
        &self,
        name: &str,
        algorithm: &str,
        public_pem: &str,
        private_pem_enc: Option<&str>,
    ) -> Result<i64> {
        if self.key_name_exists(name)? {
            return Err(Error::validation("key_name_exists"));
        }
        self.conn.execute(
            "INSERT INTO keys(name, algorithm, public_pem, private_pem_enc, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![name, algorithm, public_pem, private_pem_enc, now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn key_name_exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM keys WHERE name = ?1", [name], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {KEY_COLS} FROM keys k ORDER BY k.id"))?;
        let rows = st.query_map([], key_row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn get_key(&self, id: i64) -> Result<KeyRow> {
        self.conn
            .query_row(
                &format!("SELECT {KEY_COLS} FROM keys k WHERE k.id = ?1"),
                [id],
                key_row,
            )
            .optional()?
            .ok_or(Error::NotFound("key"))
    }

    pub fn find_key_by_public(&self, public_pem: &str) -> Result<Option<KeyRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {KEY_COLS} FROM keys k WHERE k.public_pem = ?1"),
                [public_pem],
                key_row,
            )
            .optional()?)
    }

    pub fn set_key_private(&self, id: i64, private_pem_enc: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE keys SET private_pem_enc = ?1 WHERE id = ?2",
            params![private_pem_enc, id],
        )?;
        Ok(())
    }

    pub fn rename_key(&self, id: i64, name: &str) -> Result<()> {
        let current = self.get_key(id)?;
        if current.name != name && self.key_name_exists(name)? {
            return Err(Error::validation("key_name_exists"));
        }
        self.conn
            .execute("UPDATE keys SET name = ?1 WHERE id = ?2", params![name, id])?;
        Ok(())
    }

    /// Deletes a key. Blocked when a CA certificate uses it; references from
    /// other certificates and CSRs are cleared.
    pub fn delete_key(&mut self, id: i64) -> Result<()> {
        self.get_key(id)?;
        let ca_uses: i64 = self.conn.query_row(
            "SELECT count(*) FROM certificates WHERE key_id = ?1 AND is_ca = 1",
            [id],
            |r| r.get(0),
        )?;
        if ca_uses > 0 {
            return Err(Error::validation("key_used_by_ca"));
        }
        let tx = self.conn.transaction()?;
        tx.execute("UPDATE certificates SET key_id = NULL WHERE key_id = ?1", [id])?;
        tx.execute("UPDATE csrs SET key_id = NULL WHERE key_id = ?1", [id])?;
        tx.execute("DELETE FROM keys WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    // ---- certificates -----------------------------------------------------

    pub fn insert_cert(&self, c: &NewCert) -> Result<i64> {
        let dup: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM certificates WHERE fingerprint_sha256 = ?1",
                [&c.fingerprint_sha256],
                |r| r.get(0),
            )
            .optional()?;
        if dup.is_some() {
            return Err(Error::validation("cert_exists"));
        }
        self.conn.execute(
            "INSERT INTO certificates(name, key_id, issuer_id, template, is_ca, subject, issuer,
               serial, sig_algorithm, key_algorithm, not_before, not_after, fingerprint_sha256,
               pem, created_at, profile_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                c.name,
                c.key_id,
                c.issuer_id,
                c.template,
                c.is_ca as i64,
                c.subject,
                c.issuer,
                c.serial,
                c.sig_algorithm,
                c.key_algorithm,
                c.not_before,
                c.not_after,
                c.fingerprint_sha256,
                c.pem,
                now(),
                c.profile
                    .as_ref()
                    .map(|p| serde_json::to_string(p).expect("profile serializes"))
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_certs(&self) -> Result<Vec<CertRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {CERT_COLS} FROM certificates ORDER BY id"))?;
        let rows = st.query_map([], cert_row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn get_cert(&self, id: i64) -> Result<CertRow> {
        self.conn
            .query_row(
                &format!("SELECT {CERT_COLS} FROM certificates WHERE id = ?1"),
                [id],
                cert_row,
            )
            .optional()?
            .ok_or(Error::NotFound("certificate"))
    }

    pub fn set_cert_issuer(&self, id: i64, issuer_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE certificates SET issuer_id = ?1 WHERE id = ?2",
            params![issuer_id, id],
        )?;
        Ok(())
    }

    pub fn set_cert_key(&self, id: i64, key_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE certificates SET key_id = ?1 WHERE id = ?2",
            params![key_id, id],
        )?;
        Ok(())
    }

    /// Deletes a certificate that has not issued other certificates.
    ///
    /// A revoked certificate stays on its issuer's future CRLs: the
    /// revocation is archived before the row goes. Deleting a CA also deletes
    /// its CRLs and archived revocations, which nothing else can sign again.
    pub fn delete_cert(&mut self, id: i64) -> Result<()> {
        let cert = self.get_cert(id)?;
        let children: i64 = self.conn.query_row(
            "SELECT count(*) FROM certificates WHERE issuer_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        if children > 0 {
            return Err(Error::validation("cert_has_children"));
        }
        let tx = self.conn.transaction()?;
        if let (Some(issuer_id), Some(revoked_at)) = (cert.issuer_id, &cert.revoked_at) {
            tx.execute(
                "INSERT INTO revocation_archive(issuer_id, serial, not_after, revoked_at, reason, archived_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    issuer_id,
                    cert.serial,
                    cert.not_after,
                    revoked_at,
                    cert.revocation_reason.as_deref().unwrap_or("unspecified"),
                    now()
                ],
            )?;
        }
        tx.execute("DELETE FROM crls WHERE issuer_id = ?1", [id])?;
        tx.execute("DELETE FROM crl_counters WHERE issuer_id = ?1", [id])?;
        tx.execute("DELETE FROM revocation_archive WHERE issuer_id = ?1", [id])?;
        tx.execute(
            "UPDATE csrs SET signed_cert_id = NULL WHERE signed_cert_id = ?1",
            [id],
        )?;
        tx.execute("DELETE FROM certificates WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    // ---- CSRs -------------------------------------------------------------

    pub fn insert_csr(
        &self,
        name: &str,
        key_id: Option<i64>,
        subject: &str,
        key_algorithm: &str,
        pem: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO csrs(name, key_id, subject, key_algorithm, pem, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, key_id, subject, key_algorithm, pem, now()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_csrs(&self) -> Result<Vec<CsrRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {CSR_COLS} FROM csrs ORDER BY id"))?;
        let rows = st.query_map([], csr_row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn get_csr(&self, id: i64) -> Result<CsrRow> {
        self.conn
            .query_row(
                &format!("SELECT {CSR_COLS} FROM csrs WHERE id = ?1"),
                [id],
                csr_row,
            )
            .optional()?
            .ok_or(Error::NotFound("csr"))
    }

    pub fn set_csr_signed(&self, id: i64, cert_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE csrs SET signed_cert_id = ?1 WHERE id = ?2",
            params![cert_id, id],
        )?;
        Ok(())
    }

    pub fn delete_csr(&self, id: i64) -> Result<()> {
        self.get_csr(id)?;
        self.conn.execute("DELETE FROM csrs WHERE id = ?1", [id])?;
        Ok(())
    }

    // ---- revocation -------------------------------------------------------

    pub fn set_revocation(&self, id: i64, revocation: Option<(&str, &str)>) -> Result<()> {
        self.get_cert(id)?;
        let (at, reason) = revocation.unzip();
        self.conn.execute(
            "UPDATE certificates SET revoked_at = ?1, revocation_reason = ?2 WHERE id = ?3",
            params![at, reason, id],
        )?;
        Ok(())
    }

    /// Entries for the next CRL of `issuer_id`: its revoked certificates,
    /// including deleted ones, in revocation order.
    pub fn revocation_entries(&self, issuer_id: i64) -> Result<Vec<RevocationEntry>> {
        let mut st = self.conn.prepare(
            "SELECT serial, not_after, revoked_at, COALESCE(revocation_reason, 'unspecified')
               FROM certificates WHERE issuer_id = ?1 AND revoked_at IS NOT NULL
             UNION ALL
             SELECT serial, not_after, revoked_at, reason
               FROM revocation_archive WHERE issuer_id = ?1
             ORDER BY 3",
        )?;
        let rows = st
            .query_map([issuer_id], |r| {
                Ok(RevocationEntry {
                    serial: r.get(0)?,
                    not_after: r.get(1)?,
                    revoked_at: r.get(2)?,
                    reason: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    // ---- templates --------------------------------------------------------

    pub fn list_templates(&self) -> Result<Vec<TemplateRow>> {
        let mut st = self
            .conn
            .prepare("SELECT id, name, profile_json, created_at FROM templates ORDER BY name")?;
        let rows = st.query_map([], template_row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn get_template(&self, id: i64) -> Result<TemplateRow> {
        self.conn
            .query_row(
                "SELECT id, name, profile_json, created_at FROM templates WHERE id = ?1",
                [id],
                template_row,
            )
            .optional()?
            .ok_or(Error::NotFound("template"))
    }

    /// Inserts (id = None) or updates a user template.
    pub fn save_template(&self, id: Option<i64>, name: &str, profile_json: &str) -> Result<i64> {
        let clash: Option<i64> = self
            .conn
            .query_row("SELECT id FROM templates WHERE name = ?1", [name], |r| r.get(0))
            .optional()?;
        if clash.is_some_and(|c| Some(c) != id) {
            return Err(Error::validation("template_name_exists"));
        }
        match id {
            Some(id) => {
                self.get_template(id)?;
                self.conn.execute(
                    "UPDATE templates SET name = ?1, profile_json = ?2 WHERE id = ?3",
                    params![name, profile_json, id],
                )?;
                Ok(id)
            }
            None => {
                self.conn.execute(
                    "INSERT INTO templates(name, profile_json, created_at) VALUES(?1, ?2, ?3)",
                    params![name, profile_json, now()],
                )?;
                Ok(self.conn.last_insert_rowid())
            }
        }
    }

    pub fn delete_template(&self, id: i64) -> Result<()> {
        self.get_template(id)?;
        self.conn.execute("DELETE FROM templates WHERE id = ?1", [id])?;
        Ok(())
    }

    // ---- CRLs -------------------------------------------------------------

    pub fn next_crl_number(&self, issuer_id: i64) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT MAX(
               COALESCE((SELECT last_number FROM crl_counters WHERE issuer_id = ?1), 0),
               COALESCE((SELECT MAX(number) FROM crls WHERE issuer_id = ?1), 0)
             ) + 1",
            [issuer_id],
            |r| r.get(0),
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_crl(
        &self,
        issuer_id: i64,
        number: i64,
        this_update: &str,
        next_update: &str,
        revoked_count: i64,
        pem: &str,
    ) -> Result<i64> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO crls(issuer_id, number, this_update, next_update, revoked_count, pem, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                issuer_id,
                number,
                this_update,
                next_update,
                revoked_count,
                pem,
                now()
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO crl_counters(issuer_id, last_number) VALUES(?1, ?2)
             ON CONFLICT(issuer_id) DO UPDATE SET last_number = MAX(last_number, excluded.last_number)",
            params![issuer_id, number],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn list_crls(&self) -> Result<Vec<CrlRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {CRL_COLS} FROM crls ORDER BY issuer_id, number"))?;
        let rows = st.query_map([], crl_row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    pub fn get_crl(&self, id: i64) -> Result<CrlRow> {
        self.conn
            .query_row(
                &format!("SELECT {CRL_COLS} FROM crls WHERE id = ?1"),
                [id],
                crl_row,
            )
            .optional()?
            .ok_or(Error::NotFound("crl"))
    }

    pub fn latest_crl(&self, issuer_id: i64) -> Result<Option<CrlRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {CRL_COLS} FROM crls WHERE issuer_id = ?1 ORDER BY number DESC LIMIT 1"),
                [issuer_id],
                crl_row,
            )
            .optional()?)
    }

    pub fn delete_crl(&self, id: i64) -> Result<()> {
        self.get_crl(id)?;
        self.conn.execute("DELETE FROM crls WHERE id = ?1", [id])?;
        Ok(())
    }
}
