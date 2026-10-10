//! Temporary files, keys at rest, logs and the
//! master password.

mod common;

use common::{find_plain_private_keys, walk, Lab, MASTER};
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::pki::{CsrRequest, Pki};
use pqlab_lib::security::Secret;
use pqlab_lib::validation::SubjectInput;

#[test]
fn no_temp_dirs_no_plain_keys_no_passwords_in_logs() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa87);
    lab.assert_tmp_clean();
    let i = lab.intermediate("Inter", Algorithm::SlhDsaSha2_128f, r.id);
    lab.assert_tmp_clean();
    let srv = lab.cert("srv.lab", Algorithm::MlDsa44, Some(i.id), "server");
    lab.assert_tmp_clean();
    lab.cert("kem.lab", Algorithm::MlKem1024, Some(i.id), "kem");
    lab.assert_tmp_clean();
    lab.pki.revoke_certificate(srv.id, "superseded").unwrap();
    lab.pki.generate_crl(i.id, 7).unwrap();
    lab.assert_tmp_clean();
    lab.pki.renew_certificate(srv.id, &Default::default()).unwrap();
    lab.assert_tmp_clean();
    let p12 = lab
        .pki
        .export_pkcs12(srv.id, &Secret::new("p12-secret-77"), true)
        .unwrap();
    lab.assert_tmp_clean();
    let k = lab.key("csr", Algorithm::MlDsa44);
    lab.pki
        .generate_csr(&CsrRequest {
            name: "csr".into(),
            key_id: k,
            subject: SubjectInput::cn("csr"),
            profile: None,
        })
        .unwrap();
    lab.assert_tmp_clean();
    lab.pki
        .export_private_key(k, &Secret::new("export-secret-9"))
        .unwrap();
    lab.assert_tmp_clean();
    // Clear-text import travels through stdin only.
    let dir = tempfile::tempdir().unwrap();
    assert!(
        common::run_in(
            dir.path(),
            &["genpkey", "-algorithm", "ML-DSA-44", "-out", "c.pem"]
        )
        .0
    );
    let clear = std::fs::read_to_string(dir.path().join("c.pem")).unwrap();
    drop(dir);
    lab.pki.import_key("imported", &clear, None).unwrap();
    lab.assert_tmp_clean();
    let other = Lab::new();
    other
        .pki
        .import_pkcs12("p12", &p12, &Secret::new("p12-secret-77"))
        .unwrap();
    other.assert_tmp_clean();
    assert!(find_plain_private_keys(&other.data_dir()).is_empty());
    lab.pki.verify_chain(r.id).unwrap();
    lab.assert_tmp_clean();

    // An operation that fails inside openssl also cleans up.
    let bad = lab.pki.import_key(
        "bad",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        None,
    );
    assert!(bad.is_err());
    lab.assert_tmp_clean();

    assert!(find_plain_private_keys(&lab.data_dir()).is_empty());
    assert!(find_plain_private_keys(&lab.tmp_root()).is_empty());
    let db = std::fs::read(lab.db_path()).unwrap();
    let db_text = String::from_utf8_lossy(&db);
    assert!(db_text.contains("BEGIN ENCRYPTED PRIVATE KEY"));
    assert!(!db_text.contains(MASTER));

    let log = std::fs::read_to_string(lab.data_dir().join("pqlab.log")).unwrap();
    assert!(log.contains("openssl genpkey"), "log must record invocations");
    for secret in [MASTER, "export-secret-9", "p12-secret-77"] {
        assert!(!log.contains(secret), "password leaked to log");
        for f in walk(&lab.data_dir()) {
            let content = String::from_utf8_lossy(&std::fs::read(&f).unwrap()).into_owned();
            assert!(!content.contains(secret), "password found in {f:?}");
        }
    }
    assert!(!log.contains("PRIVATE KEY"));
}

#[test]
fn wrong_master_password_is_rejected() {
    let lab = Lab::new();
    lab.key("k", Algorithm::MlDsa44);
    let path = lab.db_path();
    let mut pki = Pki::new(common::openssl(), lab.tmp_root());
    let err = pki
        .open_database(&path, Secret::new("not-the-password"))
        .unwrap_err();
    assert_eq!(err.code(), "wrong_password");
    assert_eq!(pki.list_keys().unwrap_err().code(), "locked");
    assert_eq!(
        pki.generate_key("x", Algorithm::MlDsa44).unwrap_err().code(),
        "locked"
    );
    pki.open_database(&path, Secret::new(MASTER)).unwrap();
    assert_eq!(pki.list_keys().unwrap().len(), 1);
}

#[test]
fn database_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.db");
    let mut pki = Pki::new(common::openssl(), dir.path().join("tmp"));
    assert_eq!(
        pki.create_database(&path, Secret::new("short"))
            .unwrap_err()
            .code(),
        "password_too_short"
    );
    pki.create_database(&path, Secret::new(MASTER)).unwrap();
    assert_eq!(
        pki.create_database(&path, Secret::new(MASTER))
            .unwrap_err()
            .code(),
        "db_already_exists"
    );
    pki.lock();
    std::fs::write(dir.path().join("junk.db"), b"not sqlite").unwrap();
    assert!(pki
        .open_database(&dir.path().join("junk.db"), Secret::new(MASTER))
        .is_err());
    assert_eq!(
        pki.open_database(&dir.path().join("missing.db"), Secret::new(MASTER))
            .unwrap_err()
            .code(),
        "db_not_found"
    );
}

#[cfg(unix)]
#[test]
fn work_dirs_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let w = pqlab_lib::security::WorkDir::new(base.path()).unwrap();
    let mode = std::fs::metadata(w.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let p = w.path().to_path_buf();
    drop(w);
    assert!(!p.exists());
}
