//! PKCS#12 export and import.

mod common;

use common::{find_plain_private_keys, run_in, Lab};
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::security::Secret;

#[test]
fn pkcs12_round_trip() {
    let src = Lab::new();
    let r = src.root("Root", Algorithm::MlDsa87);
    let i = src.intermediate("Inter", Algorithm::MlDsa65, r.id);
    let l = src.cert("p12.pq.lab", Algorithm::SlhDsaSha2_128f, Some(i.id), "server");
    let p12 = src
        .pki
        .export_pkcs12(l.id, &Secret::new("p12-pass-123"), true)
        .unwrap();
    src.assert_tmp_clean();

    // External openssl can read it.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("x.p12"), &p12).unwrap();
    let (ok, out) = run_in(
        d,
        &[
            "pkcs12",
            "-in",
            "x.p12",
            "-passin",
            "pass:p12-pass-123",
            "-info",
            "-noout",
        ],
    );
    assert!(ok, "{out}");
    assert!(out.contains("AES-256-CBC"), "{out}");
    let (ok, out) = run_in(
        d,
        &[
            "pkcs12",
            "-in",
            "x.p12",
            "-passin",
            "pass:p12-pass-123",
            "-nokeys",
            "-out",
            "certs.pem",
        ],
    );
    assert!(ok, "{out}");
    let certs = std::fs::read_to_string(d.join("certs.pem")).unwrap();
    assert_eq!(certs.matches("BEGIN CERTIFICATE").count(), 3);

    // Wrong password, then import into a fresh database.
    let dst = Lab::new();
    assert_eq!(
        dst.pki
            .import_pkcs12("p12", &p12, &Secret::new("wrong-pass"))
            .unwrap_err()
            .code(),
        "import_p12_failed"
    );
    let imported = dst
        .pki
        .import_pkcs12("p12.pq.lab", &p12, &Secret::new("p12-pass-123"))
        .unwrap();
    assert_eq!(imported.cert_ids.len(), 3);
    let keys = dst.pki.list_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].algorithm, "SLH-DSA-SHA2-128f");
    assert!(keys[0].has_private);
    let certs = dst.pki.list_certs().unwrap();
    let leaf = certs.iter().find(|c| c.name == "p12.pq.lab").unwrap();
    assert_eq!(leaf.key_id, Some(keys[0].id));
    let v = dst.pki.verify_chain(leaf.id).unwrap();
    assert!(v.ok, "{}", v.output);
    assert_eq!(v.chain.len(), 3);
    dst.assert_tmp_clean();
    assert!(find_plain_private_keys(&dst.data_dir()).is_empty());
    assert!(find_plain_private_keys(&dst.tmp_root()).is_empty());

    // Importing again only reuses what exists.
    let again = dst
        .pki
        .import_pkcs12("p12.pq.lab", &p12, &Secret::new("p12-pass-123"))
        .unwrap();
    assert!(again.cert_ids.is_empty());
    assert_eq!(again.key_id, Some(keys[0].id));
}

#[test]
fn pkcs12_requires_private_key_and_strong_password() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa44);
    assert_eq!(
        lab.pki
            .export_pkcs12(r.id, &Secret::new("short"), false)
            .unwrap_err()
            .code(),
        "password_too_short"
    );
    let src = Lab::new();
    let ext = src.root("Ext", Algorithm::MlDsa44);
    let imported = lab.pki.import_certificate("ext", &src.pem(ext.id)).unwrap();
    assert_eq!(
        lab.pki
            .export_pkcs12(imported.id, &Secret::new("long-enough-1"), false)
            .unwrap_err()
            .code(),
        "key_no_private"
    );
}

#[test]
fn rejected_pkcs12_imports_nothing() {
    // A PQ CA certificate followed by a classic RSA certificate: the CA is
    // imported first, then the RSA one is rejected and everything rolls back.
    let src = Lab::new();
    let r = src.root("Root", Algorithm::MlDsa65);
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("root.pem"), src.pem(r.id)).unwrap();
    let (ok, out) = run_in(
        d,
        &[
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "rsa.key", "-subj", "/CN=rsa",
            "-days", "1", "-out", "rsa.pem",
        ],
    );
    assert!(ok, "{out}");
    let both = std::fs::read_to_string(d.join("root.pem")).unwrap()
        + &std::fs::read_to_string(d.join("rsa.pem")).unwrap();
    std::fs::write(d.join("both.pem"), both).unwrap();
    let (ok, out) = run_in(
        d,
        &[
            "pkcs12",
            "-export",
            "-nokeys",
            "-in",
            "both.pem",
            "-passout",
            "pass:p12-pass-123",
            "-out",
            "m.p12",
        ],
    );
    assert!(ok, "{out}");

    let dst = Lab::new();
    let data = std::fs::read(d.join("m.p12")).unwrap();
    assert!(dst
        .pki
        .import_pkcs12("mixed", &data, &Secret::new("p12-pass-123"))
        .is_err());
    assert!(dst.pki.list_certs().unwrap().is_empty());
    assert!(dst.pki.list_keys().unwrap().is_empty());
}
