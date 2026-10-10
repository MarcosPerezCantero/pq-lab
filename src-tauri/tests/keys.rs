//! Keys of every algorithm, plus import/export round trips.

mod common;

use common::{run_in, Lab, MASTER};
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::security::Secret;

/// Independent algorithm detection with `openssl pkey -text`.
fn openssl_key_text(private_enc: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("k.pem"), private_enc).unwrap();
    let (ok, out) = run_in(
        dir.path(),
        &[
            "pkey",
            "-in",
            "k.pem",
            "-passin",
            &format!("pass:{MASTER}"),
            "-noout",
            "-text_pub",
        ],
    );
    assert!(ok, "{out}");
    out
}

#[test]
fn generates_every_algorithm() {
    let lab = Lab::new();
    for &alg in Algorithm::ALL {
        let id = lab.key(alg.id(), alg);
        let keys = lab.pki.list_keys().unwrap();
        let row = keys.iter().find(|k| k.id == id).unwrap();
        assert_eq!(row.algorithm, alg.id());
        let enc = lab
            .pki
            .export_private_key(id, &Secret::new("export-pass-1"))
            .unwrap();
        assert!(enc.contains("BEGIN ENCRYPTED PRIVATE KEY"));
        // The stored key is encrypted with the master password.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("e.pem"), &enc).unwrap();
        let (ok, text) = run_in(
            dir.path(),
            &[
                "pkey",
                "-in",
                "e.pem",
                "-passin",
                "pass:export-pass-1",
                "-noout",
                "-text_pub",
            ],
        );
        assert!(ok, "{text}");
        assert_eq!(Algorithm::detect_from_key_text(&text), Some(alg), "{text}");
        let pub_text = openssl_key_text(&row_private(&lab, id));
        assert_eq!(Algorithm::detect_from_key_text(&pub_text), Some(alg));
        lab.assert_tmp_clean();
    }
}

fn row_private(lab: &Lab, id: i64) -> String {
    // Re-export under the master password to get the stored ciphertext shape.
    lab.pki.export_private_key(id, &Secret::new(MASTER)).unwrap()
}

#[test]
fn import_clear_encrypted_and_public_keys() {
    let lab = Lab::new();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert!(run_in(d, &["genpkey", "-algorithm", "ML-DSA-44", "-out", "clear.pem"]).0);
    assert!(
        run_in(
            d,
            &[
                "genpkey",
                "-algorithm",
                "SLH-DSA-SHAKE-192f",
                "-aes-256-cbc",
                "-pass",
                "pass:imp-pass-1",
                "-out",
                "enc.pem"
            ]
        )
        .0
    );
    assert!(run_in(d, &["genpkey", "-algorithm", "ML-KEM-1024", "-out", "kem.pem"]).0);
    assert!(run_in(d, &["pkey", "-in", "kem.pem", "-pubout", "-out", "kem_pub.pem"]).0);
    let read = |n: &str| std::fs::read_to_string(d.join(n)).unwrap();

    let a = lab.pki.import_key("clear", &read("clear.pem"), None).unwrap();
    let e = lab
        .pki
        .import_key("enc", &read("enc.pem"), Some(Secret::new("imp-pass-1")))
        .unwrap();
    let p = lab.pki.import_key("kem-pub", &read("kem_pub.pem"), None).unwrap();
    let keys = lab.pki.list_keys().unwrap();
    let get = |id| keys.iter().find(|k| k.id == id).unwrap();
    assert_eq!(get(a).algorithm, "ML-DSA-44");
    assert!(get(a).has_private);
    assert_eq!(get(e).algorithm, "SLH-DSA-SHAKE-192f");
    assert!(get(e).has_private);
    assert_eq!(get(p).algorithm, "ML-KEM-1024");
    assert!(!get(p).has_private);

    // Wrong or missing import password.
    let err = lab
        .pki
        .import_key("enc2", &read("enc.pem"), Some(Secret::new("nope-nope")))
        .unwrap_err();
    assert_eq!(err.code(), "import_key_failed");
    let err = lab.pki.import_key("enc3", &read("enc.pem"), None).unwrap_err();
    assert_eq!(err.code(), "import_password_required");
    // Same key twice.
    let err = lab.pki.import_key("again", &read("clear.pem"), None).unwrap_err();
    assert_eq!(err.code(), "key_exists");
    // Importing the private half of a public-only key completes it.
    let full = lab.pki.import_key("kem-full", &read("kem.pem"), None).unwrap();
    assert_eq!(full, p);
    assert!(
        lab.pki
            .list_keys()
            .unwrap()
            .iter()
            .find(|k| k.id == p)
            .unwrap()
            .has_private
    );
    lab.assert_tmp_clean();
    assert!(common::find_plain_private_keys(&lab.data_dir()).is_empty());
}

#[test]
fn rename_and_delete_keys() {
    let lab = Lab::new();
    let id = lab.key("k1", Algorithm::MlDsa44);
    lab.key("k2", Algorithm::MlDsa44);
    assert_eq!(
        lab.pki.rename_key(id, "k2").unwrap_err().code(),
        "key_name_exists"
    );
    lab.pki.rename_key(id, "renamed").unwrap();
    let mut lab = lab;
    lab.pki.delete_key(id).unwrap();
    assert!(lab.pki.list_keys().unwrap().iter().all(|k| k.id != id));
    // A key used by a CA cannot be deleted.
    let root = lab.root("Root", Algorithm::MlDsa44);
    let cert = lab
        .pki
        .list_certs()
        .unwrap()
        .into_iter()
        .find(|c| c.id == root.id)
        .unwrap();
    assert_eq!(
        lab.pki.delete_key(cert.key_id.unwrap()).unwrap_err().code(),
        "key_used_by_ca"
    );
}

#[test]
fn exported_public_key_matches() {
    let lab = Lab::new();
    let id = lab.key("k", Algorithm::SlhDsaShake128f);
    let pem = lab.pki.export_public_key(id).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("p.pem"), &pem).unwrap();
    let (ok, text) = run_in(dir.path(), &["pkey", "-pubin", "-in", "p.pem", "-noout", "-text"]);
    assert!(ok);
    assert!(text.contains("SLH-DSA-SHAKE-128f Public-Key"));
}

#[test]
fn classical_keys_are_rejected() {
    let lab = Lab::new();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for (n, args) in [
        (
            "rsa.pem",
            vec![
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                "rsa.pem",
            ],
        ),
        (
            "ec.pem",
            vec![
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "ec.pem",
            ],
        ),
        (
            "ed.pem",
            vec!["genpkey", "-algorithm", "ED25519", "-out", "ed.pem"],
        ),
    ] {
        assert!(run_in(d, &args).0);
        let pem = std::fs::read_to_string(d.join(n)).unwrap();
        let err = lab.pki.import_key(n, &pem, None).unwrap_err();
        assert_eq!(err.code(), "algorithm_unsupported", "{n}");
    }
    assert!(lab.pki.list_keys().unwrap().is_empty());
    lab.assert_tmp_clean();
}
