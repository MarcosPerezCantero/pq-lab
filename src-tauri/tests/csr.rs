//! External CSRs and tampered CSRs.

mod common;

use common::{cert_text, external_verify, run_in, Lab};
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::pki::{CsrRequest, SignCsrRequest, Validity};
use pqlab_lib::profile::preset;
use pqlab_lib::validation::SubjectInput;

fn external_csr(dir: &std::path::Path) -> String {
    assert!(run_in(dir, &["genpkey", "-algorithm", "ML-DSA-65", "-out", "ext.key"]).0);
    let (ok, out) = run_in(
        dir,
        &[
            "req",
            "-new",
            "-key",
            "ext.key",
            "-subj",
            "/CN=external.lab/O=Outside",
            "-addext",
            "subjectAltName=DNS:external.lab",
            "-out",
            "ext.csr",
        ],
    );
    assert!(ok, "{out}");
    std::fs::read_to_string(dir.join("ext.csr")).unwrap()
}

#[test]
fn import_and_sign_external_ml_dsa_csr() {
    let lab = Lab::new();
    let root = lab.root("Root", Algorithm::MlDsa87);
    let dir = tempfile::tempdir().unwrap();
    let csr_pem = external_csr(dir.path());

    let csr_id = lab.pki.import_csr("external", &csr_pem).unwrap();
    let csr = lab.pki.view_csr(csr_id).unwrap();
    assert_eq!(csr.row.key_algorithm, "ML-DSA-65");
    assert_eq!(csr.row.key_id, None);
    assert_eq!(csr.info.sans, vec!["external.lab"]);

    let mut profile = preset("server").unwrap().profile;
    profile.san = csr.info.sans.clone();
    let issued = lab
        .pki
        .sign_csr(&SignCsrRequest {
            csr_id,
            issuer_id: root.id,
            name: "external.lab".into(),
            profile,
            validity: Validity::days(90),
            template: "server".into(),
        })
        .unwrap();
    let pem = lab.pem(issued.id);
    let (ok, out) = external_verify(&lab.pem(root.id), &[], &pem);
    assert!(ok, "{out}");
    let text = cert_text(&pem);
    assert!(text.contains("Public Key Algorithm: ML-DSA-65"));
    assert!(text.contains("Signature Algorithm: ML-DSA-87"));
    assert!(text.contains("CN=external.lab"));
    assert_eq!(
        lab.pki.view_csr(csr_id).unwrap().row.signed_cert_id,
        Some(issued.id)
    );
    std::fs::write(dir.path().join("issued.pem"), &pem).unwrap();
    let (_, a) = run_in(dir.path(), &["x509", "-in", "issued.pem", "-noout", "-pubkey"]);
    let (_, b) = run_in(dir.path(), &["pkey", "-in", "ext.key", "-pubout"]);
    assert_eq!(a, b);
    lab.assert_tmp_clean();
}

#[test]
fn tampered_csr_is_rejected() {
    let lab = Lab::new();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    external_csr(d);
    assert!(
        run_in(
            d,
            &["req", "-in", "ext.csr", "-outform", "DER", "-out", "ext.der"]
        )
        .0
    );
    let mut der = std::fs::read(d.join("ext.der")).unwrap();
    let pos = der.windows(12).position(|w| w == b"external.lab").unwrap();
    der[pos] = b'f';
    std::fs::write(d.join("bad.der"), &der).unwrap();
    let (ok, out) = run_in(d, &["req", "-inform", "DER", "-in", "bad.der", "-out", "bad.csr"]);
    assert!(ok, "{out}");
    let (verifies, _) = run_in(d, &["req", "-in", "bad.csr", "-noout", "-verify"]);
    assert!(!verifies, "precondition: openssl itself rejects the tampered CSR");
    let err = lab
        .pki
        .import_csr("bad", &std::fs::read_to_string(d.join("bad.csr")).unwrap())
        .unwrap_err();
    assert_eq!(err.code(), "csr_bad_signature");
    assert!(lab.pki.list_csrs().unwrap().is_empty());
    lab.assert_tmp_clean();
}

#[test]
fn generate_own_csr_with_extensions_and_sign_it() {
    let lab = Lab::new();
    let root = lab.root("Root", Algorithm::SlhDsaShake128f);
    let key = lab.key("client-key", Algorithm::MlDsa44);
    let mut requested = preset("smime").unwrap().profile;
    requested.san = vec!["alice@pq.lab".into()];
    let csr_id = lab
        .pki
        .generate_csr(&CsrRequest {
            name: "client csr".into(),
            key_id: key,
            subject: SubjectInput {
                cn: "Año ñandú".into(),
                o: "PQ Lab".into(),
                c: "ES".into(),
                ..Default::default()
            },
            profile: Some(requested.clone()),
        })
        .unwrap();
    let csr = lab.pki.view_csr(csr_id).unwrap();
    assert_eq!(csr.row.key_id, Some(key));
    assert!(csr.row.subject.contains("CN=Año ñandú"), "{}", csr.row.subject);
    assert!(csr.text.contains("Requested Extensions"));
    assert!(csr.text.contains("E-mail Protection"));
    let issued = lab
        .pki
        .sign_csr(&SignCsrRequest {
            csr_id,
            issuer_id: root.id,
            name: "client".into(),
            profile: requested,
            validity: Validity::default(),
            template: "smime".into(),
        })
        .unwrap();
    let cert = lab.pki.view_certificate(issued.id).unwrap();
    assert_eq!(cert.row.key_id, Some(key));
    assert!(cert.text.contains("email:alice@pq.lab"));
    assert!(cert.text.contains("Non Repudiation"));
    let (ok, out) = external_verify(&lab.pem(root.id), &[], &lab.pem(issued.id));
    assert!(ok, "{out}");
}

#[test]
fn ml_kem_key_cannot_generate_csr() {
    let lab = Lab::new();
    let key = lab.key("kem", Algorithm::MlKem512);
    let err = lab
        .pki
        .generate_csr(&CsrRequest {
            name: "x".into(),
            key_id: key,
            subject: SubjectInput::cn("x"),
            profile: None,
        })
        .unwrap_err();
    assert_eq!(err.code(), "kem_no_csr");
}
