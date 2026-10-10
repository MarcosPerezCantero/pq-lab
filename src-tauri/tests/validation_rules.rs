//! Validation negatives.

mod common;

use common::Lab;
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::profile::{preset, KeyUsage};

#[test]
fn ml_kem_cannot_be_ca_or_self_signed() {
    let lab = Lab::new();
    let kem = lab.key("kem", Algorithm::MlKem768);
    let root = preset("root").unwrap().profile;
    assert_eq!(
        lab.issue("kem root", kem, None, root.clone()).unwrap_err().code(),
        "kem_cannot_be_ca"
    );
    let r = lab.root("Root", Algorithm::MlDsa44);
    let inter = preset("intermediate").unwrap().profile;
    assert_eq!(
        lab.issue("kem inter", kem, Some(r.id), inter).unwrap_err().code(),
        "kem_cannot_be_ca"
    );
    let kem_profile = preset("kem").unwrap().profile;
    assert_eq!(
        lab.issue("kem self", kem, None, kem_profile).unwrap_err().code(),
        "kem_cannot_self_sign"
    );
    assert_eq!(lab.pki.list_certs().unwrap().len(), 1);
}

#[test]
fn key_usage_must_match_algorithm() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa44);
    let dsa = lab.key("dsa", Algorithm::MlDsa44);
    let kem = lab.key("kem", Algorithm::MlKem512);
    // ML-DSA with keyEncipherment (the old "ML-KEM template with ML-DSA key").
    let kem_profile = preset("kem").unwrap().profile;
    let err = lab.issue("x", dsa, Some(r.id), kem_profile).unwrap_err();
    assert_eq!(err.code(), "ku_not_allowed");
    // ML-KEM with digitalSignature.
    let client = preset("client").unwrap().profile;
    let err = lab.issue("y", kem, Some(r.id), client).unwrap_err();
    assert_eq!(err.code(), "ku_not_allowed");
    for bad in [KeyUsage::KeyAgreement, KeyUsage::DataEncipherment] {
        let mut p = preset("client").unwrap().profile;
        p.key_usage.push(bad);
        assert_eq!(
            lab.issue("z", dsa, Some(r.id), p).unwrap_err().code(),
            "ku_not_allowed"
        );
    }
}

#[test]
fn kem_subject_must_be_ascii() {
    let lab = Lab::new();
    let root = lab.root("Root", Algorithm::MlDsa44);
    let kem = lab.key("kem", Algorithm::MlKem512);
    let req = pqlab_lib::pki::IssueRequest {
        name: "kem".into(),
        key_id: kem,
        issuer_id: Some(root.id),
        subject: pqlab_lib::validation::SubjectInput::cn("cañón"),
        profile: preset("kem").unwrap().profile,
        validity: Default::default(),
        template: "kem".into(),
    };
    assert_eq!(
        lab.pki.issue_certificate(&req).unwrap_err().code(),
        "subject_ascii_only"
    );
}

#[test]
fn server_requires_valid_san() {
    let lab = Lab::new();
    let root = lab.root("Root", Algorithm::MlDsa44);
    let k = lab.key("srv", Algorithm::MlDsa44);
    let mut p = preset("server").unwrap().profile;
    assert_eq!(
        lab.issue("s", k, Some(root.id), p.clone()).unwrap_err().code(),
        "server_requires_san"
    );
    p.san = vec!["bad host".into()];
    assert_eq!(
        lab.issue("s", k, Some(root.id), p.clone()).unwrap_err().code(),
        "san_invalid"
    );
    p.san = vec!["x\nDNS.2 = evil".into()];
    assert_eq!(
        lab.issue("s", k, Some(root.id), p.clone()).unwrap_err().code(),
        "san_invalid"
    );
    p.san = vec!["ok.lab".into(), "10.1.2.3".into()];
    lab.issue("s", k, Some(root.id), p).unwrap();
}

#[test]
fn intermediate_respects_path_len() {
    let lab = Lab::new();
    let root = lab.root("Root", Algorithm::MlDsa65);
    let i = lab.intermediate("Inter", Algorithm::MlDsa65, root.id);
    let k = lab.key("sub", Algorithm::MlDsa65);
    let inter = preset("intermediate").unwrap().profile;
    assert_eq!(
        lab.issue("Sub", k, Some(i.id), inter.clone()).unwrap_err().code(),
        "pathlen_violation"
    );
    let mut p1 = inter.clone();
    p1.path_len = Some(1);
    let i2 = lab.cert_with("Inter2", Algorithm::MlDsa65, Some(root.id), p1);
    let mut p5 = inter;
    p5.path_len = Some(5);
    let i3 = lab.cert_with("Inter3", Algorithm::MlDsa65, Some(i2.id), p5);
    assert!(i3
        .warnings
        .iter()
        .any(|w| w.code == pqlab_lib::validation::WARN_PATHLEN_CLIPPED));
    assert!(common::cert_text(&lab.pem(i3.id)).contains("pathlen:0"));
    assert!(lab.pki.verify_chain(i3.id).unwrap().ok);
}

#[test]
fn issuing_requires_unlocked_db_valid_ca_and_private_key() {
    let mut lab = Lab::new();
    let root = lab.root("Root", Algorithm::MlDsa44);
    let leaf = lab.cert("leaf", Algorithm::MlDsa44, Some(root.id), "client");
    let k2 = lab.key("leaf2", Algorithm::MlDsa44);
    let client = preset("client").unwrap().profile;
    assert_eq!(
        lab.issue("x", k2, Some(leaf.id), client.clone())
            .unwrap_err()
            .code(),
        "issuer_not_ca"
    );
    let src = Lab::new();
    let ext = src.root("Ext", Algorithm::MlDsa44);
    let imported = lab.pki.import_certificate("ext", &src.pem(ext.id)).unwrap();
    assert_eq!(
        lab.issue("x", k2, Some(imported.id), client.clone())
            .unwrap_err()
            .code(),
        "issuer_no_private"
    );
    // Revoked CA.
    let inter = lab.intermediate("Inter", Algorithm::MlDsa44, root.id);
    lab.pki.revoke_certificate(inter.id, "keyCompromise").unwrap();
    assert_eq!(
        lab.issue("x", k2, Some(inter.id), client.clone())
            .unwrap_err()
            .code(),
        "issuer_revoked"
    );
    lab.pki.lock();
    assert_eq!(
        lab.issue("x", k2, Some(root.id), client).unwrap_err().code(),
        "locked"
    );
    assert_eq!(lab.pki.list_certs().unwrap_err().code(), "locked");
}

#[test]
fn start_date_after_issuer_expiry_is_rejected() {
    let lab = common::Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa44);
    let key = lab.key("late", Algorithm::MlDsa44);
    let err = lab
        .pki
        .issue_certificate(&pqlab_lib::pki::IssueRequest {
            name: "late".into(),
            key_id: key,
            issuer_id: Some(r.id),
            subject: pqlab_lib::validation::SubjectInput::cn("late"),
            profile: pqlab_lib::profile::preset("client").unwrap().profile,
            validity: pqlab_lib::pki::Validity {
                days: Some(10),
                not_before: Some("2090-01-01".into()),
                not_after: None,
            },
            template: "custom".into(),
        })
        .unwrap_err();
    assert_eq!(err.code(), "validity_after_issuer");
}
