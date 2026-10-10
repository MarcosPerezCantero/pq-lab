//! Self-signed roots, full chains, chain export and renewal.

mod common;

use common::{cert_text, external_verify, has_warning, run_in, Lab};
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::pki::Validity;

#[test]
fn self_signed_root_for_every_ca_algorithm() {
    let lab = Lab::new();
    for &alg in Algorithm::ALL.iter().filter(|a| a.can_be_ca()) {
        let root = lab.root(&format!("Root {}", alg.id()), alg);
        let pem = lab.pem(root.id);
        let (ok, out) = external_verify(&pem, &[], &pem);
        assert!(ok, "{}: {out}", alg.id());
        let text = cert_text(&pem);
        assert!(text.contains("CA:TRUE"), "{text}");
        assert!(text.contains("Certificate Sign, CRL Sign"));
        assert!(
            text.contains(&format!("Signature Algorithm: {}", alg.id())),
            "{text}"
        );
        lab.assert_tmp_clean();
    }
}

/// Builds root → intermediate → leaf and verifies it externally.
fn chain(root: Algorithm, inter: Algorithm, leaf: Algorithm, preset: &str) -> (Lab, i64) {
    let lab = Lab::new();
    let r = lab.root("Root", root);
    let i = lab.intermediate("Intermediate", inter, r.id);
    let l = lab.cert("leaf.lab", leaf, Some(i.id), preset);
    let (ok, out) = external_verify(&lab.pem(r.id), &[lab.pem(i.id)], &lab.pem(l.id));
    assert!(ok, "{out}");
    assert!(out.contains("leaf.pem: OK"));
    let v = lab.pki.verify_chain(l.id).unwrap();
    assert!(v.ok, "{}", v.output);
    assert_eq!(v.chain, vec!["leaf.lab", "Intermediate", "Root"]);
    lab.assert_tmp_clean();
    (lab, l.id)
}

#[test]
fn chain_ml_dsa_87_65_44() {
    let (lab, leaf) = chain(
        Algorithm::MlDsa87,
        Algorithm::MlDsa65,
        Algorithm::MlDsa44,
        "server",
    );
    let text = cert_text(&lab.pem(leaf));
    assert!(text.contains("Signature Algorithm: ML-DSA-65"));
    assert!(text.contains("Public Key Algorithm: ML-DSA-44"));
    assert!(text.contains("TLS Web Server Authentication"));
    assert!(text.contains("DNS:leaf.lab"));
    assert!(!text.contains("Key Encipherment"));
}

#[test]
fn chain_slh_dsa_root_ml_dsa() {
    chain(
        Algorithm::SlhDsaSha2_128s,
        Algorithm::MlDsa65,
        Algorithm::MlDsa65,
        "server",
    );
}

#[test]
fn chain_ml_dsa_with_ml_kem_leaf() {
    let (lab, leaf) = chain(Algorithm::MlDsa65, Algorithm::MlDsa65, Algorithm::MlKem768, "kem");
    let text = cert_text(&lab.pem(leaf));
    assert!(text.contains("Public Key Algorithm: ML-KEM-768"));
    assert!(text.contains("Key Encipherment"));
    assert!(text.contains("CA:FALSE"));
}

#[test]
fn chain_slh_dsa_shake_sha2_ml_dsa() {
    chain(
        Algorithm::SlhDsaShake256f,
        Algorithm::SlhDsaSha2_192s,
        Algorithm::MlDsa87,
        "client",
    );
}

#[test]
fn every_preset_issues_and_verifies() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    for p in pqlab_lib::profile::presets()
        .iter()
        .filter(|p| !p.profile.ca || p.id == "intermediate")
    {
        let alg = if p.kem {
            Algorithm::MlKem512
        } else {
            Algorithm::MlDsa44
        };
        let c = lab.cert(&format!("{}.lab", p.id.replace('_', "-")), alg, Some(r.id), p.id);
        let (ok, out) = external_verify(&lab.pem(r.id), &[], &lab.pem(c.id));
        assert!(ok, "{}: {out}", p.id);
    }
}

#[test]
fn exported_chain_verifies_from_clean_directory() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa87);
    let i1 = lab.intermediate("Inter 1", Algorithm::MlDsa65, r.id);
    let l = lab.cert("kem.lab", Algorithm::MlKem768, Some(i1.id), "kem");
    let chain = lab.pki.export_chain(l.id).unwrap();
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 3);

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("chain.pem"), &chain).unwrap();
    let der = lab
        .pki
        .export_certificate(r.id, pqlab_lib::pki::CertFormat::Der)
        .unwrap();
    std::fs::write(d.join("root.der"), der).unwrap();
    assert!(
        run_in(
            d,
            &["x509", "-inform", "DER", "-in", "root.der", "-out", "root.pem"]
        )
        .0
    );
    let blocks: Vec<String> = chain
        .split_inclusive("-----END CERTIFICATE-----\n")
        .map(String::from)
        .collect();
    std::fs::write(d.join("leaf.pem"), &blocks[0]).unwrap();
    std::fs::write(d.join("inter.pem"), &blocks[1]).unwrap();
    let (ok, out) = run_in(
        d,
        &[
            "verify",
            "-CAfile",
            "root.pem",
            "-untrusted",
            "inter.pem",
            "leaf.pem",
        ],
    );
    assert!(ok, "{out}");
    assert!(out.contains("leaf.pem: OK"));
}

#[test]
fn validity_is_clipped_to_issuer_and_dates_are_exact() {
    let lab = Lab::new();
    let key = lab.key("rk", Algorithm::MlDsa44);
    let mut req = pqlab_lib::pki::IssueRequest {
        name: "Short Root".into(),
        key_id: key,
        issuer_id: None,
        subject: pqlab_lib::validation::SubjectInput::cn("Short Root"),
        profile: pqlab_lib::profile::preset("root").unwrap().profile,
        validity: Validity {
            days: None,
            not_before: Some("2026-01-01".into()),
            not_after: Some("2031-06-30".into()),
        },
        template: "root".into(),
    };
    let r = lab.pki.issue_certificate(&req).unwrap();
    let root = lab.pki.view_certificate(r.id).unwrap().row;
    assert_eq!(root.not_before, "2026-01-01T00:00:00Z");
    assert_eq!(root.not_after, "2031-06-30T23:59:59Z");

    req.name = "Inter".into();
    req.key_id = lab.key("ik", Algorithm::MlDsa44);
    req.issuer_id = Some(r.id);
    req.profile = pqlab_lib::profile::preset("intermediate").unwrap().profile;
    req.validity = Validity::days(3650);
    let i = lab.pki.issue_certificate(&req).unwrap();
    assert!(has_warning(&i, pqlab_lib::validation::WARN_VALIDITY_CLIPPED));
    let inter = lab.pki.view_certificate(i.id).unwrap().row;
    assert_eq!(inter.not_after, root.not_after);

    req.validity = Validity {
        days: None,
        not_before: Some("2027-01-01".into()),
        not_after: Some("2026-01-01".into()),
    };
    assert_eq!(
        lab.pki.issue_certificate(&req).unwrap_err().code(),
        "validity_invalid"
    );
}

#[test]
fn renewal_keeps_subject_key_and_extensions() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    let l = lab.cert("srv.lab", Algorithm::MlDsa44, Some(r.id), "server");
    let k = lab.cert("kem.lab", Algorithm::MlKem768, Some(r.id), "kem");
    for old_id in [l.id, k.id, r.id] {
        let old = lab.pki.view_certificate(old_id).unwrap();
        let renewed = lab.pki.renew_certificate(old_id, &Validity::days(90)).unwrap();
        let new = lab.pki.view_certificate(renewed.id).unwrap();
        assert_ne!(new.row.serial, old.row.serial);
        assert_eq!(new.row.subject, old.row.subject);
        assert_eq!(new.row.key_id, old.row.key_id);
        assert_eq!(new.row.issuer_id, old.row.issuer_id);
        assert_eq!(new.info.key_usage, old.info.key_usage);
        assert_eq!(new.info.ext_key_usage, old.info.ext_key_usage);
        assert_eq!(new.info.sans, old.info.sans);
        let pk = |pem: &str| {
            let d = tempfile::tempdir().unwrap();
            std::fs::write(d.path().join("c.pem"), pem).unwrap();
            run_in(d.path(), &["x509", "-in", "c.pem", "-noout", "-pubkey"]).1
        };
        assert_eq!(pk(&new.row.pem), pk(&old.row.pem));
        let root_pem = if old_id == r.id {
            new.row.pem.clone()
        } else {
            lab.pem(r.id)
        };
        let (ok, out) = external_verify(&root_pem, &[], &new.row.pem);
        assert!(ok, "{out}");
        lab.assert_tmp_clean();
    }
}

#[test]
fn import_certificate_links_issuer_and_key() {
    let src = Lab::new();
    let r = src.root("Ext Root", Algorithm::MlDsa65);
    let l = src.cert("ext.lab", Algorithm::MlDsa44, Some(r.id), "server");

    let lab = Lab::new();
    let leaf = lab.pki.import_certificate("leaf", &src.pem(l.id)).unwrap();
    let root = lab.pki.import_certificate("root", &src.pem(r.id)).unwrap();
    let certs = lab.pki.list_certs().unwrap();
    assert_eq!(
        certs.iter().find(|c| c.id == leaf.id).unwrap().issuer_id,
        Some(root.id)
    );
    assert_eq!(
        certs.iter().find(|c| c.id == root.id).unwrap().template,
        "imported"
    );
    assert!(lab.pki.verify_chain(leaf.id).unwrap().ok);
    let dup = lab.pki.import_certificate("again", &src.pem(r.id)).unwrap_err();
    assert_eq!(dup.code(), "cert_exists");
    assert_eq!(
        lab.pki
            .renew_certificate(root.id, &Validity::default())
            .unwrap_err()
            .code(),
        "renew_no_profile"
    );
}

#[test]
fn classical_certificates_are_rejected() {
    let lab = Lab::new();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert!(
        run_in(
            d,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "k.pem"
            ]
        )
        .0
    );
    assert!(
        run_in(
            d,
            &["req", "-x509", "-new", "-key", "k.pem", "-subj", "/CN=ec", "-out", "c.pem"]
        )
        .0
    );
    let pem = std::fs::read_to_string(d.join("c.pem")).unwrap();
    assert_eq!(
        lab.pki.import_certificate("ec", &pem).unwrap_err().code(),
        "algorithm_unsupported"
    );
}
