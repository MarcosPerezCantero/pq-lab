//! Every profile field reaches the certificate, name
//! constraints are enforced by `openssl verify`, and user templates work.

mod common;

use common::{cert_text, external_verify, Lab};
use pqlab_lib::algorithms::Algorithm;
use pqlab_lib::profile::{preset, CertProfile, KeyUsage};

#[test]
fn every_profile_field_is_rendered() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa87);
    let profile = CertProfile {
        ca: false,
        bc_critical: false,
        key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::NonRepudiation],
        ku_critical: true,
        ext_key_usage: vec![
            "serverAuth".into(),
            "clientAuth".into(),
            "codeSigning".into(),
            "1.3.6.1.5.5.7.3.17".into(),
        ],
        eku_critical: true,
        ski: true,
        aki: true,
        san: vec![
            "www.pq.lab".into(),
            "10.9.8.7".into(),
            "fd00::1".into(),
            "ops@pq.lab".into(),
            "https://pq.lab/id/1".into(),
        ],
        san_critical: false,
        policies: vec!["anyPolicy".into(), "1.3.6.1.4.1.99999.1.2".into()],
        crl_dp: vec!["http://crl.pq.lab/root.crl".into()],
        ocsp: vec!["http://ocsp.pq.lab".into()],
        ca_issuers: vec!["http://pq.lab/root.cer".into()],
        ..Default::default()
    };
    let c = lab.cert_with("full", Algorithm::MlDsa65, Some(r.id), profile);
    let text = cert_text(&lab.pem(c.id));
    for needle in [
        "X509v3 Basic Constraints: \n                CA:FALSE",
        "X509v3 Key Usage: critical\n                Digital Signature, Non Repudiation",
        "X509v3 Extended Key Usage: critical\n                TLS Web Server Authentication, TLS Web Client Authentication, Code Signing, ipsec Internet Key Exchange",
        "X509v3 Subject Key Identifier",
        "X509v3 Authority Key Identifier",
        "DNS:www.pq.lab, IP Address:10.9.8.7, IP Address:FD00:0:0:0:0:0:0:1, email:ops@pq.lab, URI:https://pq.lab/id/1",
        "Policy: X509v3 Any Policy",
        "Policy: 1.3.6.1.4.1.99999.1.2",
        "URI:http://crl.pq.lab/root.crl",
        "OCSP - URI:http://ocsp.pq.lab",
        "CA Issuers - URI:http://pq.lab/root.cer",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
    let (ok, out) = external_verify(&lab.pem(r.id), &[], &lab.pem(c.id));
    assert!(ok, "{out}");
}

#[test]
fn name_constraints_are_enforced_by_openssl() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    let mut inter = preset("intermediate").unwrap().profile;
    inter.nc_permitted = vec![".pq.lab".into(), "10.0.0.0/8".into()];
    inter.nc_excluded = vec!["secret.pq.lab".into()];
    let i = lab.cert_with("Constrained", Algorithm::MlDsa65, Some(r.id), inter);
    let text = cert_text(&lab.pem(i.id));
    assert!(text.contains("X509v3 Name Constraints: critical"), "{text}");
    assert!(text.contains("DNS:.pq.lab"));
    assert!(text.contains("IP:10.0.0.0/255.0.0.0"));

    let inside = lab.cert("www.pq.lab", Algorithm::MlDsa44, Some(i.id), "server");
    let (ok, out) = external_verify(&lab.pem(r.id), &[lab.pem(i.id)], &lab.pem(inside.id));
    assert!(ok, "{out}");
    for bad in ["www.other.lab", "secret.pq.lab"] {
        let outside = lab.cert(bad, Algorithm::MlDsa44, Some(i.id), "server");
        let (ok, out) = external_verify(&lab.pem(r.id), &[lab.pem(i.id)], &lab.pem(outside.id));
        assert!(!ok, "{bad} must violate the name constraints");
        assert!(
            out.contains("name constraint") || out.contains("subtree"),
            "{out}"
        );
    }
}

#[test]
fn user_templates_crud_and_use() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    let mut profile = preset("server_client").unwrap().profile;
    profile.crl_dp = vec!["http://crl.pq.lab/r.crl".into()];
    let id = lab.pki.save_template(None, "Web + CRL", &profile).unwrap();
    assert_eq!(
        lab.pki
            .save_template(None, "Web + CRL", &profile)
            .unwrap_err()
            .code(),
        "template_name_exists"
    );
    let all = lab.pki.list_templates().unwrap();
    assert_eq!(all.presets.len(), 10);
    let t = all.user.iter().find(|t| t.id == id).unwrap();
    assert_eq!(t.profile, profile);

    let mut used = t.profile.clone();
    used.san = vec!["app.pq.lab".into()];
    let c = lab.cert_with("app.pq.lab", Algorithm::MlDsa44, Some(r.id), used);
    let text = cert_text(&lab.pem(c.id));
    assert!(text.contains("TLS Web Server Authentication, TLS Web Client Authentication"));
    assert!(text.contains("URI:http://crl.pq.lab/r.crl"));

    profile.crl_dp.clear();
    lab.pki.save_template(Some(id), "Web", &profile).unwrap();
    assert_eq!(lab.pki.list_templates().unwrap().user[0].name, "Web");
    let mut bad = profile.clone();
    bad.ocsp = vec!["ftp://nope".into()];
    assert_eq!(
        lab.pki.save_template(None, "bad", &bad).unwrap_err().code(),
        "uri_invalid"
    );
    lab.pki.delete_template(id).unwrap();
    assert!(lab.pki.list_templates().unwrap().user.is_empty());
}

#[test]
fn self_signed_end_entity() {
    let lab = Lab::new();
    let mut p = preset("server").unwrap().profile;
    p.san = vec!["self.pq.lab".into()];
    let c = lab.cert_with("self.pq.lab", Algorithm::MlDsa44, None, p);
    let pem = lab.pem(c.id);
    let (ok, out) = external_verify(&pem, &[], &pem);
    assert!(ok, "{out}");
    assert!(cert_text(&pem).contains("CA:FALSE"));
}
