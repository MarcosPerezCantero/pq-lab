//! Revocation and CRLs.

mod common;

use common::{run_in, Lab};
use pqlab_lib::algorithms::Algorithm;

#[test]
fn revoked_certificate_is_rejected_with_crl() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    let i = lab.intermediate("Inter", Algorithm::SlhDsaSha2_128f, r.id);
    let good = lab.cert("good.pq.lab", Algorithm::MlDsa44, Some(i.id), "server");
    let bad = lab.cert("bad.pq.lab", Algorithm::MlDsa44, Some(i.id), "server");
    let kem = lab.cert("kem.pq.lab", Algorithm::MlKem768, Some(i.id), "kem");

    assert_eq!(
        lab.pki.revoke_certificate(bad.id, "nope").unwrap_err().code(),
        "revocation_reason_invalid"
    );
    assert_eq!(
        lab.pki
            .revoke_certificate(r.id, "keyCompromise")
            .unwrap_err()
            .code(),
        "revoke_no_issuer"
    );
    lab.pki.revoke_certificate(bad.id, "keyCompromise").unwrap();
    lab.pki.revoke_certificate(kem.id, "superseded").unwrap();
    assert_eq!(
        lab.pki
            .revoke_certificate(bad.id, "keyCompromise")
            .unwrap_err()
            .code(),
        "already_revoked"
    );

    let crl_id = lab.pki.generate_crl(i.id, 7).unwrap();
    let crl = lab.pki.view_crl(crl_id).unwrap();
    assert_eq!(crl.row.number, 1);
    assert_eq!(crl.row.revoked_count, 2);
    assert!(crl.text.contains("Signature Algorithm: SLH-DSA-SHA2-128f"));
    assert!(crl.text.contains("Key Compromise"));
    assert!(crl.text.contains("Superseded"));
    lab.assert_tmp_clean();

    // Independent checks from a clean directory.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(d.join("root.pem"), lab.pem(r.id)).unwrap();
    std::fs::write(d.join("inter.pem"), lab.pem(i.id)).unwrap();
    std::fs::write(d.join("good.pem"), lab.pem(good.id)).unwrap();
    std::fs::write(d.join("bad.pem"), lab.pem(bad.id)).unwrap();
    std::fs::write(d.join("i.crl"), lab.pki.export_crl(crl_id, true).unwrap()).unwrap();
    let (ok, out) = run_in(d, &["crl", "-inform", "DER", "-in", "i.crl", "-out", "i.pem.crl"]);
    assert!(ok, "{out}");
    let (ok, out) = run_in(
        d,
        &[
            "crl",
            "-in",
            "i.pem.crl",
            "-CAfile",
            "inter.pem",
            "-noout",
            "-verify",
        ],
    );
    assert!(ok && out.contains("verify OK"), "{out}");
    let verify = |leaf: &str| {
        run_in(
            d,
            &[
                "verify",
                "-crl_check",
                "-CAfile",
                "root.pem",
                "-untrusted",
                "inter.pem",
                "-CRLfile",
                "i.pem.crl",
                leaf,
            ],
        )
    };
    let (ok, out) = verify("good.pem");
    assert!(ok, "{out}");
    let (ok, out) = verify("bad.pem");
    assert!(!ok);
    assert!(out.contains("certificate revoked"), "{out}");

    // The app's own chain check uses the CRL too.
    let v = lab.pki.verify_chain(bad.id).unwrap();
    assert!(!v.ok && v.crl_checked && v.revoked, "{}", v.output);
    assert!(lab.pki.verify_chain(good.id).unwrap().ok);

    // Unrevoke and issue CRL #2.
    lab.pki.unrevoke_certificate(bad.id).unwrap();
    let crl2 = lab.pki.generate_crl(i.id, 30).unwrap();
    let v2 = lab.pki.view_crl(crl2).unwrap();
    assert_eq!(v2.row.number, 2);
    assert_eq!(v2.row.revoked_count, 1);
    assert!(lab.pki.verify_chain(bad.id).unwrap().ok);
    assert_eq!(lab.pki.list_crls().unwrap().len(), 2);
    lab.pki.delete_crl(crl_id).unwrap();
    assert_eq!(lab.pki.list_crls().unwrap().len(), 1);
}

#[test]
fn crl_requires_ca_with_crl_sign() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa44);
    let leaf = lab.cert("leaf", Algorithm::MlDsa44, Some(r.id), "client");
    assert_eq!(
        lab.pki.generate_crl(leaf.id, 7).unwrap_err().code(),
        "issuer_not_ca"
    );
    let mut p = pqlab_lib::profile::preset("root").unwrap().profile;
    p.key_usage = vec![pqlab_lib::profile::KeyUsage::KeyCertSign];
    let no_crl = lab.cert_with("NoCrl", Algorithm::MlDsa44, None, p);
    assert_eq!(
        lab.pki.generate_crl(no_crl.id, 7).unwrap_err().code(),
        "issuer_no_crlsign"
    );
    // An empty CRL is fine.
    let id = lab.pki.generate_crl(r.id, 7).unwrap();
    assert_eq!(lab.pki.view_crl(id).unwrap().row.revoked_count, 0);
}

fn has(v: &pqlab_lib::pki::VerifyResult, code: &str) -> bool {
    v.warnings.iter().any(|w| w.code == code)
}

#[test]
fn revoked_leaf_fails_before_any_crl() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    let i = lab.intermediate("Inter", Algorithm::MlDsa65, r.id);
    let leaf = lab.cert("leaf.pq.lab", Algorithm::MlDsa44, Some(i.id), "server");
    lab.pki.revoke_certificate(leaf.id, "keyCompromise").unwrap();

    // No CRL yet: the database revocation alone fails the check.
    let v = lab.pki.verify_chain(leaf.id).unwrap();
    assert!(!v.ok && v.revoked && !v.crl_checked);
    assert_eq!(v.revoked_chain, vec!["leaf.pq.lab"]);
    assert!(has(&v, "revocation_unpublished"));

    // A CRL from before the revocation does not publish it either.
    lab.pki.unrevoke_certificate(leaf.id).unwrap();
    lab.pki.generate_crl(i.id, 7).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    lab.pki.revoke_certificate(leaf.id, "keyCompromise").unwrap();
    let v = lab.pki.verify_chain(leaf.id).unwrap();
    assert!(!v.ok && v.crl_checked && has(&v, "revocation_unpublished"));

    // Once published, OpenSSL itself rejects it.
    lab.pki.generate_crl(i.id, 7).unwrap();
    let v = lab.pki.verify_chain(leaf.id).unwrap();
    assert!(!v.ok && !has(&v, "revocation_unpublished"));
    assert!(v.output.contains("certificate revoked"), "{}", v.output);
}

#[test]
fn revoked_intermediate_invalidates_its_leaves() {
    let lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa87);
    let i = lab.intermediate("Inter", Algorithm::MlDsa65, r.id);
    let leaf = lab.cert("leaf.pq.lab", Algorithm::MlDsa44, Some(i.id), "server");
    lab.pki.revoke_certificate(i.id, "CACompromise").unwrap();
    lab.pki.generate_crl(r.id, 7).unwrap();

    // Only the root has a CRL: partial CRL check, but the leaf still fails.
    let v = lab.pki.verify_chain(leaf.id).unwrap();
    assert!(!v.ok && !v.revoked && !v.crl_complete);
    assert_eq!(v.revoked_chain, vec!["Inter"]);
    assert!(has(&v, "crl_partial"));

    // With a CRL at every level, OpenSSL checks the whole chain.
    lab.pki.generate_crl(i.id, 7).unwrap();
    let v = lab.pki.verify_chain(leaf.id).unwrap();
    assert!(!v.ok && v.crl_complete && !has(&v, "crl_partial"));
    assert!(v.output.contains("certificate revoked"), "{}", v.output);

    // Without the revocation the full CRL check passes.
    lab.pki.unrevoke_certificate(i.id).unwrap();
    lab.pki.generate_crl(r.id, 7).unwrap();
    let v = lab.pki.verify_chain(leaf.id).unwrap();
    assert!(
        v.ok && v.crl_complete && v.revoked_chain.is_empty(),
        "{}",
        v.output
    );
}

#[test]
fn deleted_revoked_certificate_stays_on_crl() {
    let mut lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa65);
    let leaf = lab.cert("gone.pq.lab", Algorithm::MlDsa44, Some(r.id), "server");
    let serial = lab
        .pki
        .list_certs()
        .unwrap()
        .into_iter()
        .find(|c| c.id == leaf.id)
        .unwrap()
        .serial;
    lab.pki.revoke_certificate(leaf.id, "keyCompromise").unwrap();
    let crl1 = lab.pki.generate_crl(r.id, 7).unwrap();
    lab.pki.delete_cert(leaf.id).unwrap();

    let crl2 = lab.pki.generate_crl(r.id, 7).unwrap();
    let v = lab.pki.view_crl(crl2).unwrap();
    assert_eq!(v.row.revoked_count, 1);
    assert!(
        v.text.to_ascii_uppercase().contains(&serial.to_ascii_uppercase()),
        "{}",
        v.text
    );
    assert!(v.text.contains("Key Compromise"));

    // CRL numbers never repeat, even after deleting the latest CRL.
    assert_eq!(v.row.number, 2);
    lab.pki.delete_crl(crl2).unwrap();
    lab.pki.delete_crl(crl1).unwrap();
    let crl3 = lab.pki.generate_crl(r.id, 7).unwrap();
    assert_eq!(lab.pki.view_crl(crl3).unwrap().row.number, 3);
}

#[test]
fn deleting_a_ca_removes_its_crls() {
    let mut lab = Lab::new();
    let r = lab.root("Root", Algorithm::MlDsa44);
    let other = lab.root("Other", Algorithm::MlDsa44);
    let leaf = lab.cert("leaf", Algorithm::MlDsa44, Some(r.id), "client");
    lab.pki.generate_crl(r.id, 7).unwrap();
    lab.pki.generate_crl(other.id, 7).unwrap();
    assert_eq!(lab.pki.delete_cert(r.id).unwrap_err().code(), "cert_has_children");
    lab.pki.revoke_certificate(leaf.id, "superseded").unwrap();
    lab.pki.delete_cert(leaf.id).unwrap();
    lab.pki.delete_cert(r.id).unwrap();
    let crls = lab.pki.list_crls().unwrap();
    assert_eq!(crls.len(), 1);
    assert_eq!(crls[0].issuer_id, other.id);
}

#[test]
fn crl_with_windows_style_temp_path() {
    // Backslashes, `$` and `#` are configuration syntax for OpenSSL.
    let lab = Lab::with_tmp(r"C:\Users\Lab $HOME #1\Temp");
    let r = lab.root("Root", Algorithm::MlDsa44);
    let leaf = lab.cert("leaf", Algorithm::MlDsa44, Some(r.id), "client");
    lab.pki.revoke_certificate(leaf.id, "keyCompromise").unwrap();
    let crl = lab.pki.generate_crl(r.id, 7).unwrap();
    assert_eq!(lab.pki.view_crl(crl).unwrap().row.revoked_count, 1);
    lab.assert_tmp_clean();
}
