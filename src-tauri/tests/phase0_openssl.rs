//! The packaged OpenSSL is >= 3.5 and supports every algorithm of the
//! catalogue; the ML-KEM `-force_pubkey` flow verifies.

mod common;

use pqlab_lib::algorithms::{Algorithm, Family};
use pqlab_lib::openssl::{parse_version, MIN_VERSION};

#[test]
fn sidecar_version_is_at_least_3_5() {
    let o = common::openssl();
    let v = o.check_version().expect("version check");
    println!("{v} ({})", o.path().display());
    assert!(parse_version(&v).unwrap() >= MIN_VERSION);
}

#[test]
fn algorithm_table_matches_openssl() {
    let o = common::openssl();
    let sigs = o
        .run(&["list", "-signature-algorithms"], None)
        .unwrap()
        .stdout_text();
    let kems = o.run(&["list", "-kem-algorithms"], None).unwrap().stdout_text();
    let mgrs = o.run(&["list", "-key-managers"], None).unwrap().stdout_text();
    for &a in Algorithm::ALL {
        let name = a.openssl_name();
        match a.family() {
            Family::MlDsa | Family::SlhDsa => {
                assert!(
                    sigs.contains(&format!(", {name}")),
                    "{name} not in -signature-algorithms"
                );
            }
            Family::MlKem => {
                assert!(
                    kems.contains(&format!(", {name}")),
                    "{name} not in -kem-algorithms"
                );
            }
        }
        assert!(mgrs.contains(name), "{name} not in -key-managers");
    }
}

#[test]
fn ml_kem_force_pubkey_certificate_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let run = |args: &[&str]| {
        let (ok, out) = common::run_in(d, args);
        assert!(ok, "{args:?}: {out}");
        out
    };
    std::fs::write(
        d.join("ext.cnf"),
        "[req]\ndistinguished_name=dn\n[dn]\n[v3_root]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n[v3_kem]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n",
    )
    .unwrap();
    run(&["genpkey", "-algorithm", "ML-DSA-65", "-out", "ca.key"]);
    run(&[
        "req",
        "-x509",
        "-new",
        "-key",
        "ca.key",
        "-subj",
        "/CN=Root",
        "-days",
        "30",
        "-config",
        "ext.cnf",
        "-extensions",
        "v3_root",
        "-out",
        "ca.pem",
    ]);
    run(&["genpkey", "-algorithm", "ML-KEM-768", "-out", "kem.key"]);
    run(&["pkey", "-in", "kem.key", "-pubout", "-out", "kem_pub.pem"]);
    run(&[
        "x509",
        "-new",
        "-subj",
        "/CN=kem-endpoint.lab",
        "-force_pubkey",
        "kem_pub.pem",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-days",
        "30",
        "-set_serial",
        "0x01",
        "-extfile",
        "ext.cnf",
        "-extensions",
        "v3_kem",
        "-out",
        "kem.pem",
    ]);
    let out = run(&["verify", "-CAfile", "ca.pem", "kem.pem"]);
    println!("{out}");
    assert!(out.contains("kem.pem: OK"));
    let text = run(&["x509", "-in", "kem.pem", "-noout", "-text"]);
    assert!(text.contains("Public Key Algorithm: ML-KEM-768"));
    assert!(text.contains("Key Encipherment"));
}
