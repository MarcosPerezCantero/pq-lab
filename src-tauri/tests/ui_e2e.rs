//! End to end through the same Tauri commands and JSON
//! payloads the UI sends (src/api.ts), build root ML-DSA-87 → intermediate
//! ML-DSA-65 → server ML-DSA-44 + ML-KEM-768 certificate, export the chains to
//! files and validate them with an external `openssl verify`.

mod common;

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::WebviewWindowBuilder;

struct Ui {
    _app: tauri::App<tauri::test::MockRuntime>,
    webview: tauri::WebviewWindow<tauri::test::MockRuntime>,
}

impl Ui {
    fn new(data_dir: std::path::PathBuf) -> Self {
        let app = pqlab_lib::with_commands(mock_builder(), data_dir)
            .build(pqlab_lib::context())
            .unwrap();
        let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();
        Self { _app: app, webview }
    }

    fn call(&self, cmd: &str, args: Value) -> Result<Value, Value> {
        get_ipc_response(
            &self.webview,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: if cfg!(windows) {
                    "http://tauri.localhost"
                } else {
                    "tauri://localhost"
                }
                .parse()
                .unwrap(),
                body: InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_string(),
            },
        )
        .map(|b| b.deserialize::<Value>().unwrap())
    }

    fn ok(&self, cmd: &str, args: Value) -> Value {
        self.call(cmd, args)
            .unwrap_or_else(|e| panic!("{cmd} failed: {e}"))
    }
}

fn subject(cn: &str) -> Value {
    json!({ "cn": cn, "o": "PQ Lab", "ou": "", "c": "ES", "st": "", "l": "" })
}

#[test]
fn full_chain_from_ui_commands_verifies_externally() {
    let dir = tempfile::tempdir().unwrap();
    let ui = Ui::new(dir.path().join("data"));

    let catalog = ui.ok("catalog", json!({}));
    assert_eq!(catalog["algorithms"].as_array().unwrap().len(), 18);
    let status = ui.ok("app_status", json!({}));
    assert!(status["openssl_version"]
        .as_str()
        .unwrap()
        .starts_with("OpenSSL 3."));
    assert_eq!(status["unlocked"], false);

    let db = dir.path().join("lab.db");
    let db_s = db.to_str().unwrap();
    ui.ok(
        "create_database",
        json!({ "path": db_s, "password": common::MASTER }),
    );
    ui.ok("lock_database", json!({}));
    let err = ui
        .call(
            "open_database",
            json!({ "path": db_s, "password": "wrong-password" }),
        )
        .unwrap_err();
    assert_eq!(err["code"], "wrong_password");
    ui.ok(
        "open_database",
        json!({ "path": db_s, "password": common::MASTER }),
    );
    assert_eq!(ui.ok("app_status", json!({}))["unlocked"], true);

    // Keys, as NewKeyDialog / KeyPicker do.
    let k87 = ui.ok(
        "generate_key",
        json!({ "name": "root key", "algorithm": "ML-DSA-87" }),
    );
    let k65 = ui.ok(
        "generate_key",
        json!({ "name": "inter key", "algorithm": "ML-DSA-65" }),
    );
    let k44 = ui.ok(
        "generate_key",
        json!({ "name": "server key", "algorithm": "ML-DSA-44" }),
    );
    let kem = ui.ok(
        "generate_key",
        json!({ "name": "kem key", "algorithm": "ML-KEM-768" }),
    );

    // Profiles come from the presets, as the certificate dialog does.
    let templates = ui.ok("list_templates", json!({}));
    let preset = |id: &str| {
        templates["presets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .unwrap()["profile"]
            .clone()
    };
    let issue = |name: &str, key: &Value, issuer: Value, template: &str, sans: &[&str], days: u32| {
        let mut profile = preset(template);
        profile["san"] = json!(sans);
        ui.ok(
            "issue_certificate",
            json!({ "req": { "name": name, "key_id": key, "issuer_id": issuer, "subject": subject(name),
                "profile": profile, "validity": { "days": days }, "template": template } }),
        )
    };
    let root = issue("Lab Root ML-DSA-87", &k87, Value::Null, "root", &[], 3650);
    let inter = issue(
        "Lab Inter ML-DSA-65",
        &k65,
        root["id"].clone(),
        "intermediate",
        &[],
        1825,
    );
    let server = issue(
        "www.pq.lab",
        &k44,
        inter["id"].clone(),
        "server",
        &["www.pq.lab", "10.0.0.5"],
        365,
    );
    let kem_cert = issue("kem.pq.lab", &kem, inter["id"].clone(), "kem", &[], 365);
    for issued in [&root, &inter, &server, &kem_cert] {
        assert_eq!(issued["warnings"], json!([]));
    }

    // The UI never offers ML-KEM as a CA, but the backend refuses it too.
    let err = ui
        .call(
            "issue_certificate",
            json!({ "req": { "name": "bad", "key_id": kem, "issuer_id": null, "subject": subject("bad"),
                "profile": preset("root") } }),
        )
        .unwrap_err();
    assert_eq!(err["code"], "kem_cannot_be_ca");

    let certs = ui.ok("list_certificates", json!({}));
    assert_eq!(certs.as_array().unwrap().len(), 4);
    let verify = ui.ok("verify_chain", json!({ "id": kem_cert["id"] }));
    assert_eq!(verify["ok"], true, "{verify}");

    // Export as the ExportCertDialog does: chain files + root PEM.
    let out = tempfile::tempdir().unwrap();
    let o = out.path();
    let path = |n: &str| o.join(n).to_str().unwrap().to_string();
    ui.ok(
        "export_certificate",
        json!({ "id": root["id"], "format": "pem", "path": path("root.pem") }),
    );
    ui.ok(
        "export_certificate",
        json!({ "id": inter["id"], "format": "pem", "path": path("inter.pem") }),
    );
    ui.ok(
        "export_chain",
        json!({ "id": server["id"], "path": path("server.chain.pem") }),
    );
    ui.ok(
        "export_chain",
        json!({ "id": kem_cert["id"], "path": path("kem.chain.pem") }),
    );
    ui.ok(
        "export_certificate",
        json!({ "id": server["id"], "format": "der", "path": path("server.der") }),
    );

    let (ok, server_out) = common::run_in(
        o,
        &[
            "verify",
            "-CAfile",
            "root.pem",
            "-untrusted",
            "server.chain.pem",
            "server.chain.pem",
        ],
    );
    println!("{server_out}");
    assert!(ok && server_out.contains("server.chain.pem: OK"), "{server_out}");
    let (ok, kem_out) = common::run_in(
        o,
        &[
            "verify",
            "-CAfile",
            "root.pem",
            "-untrusted",
            "inter.pem",
            "kem.chain.pem",
        ],
    );
    println!("{kem_out}");
    assert!(ok && kem_out.contains("kem.chain.pem: OK"), "{kem_out}");
    let (ok, text) = common::run_in(
        o,
        &["x509", "-inform", "DER", "-in", "server.der", "-noout", "-text"],
    );
    assert!(ok);
    assert!(text.contains("Public Key Algorithm: ML-DSA-44"));
    assert!(text.contains("Signature Algorithm: ML-DSA-65"));
    assert!(text.contains("DNS:www.pq.lab, IP Address:10.0.0.5"));

    // The data directory holds the operations log, never plain keys.
    assert!(common::find_plain_private_keys(&dir.path().join("data")).is_empty());
    assert!(common::find_plain_private_keys(dir.path()).is_empty());

    // Revoke the server certificate, publish a CRL and export a PKCS#12.
    ui.ok(
        "revoke_certificate",
        json!({ "id": server["id"], "reason": "keyCompromise" }),
    );
    let crl = ui.ok("generate_crl", json!({ "issuerId": inter["id"], "days": 7 }));
    ui.ok(
        "export_crl",
        json!({ "id": crl, "format": "pem", "path": path("inter.crl") }),
    );
    let (ok, out) = common::run_in(
        o,
        &[
            "verify",
            "-crl_check",
            "-CAfile",
            "root.pem",
            "-untrusted",
            "inter.pem",
            "-CRLfile",
            "inter.crl",
            "server.chain.pem",
        ],
    );
    assert!(!ok && out.contains("certificate revoked"), "{out}");
    ui.ok(
        "export_pkcs12",
        json!({ "id": kem_cert["id"], "path": path("kem.p12"), "password": "p12-password", "chain": true }),
    );
    let (ok, out) = common::run_in(
        o,
        &[
            "pkcs12",
            "-in",
            "kem.p12",
            "-passin",
            "pass:p12-password",
            "-info",
            "-noout",
        ],
    );
    assert!(ok, "{out}");

    ui.ok("lock_database", json!({}));
    assert_eq!(ui.call("list_keys", json!({})).unwrap_err()["code"], "locked");
}
