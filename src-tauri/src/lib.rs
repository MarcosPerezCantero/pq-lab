//! PQ Lab backend: a laboratory PKI orchestrating the `openssl` 3.5 binary.

pub mod algorithms;
pub mod commands;
pub mod db;
pub mod error;
pub mod inspect;
pub mod openssl;
pub mod pki;
pub mod profile;
pub mod security;
pub mod validation;

use std::sync::Mutex;

/// Registers state and every command on a builder (shared by the app and
/// the end-to-end tests, which use Tauri's mock runtime).
pub fn with_commands<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    data_dir: std::path::PathBuf,
) -> tauri::Builder<R> {
    builder
        .manage(Mutex::new(commands::AppState::new(data_dir)))
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::catalog,
            commands::create_database,
            commands::open_database,
            commands::lock_database,
            commands::list_keys,
            commands::generate_key,
            commands::import_key,
            commands::rename_key,
            commands::delete_key,
            commands::export_public_key,
            commands::export_private_key,
            commands::list_certificates,
            commands::issue_certificate,
            commands::renew_certificate,
            commands::revoke_certificate,
            commands::unrevoke_certificate,
            commands::export_pkcs12,
            commands::import_pkcs12,
            commands::list_templates,
            commands::save_template,
            commands::delete_template,
            commands::list_crls,
            commands::generate_crl,
            commands::view_crl,
            commands::export_crl,
            commands::delete_crl,
            commands::import_certificate,
            commands::delete_certificate,
            commands::view_certificate,
            commands::verify_chain,
            commands::export_certificate,
            commands::export_chain,
            commands::list_csrs,
            commands::generate_csr,
            commands::import_csr,
            commands::sign_csr,
            commands::delete_csr,
            commands::view_csr,
            commands::export_csr,
            commands::read_pem_file,
        ])
}

/// Directory for the database and the operations log: `PQLAB_DATA_DIR`, then a
/// `pqlab-data` folder next to the executable (portable mode), then the
/// platform's per-user data directory.
fn data_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var_os("PQLAB_DATA_DIR") {
        return d.into();
    }
    if let Some(portable) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("pqlab-data")))
        .filter(|d| d.is_dir())
    {
        return portable;
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/share")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("dev.pqlab.app")
}

/// Application context (configuration, assets and ACL), shared with tests.
pub fn context<R: tauri::Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

/// Native menu bar. Custom items are forwarded to the frontend as a `menu`
/// event carrying the item id.
fn build_menu<R: tauri::Runtime>(app: &tauri::App<R>) -> tauri::Result<tauri::menu::Menu<R>> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
    let item = |id: &str, label: &str, accel: Option<&str>| {
        let b = MenuItemBuilder::with_id(id, label);
        match accel {
            Some(a) => b.accelerator(a).build(app),
            None => b.build(app),
        }
    };
    let file = SubmenuBuilder::new(app, "Archivo")
        .item(&item("new_key", "Nueva clave…", Some("CmdOrCtrl+K"))?)
        .item(&item("new_cert", "Nuevo certificado…", Some("CmdOrCtrl+N"))?)
        .item(&item("new_csr", "Nueva petición (CSR)…", None)?)
        .separator()
        .item(&item("import_pem", "Importar PEM…", Some("CmdOrCtrl+I"))?)
        .item(&item("import_p12", "Importar PKCS#12…", None)?)
        .separator()
        .item(&item("lock", "Bloquear base de datos", Some("CmdOrCtrl+L"))?)
        .separator()
        .quit_with_text("Salir")
        .build()?;
    let edit = SubmenuBuilder::new(app, "Edición")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;
    let help = SubmenuBuilder::new(app, "Ayuda")
        .item(&item("about", "Acerca de PQ Lab", None)?)
        .build()?;
    let mut menu = MenuBuilder::new(app);
    if cfg!(target_os = "macos") {
        let app_menu = SubmenuBuilder::new(app, "PQ Lab")
            .item(&item("about", "Acerca de PQ Lab", None)?)
            .separator()
            .hide_with_text("Ocultar PQ Lab")
            .hide_others_with_text("Ocultar otros")
            .show_all_with_text("Mostrar todo")
            .separator()
            .quit_with_text("Salir de PQ Lab")
            .build()?;
        menu = menu.item(&app_menu);
    }
    menu.items(&[&file, &edit, &help]).build()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use tauri::Emitter;
    let data_dir = data_dir();
    let _ = std::fs::create_dir_all(&data_dir);
    with_commands(tauri::Builder::default(), data_dir)
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let menu = build_menu(app)?;
            app.set_menu(menu)?;
            app.on_menu_event(|app, event| {
                let _ = app.emit("menu", event.id().0.clone());
            });
            Ok(())
        })
        .run(context())
        .expect("error while running PQ Lab");
}
