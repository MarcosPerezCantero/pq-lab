fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET");
    println!("cargo:rustc-env=PQLAB_TARGET_TRIPLE={target}");
    tauri_build::build()
}
