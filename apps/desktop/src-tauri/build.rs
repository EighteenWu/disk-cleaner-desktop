fn main() {
    let mut attrs = tauri_build::Attributes::new();

    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-env-changed=DISKCLEAN_NO_ELEVATION");

    // The app needs administrator rights for its real work: machine-wide temp
    // directories, Windows update leftovers, and other users' caches are all
    // ACL-protected. Injecting the manifest for every profile means the binary
    // triggers UAC on launch instead of starting unelevated and failing later.
    //
    // Set DISKCLEAN_NO_ELEVATION=1 to opt out; `tauri dev` with hot reload is
    // easier to drive when the process is not elevated.
    if std::env::var("DISKCLEAN_NO_ELEVATION").is_err() {
        attrs = attrs.windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest")),
        );
    }

    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}
