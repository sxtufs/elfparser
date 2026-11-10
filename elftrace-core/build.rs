
//! Build script for the ELFTrace native core.
//!
//! Only does work when `engine-unicorn` is enabled: on Android, `unicorn-engine-sys`
//! emits `-lpthread`, but Bionic has no standalone libpthread (pthread symbols
//! live in libc). We provide a linker-script stub `libpthread.so` containing
//! `INPUT ( -lc )` and put its directory on the linker search path.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cmake/stubs/libpthread.so");

    if std::env::var_os("CARGO_FEATURE_ENGINE_UNICORN").is_none() {
        return;
    }

    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let stub_dir = format!("{}/cmake/stubs", manifest_dir);

    // Make the stub discoverable by `-lpthread`.
    println!("cargo:rustc-link-search=native={}", stub_dir);
}
