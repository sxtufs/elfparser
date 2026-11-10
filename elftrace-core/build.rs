
//! Build script for the ELFTrace native core.
//!
//! Only does work when `engine-unicorn` is enabled, and only for Android.
//!
//! Two Android-specific link fixes for the Unicorn (QEMU) JIT core:
//!  1. `unicorn-engine-sys` emits `-lpthread`, but Bionic has no standalone
//!     libpthread (pthread symbols live in libc). We ship a linker-script stub
//!     `libpthread.so` containing `INPUT ( -lc )` and add its dir to the search
//!     path.
//!  2. Unicorn's JIT calls `__clear_cache`, which Bionic does not export and
//!     Rust's compiler_builtins omits for this target. We compile a tiny C shim
//!     (`clear_cache.c`) that forwards to `__builtin___clear_cache`.
//!
//! It also adds `-Wl,--no-undefined` so any future missing symbol is a build
//! error rather than a crash on device.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cmake/stubs/libpthread.so");
    println!("cargo:rerun-if-changed=cmake/stubs/clear_cache.c");

    if std::env::var_os("CARGO_FEATURE_ENGINE_UNICORN").is_none() {
        return;
    }

    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("android") {
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let stub_dir = format!("{}/cmake/stubs", manifest_dir);

    // Make the libpthread stub discoverable by `-lpthread`.
    println!("cargo:rustc-link-search=native={}", stub_dir);

    // Compile the __clear_cache shim (Unicorn's JIT needs it; Bionic lacks it).
    cc::Build::new()
        .file(format!("{}/clear_cache.c", stub_dir))
        .warnings(true)
        .compile("elf_clear_cache");

    // Turn unresolved symbols into BUILD errors instead of device-side
    // `dlopen` failures. Without this, a missing symbol (like __clear_cache)
    // silently ships and crashes at load time.
    println!("cargo:rustc-link-arg=-Wl,--no-undefined");
}
