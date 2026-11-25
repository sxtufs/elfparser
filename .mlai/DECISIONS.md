# Decisions

## 2026-11-25 — Native .so size budget: 12 MiB, enforced in CI
CI (`Verify .so — size, exports, stripped` in `.github/workflows/build.yml`) fails when
`app/src/main/jniLibs/arm64-v8a/libelftrace.so` exceeds 12 MiB (12582912 bytes).
`strip = "symbols"` + fat LTO are active in the release profile; the stripped check
(0 internal Rust symbols) is the authoritative strip test, so a size failure means code grew.

## 2026-11-25 — capstone builds only arm/arm64/x86
`elftrace-core/Cargo.toml` uses `default-features = false` with `full`, `std`,
`arch_arm`, `arch_arm64`, `arch_x86`. `full` must stay to keep CAPSTONE_DIET off
(diet mode drops mnemonic/op strings); the default `support_all_archs` compiled all 18
disassemblers and pushed the .so to 13.4 MB. Those three architectures are the only ones
`disasm.rs` can select (e_machine 183/40/62/3); `tests/accuracy_tests.rs`
`test_disasm_supported_architectures_still_decode` pins that they still decode.
Measured: 13,441,816 -> 8,327,960 bytes (-38%) for `aarch64-unknown-linux-gnu`.
