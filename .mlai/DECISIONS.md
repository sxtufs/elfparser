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

## 2026-11-25 — Unsupported architectures error, never decode as AArch64
`disasm.rs` used to build an ARM64 Capstone for any unknown `e_machine`, and the
decompiler fell through to `Arm64Lifter`, so RISC-V (243) and other ELFs produced
confident-looking wrong output. Now `disasm::disassemble` returns
`Unsupported architecture (e_machine = N)` for anything outside 183/40/62/3, and
`DecompilerPipeline::analyze_function` returns an error for `ArchKind::RiscV64` /
`ArchKind::Unknown` before reading any bytes. A missing ELF header is an error instead
of defaulting to 183. `ArchKind::RiscV64` stays in the enum (register/calling-convention
data is kept) as the socket for a future lifter. Pinned by
`test_disasm_unsupported_architecture_is_rejected` and
`test_decompiler_rejects_riscv_and_unknown_arch`.

## 2026-11-25 — Function discovery: bounded scan, conservative sizes
`src/discovery.rs` recovers function starts for stripped binaries by scanning the
executable regions for direct calls (`bl`/`blx` on AArch64 and ARM — Thumb-2 halfword
pairs; ARM-mode `bl`/`blx` only at 4-byte-aligned offsets; `call rel32` via Capstone on
x86). Seeds are the entry point, `.plt`, and every symbol already in `syms_map`, so
`.symtab`/`.dynsym` names are never overwritten (`entry().or_insert`). Limits:
`MAX_SCANNED_BYTES` 32 MiB per call, `MAX_FUNCTIONS` 40,000, and a discovered function's
size is the distance to the next known start capped at 32 KiB (0 for the last one).
Known symbols plus discovered starts supply the sorted start list, so sizes never
overlap. Measured on the stripped 8.39 MB release `libelftrace.so` (8,393,496 bytes,
`aarch64-unknown-linux-gnu`): 3,025 discovered, symbol table 110 -> 3,135 over 8.04 MB
of scanned code, 0.14-0.2 s depending on machine load. `.symtab` was already parsed in
`ElfContext::open`; `get_info` used to rebuild a shadowed dynsym-only table and throw it
away (dead code, now removed). Pinned by `tests/symtab_discovery_tests.rs` (synthetic
ELF64 fixture with a local-only `.symtab` symbol, plus hand-encoded BL/Thumb-BL scans).

## 2026-11-25 — Workspace persistence is Room, keyed by content hash
`app/.../core/db/WorkspaceStore.kt` (Room 2.8.5 via KSP 2.3.14) stores recent sessions,
the last address per binary, manual renames, bookmarks and the patch journal. Every row
is keyed by SHA-256 of the file, not by path: the picker copies every ELF to
`cacheDir/input_target.so`, so a path key would mix different binaries. On open the
stored renames are re-applied and the journal is replayed through the normal native
patch path, which also restores the in-memory undo stack; an undo deletes the journal row
it reverted. Sessions are verified against the current hash before reopening, so a stale
cache entry is dropped instead of opening the wrong binary.

## 2026-11-25 — Binary image is a private memory map, not a heap read
`ElfContext::raw` is `RawImage` (`src/elf_parser.rs`): a `memmap2` `mapped_copy`
(MAP_PRIVATE) of the file, falling back to `fs::read` only for empty files. Patching
writes into the mapping, so a patch copies just the touched pages into memory and never
reaches the file on disk; resident cost tracks pages actually read instead of the whole
file. `RawImage` derefs to `[u8]` so parser code is unchanged, and `Clone` produces a
detached `Owned` copy (only tests clone a context). Pinned by
`tests/mapped_image_tests.rs`, which patches a mapped synthetic ELF and asserts the
on-disk bytes are untouched, `undo_last()` restores the mapping, and the image is
`Mapped`.

## 2026-11-25 — `ElfInfo.yara` removed
The field (and `YaraDTO` in both `model.rs` and `ElfModels.kt`) was always empty:
`scanner.rs` does the real signature matching into `syms`. Removed from the DTO on both
sides, so the Kotlin deserializer no longer declares a field the native side never fills.
The `evaluateYara` flag on `getInfo`/`info0` stays, because removing it would change the
JNI signature for no functional gain.
