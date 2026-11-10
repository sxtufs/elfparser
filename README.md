# ELFTrace

A high-performance mobile reverse-engineering platform and interactive binary execution tracer for Android, written in **Kotlin + Jetpack Compose** with a native **Rust (Capstone 5.x + Emulation Engine)** core.

---

## Key Features

1. **In-Process CPU Execution Tracer**:
   * Step-by-step instruction emulation (`Step Next` and `Back`).
   * Live interactive Register Dashboard (`X0`–`X30`, `SP`, `PC`) with automatic change highlighting.
   * Arithmetic and condition flag tracking (`Z`, `N`, `C`, `V`).
   * Runs natively in-process without needing root or `/data/data/` command execution.

2. **In-Place Assembly & Hex Editing**:
   * Directly assemble and patch machine instructions (`b`, `bl`, `b.cond`, `cbz`, `cbnz`, `mov`, `nop`, `ret`).
   * Raw hex bytes editing support.
   * One-tap preset patches (`NOP`, `Force Return True`, `Force Return False`, `Early Return`).

3. **Multi-Architecture Disassembler**:
   * Powered by **Capstone 5.x** via Android Bionic.
   * Supports **ARM64 (AArch64)**, **ARM32 (ARM/Thumb mode)**, **x86**, and **x86_64**.
   * In-line string annotations (IDA Pro style) and AArch64 kernel syscall auto-resolving (`svc #0`).
   * Dual 32-bit & 64-bit dynamic JNI `RegisterNatives` scanner.

4. **High-Level C Decompiler & Control Flow Graph**:
   * Converts machine instructions into clean, readable C pseudocode.
   * Line-free basic block flowchart designed specifically for mobile screens.
   * Text selection enabled across all code views.

5. **Direct APK & Archive Inspector**:
   * Open `.apk`, `.xapk`, and `.zip` files directly from the file picker.
   * Browse internal `.so` files across all architectures and load them instantly into memory.

6. **One-Tap Frida Script Generator**:
   * Automatically produces ready-to-run Frida JavaScript hooks tailored to the selected function offset.

7. **Export Patched Binary**:
   * Save modified binaries directly to the phone's **Downloads** folder with one tap.

8. **Eye-Comfort Light & Dark Modes**:
   * Calibrated GitHub / VS Code Light palette (soft canvas, zero glare, high contrast).
   * Soft charcoal Dark Mode with floating rounded navigation containers.

---

## Project Structure

```text
ELFTrace/
├── .github/workflows/build.yml   # Automated GitHub CI/CD Release pipeline
├── app/
│   ├── build.gradle.kts
│   ├── proguard-rules.pro       # R8 code shrinking and JNI keep rules
│   └── src/main/
│       ├── AndroidManifest.xml  # Target SDK 34 (Android 14)
│       ├── jniLibs/arm64-v8a/
│       │   └── libelftrace.so   # Compiled Rust core (Capstone 5.x + Tracer)
│       └── java/io/elftrace/app/
│           ├── MainActivity.kt  # Symmetrical floating card navigation
│           ├── core/
│           │   ├── JNIBridge.kt # Strongly-typed native bridge to libelftrace.so
│           │   └── models/      # Strongly-typed data models
│           ├── ui/
│           │   ├── theme/       # Dual eye-comfort Light & Dark themes
│           │   └── screens/     # Disassembly, Decompiler, Flowchart, Tracer, etc.
│           └── viewmodel/
│               └── ELFTraceViewModel.kt
```

## How to Build

### Prerequisites

* **Android Studio** or Android SDK with Gradle
* **Rust toolchain** (1.75+): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
* **Android NDK r26b** (via Android Studio SDK Manager)
* **cargo-ndk**: `cargo install cargo-ndk --version 3.5.4 --locked`
* **Rust Android target**: `rustup target add aarch64-linux-android`

### Local Build

**Step 1 — build the native library:**
```bash
cd elftrace-core
cargo ndk -t arm64-v8a -p 24 -o ../app/src/main/jniLibs build --release
cd ..
```

This produces `app/src/main/jniLibs/arm64-v8a/libelftrace.so` (~6-7 MB, stripped).

**Step 2 — build the APK:**
```bash
./gradlew assembleRelease
```

APK output: `app/build/outputs/apk/release/app-release.apk`.

### About the .so

`libelftrace.so` is **not committed to this repository.** It is built from the Rust source in `elftrace-core/` on every build — locally by the developer, and in CI (`.github/workflows/build.yml`) on every push.

This guarantees the shipped `.so` always matches the current Rust source. The library is compiled with `strip = "symbols"` (see `elftrace-core/Cargo.toml`), which removes internal Rust function names but keeps the JNI exports required by Android.

**Consequence:** if you analyze `libelftrace.so` itself with this tool, internal Rust functions will appear as `sub_XXXXXXXX`. JNI entry points (`Java_*`, `JNI_OnLoad`) remain named.

### Running Tests

Tests run locally, not in CI:

```bash
cd elftrace-core
cargo test
```

Two self-compile-gate tests require `libelftrace.so` to be present at `app/src/main/jniLibs/arm64-v8a/` (or `ELFTRACE_SELF_SO` / `ELFTRACE_TEST_ELF` set). Build the `.so` first (step 1) if you want those tests to run; they will `SKIP` cleanly if no `.so` is available.

Before pushing code that changes `elftrace-core/src/`, run `cargo test` locally. CI does not run the Rust test suite — that is a developer responsibility by design.
