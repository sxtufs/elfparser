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

Open in **Android Studio** or build via Gradle:
```bash
./gradlew assembleRelease
```
The optimized release APK will be generated at `app/build/outputs/apk/release/app-release.apk`.
