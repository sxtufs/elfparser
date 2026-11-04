# DisElf (Modern Android Rewrite)

A modern, high-performance reverse-engineering and binary inspection tool for Android, written in **Kotlin + Jetpack Compose** with a native **Rust (Capstone 5.x + in-process ESIL tracer)** core.

---

## Key Features

1. **In-Process Binary Execution Tracer**:
   * Step-by-step instruction emulation (`Step Next` and `Step Back`).
   * Live interactive Register Dashboard (`X0`–`X30`, `SP`, `PC`) with automatic change highlighting.
   * Arithmetic and condition flag tracking (`Z`, `N`, `C`, `V`).
   * Runs natively in-process without requiring root or external binaries (`/data/data/` execution).

2. **Multi-Architecture Disassembler**:
   * Powered by **Capstone 5.x** running natively via Android Bionic.
   * Supports ARM64 (AArch64), ARM32 (ARM/Thumb mode), x86, and x86_64.
   * Virtualized instruction list handling 100,000+ instructions smoothly.

3. **High-Level C Decompiler & Lifter**:
   * Converts machine instructions into clean, readable C pseudocode.
   * Auto-resolves memory loads/stores, condition branches, and ADRP pointers.
   * Line-by-line syntax viewer with one-tap clipboard copy.

4. **Clean Control Flow Graph (Flowchart)**:
   * Symmetrical, line-free basic block flowchart designed specifically for mobile screens.
   * Direct branch indicators (`[TRUE] branch`, `[FALSE] fallthrough`, `[EXIT / RETURN]`).

5. **Modern Android Standards**:
   * Target SDK: **34 (Android 14)** | Min SDK: **24 (Android 7.0)**.
   * Storage Access Framework (SAF) + `MANAGE_EXTERNAL_STORAGE` support.
   * Zero external dependencies or telemetry trackers (removed AppCenter, FileDownloader, Jiguang).

---

## Project Structure

```text
diself-modern/
├── app/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/cn/mrack/diself/
│       │   ├── MainActivity.kt          # Material 3 Compose Navigation
│       │   ├── core/
│       │   │   ├── JNIBridge.kt         # Native JNI binding to libdiself2.so
│       │   │   └── models/ElfModels.kt  # Strongly typed data models
│       │   ├── ui/
│       │   │   ├── theme/               # Dark reverse-engineering color theme
│       │   │   └── screens/
│       │   │       ├── HomeScreen.kt    # SAF File Picker & ELF header card
│       │   │       ├── DisasmScreen.kt  # Virtualized disassembly viewer
│       │   │       ├── DecompileScreen.kt# High-level C pseudocode view
│       │   │       ├── FlowchartScreen.kt# Line-free control flow graph
│       │   │       ├── TraceScreen.kt   # Live step-by-step execution tracer
│       │   │       └── StringsScreen.kt # Searchable strings & symbol table
│       │   └── viewmodel/
│       │       └── DisElfViewModel.kt   # StateFlow reactive state management
│       └── jniLibs/arm64-v8a/
│           └── libdiself2.so            # Rust + Capstone 5.x native engine
└── build.gradle.kts
```

## How to Build

Open `/workspace/diself-modern` in **Android Studio** (or build with Gradle CLI):
```bash
./gradlew assembleRelease
```
The APK will be generated under `app/build/outputs/apk/release/`.
