//! Baseline + regression tests for the structured decompiler on real-world
//! functions. These use a real AArch64 shared library (libpowerampcore.so) so
//! improvements to the structurer are measured against actual binaries, not
//! only synthetic fixtures.
//!
//! The library is located via, in order:
//!   1. $ELFTRACE_FIXTURES_DIR/libpowerampcore.so  (CI)
//!   2. /workspace/test_fixtures/accuracy/libpowerampcore.so (CI fallback)
//!   3. ../test_fixtures/accuracy/libpowerampcore.so (repo-relative)
//! If none exist the tests SKIP (return), matching the other fixture tests.

use elftrace::decompiler::{decompile_to_c, decompile_to_c_structured};
use elftrace::elf_parser::ElfContext;

fn fixture_path() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("ELFTRACE_FIXTURES_DIR") {
        let p = std::path::Path::new(&dir).join("libpowerampcore.so");
        if p.exists() {
            return Some(p);
        }
    }
    for cand in [
        "/workspace/test_fixtures/accuracy/libpowerampcore.so",
        "test_fixtures/accuracy/libpowerampcore.so",
        "../test_fixtures/accuracy/libpowerampcore.so",
    ] {
        let p = std::path::Path::new(cand);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Baseline: JNI_OnLoad in libpowerampcore.so must decompile (both linear and
/// structured) and the structured output must remain compilable C. This test
/// records the current goto count so structurer changes that reduce it can be
/// asserted against a stable fixture, and so a regression that EXPLODES the
/// goto count is caught.
#[test]
fn test_poweramp_jni_onload_baseline() {
    let Some(path) = fixture_path() else {
        eprintln!("SKIP: libpowerampcore.so not found");
        return;
    };
    let ctx = ElfContext::open(path.to_str().unwrap()).expect("open libpowerampcore.so");
    let info = ctx.get_info().expect("get_info");
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "JNI_OnLoad")
        .expect("JNI_OnLoad symbol");
    let addr = sym.value;

    let linear = decompile_to_c(&ctx, addr);
    assert!(!linear.is_empty(), "linear decompile must be non-empty");
    assert!(
        linear.contains("JNI_OnLoad"),
        "linear output must name the function"
    );

    let structured = decompile_to_c_structured(&ctx, addr);
    assert!(!structured.is_empty(), "structured decompile must be non-empty");

    let gotos = count_occurrences(&structured, "goto loc_");
    let partial = structured.contains("partial structure");
    eprintln!(
        "JNI_OnLoad @ 0x{:x}: structured gotos = {}, partial = {}",
        addr, gotos, partial
    );

    // Hard ceiling: a structurer regression that turns this into a pathological
    // jumble of gotos should be caught. Baseline was ~92; the ladder-collapse
    // pass brought it down. Allow headroom so unrelated small changes don't
    // flake, but catch blow-ups.
    assert!(
        gotos < 400,
        "structured goto count exploded to {} (baseline ~92)",
        gotos
    );

    // Structural sanity (no compiler needed): the emitted C must have balanced
    // braces and every `goto loc_X;` must have a matching `loc_X:` label. A
    // mis-nested fold that drags a label inside an if-block produces either an
    // imbalance or an undefined-label reference — both caught here deterministically.
    let opens = structured.matches('{').count();
    let closes = structured.matches('}').count();
    assert_eq!(
        opens, closes,
        "unbalanced braces in structured output ({} open, {} close) — structurer produced invalid C",
        opens, closes
    );

    // Every referenced goto label must be defined.
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in structured.lines() {
        if let Some(pos) = line.find("goto loc_") {
            let rest = &line[pos + "goto loc_".len()..];
            let end = rest
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(rest.len());
            if end > 0 {
                referenced.insert(rest[..end].to_string());
            }
        }
    }
    for label in &referenced {
        let def = format!("loc_{}:", label);
        assert!(
            structured.contains(&def),
            "goto references undefined label `loc_{}` — structurer dropped a label",
            label
        );
    }

    // Compiler-verified gate (best-effort): when an AArch64 cross-compiler is
    // available (CI installs gcc-aarch64-linux-gnu), the real function's
    // structured output MUST compile. If no such compiler is present (e.g. on
    // the Android device itself) we skip silently — the brace/label checks
    // above still gate correctness deterministically.
    if let Some((cc, target_args)) = aarch64_compiler() {
        let tu = format!(
            "#include <stdint.h>\n#include <stddef.h>\n{}\n",
            structured
        );
        let tmp = std::env::temp_dir().join("elftrace_poweramp_jni_onload.c");
        std::fs::write(&tmp, &tu).unwrap();
        let out = std::process::Command::new(cc)
            .args(target_args)
            .arg("-std=c11")
            .arg("-Werror")
            .arg("-w") // suppress warnings about unused locals from decompiled noise
            .arg("-c")
            .arg(&tmp)
            .arg("-o")
            .arg("/dev/null")
            .output()
            .expect("run cross-compiler");
        assert!(
            out.status.success(),
            "structured JNI_OnLoad failed to compile:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        eprintln!("SKIP compile gate: no AArch64 cross-compiler on this host");
    }
}

/// Return an available AArch64 C compiler and its target args, or None.
fn aarch64_compiler() -> Option<(&'static str, &'static [&'static str])> {
    for (cc, args) in [
        ("aarch64-linux-gnu-gcc", &[][..]),
        ("clang", &["--target=aarch64-linux-gnu"][..]),
    ] {
        if std::process::Command::new(cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some((cc, args));
        }
    }
    None
}

/// Regression: shared tails that terminate in a `return` living INSIDE a Block
/// (the fallback emitter stores IrStmt::Return among block statements) were
/// never recognized as terminators by the join-inliner, so sites jumping to
/// the `x19 = -1` error tail (loc_00209610) kept their gotos. With the
/// terminator fix the tail is spliced into each site and only the last goto
/// remains.
#[test]
fn test_poweramp_jni_onload_shared_tail_inlined() {
    let Some(path) = fixture_path() else {
        eprintln!("SKIP: libpowerampcore.so not found");
        return;
    };
    let ctx = ElfContext::open(path.to_str().unwrap()).expect("open libpowerampcore.so");
    let info = ctx.get_info().expect("get_info");
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "JNI_OnLoad")
        .expect("JNI_OnLoad symbol");

    let structured = decompile_to_c_structured(&ctx, sym.value);
    let tail_gotos = count_occurrences(&structured, "goto loc_00209610;");
    assert!(
        tail_gotos <= 1,
        "shared `x19 = -1` error tail was not inlined: {} sites still goto loc_00209610",
        tail_gotos
    );

    // The inlining must not bloat the output: the 16-stmt expansion cap keeps
    // long cascading tails (the whole epilogue chain) as single gotos instead
    // of duplicating them into every site.
    let total_gotos = count_occurrences(&structured, "goto loc_");
    assert!(
        total_gotos < 200,
        "goto count exploded to {} — expansion cap not applying",
        total_gotos
    );
}

/// Regression: return-value synthesis for shared tails. The classic error
/// tail is `log(); x19 = -1; <epilogue>; return a0;` and its full expansion
/// exceeds the 16-stmt inline cap, so every error site kept a single goto.
/// With exit-block dataflow the tail's provable constant return (w19 = "-1"
/// forwarded to w0/a0) is synthesized per site as `x19 = -1; a0 = x19;
/// return a0;` — the gotos disappear without duplicating the epilogue.
#[test]
fn test_poweramp_jni_onload_return_value_synthesized() {
    let Some(path) = fixture_path() else {
        eprintln!("SKIP: libpowerampcore.so not found");
        return;
    };
    let ctx = ElfContext::open(path.to_str().unwrap()).expect("open libpowerampcore.so");
    let info = ctx.get_info().expect("get_info");
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "JNI_OnLoad")
        .expect("JNI_OnLoad symbol");

    let structured = decompile_to_c_structured(&ctx, sym.value);

    // Most error sites now return inline instead of jumping to the log tail.
    let log_tail_gotos = count_occurrences(&structured, "goto loc_0020960c;");
    assert!(
        log_tail_gotos <= 1,
        "log-tail gotos were not synthesized away: {} sites still goto loc_0020960c",
        log_tail_gotos
    );

    let synthesized = count_occurrences(&structured, "return a0;");
    assert!(
        synthesized >= 10,
        "expected >=10 synthesized returns, found {}",
        synthesized
    );

    let total_gotos = count_occurrences(&structured, "goto loc_");
    assert!(
        total_gotos <= 16,
        "goto count regressed: {} (synthesis should keep it <=16)",
        total_gotos
    );
}
