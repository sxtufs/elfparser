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
    let irreducible = structured.contains("irreducible CFG");
    eprintln!(
        "JNI_OnLoad @ 0x{:x}: structured gotos = {}, irreducible = {}",
        addr, gotos, irreducible
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
}
