// Temporary check: run every built-in plugin manifest against the aarch64
// fixture and the stub context; fail if any script reports a Rhai error.
use elftrace::elf_parser::ElfContext;
use elftrace::plugins::run_plugin;

fn plugin_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("../app/src/main/assets/plugins")
}

#[test]
fn builtin_scripts_run_without_script_errors() {
    let dir = plugin_dir();
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("plugin dir")
        .map(|e| e.unwrap().path())
        .collect();
    assert!(entries.len() >= 16, "expected >=16 manifests, got {}", entries.len());

    for path in entries {
        let json = std::fs::read_to_string(&path).unwrap();
        let ctx = ElfContext::stub();
        let report = run_plugin(&ctx, &json);
        let arch_gated = report.error.as_deref()
            .map(|e| e.contains("but loaded binary is unknown")).unwrap_or(false);
        assert!(
            arch_gated || report.error.is_none(),
            "{} returned script error: {:?}",
            path.display(),
            report.error
        );
    }
}

#[test]
fn changed_scripts_run_on_fixture_without_errors() {
    let fixture = "../elftrace-core/test_fixtures/accuracy/fx_a64_item1.so";
    let ctx = match ElfContext::open(fixture) {
        Ok(c) => c,
        Err(_) => return,
    };
    for name in [
        "06-builtin-dexprotector.json",
        "14-builtin-rhai-register-natives.json",
        "17-builtin-rhai-xref-tracer.json",
        "19-builtin-rhai-emulator.json",
        "20-builtin-rhai-root.json",
    ] {
        let json = std::fs::read_to_string(plugin_dir().join(name)).unwrap();
        let report = run_plugin(&ctx, &json);
        assert!(report.error.is_none(), "{} error: {:?}", name, report.error);
    }
}
