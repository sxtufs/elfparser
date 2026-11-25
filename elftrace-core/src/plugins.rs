use crate::disasm::disassemble;
use crate::elf_parser::ElfContext;
use crate::patcher::{apply_quick_patch, assemble_and_patch, PatchResult, QuickPatchType};
use crate::xref::find_callers_to;
use rhai::{Array, Dynamic, Engine, Map};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPatch {
    pub mode: String, // "asm", "hex", "quick"
    pub value: String,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String, // "byte_pattern", "symbol", "string"
    pub pattern: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default = "default_match_mode")]
    pub match_mode: String,
    #[serde(default)]
    pub patch: Option<PluginPatch>,
}

fn default_match_mode() -> String {
    "contains".to_string()
}

fn default_severity() -> String {
    "INFO".to_string()
}

fn default_version() -> String {
    "1.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub arch: Vec<String>,
    #[serde(default)]
    pub rules: Vec<PluginRule>,
    #[serde(default)]
    pub script: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    pub rule_name: String,
    pub rule_type: String,
    pub address: u64,
    pub offset: u64,
    pub matched_value: String,
    pub severity: String,
    pub description: String,
    pub symbol_name: Option<String>,
    pub patch: Option<PluginPatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginReport {
    pub plugin_id: String,
    pub plugin_name: String,
    pub total_findings: usize,
    pub findings: Vec<PluginFinding>,
    pub error: Option<String>,
    /// True when one or more rules hit MAX_MATCHES_PER_RULE and results were
    /// silently capped. The UI uses this to show "showing first N".
    #[serde(default)]
    pub truncated: bool,
}

const MAX_MATCHES_PER_RULE: usize = 64;

#[inline(never)]
pub fn run_plugin_json(ctx: &ElfContext, plugin_json: &str) -> String {
    let report = run_plugin(ctx, plugin_json);
    serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
}

#[inline(never)]
pub fn run_plugin(ctx: &ElfContext, plugin_json: &str) -> PluginReport {
    let manifest: PluginManifest = match serde_json::from_str(plugin_json) {
        Ok(m) => m,
        Err(e) => {
            return PluginReport {
                plugin_id: String::new(),
                plugin_name: "Invalid Plugin".to_string(),
                total_findings: 0,
                findings: Vec::new(),
                error: Some(format!("JSON parse error: {}", e)),
                truncated: false,
            };
        }
    };

    // Validate match_mode early: unknown values used to silently fall back to
    // "contains" inside rule_matches(), masking plugin authoring mistakes.
    for rule in &manifest.rules {
        let rt = rule.rule_type.to_lowercase();
        if rt == "string" || rt == "str" || rt == "symbol" || rt == "sym" {
            let mm = rule.match_mode.to_lowercase();
            if mm != "contains" && mm != "exact" && mm != "word_boundary" {
                return PluginReport {
                    plugin_id: manifest.id,
                    plugin_name: manifest.name,
                    total_findings: 0,
                    findings: Vec::new(),
                    error: Some(format!(
                        "Rule '{}' has invalid match_mode '{}' (expected contains|exact|word_boundary)",
                        rule.name, rule.match_mode
                    )),
                    truncated: false,
                };
            }
        }
    }

    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(0);
    let arch_name = match e_machine {
        183 => "aarch64",
        40 => "arm",
        62 => "x86_64",
        3 => "x86",
        _ => "unknown",
    };

    if !manifest.arch.is_empty()
        && !manifest
            .arch
            .iter()
            .any(|a| a.eq_ignore_ascii_case(arch_name) || a.eq_ignore_ascii_case("all"))
    {
        return PluginReport {
            plugin_id: manifest.id,
            plugin_name: manifest.name,
            total_findings: 0,
            findings: Vec::new(),
            error: Some(format!(
                "Plugin targets {:?}, but loaded binary is {}",
                manifest.arch, arch_name
            )),
            truncated: false,
        };
    }

    let mut findings = Vec::new();
    let mut cached_strings: Option<Vec<crate::model::SDataItem>> = None;
    // Shared truncation flag: set by rule loops that hit MAX_MATCHES_PER_RULE
    // and by the Rhai report()/report_patch() 256-cap. Surfaced in PluginReport
    // so the UI can render "showing first N" instead of silently dropping.
    let truncated_flag = Arc::new(AtomicBool::new(false));

    for rule in &manifest.rules {
        match rule.rule_type.to_lowercase().as_str() {
            "byte_pattern" | "bytes" => {
                if let Ok(pattern) = parse_ida_pattern(&rule.pattern) {
                    if !pattern.is_empty() {
                        let mut count = 0;
                        let mut i = 0;
                        let raw = &ctx.raw;
                        let plen = pattern.len();
                        while i + plen <= raw.len() && count < MAX_MATCHES_PER_RULE {
                            // (loop body unchanged)
                            let mut matched = true;
                            for (j, pat_byte) in pattern.iter().enumerate() {
                                if let Some(b) = pat_byte {
                                    if raw[i + j] != *b {
                                        matched = false;
                                        break;
                                    }
                                }
                            }
                            if matched {
                                let file_off = i as u64;
                                let vaddr = ctx.offset_to_vaddr(file_off).unwrap_or(file_off);
                                let sym_name = find_enclosing_symbol(ctx, vaddr);
                                let preview: String = raw[i..(i + plen).min(i + 16)]
                                    .iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                findings.push(PluginFinding {
                                    rule_name: rule.name.clone(),
                                    rule_type: rule.rule_type.clone(),
                                    address: vaddr,
                                    offset: file_off,
                                    matched_value: preview,
                                    severity: rule.severity.clone(),
                                    description: rule.description.clone(),
                                    symbol_name: sym_name,
                                    patch: rule.patch.clone(),
                                });
                                count += 1;
                                i += plen;
                            } else {
                                i += 1;
                            }
                        }
                        if count >= MAX_MATCHES_PER_RULE {
                            truncated_flag.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            "symbol" | "sym" => {
                if !rule.pattern.is_empty() {
                    let mut count = 0;
                    for (&addr, sym) in &ctx.syms_map {
                        if count >= MAX_MATCHES_PER_RULE {
                            truncated_flag.store(true, Ordering::Relaxed);
                            break;
                        }
                        let display = sym.demangled.as_deref().unwrap_or(sym.sym.as_str());
                        if display.starts_with("typeinfo ") || display.starts_with("vtable ") {
                            continue;
                        }
                        if rule_matches(
                            sym.sym.as_str(),
                            &rule.pattern,
                            rule.case_sensitive,
                            &rule.match_mode,
                        ) || rule_matches(
                            display,
                            &rule.pattern,
                            rule.case_sensitive,
                            &rule.match_mode,
                        ) {
                            let file_off = ctx.vaddr_to_offset(addr).unwrap_or(0);
                            findings.push(PluginFinding {
                                rule_name: rule.name.clone(),
                                rule_type: rule.rule_type.clone(),
                                address: addr,
                                offset: file_off,
                                matched_value: display.to_string(),
                                severity: rule.severity.clone(),
                                description: rule.description.clone(),
                                symbol_name: Some(display.to_string()),
                                patch: rule.patch.clone(),
                            });
                            count += 1;
                        }
                    }
                }
            }
            "string" | "str" => {
                if !rule.pattern.is_empty() {
                    if cached_strings.is_none() {
                        cached_strings = ctx.extract_strings().ok().map(|s| s.data);
                    }
                    if let Some(ref strings) = cached_strings {
                        let mut count = 0;
                        for item in strings {
                            if count >= MAX_MATCHES_PER_RULE {
                                truncated_flag.store(true, Ordering::Relaxed);
                                break;
                            }
                            let hit = rule_matches(
                                &item.string,
                                &rule.pattern,
                                rule.case_sensitive,
                                &rule.match_mode,
                            );
                            if hit {
                                findings.push(PluginFinding {
                                    rule_name: rule.name.clone(),
                                    rule_type: rule.rule_type.clone(),
                                    address: item.vaddr,
                                    offset: item.paddr,
                                    matched_value: item.string.clone(),
                                    severity: rule.severity.clone(),
                                    description: rule.description.clone(),
                                    symbol_name: None,
                                    patch: rule.patch.clone(),
                                });
                                count += 1;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut script_error: Option<String> = None;
    if let Some(ref script_src) = manifest.script {
        if !script_src.trim().is_empty() {
            match execute_rhai_script(ctx, arch_name, script_src, &truncated_flag) {
                Ok(mut script_findings) => findings.append(&mut script_findings),
                Err(e) => script_error = Some(e),
            }
        }
    }

    // Deduplicate findings produced by overlapping rules within this plugin.
    // Key is (address, rule_name) so distinct rules at the same address are kept.
    {
        use std::collections::HashSet;
        let mut seen: HashSet<(u64, String)> = HashSet::new();
        findings.retain(|f| seen.insert((f.address, f.rule_name.clone())));
    }

    let total = findings.len();
    let truncated = truncated_flag.load(Ordering::Relaxed);
    PluginReport {
        plugin_id: manifest.id,
        plugin_name: manifest.name,
        total_findings: total,
        findings,
        error: script_error,
        truncated,
    }
}

#[inline(never)]
fn execute_rhai_script(
    ctx: &ElfContext,
    arch_name: &str,
    script_src: &str,
    truncated_flag: &Arc<AtomicBool>,
) -> Result<Vec<PluginFinding>, String> {
    let mut engine = Engine::new();
    // Bound total work and recursion so a pathological or malicious plugin script
    // cannot hang or stack-overflow the single native thread (DoS).
    engine.set_max_operations(200_000);
    engine.set_max_expr_depths(64, 32);
    engine.set_max_call_levels(64);
    // Bound string/array growth too: the op budget alone still allows a script
    // to build huge arrays/strings within few operations and DoS the native thread.
    engine.set_max_string_size(64 * 1024);
    engine.set_max_array_size(4_096);
    engine.set_max_map_size(4_096);

    let arch_owned = arch_name.to_string();
    engine.register_fn("arch", move || -> String { arch_owned.clone() });
    engine.register_fn("hex", |val: i64| -> String { format!("0x{:x}", val as u64) });
    engine.register_fn("parse_addr", |s: &str| -> i64 {
        for part in s.split(',') {
            let t = part
                .trim()
                .trim_end_matches(']')
                .trim()
                .trim_start_matches('#');
            if let Some(hex_str) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                if let Ok(v) = u64::from_str_radix(hex_str, 16) {
                    return v as i64;
                }
            } else if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(v) = t.parse::<u64>() {
                    return v as i64;
                }
            }
        }
        -1
    });

    // Safety: `ctx` outlives `engine` within this synchronous function call.
    let ctx_ptr = ctx as *const ElfContext as usize;

    engine.register_fn("find_bytes", move |pattern: &str| -> Array {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        let mut out = Array::new();
        if let Ok(pat) = parse_ida_pattern(pattern) {
            if !pat.is_empty() {
                let raw = &ctx_ref.raw;
                let plen = pat.len();
                let mut i = 0;
                while i + plen <= raw.len() && out.len() < MAX_MATCHES_PER_RULE {
                    let mut matched = true;
                    for (j, pb) in pat.iter().enumerate() {
                        if let Some(b) = pb {
                            if raw[i + j] != *b {
                                matched = false;
                                break;
                            }
                        }
                    }
                    if matched {
                        let vaddr = ctx_ref.offset_to_vaddr(i as u64).unwrap_or(i as u64);
                        out.push(Dynamic::from(vaddr as i64));
                        i += plen;
                    } else {
                        i += 1;
                    }
                }
            }
        }
        out
    });

    engine.register_fn("find_symbols", move |needle: &str| -> Array {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        let q = needle.to_lowercase();
        let mut out = Array::new();
        if q.is_empty() {
            return out;
        }
        for (&addr, sym) in &ctx_ref.syms_map {
            if out.len() >= MAX_MATCHES_PER_RULE {
                break;
            }
            let display = sym.demangled.as_deref().unwrap_or(sym.sym.as_str());
            if sym.sym.to_lowercase().contains(&q) || display.to_lowercase().contains(&q) {
                let mut m = Map::new();
                m.insert("address".into(), Dynamic::from(addr as i64));
                m.insert("name".into(), Dynamic::from(display.to_string()));
                m.insert("size".into(), Dynamic::from(sym.size as i64));
                out.push(Dynamic::from(m));
            }
        }
        out
    });

    engine.register_fn("find_strings", move |needle: &str| -> Array {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        let q = needle.to_lowercase();
        let mut out = Array::new();
        if q.is_empty() {
            return out;
        }
        if let Ok(sdata) = ctx_ref.extract_strings() {
            for item in sdata.data {
                if out.len() >= MAX_MATCHES_PER_RULE {
                    break;
                }
                if item.string.to_lowercase().contains(&q) {
                    let mut m = Map::new();
                    m.insert("address".into(), Dynamic::from(item.vaddr as i64));
                    m.insert("offset".into(), Dynamic::from(item.paddr as i64));
                    m.insert("value".into(), Dynamic::from(item.string));
                    out.push(Dynamic::from(m));
                }
            }
        }
        out
    });

    engine.register_fn("get_xrefs", move |addr: i64| -> Array {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        let refs = find_callers_to(ctx_ref, addr as u64);
        let mut out = Array::new();
        for r in refs.into_iter().take(MAX_MATCHES_PER_RULE) {
            let mut m = Map::new();
            m.insert("from".into(), Dynamic::from(r.from_address as i64));
            m.insert("kind".into(), Dynamic::from(r.kind));
            m.insert("instruction".into(), Dynamic::from(r.instruction));
            m.insert(
                "caller".into(),
                Dynamic::from(r.caller_func.unwrap_or_default()),
            );
            out.push(Dynamic::from(m));
        }
        out
    });

    engine.register_fn("disasm", move |addr: i64, size: i64| -> Array {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        let mut out = Array::new();
        let vaddr = addr as u64;
        let sz = (size.clamp(4, 1024)) as u64;
        if let Some(off) = ctx_ref.vaddr_to_offset(vaddr) {
            let off = off as usize;
            if off < ctx_ref.raw.len() {
                let e_machine = ctx_ref.get_info().map(|i| i.e_machine).unwrap_or(183);
                let is_thumb = if e_machine == 40 {
                    (vaddr & 1) != 0 || crate::decompiler::find_function_range(ctx_ref, vaddr).thumb
                } else {
                    false
                };
                let clean_vaddr = if e_machine == 40 { vaddr & !1 } else { vaddr };
                if let Ok(code) =
                    disassemble(&ctx_ref.raw[off..], clean_vaddr, sz, e_machine, is_thumb)
                {
                    for ins in code.data {
                        let mut m = Map::new();
                        m.insert("address".into(), Dynamic::from(ins.address as i64));
                        m.insert("mnemonic".into(), Dynamic::from(ins.mnemonic));
                        m.insert("op_str".into(), Dynamic::from(ins.op_str));
                        m.insert("thumb".into(), Dynamic::from(is_thumb));
                        out.push(Dynamic::from(m));
                    }
                }
            }
        }
        out
    });

    engine.register_fn("find_jni_methods", move || -> Array {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        scan_jni_native_methods(ctx_ref)
    });

    engine.register_fn("read_u32", move |addr: i64| -> i64 {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        if let Some(off) = ctx_ref.vaddr_to_offset(addr as u64) {
            let off = off as usize;
            if off + 4 <= ctx_ref.raw.len() {
                let val = u32::from_le_bytes(ctx_ref.raw[off..off + 4].try_into().unwrap());
                return val as i64;
            }
        }
        -1
    });

    // 64-bit load. Rhai's i64 can hold the full value; a value that would
    // overflow the signed range is returned as the wrapped i64 (bit-identical),
    // so plugin bit-twiddling on masks remains correct.
    engine.register_fn("read_u64", move |addr: i64| -> i64 {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        if let Some(off) = ctx_ref.vaddr_to_offset(addr as u64) {
            let off = off as usize;
            if off + 8 <= ctx_ref.raw.len() {
                return u64::from_le_bytes(ctx_ref.raw[off..off + 8].try_into().unwrap()) as i64;
            }
        }
        -1
    });

    // Read a NUL-terminated C string at a virtual address. Bounded to 4 KiB so
    // a missing terminator cannot scan the whole file. Returns "" when the
    // address is unmapped. Ideal for recovering format strings / paths that a
    // `string` rule can't reach because they are built in code, not .rodata.
    engine.register_fn("read_cstr", move |addr: i64| -> String {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        ctx_ref.read_string_at(addr as u64, 4096)
    });

    // Name of the section containing a virtual address (e.g. ".text").
    // Returns "" when unmapped. Lets scripts skip findings in .eh_frame,
    // .rodata, etc.
    engine.register_fn("section_of", move |addr: i64| -> String {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        ctx_ref
            .get_section_name_for_vaddr(addr as u64)
            .unwrap_or_default()
    });

    // Symbol name whose range encloses the address, or "" if none.
    // O(log n) via the shared sorted symbol index.
    engine.register_fn("symbol_at", move |addr: i64| -> String {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        ctx_ref.enclosing_symbol(addr as u64).unwrap_or_default()
    });

    // True when the address maps to an executable segment. Lets scripts avoid
    // reporting data as a callable target.
    engine.register_fn("is_executable", move |addr: i64| -> bool {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        ctx_ref.is_executable_address(addr as u64)
    });

    // Shannon entropy (0.0..=8.0) of the section containing the address.
    // Reuses the same section-entropy report as the Entropy tab so plugin
    // verdicts match it exactly. -1.0 when the address is unmapped or the
    // section is not present in the report.
    engine.register_fn("entropy_of", move |addr: i64| -> f64 {
        let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
        let section = match ctx_ref.get_section_name_for_vaddr(addr as u64) {
            Some(s) => s,
            None => return -1.0,
        };
        let report = crate::scanner::calculate_entropy_report(ctx_ref);
        report
            .sections
            .iter()
            .find(|s| s.name == section)
            .map(|s| s.entropy)
            .unwrap_or(-1.0)
    });

    let collected: Arc<Mutex<Vec<PluginFinding>>> = Arc::new(Mutex::new(Vec::new()));

    let c1 = Arc::clone(&collected);
    let tf1 = Arc::clone(truncated_flag);
    engine.register_fn(
        "report",
        move |rule_name: &str, addr: i64, severity: &str, desc: &str| {
            let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
            let vaddr = addr as u64;
            let offset = ctx_ref.vaddr_to_offset(vaddr).unwrap_or(0);
            let sym_name = find_enclosing_symbol(ctx_ref, vaddr);
            if let Ok(mut list) = c1.lock() {
                if list.len() < 256 {
                    list.push(PluginFinding {
                        rule_name: rule_name.to_string(),
                        rule_type: "rhai".to_string(),
                        address: vaddr,
                        offset,
                        matched_value: format!("0x{:x}", vaddr),
                        severity: severity.to_string(),
                        description: desc.to_string(),
                        symbol_name: sym_name,
                        patch: None,
                    });
                } else {
                    tf1.store(true, Ordering::Relaxed);
                }
            }
        },
    );

    let c2 = Arc::clone(&collected);
    let tf2 = Arc::clone(truncated_flag);
    engine.register_fn(
        "report_patch",
        move |rule_name: &str,
              addr: i64,
              severity: &str,
              desc: &str,
              mode: &str,
              value: &str| {
            // Scripts call this with 6 args (no explicit patch offset). The
            // patch is applied at the reported address, so offset defaults to 0.
            let patch_offset: i64 = 0;
            let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
            let vaddr = addr as u64;
            let file_offset = ctx_ref.vaddr_to_offset(vaddr).unwrap_or(0);
            let sym_name = find_enclosing_symbol(ctx_ref, vaddr);
            if let Ok(mut list) = c2.lock() {
                if list.len() < 256 {
                    list.push(PluginFinding {
                        rule_name: rule_name.to_string(),
                        rule_type: "rhai".to_string(),
                        address: vaddr,
                        offset: file_offset,
                        matched_value: format!("0x{:x}", vaddr),
                        severity: severity.to_string(),
                        description: desc.to_string(),
                        symbol_name: sym_name,
                        patch: Some(PluginPatch {
                            mode: mode.to_string(),
                            value: value.to_string(),
                            offset: patch_offset,
                        }),
                    });
                } else {
                    tf2.store(true, Ordering::Relaxed);
                }
            }
        },
    );

    // 7-argument overload (with explicit patch offset), used by some built-in
    // scripts (e.g. Direct Syscall Tracer). Rhai dispatches report_patch by
    // arity, so both the 6-arg and 7-arg forms must be registered.
    let c3 = Arc::clone(&collected);
    let tf3 = Arc::clone(truncated_flag);
    engine.register_fn(
        "report_patch",
        move |rule_name: &str,
              addr: i64,
              severity: &str,
              desc: &str,
              mode: &str,
              value: &str,
              patch_offset: i64| {
            let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
            let vaddr = addr as u64;
            let file_offset = ctx_ref.vaddr_to_offset(vaddr).unwrap_or(0);
            let sym_name = find_enclosing_symbol(ctx_ref, vaddr);
            if let Ok(mut list) = c3.lock() {
                if list.len() < 256 {
                    list.push(PluginFinding {
                        rule_name: rule_name.to_string(),
                        rule_type: "rhai".to_string(),
                        address: vaddr,
                        offset: file_offset,
                        matched_value: format!("0x{:x}", vaddr),
                        severity: severity.to_string(),
                        description: desc.to_string(),
                        symbol_name: sym_name,
                        patch: Some(PluginPatch {
                            mode: mode.to_string(),
                            value: value.to_string(),
                            offset: patch_offset,
                        }),
                    });
                } else {
                    tf3.store(true, Ordering::Relaxed);
                }
            }
        },
    );

    engine
        .run(script_src)
        .map_err(|e| format!("Rhai script error: {}", e))?;

    let out = collected.lock().map(|g| g.clone()).unwrap_or_default();
    Ok(out)
}

#[inline(never)]
pub fn apply_plugin_patch(
    ctx: &mut ElfContext,
    address: u64,
    mode: &str,
    value: &str,
) -> PatchResult {
    match mode.to_lowercase().as_str() {
        "quick" => {
            let ptype = match value.trim().to_lowercase().as_str() {
                "nop" => QuickPatchType::Nop,
                "ret_true" | "return_true" | "true" => QuickPatchType::ReturnTrue,
                "ret_false" | "return_false" | "false" => QuickPatchType::ReturnFalse,
                "ret_void" | "return_void" | "void" => QuickPatchType::ReturnVoid,
                _ => {
                    return PatchResult {
                        address,
                        original_bytes: vec![],
                        patched_bytes: vec![],
                        patch_type: format!("Plugin Quick: {}", value),
                        success: false,
                        error: Some(format!("Unknown quick patch type: {}", value)),
                    };
                }
            };
            let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
            let is_thumb = if e_machine == 40 {
                (address & 1) != 0 || crate::decompiler::find_function_range(ctx, address).thumb
            } else {
                false
            };
            apply_quick_patch(ctx, address & !1, ptype, is_thumb)
        }
        "asm" | "hex" => {
            let parts: Vec<&str> = value
                .split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                return PatchResult {
                    address,
                    original_bytes: vec![],
                    patched_bytes: vec![],
                    patch_type: "Plugin Patch".to_string(),
                    success: false,
                    error: Some("Empty patch value".to_string()),
                };
            }
            let mut cur_addr = address;
            let mut all_orig = Vec::new();
            let mut all_patched = Vec::new();
            for part in parts {
                let res = assemble_and_patch(ctx, cur_addr, part);
                if !res.success {
                    return res;
                }
                cur_addr += res.patched_bytes.len() as u64;
                all_orig.extend(res.original_bytes);
                all_patched.extend(res.patched_bytes);
            }
            PatchResult {
                address,
                original_bytes: all_orig,
                patched_bytes: all_patched,
                patch_type: format!("Plugin ({}): {}", mode, value.trim()),
                success: true,
                error: None,
            }
        }
        _ => PatchResult {
            address,
            original_bytes: vec![],
            patched_bytes: vec![],
            patch_type: format!("Plugin: {}", mode),
            success: false,
            error: Some(format!("Unsupported patch mode: {}", mode)),
        },
    }
}

/// Returns true if `haystack` matches `needle` according to the rule's match mode.
/// `match_mode` may be "contains" (default), "exact", or "word_boundary".
/// When `case_sensitive` is false, comparison is done on lowercased strings.
fn rule_matches(haystack: &str, needle: &str, case_sensitive: bool, match_mode: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    if case_sensitive {
        match match_mode.to_lowercase().as_str() {
            "exact" => haystack == needle,
            "word_boundary" => word_boundary_contains(haystack, needle),
            _ => haystack.contains(needle),
        }
    } else {
        let h = haystack.to_lowercase();
        let n = needle.to_lowercase();
        match match_mode.to_lowercase().as_str() {
            "exact" => h == n,
            "word_boundary" => word_boundary_contains(&h, &n),
            _ => h.contains(&n),
        }
    }
}

/// Case-sensitive word-boundary containment: `needle` must not be immediately
/// preceded or followed by an alphanumeric character (`[A-Za-z0-9]`).
/// Underscore is treated as a boundary so a rule for `connect` matches the
/// C-style wrapper/call site `posix_connect`, while still rejecting the
/// embedded substrings `disconnect` / `reconnect` / `connectivity`.
fn word_boundary_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_ascii_alphanumeric();
    let h_bytes = haystack.as_bytes();
    let mut start = 0usize;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let before_ok = abs == 0 || !is_word(h_bytes[abs - 1] as char);
        let end = abs + needle.len();
        let after_ok = end >= haystack.len() || !is_word(h_bytes[end] as char);
        if before_ok && after_ok {
            return true;
        }
        start = abs + needle.len().max(1);
        if start >= haystack.len() {
            break;
        }
    }
    false
}

fn parse_ida_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let mut out = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            out.push(None);
        } else {
            let b = u8::from_str_radix(token, 16)
                .map_err(|_| format!("Invalid hex byte in pattern: {}", token))?;
            out.push(Some(b));
        }
    }
    Ok(out)
}

fn scan_jni_native_methods(ctx: &ElfContext) -> Array {
    use object::{Object, ObjectSection, ObjectSegment, RelocationTarget};
    let mut out = Array::new();
    let Ok(obj) = object::File::parse(&*ctx.raw) else {
        return out;
    };

    let is_64 = obj.is_64();
    let ptr_size = if is_64 { 8usize } else { 4usize };

    // Collect executable address ranges (.text, or PF_X PT_LOAD segments for LIAPP/stripped ELFs)
    let mut exec_ranges: Vec<(u64, u64)> = Vec::new();
    for sec in obj.sections() {
        if sec.kind() == object::SectionKind::Text && sec.size() > 16 {
            let start = sec.address();
            let end = start.saturating_add(sec.size());
            if end > start {
                exec_ranges.push((start, end));
            }
        }
    }
    if exec_ranges.is_empty() {
        for seg in obj.segments() {
            if let object::SegmentFlags::Elf { p_flags } = seg.flags() {
                if (p_flags & 1) != 0 && seg.size() > 0 {
                    let start = seg.address();
                    let end = start.saturating_add(seg.size());
                    if end > start {
                        exec_ranges.push((start, end));
                    }
                }
            }
        }
    }
    let is_exec = |addr: u64| -> bool {
        let clean = if is_64 { addr } else { addr & !1 };
        exec_ranges.iter().any(|&(s, e)| clean >= s && clean < e)
    };

    // Build relocation map: slot_vaddr -> target_vaddr (for PIE R_*_RELATIVE)
    let mut reloc_map: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for sec in obj.sections() {
        for (offset, reloc) in sec.relocations() {
            if let RelocationTarget::Absolute = reloc.target() {
                if reloc.addend() > 0 {
                    reloc_map.insert(offset, reloc.addend() as u64);
                }
            }
        }
    }
    if let Some(dyn_relocs) = obj.dynamic_relocations() {
        for (offset, reloc) in dyn_relocs {
            if reloc.addend() > 0 {
                reloc_map.insert(offset, reloc.addend() as u64);
            }
        }
    }

    let read_ptr = |slot_vaddr: u64, raw_slice: &[u8]| -> u64 {
        if let Some(&target) = reloc_map.get(&slot_vaddr) {
            return target;
        }
        if is_64 && raw_slice.len() >= 8 {
            u64::from_le_bytes(raw_slice[0..8].try_into().unwrap())
        } else if !is_64 && raw_slice.len() >= 4 {
            u32::from_le_bytes(raw_slice[0..4].try_into().unwrap()) as u64
        } else {
            0
        }
    };

    let is_valid_jni_sig = |s: &str| -> bool {
        if !s.starts_with('(') || s.len() < 3 || s.len() > 256 {
            return false;
        }
        let Some(close) = s.find(')') else {
            return false;
        };
        let ret = &s[close + 1..];
        !ret.is_empty()
            && matches!(
                ret.as_bytes()[0],
                b'V' | b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'['
            )
    };

    let is_valid_ident = |s: &str| -> bool {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
    };

    let mut data_regions: Vec<(u64, &[u8])> = Vec::new();
    for sec in obj.sections() {
        let name = sec.name().unwrap_or("");
        if name == ".data" || name == ".data.rel.ro" || name == ".rodata" {
            if let Ok(data) = sec.data() {
                if data.len() > 16 {
                    data_regions.push((sec.address(), data));
                }
            }
        }
    }
    if data_regions.is_empty() {
        for seg in obj.segments() {
            if let Ok(data) = seg.data() {
                if data.len() > 16 {
                    data_regions.push((seg.address(), data));
                }
            }
        }
    }

    for (base_vaddr, data) in data_regions {
        let triplet_size = ptr_size * 3;
        let mut off = 0usize;
        while off + triplet_size <= data.len() && out.len() < MAX_MATCHES_PER_RULE {
            let p_name = read_ptr(base_vaddr + off as u64, &data[off..off + ptr_size]);
            let p_sig = read_ptr(
                base_vaddr + (off + ptr_size) as u64,
                &data[off + ptr_size..off + ptr_size * 2],
            );
            let p_fn = read_ptr(
                base_vaddr + (off + ptr_size * 2) as u64,
                &data[off + ptr_size * 2..off + triplet_size],
            );

            if p_name != 0 && p_sig != 0 && is_exec(p_fn) {
                if let (Some(m_name), Some(m_sig)) = (
                    ctx.get_string_at_vaddr(p_name),
                    ctx.get_string_at_vaddr(p_sig),
                ) {
                    if is_valid_ident(&m_name) && is_valid_jni_sig(&m_sig) {
                        let mut m = Map::new();
                        m.insert("name".into(), Dynamic::from(m_name));
                        m.insert("signature".into(), Dynamic::from(m_sig));
                        m.insert("address".into(), Dynamic::from(p_fn as i64));
                        out.push(Dynamic::from(m));
                        off += triplet_size;
                        continue;
                    }
                }
            }
            off += ptr_size;
        }
    }

    out
}

fn find_enclosing_symbol(ctx: &ElfContext, vaddr: u64) -> Option<String> {
    // Delegates to the cached, binary-searched symbol index on ElfContext.
    // Previously this was an O(n) linear scan per finding.
    ctx.enclosing_symbol(vaddr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_is_case_insensitive_by_default() {
        assert!(rule_matches("Friday", "frida", false, "contains"));
        assert!(rule_matches("FRIDA", "frida", false, "contains"));
    }

    #[test]
    fn friday_not_matched_when_case_sensitive() {
        // Regression: the Frida rule must not flag the word "Friday".
        assert!(!rule_matches("Friday", "frida", true, "contains"));
        // Real frida artifacts are lowercase and must still match.
        assert!(rule_matches("frida", "frida", true, "contains"));
        assert!(rule_matches("/data/local/tmp/frida-server", "frida", true, "contains"));
    }

    #[test]
    fn word_boundary_rejects_embedded_substring() {
        // "connect" must not match "disconnect" / "reconnect" / "connectivity".
        assert!(!rule_matches("disconnect", "connect", true, "word_boundary"));
        assert!(!rule_matches("reconnect", "connect", true, "word_boundary"));
        assert!(!rule_matches("connectivity", "connect", true, "word_boundary"));
        // Standalone symbol/string must match.
        assert!(rule_matches("connect", "connect", true, "word_boundary"));
        assert!(rule_matches("posix_connect", "connect", true, "word_boundary"));
        assert!(rule_matches("connect()", "connect", true, "word_boundary"));
    }

    #[test]
    fn word_boundary_handles_edges() {
        assert!(word_boundary_contains("connect", "connect"));
        assert!(word_boundary_contains(" connect ", "connect"));
        assert!(word_boundary_contains("a.connect.b", "connect"));
        assert!(!word_boundary_contains("xconnect", "connect"));
        assert!(!word_boundary_contains("connectx", "connect"));
        assert!(!word_boundary_contains("", "connect"));
        assert!(!word_boundary_contains("abc", ""));
    }

    #[test]
    fn word_boundary_is_case_aware_after_lowering() {
        // Default (case-insensitive) word_boundary: "Connect" matches "connect".
        assert!(rule_matches("Connect", "connect", false, "word_boundary"));
        // Case-sensitive: "Connect" must not match lowercase needle.
        assert!(!rule_matches("Connect", "connect", true, "word_boundary"));
    }

    #[test]
    fn exact_mode() {
        assert!(rule_matches("frida", "frida", true, "exact"));
        assert!(!rule_matches("frida-server", "frida", true, "exact"));
        assert!(rule_matches("FRIDA", "frida", false, "exact"));
    }

    #[test]
    fn empty_needle_never_matches() {
        assert!(!rule_matches("anything", "", false, "contains"));
        assert!(!rule_matches("anything", "", false, "exact"));
        assert!(!rule_matches("anything", "", false, "word_boundary"));
    }

    #[test]
    fn parse_ida_pattern_roundtrip() {
        let p = parse_ida_pattern("01 00 ?? D4").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], Some(0x01));
        assert_eq!(p[2], None);
        assert!(parse_ida_pattern("zz").is_err());
    }

    #[test]
    fn plugin_rule_deserializes_match_options() {
        // Ensures the JSON schema accepts case_sensitive + match_mode and that
        // defaults apply when omitted (backward compatibility).
        let with_opts: PluginRule = serde_json::from_str(
            r#"{"name":"r","type":"string","pattern":"connect","case_sensitive":true,"match_mode":"word_boundary"}"#,
        )
        .unwrap();
        assert!(with_opts.case_sensitive);
        assert_eq!(with_opts.match_mode, "word_boundary");

        let defaults: PluginRule =
            serde_json::from_str(r#"{"name":"r","type":"string","pattern":"frida"}"#).unwrap();
        assert!(!defaults.case_sensitive);
        assert_eq!(defaults.match_mode, "contains");
    }
}
