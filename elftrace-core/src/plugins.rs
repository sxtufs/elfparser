use crate::disasm::disassemble;
use crate::elf_parser::ElfContext;
use crate::patcher::{apply_quick_patch, assemble_and_patch, PatchResult, QuickPatchType};
use crate::xref::find_callers_to;
use rhai::{Array, Dynamic, Engine, Map};
use serde::{Deserialize, Serialize};
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
    pub patch: Option<PluginPatch>,
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
            };
        }
    };

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
        };
    }

    let mut findings = Vec::new();
    let mut cached_strings: Option<Vec<crate::model::SDataItem>> = None;

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
                    }
                }
            }
            "symbol" | "sym" => {
                let needle = rule.pattern.to_lowercase();
                if !needle.is_empty() {
                    let mut count = 0;
                    for (&addr, sym) in &ctx.syms_map {
                        if count >= MAX_MATCHES_PER_RULE {
                            break;
                        }
                        let display = sym.demangled.as_deref().unwrap_or(sym.sym.as_str());
                        if sym.sym.to_lowercase().contains(&needle)
                            || display.to_lowercase().contains(&needle)
                        {
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
                let needle = rule.pattern.to_lowercase();
                if !needle.is_empty() {
                    if cached_strings.is_none() {
                        cached_strings = ctx.extract_strings().ok().map(|s| s.data);
                    }
                    if let Some(ref strings) = cached_strings {
                        let mut count = 0;
                        for item in strings {
                            if count >= MAX_MATCHES_PER_RULE {
                                break;
                            }
                            if item.string.to_lowercase().contains(&needle) {
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
            match execute_rhai_script(ctx, arch_name, script_src) {
                Ok(mut script_findings) => findings.append(&mut script_findings),
                Err(e) => script_error = Some(e),
            }
        }
    }

    let total = findings.len();
    PluginReport {
        plugin_id: manifest.id,
        plugin_name: manifest.name,
        total_findings: total,
        findings,
        error: script_error,
    }
}

#[inline(never)]
fn execute_rhai_script(
    ctx: &ElfContext,
    arch_name: &str,
    script_src: &str,
) -> Result<Vec<PluginFinding>, String> {
    let mut engine = Engine::new();
    engine.set_max_operations(200_000);

    let arch_owned = arch_name.to_string();
    engine.register_fn("arch", move || -> String { arch_owned.clone() });
    engine.register_fn("hex", |val: i64| -> String { format!("0x{:x}", val as u64) });

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
                let is_thumb = ctx_ref
                    .syms_map
                    .get(&vaddr)
                    .map(|s| s.thumb)
                    .unwrap_or(false);
                if let Ok(code) = disassemble(&ctx_ref.raw[off..], vaddr, sz, e_machine, is_thumb) {
                    for ins in code.data {
                        let mut m = Map::new();
                        m.insert("address".into(), Dynamic::from(ins.address as i64));
                        m.insert("mnemonic".into(), Dynamic::from(ins.mnemonic));
                        m.insert("op_str".into(), Dynamic::from(ins.op_str));
                        out.push(Dynamic::from(m));
                    }
                }
            }
        }
        out
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

    let collected: Arc<Mutex<Vec<PluginFinding>>> = Arc::new(Mutex::new(Vec::new()));

    let c1 = Arc::clone(&collected);
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
                }
            }
        },
    );

    let c2 = Arc::clone(&collected);
    engine.register_fn(
        "report_patch",
        move |rule_name: &str,
              addr: i64,
              severity: &str,
              desc: &str,
              mode: &str,
              value: &str| {
            let ctx_ref = unsafe { &*(ctx_ptr as *const ElfContext) };
            let vaddr = addr as u64;
            let offset = ctx_ref.vaddr_to_offset(vaddr).unwrap_or(0);
            let sym_name = find_enclosing_symbol(ctx_ref, vaddr);
            if let Ok(mut list) = c2.lock() {
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
                        patch: Some(PluginPatch {
                            mode: mode.to_string(),
                            value: value.to_string(),
                            offset: 0,
                        }),
                    });
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
            let is_thumb = ctx.syms_map.get(&address).map(|s| s.thumb).unwrap_or(false);
            apply_quick_patch(ctx, address, ptype, is_thumb)
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

fn find_enclosing_symbol(ctx: &ElfContext, vaddr: u64) -> Option<String> {
    if let Some(sym) = ctx.syms_map.get(&vaddr) {
        return Some(sym.demangled.as_deref().unwrap_or(&sym.sym).to_string());
    }
    let mut best: Option<(u64, &str)> = None;
    for (&addr, sym) in &ctx.syms_map {
        if addr != 0 && addr <= vaddr {
            let end = if sym.size > 0 {
                addr + sym.size
            } else {
                addr + 0x1000
            };
            if vaddr < end && best.map(|(b_addr, _)| addr > b_addr).unwrap_or(true) {
                let name = sym.demangled.as_deref().unwrap_or(&sym.sym);
                best = Some((addr, name));
            }
        }
    }
    best.map(|(_, name)| name.to_string())
}
