use crate::elf_parser::ElfContext;
use crate::patcher::{apply_quick_patch, assemble_and_patch, PatchResult, QuickPatchType};
use serde::{Deserialize, Serialize};

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

    let total = findings.len();
    PluginReport {
        plugin_id: manifest.id,
        plugin_name: manifest.name,
        total_findings: total,
        findings,
        error: None,
    }
}

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
