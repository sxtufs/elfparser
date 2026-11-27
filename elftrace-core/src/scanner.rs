use crate::elf_parser::ElfContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub category: String,
    pub name: String,
    pub address: u64,
    pub offset: u64,
    pub matched_value: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub total_findings: usize,
    pub findings: Vec<SecurityFinding>,
}

// Signatures are stored XOR-masked with 0x5A so the scanner does NOT match its own .rodata table
const XOR_KEY: u8 = 0x5A;

const AES_SBOX_MASKED: [u8; 16] = [
    57, 38, 45, 33, 168, 49, 53, 159, 106, 91, 61, 113, 164, 141, 241, 44,
];
const AES_INVSBOX_MASKED: [u8; 16] = [
    8, 83, 48, 143, 106, 108, 255, 98, 229, 26, 249, 196, 219, 169, 141, 161,
];
const SHA256_K_MASKED: [u8; 16] = [
    194, 117, 208, 24, 203, 30, 109, 43, 149, 161, 154, 239, 255, 129, 239, 179,
];
const MD5_INIT_MASKED: [u8; 16] = [
    91, 121, 31, 61, 211, 241, 151, 181, 164, 134, 224, 194, 44, 14, 104, 74,
];

fn unmask(masked: &[u8]) -> Vec<u8> {
    masked.iter().map(|b| b ^ XOR_KEY).collect()
}

pub fn scan_security(ctx: &ElfContext) -> ScanReport {
    let mut findings = Vec::new();
    let raw = &ctx.raw;

    // 1. Binary Signatures (Crypto) - dynamically unmasked in RAM
    let aes_sbox = unmask(&AES_SBOX_MASKED);
    let aes_inv = unmask(&AES_INVSBOX_MASKED);
    let sha256_k = unmask(&SHA256_K_MASKED);
    let md5_init = unmask(&MD5_INIT_MASKED);

    let patterns = [
        (
            &aes_sbox[..],
            "Cryptography",
            "AES S-Box Substitution Table",
            "Medium",
            "Standard AES-128 / 256 encryption or decryption table found",
        ),
        (
            &aes_inv[..],
            "Cryptography",
            "AES Inverse S-Box Table",
            "Medium",
            "Standard AES decryption table found",
        ),
        (
            &sha256_k[..],
            "Cryptography",
            "SHA-256 Round Constants",
            "Low",
            "Standard SHA-256 hashing algorithm constants found",
        ),
        (
            &md5_init[..],
            "Cryptography",
            "MD5 Initialization Constants",
            "Low",
            "Standard MD5 hashing algorithm initialization vector found",
        ),
    ];

    // Single pass over the file: every signature here is the same fixed length
    // (16 bytes). The old code did one full `windows()` scan per pattern (4
    // passes over the whole binary); this does one pass and checks all patterns
    // at each offset. For a large .so that cuts the work ~4x.
    if !patterns.is_empty() {
        let sig_len = patterns[0].0.len();
        if sig_len > 0 && raw.len() >= sig_len {
            for off in 0..=(raw.len() - sig_len) {
                let window = &raw[off..off + sig_len];
                for (pat, cat, name, sev, desc) in patterns.iter() {
                    if window == *pat {
                        let off_u64 = off as u64;
                        let vaddr = offset_to_vaddr(ctx, off_u64).unwrap_or(0);
                        findings.push(SecurityFinding {
                            category: cat.to_string(),
                            name: name.to_string(),
                            address: vaddr,
                            offset: off_u64,
                            matched_value: format!("{:02X?}", &pat[..8]),
                            severity: sev.to_string(),
                            description: desc.to_string(),
                        });
                    }
                }
            }
        }
    }

    // 2. String Signatures (Anti-Debug, Root, Tamper, Packers) - XOR masked
    let string_rules: [(&[u8], &str, &str, &str, &str); 14] = [
        (
            &[14, 40, 59, 57, 63, 40, 10, 51, 62],
            "Anti-Debug",
            "TracerPid Check",
            "High",
            "Process status check used to detect attach of debuggers (GDB/LLDB)",
        ),
        (
            &[
                117, 42, 40, 53, 57, 117, 41, 63, 54, 60, 117, 41, 46, 59, 46, 47, 41,
            ],
            "Anti-Debug",
            "/proc/self/status Check",
            "Medium",
            "Inspection of own Linux process status for debug/sandbox flags",
        ),
        (
            &[42, 46, 40, 59, 57, 63],
            "Anti-Debug",
            "ptrace() API Call",
            "High",
            "Direct call or string referencing ptrace (often used with PTRACE_TRACEME)",
        ),
        (
            &[117, 41, 35, 41, 46, 63, 55, 117, 56, 51, 52, 117, 41, 47],
            "Root Detection",
            "SuperUser Binary Check",
            "Medium",
            "Standard Android root verification path",
        ),
        (
            &[
                117, 41, 35, 41, 46, 63, 55, 117, 34, 56, 51, 52, 117, 41, 47,
            ],
            "Root Detection",
            "SuperUser Binary Check",
            "Medium",
            "Standard Android root verification path",
        ),
        (
            &[55, 59, 61, 51, 41, 49],
            "Root Detection",
            "Magisk Root Detection",
            "High",
            "Searches for Magisk root manager files or sockets",
        ),
        (
            &[60, 40, 51, 62, 59, 119, 41, 63, 40, 44, 63, 40],
            "Hook Detection",
            "Frida Instrumentation Check",
            "High",
            "Detection of Frida dynamic instrumentation toolkit",
        ),
        (
            &[34, 42, 53, 41, 63, 62],
            "Hook Detection",
            "Xposed Framework Check",
            "Medium",
            "Detection of Xposed hooking bridge",
        ),
        (
            &[54, 51, 56, 48, 51, 59, 61, 47],
            "Packer Detection",
            "Qihoo 360 Jiagu Protection",
            "High",
            "ELF is protected with Qihoo 360 Jiagu packer",
        ),
        (
            &[54, 51, 56, 41, 63, 57, 55, 59, 51, 52],
            "Packer Detection",
            "Bangcle Protection",
            "High",
            "ELF is protected with Bangcle packer/protector",
        ),
        (
            &[54, 51, 56, 41, 50, 63, 34],
            "Packer Detection",
            "Tencent Legu Protection",
            "High",
            "ELF is protected with Tencent Legu packer",
        ),
        (
            &[54, 51, 56, 30, 63, 34, 18, 63, 54, 42, 63, 40],
            "Packer Detection",
            "SecNeo Protection",
            "High",
            "ELF is protected with SecNeo packer/encryption",
        ),
        (
            &[54, 51, 56, 56, 59, 51, 62, 47, 42, 40, 53, 46, 63, 57, 46],
            "Packer Detection",
            "Baidu Protect",
            "High",
            "ELF is protected with Baidu enterprise protector",
        ),
        (
            &[53, 54, 54, 44, 55],
            "Obfuscation",
            "Obfuscator-LLVM (OLLVM)",
            "Medium",
            "Contains Obfuscator-LLVM string encryption or flattening markers",
        ),
    ];

    if let Ok(sdata) = ctx.extract_strings() {
        for item in sdata.data {
            let s_lower = item.string.to_lowercase();
            for (masked_kw, cat, name, sev, desc) in string_rules {
                let kw_vec = unmask(masked_kw);
                if let Ok(kw_str) = std::str::from_utf8(&kw_vec) {
                    if s_lower.contains(&kw_str.to_lowercase()) {
                        findings.push(SecurityFinding {
                            category: cat.to_string(),
                            name: name.to_string(),
                            address: item.vaddr,
                            offset: item.paddr,
                            matched_value: item.string.clone(),
                            severity: sev.to_string(),
                            description: desc.to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    // 3. Section Shannon Entropy Analysis
    if let Ok(obj_file) = object::File::parse(&*ctx.raw) {
        use object::{Object, ObjectSection};
        for section in obj_file.sections() {
            let name = section.name().unwrap_or("").to_string();
            if let Ok(data) = section.data() {
                if data.len() >= 1024 {
                    let ent = calculate_entropy(data);
                    if ent > 7.45 {
                        findings.push(SecurityFinding {
                            category: "Entropy".to_string(),
                            name: format!("High Entropy: {}", name),
                            address: section.address(),
                            offset: section.file_range().map(|(o, _)| o).unwrap_or(0),
                            matched_value: format!("{:.2} / 8.0", ent),
                            severity: "Medium".to_string(),
                            description: format!("Section {} has high Shannon entropy ({:.2}/8.0), suggesting encryption or compressed payload.", name, ent),
                        });
                    }
                }
            }
        }
    }

    ScanReport {
        total_findings: findings.len(),
        findings,
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut ent = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            ent -= p * p.log2();
        }
    }
    ent
}

fn offset_to_vaddr(ctx: &ElfContext, offset: u64) -> Option<u64> {
    ctx.offset_to_vaddr(offset)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_high_entropy: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub overall_entropy: f64,
    pub overall_verdict: String,
    pub is_likely_packed: bool,
    pub sections: Vec<SectionEntropy>,
}

pub fn calculate_entropy_report(ctx: &ElfContext) -> EntropyReport {
    let overall_ent = calculate_entropy(&ctx.raw);
    let mut sections = Vec::new();

    if let Ok(obj_file) = object::File::parse(&*ctx.raw) {
        use object::{Object, ObjectSection};
        for sec in obj_file.sections() {
            let name = sec.name().unwrap_or("").to_string();
            if name.is_empty() || sec.size() == 0 {
                continue;
            }
            if let Ok(data) = sec.data() {
                let ent = calculate_entropy(data);
                let is_exec = sec.kind() == object::SectionKind::Text
                    || name == ".text"
                    || name.starts_with(".text.");
                let is_high = ent > 7.1;
                let status = if is_high {
                    if is_exec {
                        "Encrypted Code / Packed"
                    } else {
                        "Compressed / Encrypted Data"
                    }
                } else if is_exec {
                    "Standard Executable Code"
                } else {
                    "Plain Data / Constants"
                };

                sections.push(SectionEntropy {
                    name,
                    address: sec.address(),
                    size: sec.size(),
                    entropy: (ent * 100.0).round() / 100.0,
                    is_executable: is_exec,
                    is_high_entropy: is_high,
                    status: status.to_string(),
                });
            }
        }

        // Fallback to PT_LOAD segments when section headers are stripped/corrupted (e.g. LIAPP)
        if sections.is_empty() || sections.iter().all(|s| s.size <= 16) {
            sections.clear();
            use object::ObjectSegment;
            for (idx, seg) in obj_file.segments().enumerate() {
                if let Ok(data) = seg.data() {
                    if data.is_empty() {
                        continue;
                    }
                    let ent = calculate_entropy(data);
                    let is_exec = matches!(
                        seg.flags(),
                        object::SegmentFlags::Elf { p_flags, .. } if (p_flags.0 & 1) != 0
                    );
                    let is_high = ent > 7.1;
                    let status = if is_high {
                        if is_exec {
                            "Encrypted Code / Packed"
                        } else {
                            "Compressed / Encrypted Data"
                        }
                    } else if is_exec {
                        "Standard Executable Code"
                    } else {
                        "Plain Data / Constants"
                    };
                    sections.push(SectionEntropy {
                        name: format!("PT_LOAD[{}]", idx),
                        address: seg.address(),
                        size: data.len() as u64,
                        entropy: (ent * 100.0).round() / 100.0,
                        is_executable: is_exec,
                        is_high_entropy: is_high,
                        status: status.to_string(),
                    });
                }
            }
        }
    }

    let is_likely_packed = overall_ent > 7.1
        || sections
            .iter()
            .any(|s| s.is_executable && s.is_high_entropy);
    let overall_verdict = if is_likely_packed {
        "High Entropy • Likely Packed".to_string()
    } else if overall_ent > 6.4 {
        "Moderate Entropy • Standard".to_string()
    } else {
        "Low Entropy • Normal".to_string()
    };

    EntropyReport {
        overall_entropy: (overall_ent * 100.0).round() / 100.0,
        overall_verdict,
        is_likely_packed,
        sections,
    }
}

// ---------------------------------------------------------------------------
// Binary triage / security posture (checksec-style report for the Triage tab)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageItem {
    pub name: String,
    /// "Good" (hardened), "Weak" (missing protection), "Warn" (worth a look),
    /// "Info" (factual).
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub items: Vec<TriageItem>,
    pub needed_libs: Vec<String>,
    pub exported_functions: usize,
    pub init_constructors: usize,
    /// "Present" or "Stripped" (no non-dynamic symbol table).
    pub symbol_table: String,
    /// Number of *_chk FORTIFY_SOURCE wrappers linked in.
    pub fortify_count: usize,
}

const DT_BIND_NOW: u64 = 24;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_RPATH: u64 = 15;
const DT_FLAGS_1: u64 = 0x6fff_fffb;

pub fn build_triage_report(ctx: &ElfContext) -> TriageReport {
    let mut items = Vec::new();
    let mut needed = Vec::new();
    let mut exported_functions = 0usize;
    let mut init_constructors = 0usize;
    let mut symbol_table = String::from("Stripped");
    let mut fortify_count = 0usize;
    let mut has_canary = false;
    let mut bind_now = false;
    let mut runpath: Option<String> = None;
    let mut has_relro = false;
    let mut nx_enabled: Option<bool> = None;
    let mut is_pie = false;

    if let Ok(obj_file) = object::File::parse(&*ctx.raw) {
        // ET_DYN (3) means position-independent for both shared objects and PIE
        // executables. e_type lives at byte offset 16 of the ELF header.
        is_pie = ctx.raw.len() > 18 && u16::from_le_bytes([ctx.raw[16], ctx.raw[17]]) == 3;

        // Program-header facts come from the parser's own segment extraction
        // (get_info reuses the same data the UI shows).
        if let Ok(info) = ctx.get_info() {
            for seg in &info.segments {
                match seg.p_type.as_str() {
                    "GNU_RELRO" => has_relro = true,
                    "GNU_STACK" => nx_enabled = Some(!seg.flags.ends_with('X')),
                    _ => {}
                }
            }
            needed = info.libraries.clone();
        }

        let is64 = obj_file.is_64();
        for sec in obj_file.sections() {
            if let Ok(data) = sec.data() {
                let name = sec.name().unwrap_or("");
                if name == ".dynamic" && data.len() >= 8 {
                    let esz = if is64 { 16 } else { 8 };
                    for i in 0..(data.len() / esz) {
                        let c = &data[i * esz..(i + 1) * esz];
                        let (tag, val): (u64, u64) = if is64 {
                            (
                                u64::from_le_bytes(c[0..8].try_into().unwrap()),
                                u64::from_le_bytes(c[8..16].try_into().unwrap()),
                            )
                        } else {
                            (
                                u32::from_le_bytes(c[0..4].try_into().unwrap()) as u64,
                                u32::from_le_bytes(c[4..8].try_into().unwrap()) as u64,
                            )
                        };
                        match tag {
                            DT_BIND_NOW => bind_now = true,
                            DT_FLAGS => bind_now = bind_now || (val & 0x8) != 0,
                            DT_FLAGS_1 => bind_now = bind_now || (val & 0x1) != 0,
                            DT_RUNPATH | DT_RPATH => {
                                if runpath.is_none() {
                                    runpath = dynstr_at(ctx, val);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if name == ".init_array" && data.len() >= 8 {
                    let esz = if is64 { 8 } else { 4 };
                    init_constructors = data.len() / esz;
                }
            }
        }

        use object::{Object, ObjectSection, ObjectSymbol};
        let mut has_nondyn_syms = false;
        for sym in obj_file.symbols() {
            if sym.is_definition() || !sym.name_bytes().map(|n| n.is_empty()).unwrap_or(true) {
                has_nondyn_syms = true;
            }
            if let Ok(n) = sym.name() {
                if n.contains("__stack_chk") {
                    has_canary = true;
                }
                if n.ends_with("_chk") && n.starts_with("__") {
                    fortify_count += 1;
                }
            }
        }
        if has_nondyn_syms {
            symbol_table = "Present".to_string();
        }
        for sym in obj_file.dynamic_symbols() {
            if let object::SymbolKind::Text = sym.kind() {
                if sym.is_definition() {
                    exported_functions += 1;
                }
            }
            if let Ok(n) = sym.name() {
                if n.contains("__stack_chk") {
                    has_canary = true;
                }
                if n.ends_with("_chk") && n.starts_with("__") {
                    fortify_count += 1;
                }
            }
        }
    }

    // DT_NEEDED comes from the parser (already resolves dynstr).

    items.push(TriageItem {
        name: "PIE".into(),
        status: if is_pie { "Good".into() } else { "Weak".into() },
        detail: if is_pie {
            "ET_DYN — position independent".into()
        } else {
            "Fixed load address (ET_EXEC)".into()
        },
    });
    items.push(TriageItem {
        name: "RELRO".into(),
        status: if !has_relro {
            "Weak".into()
        } else if bind_now {
            "Good".into()
        } else {
            "Warn".into()
        },
        detail: if !has_relro {
            "No PT_GNU_RELRO segment".into()
        } else if bind_now {
            "Full RELRO (BIND_NOW)".into()
        } else {
            "Partial RELRO — GOT still writable".into()
        },
    });
    items.push(TriageItem {
        name: "NX".into(),
        status: match nx_enabled {
            Some(true) => "Good".into(),
            Some(false) => "Weak".into(),
            None => "Warn".into(),
        },
        detail: match nx_enabled {
            Some(true) => "Stack not executable".into(),
            Some(false) => "PT_GNU_STACK is executable".into(),
            None => "No PT_GNU_STACK header (arch-dependent default)".into(),
        },
    });
    items.push(TriageItem {
        name: "Stack Canary".into(),
        status: if has_canary { "Good".into() } else { "Weak".into() },
        detail: if has_canary {
            "__stack_chk symbols linked".into()
        } else {
            "No stack-protector references".into()
        },
    });
    items.push(TriageItem {
        name: "FORTIFY".into(),
        status: if fortify_count > 0 { "Good".into() } else { "Warn".into() },
        detail: format!("{fortify_count} _chk wrapper(s) linked"),
    });
    items.push(TriageItem {
        name: "Symbol Table".into(),
        status: "Info".into(),
        detail: format!("{symbol_table} (exported functions: {exported_functions})"),
    });
    items.push(TriageItem {
        name: "Init Constructors".into(),
        status: "Info".into(),
        detail: if init_constructors > 0 {
            format!("{init_constructors} entry(ies) in .init_array")
        } else {
            "None".into()
        },
    });
    items.push(TriageItem {
        name: "RPATH / RUNPATH".into(),
        status: if runpath.is_some() { "Warn".into() } else { "Good".into() },
        detail: runpath.clone().unwrap_or_else(|| "None".into()),
    });

    TriageReport {
        items,
        needed_libs: needed,
        exported_functions,
        init_constructors,
        symbol_table,
        fortify_count,
    }
}

/// Resolve an offset into .dynstr.
fn dynstr_at(ctx: &ElfContext, off: u64) -> Option<String> {
    let obj_file = object::File::parse(&*ctx.raw).ok()?;
    use object::{Object, ObjectSection};
    for sec in obj_file.sections() {
        if sec.name().unwrap_or("") == ".dynstr" {
            let data = sec.data().ok()?;
            let start = off as usize;
            if start >= data.len() {
                return None;
            }
            let end = data[start..].iter().position(|&b| b == 0)? + start;
            return Some(String::from_utf8_lossy(&data[start..end]).into_owned());
        }
    }
    None
}
