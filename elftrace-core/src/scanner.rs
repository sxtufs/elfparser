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

    for (pat, cat, name, sev, desc) in patterns {
        for (off, window) in raw.windows(pat.len()).enumerate() {
            if window == pat {
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
