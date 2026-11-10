use crate::elf_parser::ElfContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResult {
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub patched_bytes: Vec<u8>,
    pub patch_type: String,
    pub success: bool,
    pub error: Option<String>,
}

pub enum QuickPatchType {
    Nop,
    ReturnTrue,
    ReturnFalse,
    ReturnVoid,
}

pub fn apply_quick_patch(
    ctx: &mut ElfContext,
    address: u64,
    patch_type: QuickPatchType,
    is_thumb: bool,
) -> PatchResult {
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);

    let (patch_bytes_opt, type_name) = match patch_type {
        QuickPatchType::Nop => {
            let bytes = match e_machine {
                183 => Some(vec![0x1f, 0x20, 0x03, 0xd5]), // ARM64: nop
                40 if is_thumb => Some(vec![0x00, 0xbf]),  // Thumb: nop
                40 => Some(vec![0x00, 0xf0, 0x20, 0xe3]),  // ARM32: nop
                62 | 3 => Some(vec![0x90]),                // x86/x64: nop
                _ => None,
            };
            (bytes, "NOP")
        }
        QuickPatchType::ReturnTrue => {
            let bytes = match e_machine {
                183 => Some(vec![0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]),
                40 if is_thumb => Some(vec![0x01, 0x20, 0x70, 0x47]),
                40 => Some(vec![0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1]),
                62 | 3 => Some(vec![0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]),
                _ => None,
            };
            (bytes, "Force Return True")
        }
        QuickPatchType::ReturnFalse => {
            let bytes = match e_machine {
                183 => Some(vec![0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]),
                40 if is_thumb => Some(vec![0x00, 0x20, 0x70, 0x47]),
                40 => Some(vec![0x00, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1]),
                62 | 3 => Some(vec![0x31, 0xc0, 0xc3]),
                _ => None,
            };
            (bytes, "Force Return False")
        }
        QuickPatchType::ReturnVoid => {
            let bytes = match e_machine {
                183 => Some(vec![0xc0, 0x03, 0x5f, 0xd6]),
                40 if is_thumb => Some(vec![0x70, 0x47]),
                40 => Some(vec![0x1e, 0xff, 0x2f, 0xe1]),
                62 | 3 => Some(vec![0xc3]),
                _ => None,
            };
            (bytes, "Return Void (Skip)")
        }
    };

    let patch_bytes = match patch_bytes_opt {
        Some(b) => b,
        None => {
            return PatchResult {
                address,
                original_bytes: vec![],
                patched_bytes: vec![],
                patch_type: type_name.to_string(),
                success: false,
                error: Some(format!("Unsupported e_machine: {}", e_machine)),
            };
        }
    };

    let offset = match ctx.vaddr_to_offset(address) {
        Some(off) => off as usize,
        None => {
            return PatchResult {
                address,
                original_bytes: vec![],
                patched_bytes: patch_bytes,
                patch_type: type_name.to_string(),
                success: false,
                error: Some(format!("Address 0x{:08x} not mapped in ELF", address)),
            }
        }
    };

    let patch_len = patch_bytes.len();
    if offset + patch_len > ctx.raw.len() {
        return PatchResult {
            address,
            original_bytes: vec![],
            patched_bytes: patch_bytes,
            patch_type: type_name.to_string(),
            success: false,
            error: Some("Patch exceeds file size".to_string()),
        };
    }

    let original = ctx.raw[offset..offset + patch_len].to_vec();
    ctx.raw[offset..offset + patch_len].copy_from_slice(&patch_bytes);

    PatchResult {
        address,
        original_bytes: original,
        patched_bytes: patch_bytes,
        patch_type: type_name.to_string(),
        success: true,
        error: None,
    }
}

pub fn assemble_and_patch(ctx: &mut ElfContext, address: u64, text: &str) -> PatchResult {
    let patch_bytes = match assemble_instruction(text, address) {
        Ok(b) => b,
        Err(e) => {
            return PatchResult {
                address,
                original_bytes: vec![],
                patched_bytes: vec![],
                patch_type: "Assemble".to_string(),
                success: false,
                error: Some(e),
            }
        }
    };

    let offset = match ctx.vaddr_to_offset(address) {
        Some(off) => off as usize,
        None => {
            return PatchResult {
                address,
                original_bytes: vec![],
                patched_bytes: patch_bytes,
                patch_type: "Assemble".to_string(),
                success: false,
                error: Some(format!("Address 0x{:08x} not mapped in ELF", address)),
            }
        }
    };

    let patch_len = patch_bytes.len();
    if offset + patch_len > ctx.raw.len() {
        return PatchResult {
            address,
            original_bytes: vec![],
            patched_bytes: patch_bytes,
            patch_type: "Assemble".to_string(),
            success: false,
            error: Some("Patch exceeds file size".to_string()),
        };
    }

    let original = ctx.raw[offset..offset + patch_len].to_vec();
    ctx.raw[offset..offset + patch_len].copy_from_slice(&patch_bytes);

    PatchResult {
        address,
        original_bytes: original,
        patched_bytes: patch_bytes,
        patch_type: format!("Assemble: {}", text.trim()),
        success: true,
        error: None,
    }
}

pub fn assemble_instruction(text: &str, address: u64) -> Result<Vec<u8>, String> {
    let t = text.trim();

    // 1. Check if raw hex bytes: e.g. "C4 26 00 14" or "C4260014"
    let clean_hex: String = t
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect();
    let clean_hex = clean_hex.trim_start_matches("0x").trim_start_matches("0X");
    if clean_hex.len() >= 4
        && clean_hex.len().is_multiple_of(2)
        && clean_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        let mut bytes = Vec::new();
        for i in (0..clean_hex.len()).step_by(2) {
            if let Ok(b) = u8::from_str_radix(&clean_hex[i..i + 2], 16) {
                bytes.push(b);
            }
        }
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }

    // 2. Parse Mnemonic and Operands
    let mut parts = t.splitn(2, char::is_whitespace);
    let mnem = parts.next().unwrap_or("").to_lowercase();
    let ops = parts.next().unwrap_or("").trim();

    match mnem.as_str() {
        "nop" => Ok(vec![0x1f, 0x20, 0x03, 0xd5]),
        "ret" => Ok(vec![0xc0, 0x03, 0x5f, 0xd6]),

        "b" | "bl" => {
            let target = parse_imm(ops)?;
            let diff = (target as i64 - address as i64) / 4;
            if !(-(1 << 25)..=(1 << 25) - 1).contains(&diff) {
                return Err(format!(
                    "Branch target 0x{:x} is out of range (+/- 128 MB max for ARM64 b/bl)",
                    target
                ));
            }
            let imm26 = (diff as u32) & 0x03FF_FFFF;
            let op_base = if mnem == "bl" {
                0x9400_0000
            } else {
                0x1400_0000
            };
            let code = op_base | imm26;
            Ok(code.to_le_bytes().to_vec())
        }

        "b.eq" | "b.ne" | "b.cs" | "b.cc" | "b.mi" | "b.pl" | "b.vs" | "b.vc" | "b.hi" | "b.ls"
        | "b.ge" | "b.lt" | "b.gt" | "b.le" => {
            let cond_code: u32 = match mnem.as_str() {
                "b.eq" => 0,
                "b.ne" => 1,
                "b.cs" => 2,
                "b.cc" => 3,
                "b.mi" => 4,
                "b.pl" => 5,
                "b.vs" => 6,
                "b.vc" => 7,
                "b.hi" => 8,
                "b.ls" => 9,
                "b.ge" => 10,
                "b.lt" => 11,
                "b.gt" => 12,
                "b.le" => 13,
                _ => 0,
            };
            let target = parse_imm(ops)?;
            let diff = (target as i64 - address as i64) / 4;
            if !(-(1 << 18)..=(1 << 18) - 1).contains(&diff) {
                return Err(format!(
                    "Conditional branch target 0x{:x} is out of range (+/- 1 MB max for b.cond)",
                    target
                ));
            }
            let imm19 = ((diff as u32) & 0x0007_FFFF) << 5;
            let code = 0x5400_0000 | imm19 | cond_code;
            Ok(code.to_le_bytes().to_vec())
        }

        "cbz" | "cbnz" => {
            let op_parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if op_parts.len() != 2 {
                return Err("Format: cbz <reg>, <target>".to_string());
            }
            let (reg_num, is_64) = parse_reg(op_parts[0])?;
            let target = parse_imm(op_parts[1])?;
            let diff = (target as i64 - address as i64) / 4;
            let imm19 = ((diff as u32) & 0x0007_FFFF) << 5;
            let op_base = match (is_64, mnem.as_str()) {
                (true, "cbz") => 0xB400_0000,
                (true, "cbnz") => 0xB500_0000,
                (false, "cbz") => 0x3400_0000,
                (false, "cbnz") => 0x3500_0000,
                _ => 0x3400_0000,
            };
            let code = op_base | imm19 | reg_num;
            Ok(code.to_le_bytes().to_vec())
        }

        "mov" | "movz" => {
            let op_parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if op_parts.len() != 2 {
                return Err("Format: mov <reg>, #<imm>".to_string());
            }
            let (reg_num, is_64) = parse_reg(op_parts[0])?;
            let imm = parse_imm(op_parts[1])?;
            let imm16 = ((imm & 0xFFFF) as u32) << 5;
            let op_base = if is_64 { 0xD280_0000 } else { 0x5280_0000 };
            let code = op_base | imm16 | reg_num;
            Ok(code.to_le_bytes().to_vec())
        }

        _ => Err(format!(
            "Instruction '{}' not directly assembleable. You can enter 4 raw hex bytes instead.",
            mnem
        )),
    }
}

fn parse_imm(s: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches('#');
    if t.starts_with("0x") || t.starts_with("0X") {
        u64::from_str_radix(&t[2..], 16).map_err(|_| format!("Invalid hex: {}", s))
    } else {
        t.parse::<u64>()
            .map_err(|_| format!("Invalid number: {}", s))
    }
}

fn parse_reg(s: &str) -> Result<(u32, bool), String> {
    let t = s.trim().to_lowercase();
    if let Some(num_str) = t.strip_prefix('x') {
        let num: u32 = num_str
            .parse()
            .map_err(|_| format!("Invalid register: {}", s))?;
        if num < 31 {
            Ok((num, true))
        } else {
            Err("Register X must be 0-30".to_string())
        }
    } else if let Some(num_str) = t.strip_prefix('w') {
        let num: u32 = num_str
            .parse()
            .map_err(|_| format!("Invalid register: {}", s))?;
        if num < 31 {
            Ok((num, false))
        } else {
            Err("Register W must be 0-30".to_string())
        }
    } else {
        Err(format!("Expected register X0-X30 or W0-W30, got: {}", s))
    }
}
