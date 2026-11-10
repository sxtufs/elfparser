use crate::disasm::disassemble;
use crate::elf_parser::ElfContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefItem {
    pub from_address: u64,
    pub to_address: u64,
    pub kind: String,
    pub instruction: String,
    pub caller_func: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRefResponse {
    pub target_address: u64,
    pub refs: Vec<XRefItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalleeItem {
    pub target_address: u64,
    pub target_name: String,
    pub instruction: String,
    pub call_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallHierarchy {
    pub function_address: u64,
    pub function_name: String,
    pub callers: Vec<XRefItem>,
    pub callees: Vec<CalleeItem>,
}

/// Decode one ARM64 branch instruction word into (target, kind, mnemonic).
/// `kind` is "Call" for BL, "Jump" for everything else.
/// Returns None if the word is not a recognized branch.
pub fn decode_arm64_branch_insn(
    word: u32,
    from_addr: u64,
) -> Option<(u64, &'static str, &'static str)> {
    // 1. BL
    if (word & 0xFC00_0000) == 0x9400_0000 {
        let imm26 = word & 0x03FF_FFFF;
        let offset = if (imm26 & 0x0200_0000) != 0 {
            ((imm26 as i64) | !0x03FF_FFFF) << 2
        } else {
            (imm26 as i64) << 2
        };
        let to_addr = (from_addr as i64).wrapping_add(offset) as u64;
        return Some((to_addr, "Call", "bl"));
    }
    // 2. B
    if (word & 0xFC00_0000) == 0x1400_0000 {
        let imm26 = word & 0x03FF_FFFF;
        let offset = if (imm26 & 0x0200_0000) != 0 {
            ((imm26 as i64) | !0x03FF_FFFF) << 2
        } else {
            (imm26 as i64) << 2
        };
        let to_addr = (from_addr as i64).wrapping_add(offset) as u64;
        return Some((to_addr, "Jump", "b"));
    }
    // 3. B.cond
    if (word & 0xFF00_0010) == 0x5400_0000 {
        let imm19 = (word >> 5) & 0x0007_FFFF;
        let offset = if (imm19 & 0x0004_0000) != 0 {
            ((imm19 as i64) | !0x0007_FFFF) << 2
        } else {
            (imm19 as i64) << 2
        };
        let to_addr = (from_addr as i64).wrapping_add(offset) as u64;
        return Some((to_addr, "Jump", "b.cond"));
    }
    // 4. CBZ / CBNZ
    if (word & 0x7E00_0000) == 0x3400_0000 {
        let imm19 = (word >> 5) & 0x0007_FFFF;
        let offset = if (imm19 & 0x0004_0000) != 0 {
            ((imm19 as i64) | !0x0007_FFFF) << 2
        } else {
            (imm19 as i64) << 2
        };
        let to_addr = (from_addr as i64).wrapping_add(offset) as u64;
        let mnem = if (word & 0x0100_0000) != 0 {
            "cbnz"
        } else {
            "cbz"
        };
        return Some((to_addr, "Jump", mnem));
    }
    // 5. TBZ / TBNZ
    if (word & 0x7E00_0000) == 0x3600_0000 {
        let imm14 = (word >> 5) & 0x0000_3FFF;
        let offset = if (imm14 & 0x0000_2000) != 0 {
            ((imm14 as i64) | !0x3FFF) << 2
        } else {
            (imm14 as i64) << 2
        };
        let to_addr = (from_addr as i64).wrapping_add(offset) as u64;
        let mnem = if (word & 0x0100_0000) != 0 {
            "tbnz"
        } else {
            "tbz"
        };
        return Some((to_addr, "Jump", mnem));
    }
    None
}

/// On-demand targeted XREF scanner:
/// Only finds callers to `target_vaddr`.
/// Allocates ZERO memory for unrelated instructions in massive binaries like Chrome.
pub fn find_callers_to(ctx: &ElfContext, target_vaddr: u64) -> Vec<XRefItem> {
    let mut refs = Vec::new();
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);

    let obj_file = match object::File::parse(&*ctx.raw) {
        Ok(f) => f,
        Err(_) => return refs,
    };

    use object::{Object, ObjectSection, ObjectSymbol};

    // Symbol bounds for naming callers (binary search)
    let mut sym_table: Vec<(u64, u64, String)> = Vec::new();
    for sym in obj_file.symbols() {
        if let Ok(name) = sym.name() {
            if !name.is_empty() && sym.size() > 0 {
                sym_table.push((sym.address(), sym.address() + sym.size(), name.to_string()));
            }
        }
    }
    for sym in obj_file.dynamic_symbols() {
        if let Ok(name) = sym.name() {
            if !name.is_empty() && sym.size() > 0 {
                sym_table.push((sym.address(), sym.address() + sym.size(), name.to_string()));
            }
        }
    }
    sym_table.sort_by_key(|s| s.0);

    let find_caller = |addr: u64| -> Option<String> {
        match sym_table.binary_search_by(|(start, end, _)| {
            if addr < *start {
                std::cmp::Ordering::Greater
            } else if addr >= *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(idx) => Some(sym_table[idx].2.clone()),
            Err(_) => None,
        }
    };

    // Scan executable sections directly
    for section in obj_file.sections() {
        let name = section.name().unwrap_or("");
        if name == ".text" || name == ".plt" {
            if let Ok(data) = section.data() {
                let sec_vaddr = section.address();

                if e_machine == 183 {
                    // Fast direct 4-byte ARM64 hardware decoding
                    let mut i = 0;
                    while i + 4 <= data.len() {
                        let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
                        let from_addr = sec_vaddr + i as u64;

                        if let Some((to_addr, kind, mnem)) =
                            decode_arm64_branch_insn(word, from_addr)
                        {
                            if to_addr == target_vaddr {
                                refs.push(XRefItem {
                                    from_address: from_addr,
                                    to_address: to_addr,
                                    kind: kind.to_string(),
                                    instruction: format!("{:<7} #0x{:x}", mnem, to_addr),
                                    caller_func: find_caller(from_addr),
                                });
                            }
                        }

                        i += 4;
                    }
                } else {
                    // Fallback Capstone scan for non-ARM64 (x86, ARM32)
                    let insns =
                        match disassemble(data, sec_vaddr, data.len() as u64, e_machine, false) {
                            Ok(c) => c.data,
                            Err(_) => continue,
                        };
                    for ins in insns {
                        let mnem = ins.mnemonic.as_str();
                        let ops = ins.op_str.as_str();
                        let from_addr = ins.address;
                        if mnem == "bl" || mnem == "blx" || mnem == "call" {
                            if let Some(to_addr) = parse_imm_addr(ops) {
                                if to_addr == target_vaddr {
                                    refs.push(XRefItem {
                                        from_address: from_addr,
                                        to_address: to_addr,
                                        kind: "Call".to_string(),
                                        instruction: format!("{:<7} {}", mnem, ops),
                                        caller_func: find_caller(from_addr),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    refs
}

/// Extracts the Call Hierarchy (Callers & Callees) for a specific function on demand
pub fn get_hierarchy(ctx: &ElfContext, address: u64) -> CallHierarchy {
    let fn_range = crate::decompiler::find_function_range(ctx, address);
    let callers = find_callers_to(ctx, address);

    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    let mut callees_map: HashMap<u64, (String, String, usize)> = HashMap::new();

    if let Some(offset) = ctx.vaddr_to_offset(fn_range.start) {
        let max_bytes = (fn_range.size as usize).min(ctx.raw.len().saturating_sub(offset as usize));
        let slice = &ctx.raw[offset as usize..offset as usize + max_bytes];
        if let Ok(insns) = disassemble(
            slice,
            fn_range.start,
            max_bytes as u64,
            e_machine,
            fn_range.thumb,
        ) {
            let mut jni_regs: HashMap<String, &'static str> = HashMap::new();
            for ins in insns.data {
                let mnem = ins.mnemonic.as_str();
                let ops = ins.op_str.as_str();

                if mnem == "ldr" {
                    if let Some(start_b) = ops.find('[') {
                        if let Some(end_b) = ops.find(']') {
                            let inside = &ops[start_b + 1..end_b];
                            let parts: Vec<&str> = inside.split(',').map(|s| s.trim()).collect();
                            if parts.len() == 2 {
                                let base_reg = parts[0].to_lowercase();
                                if base_reg != "sp" && base_reg != "x29" {
                                    let imm_str = parts[1].trim_start_matches('#');
                                    let off_opt =
                                        if imm_str.starts_with("0x") || imm_str.starts_with("0X") {
                                            u64::from_str_radix(&imm_str[2..], 16).ok()
                                        } else {
                                            imm_str.parse::<u64>().ok()
                                        };
                                    if let Some(off) = off_opt {
                                        if let Some(jni_fn) =
                                            crate::jni_resolver::resolve_jni_offset(
                                                off,
                                                e_machine == 183,
                                            )
                                        {
                                            let dst_reg = ops
                                                .split(',')
                                                .next()
                                                .unwrap_or("")
                                                .trim()
                                                .to_lowercase();
                                            jni_regs.insert(dst_reg, jni_fn);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if mnem == "bl" || mnem == "blx" || mnem == "call" {
                    if let Some(target) = parse_imm_addr(ops) {
                        let name = ctx
                            .syms_map
                            .get(&target)
                            .map(|s| s.sym.clone())
                            .unwrap_or_else(|| format!("sub_{:08X}", target));
                        let entry = callees_map.entry(target).or_insert((
                            name,
                            format!("{} {}", mnem, ops),
                            0,
                        ));
                        entry.2 += 1;
                    }
                } else if mnem == "blr" || mnem == "br" {
                    let reg = ops.trim().to_lowercase();
                    if let Some(&jni_fn) = jni_regs.get(&reg) {
                        let fake_addr = 0;
                        let entry = callees_map.entry(fake_addr).or_insert((
                            format!("JNI: {}", jni_fn),
                            format!("{} {}", mnem, ops),
                            0,
                        ));
                        entry.2 += 1;
                    }
                }
            }
        }
    }

    let mut callees: Vec<CalleeItem> = callees_map
        .into_iter()
        .map(|(addr, (name, insn, count))| CalleeItem {
            target_address: addr,
            target_name: name,
            instruction: insn,
            call_count: count,
        })
        .collect();
    callees.sort_by_key(|c| c.target_address);

    CallHierarchy {
        function_address: address,
        function_name: fn_range.name,
        callers,
        callees,
    }
}

fn parse_imm_addr(s: &str) -> Option<u64> {
    for part in s.split(',') {
        let trimmed = part.trim().trim_start_matches('#');
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            if let Ok(addr) = u64::from_str_radix(&trimmed[2..], 16) {
                return Some(addr);
            }
        } else if let Ok(addr) = u64::from_str_radix(trimmed, 16) {
            if addr > 0x1000 {
                return Some(addr);
            }
        }
    }
    None
}
