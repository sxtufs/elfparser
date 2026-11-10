//! Multi-Architecture Native Decompiler Engine for ELFTrace.

pub mod analysis;
pub mod arch;
pub mod codegen;
pub mod ir;
pub mod lifters;
pub mod structuring;

use self::analysis::DecompilerPipeline;
use self::arch::ArchKind;
use self::codegen::CodeGenerator;
use crate::disasm::{disassemble, disassemble_with_resolver};
use crate::elf_parser::ElfContext;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct FunctionRange {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub thumb: bool,
}

pub fn find_function_range(ctx: &ElfContext, address: u64) -> FunctionRange {
    // 1. Exact match first
    if let Some(sym) = ctx.syms_map.get(&address) {
        if !sym.sym.starts_with('$') {
            let size = if sym.size > 0 { sym.size } else { 128 };
            return FunctionRange {
                name: sym.sym.clone(),
                start: address,
                size,
                thumb: sym.thumb,
            };
        }
    }

    // 2. Enclosing range (only consider real symbols with size > 0)
    for sym in ctx.syms_map.values() {
        if sym.sym.starts_with('$') || sym.size == 0 {
            continue;
        }
        let start = sym.value;
        if address >= start && address < start + sym.size {
            return FunctionRange {
                name: sym.sym.clone(),
                start,
                size: sym.size,
                thumb: sym.thumb,
            };
        }
    }

    FunctionRange {
        name: format!("sub_{:08x}", address),
        start: address,
        size: 256,
        thumb: false,
    }
}

pub fn decompile_to_c(ctx: &ElfContext, address: u64) -> String {
    let fn_range = find_function_range(ctx, address);
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    let arch = ArchKind::from_e_machine(e_machine);
    let codegen = CodeGenerator::new(ctx, arch);

    // 1. Data Symbol Handling: If address is in .rodata / .data / non-executable section
    if !ctx.is_executable_address(fn_range.start) {
        return codegen.generate_data_declaration(&fn_range.name, fn_range.start, fn_range.size);
    }

    // 2. Shared Multi-Architecture Analysis & Decompilation Pipeline
    let pipeline = DecompilerPipeline::new(arch);
    match pipeline.analyze_function(
        ctx,
        fn_range.name,
        fn_range.start,
        fn_range.size,
        fn_range.thumb,
    ) {
        Ok(func) => codegen.generate_c_pseudocode(&func),
        Err(err) => format!("// [Decompilation Error] {}\n", err),
    }
}

pub fn decompile_to_c_structured(ctx: &ElfContext, address: u64) -> String {
    self::structuring::decompile_to_c_structured(ctx, address)
}

pub fn generate_disassembly_text(ctx: &ElfContext, address: u64) -> String {
    let fn_range = find_function_range(ctx, address);
    let offset = match ctx.vaddr_to_offset(fn_range.start) {
        Some(off) => off as usize,
        None => {
            return format!(
                "; [Error] Failed to resolve address 0x{:08x} to file offset\n",
                address
            )
        }
    };

    if offset >= ctx.raw.len() {
        return "; [Error] Offset out of file bounds\n".to_string();
    }

    let code_slice = &ctx.raw[offset..];
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);

    let is_jni = ctx
        .syms_map
        .get(&fn_range.start)
        .map(|s| s.sym.starts_with("Java_") || s.sym == "JNI_OnLoad" || s.jni_method.is_some())
        .unwrap_or(false);

    let insns = match disassemble_with_resolver(
        code_slice,
        fn_range.start,
        fn_range.size,
        e_machine,
        fn_range.thumb,
        None,
        is_jni,
    ) {
        Ok(c) => c.data,
        Err(e) => return format!("; [Disassembly Error] {}\n", e),
    };

    let mut targets = HashSet::new();
    for ins in &insns {
        let op = &ins.mnemonic;
        if op.starts_with('b')
            || op.starts_with('j')
            || op.starts_with("cb")
            || op.starts_with("tb")
        {
            if let Some(target) = parse_target_addr(&ins.op_str) {
                targets.insert(target);
            }
        }
    }

    let mut out = String::new();
    out.push_str(&format!("; Function: {}\n", fn_range.name));
    out.push_str(&format!(
        "; Address:  0x{:08x} - 0x{:08x} ({} bytes)\n\n",
        fn_range.start,
        fn_range.start + fn_range.size,
        fn_range.size
    ));
    out.push_str(&format!("{}:\n", fn_range.name));

    for ins in &insns {
        if targets.contains(&ins.address) {
            out.push_str(&format!("\nloc_{:08x}:\n", ins.address));
        }

        let bytes_hex = ins
            .bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let comment_str = ins
            .comment
            .as_deref()
            .map(|c| format!("    {}", c))
            .unwrap_or_default();

        out.push_str(&format!(
            "  0x{:08x}:  {:<12}  {:<8} {}{}\n",
            ins.address, bytes_hex, ins.mnemonic, ins.op_str, comment_str
        ));
    }

    out
}

pub fn generate_flowchart_text(ctx: &ElfContext, address: u64) -> String {
    let fn_range = find_function_range(ctx, address);
    let offset = match ctx.vaddr_to_offset(fn_range.start) {
        Some(off) => off as usize,
        None => {
            return format!(
                "; [Error] Failed to resolve address 0x{:08x} to file offset\n",
                address
            )
        }
    };

    if offset >= ctx.raw.len() {
        return "; [Error] Offset out of file bounds\n".to_string();
    }

    if !ctx.is_executable_address(fn_range.start) {
        return format!(
            "// CONTROL FLOW GRAPH NOT AVAILABLE FOR DATA SYMBOL\n\
             // Symbol '{}' is stored in non-executable section ({}).\n\
             // It is a read-only data structure / string, not machine code.\n\
             // View its definition in the [Decompile] or [Hex] tab.\n",
            fn_range.name,
            ctx.get_section_name_for_vaddr(fn_range.start)
                .unwrap_or_else(|| "data".to_string())
        );
    }

    let code_slice = &ctx.raw[offset..];
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);

    let insns = match disassemble(
        code_slice,
        fn_range.start,
        fn_range.size,
        e_machine,
        fn_range.thumb,
    ) {
        Ok(c) => c.data,
        Err(e) => return format!("; [Disassembly Error] {}\n", e),
    };

    if insns.is_empty() {
        return "; [Error] No instructions found\n".to_string();
    }

    // Partition instructions into basic blocks
    let mut block_starts = HashSet::new();
    block_starts.insert(insns[0].address);

    for (i, ins) in insns.iter().enumerate() {
        let op = &ins.mnemonic;
        let is_branch = op.starts_with('b')
            || op.starts_with('j')
            || op.starts_with("cb")
            || op.starts_with("tb");
        let is_ret = op == "ret" || op == "leave" || (op == "bx" && ins.op_str == "lr");

        if is_branch {
            if let Some(target) = parse_target_addr(&ins.op_str) {
                block_starts.insert(target);
            }
            if i + 1 < insns.len() {
                block_starts.insert(insns[i + 1].address);
            }
        } else if is_ret && i + 1 < insns.len() {
            block_starts.insert(insns[i + 1].address);
        }
    }

    // Group into blocks
    let mut blocks = Vec::new();
    let mut current_block = Vec::new();

    for ins in &insns {
        if block_starts.contains(&ins.address) && !current_block.is_empty() {
            blocks.push(current_block);
            current_block = Vec::new();
        }
        current_block.push(ins);
    }
    if !current_block.is_empty() {
        blocks.push(current_block);
    }

    // Map block start address to block index for clean graph labels (Block 0, Block 1...)
    let mut block_map = HashMap::new();
    for (idx, block) in blocks.iter().enumerate() {
        if let Some(first) = block.first() {
            block_map.insert(first.address, idx);
        }
    }

    let mut out = String::new();
    out.push_str(&format!("// CONTROL FLOW GRAPH: {}\n", fn_range.name));
    out.push_str(&format!(
        "// Blocks: {} | Size: {} bytes (0x{:08x} - 0x{:08x})\n\n",
        blocks.len(),
        fn_range.size,
        fn_range.start,
        fn_range.start + fn_range.size
    ));

    for (idx, block) in blocks.iter().enumerate() {
        let b_start = block.first().unwrap().address;
        let b_end = block.last().unwrap().address;

        if b_start == b_end {
            out.push_str(&format!("Block {} (0x{:08x})\n\n", idx, b_start));
        } else {
            out.push_str(&format!(
                "Block {} (0x{:08x} - 0x{:08x})\n\n",
                idx, b_start, b_end
            ));
        }
        for ins in block {
            out.push_str(&format!(
                "  0x{:08x}:  {:<7} {}\n",
                ins.address, ins.mnemonic, ins.op_str
            ));
        }
        out.push('\n');

        let last_ins = block.last().unwrap();
        let op = &last_ins.mnemonic;
        let next_idx = idx + 1;

        let is_ret = op == "ret" || op == "leave" || (op == "bx" && last_ins.op_str == "lr");
        let is_uncond_jump = op == "b" || op == "jmp" || (op == "bx" && last_ins.op_str != "lr");
        let is_cond_branch = !is_uncond_jump
            && !is_ret
            && (
                op.starts_with("b.")
                    || op.starts_with("beq")
                    || op.starts_with("bne")
                    || op.starts_with("blt")
                    || op.starts_with("ble")
                    || op.starts_with("bgt")
                    || op.starts_with("bge")
                    || op.starts_with("bhi")
                    || op.starts_with("bls")
                    || op.starts_with("cb")
                    || op.starts_with("tb")
                    || op.starts_with('j')
                // x86/x64: je, jne, jl, jle, jg, jge, ja, jb, jz, jnz
            );

        if is_ret {
            out.push_str("       ▼ [EXIT / RETURN]\n\n");
        } else if is_uncond_jump {
            if let Some(target) = parse_target_addr(&last_ins.op_str) {
                let target_label = block_map
                    .get(&target)
                    .map(|i| format!("Block {} (0x{:08x})", i, target))
                    .unwrap_or_else(|| format!("0x{:08x}", target));
                out.push_str(&format!(
                    "       │ (jump -> {})\n       ▼\n\n",
                    target_label
                ));
            } else {
                out.push_str("       │ (jump)\n       ▼\n\n");
            }
        } else if is_cond_branch {
            if let Some(target) = parse_target_addr(&last_ins.op_str) {
                let target_label = block_map
                    .get(&target)
                    .map(|i| format!("Block {} (0x{:08x})", i, target))
                    .unwrap_or_else(|| format!("0x{:08x}", target));
                out.push_str(&format!("       ├─► [TRUE]  branch -> {}\n", target_label));
                if next_idx < blocks.len() {
                    out.push_str(&format!(
                        "       ▼   [FALSE] fallthrough to Block {}\n\n",
                        next_idx
                    ));
                } else {
                    out.push_str("       ▼   [FALSE] fallthrough\n\n");
                }
            } else {
                out.push_str("       ├─► [TRUE]  branch\n");
                if next_idx < blocks.len() {
                    out.push_str(&format!(
                        "       ▼   [FALSE] fallthrough to Block {}\n\n",
                        next_idx
                    ));
                } else {
                    out.push_str("       ▼   [FALSE] fallthrough\n\n");
                }
            }
        } else {
            if next_idx < blocks.len() {
                out.push_str(&format!(
                    "       │\n       ▼ (fallthrough to Block {})\n\n",
                    next_idx
                ));
            } else {
                out.push_str("       │\n       ▼ (fallthrough)\n\n");
            }
        }
    }

    out
}

fn parse_target_addr(op_str: &str) -> Option<u64> {
    for part in op_str.split(',') {
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
