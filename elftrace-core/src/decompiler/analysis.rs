//! Shared Control-Flow and Data-Flow Analysis Pipeline.

use super::arch::ArchKind;
use super::ir::{BinaryOp, IrBlock, IrExpr, IrFunction, IrStmt, IrType, ParamInfo};
use super::lifters::arm32::Arm32Lifter;
use super::lifters::arm64::Arm64Lifter;
use super::lifters::x86_32::X86_32Lifter;
use super::lifters::x86_64::X86_64Lifter;
use super::lifters::InstructionLifter;
use crate::disasm::disassemble;
use crate::elf_parser::ElfContext;
use std::collections::{HashMap, HashSet};

pub struct DecompilerPipeline {
    pub arch: ArchKind,
}

impl DecompilerPipeline {
    pub fn new(arch: ArchKind) -> Self {
        Self { arch }
    }

    pub fn analyze_function(
        &self,
        ctx: &ElfContext,
        name: String,
        address: u64,
        size: u64,
        thumb: bool,
    ) -> Result<IrFunction, String> {
        let offset = match ctx.vaddr_to_offset(address) {
            Some(off) => off as usize,
            None => {
                return Err(format!(
                    "Failed to resolve address 0x{:08x} to file offset",
                    address
                ))
            }
        };

        if offset >= ctx.raw.len() {
            return Err("Offset out of file bounds".to_string());
        }

        let code_slice = &ctx.raw[offset..];
        let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);

        let insns = disassemble(code_slice, address, size, e_machine, thumb)
            .map_err(|e| format!("Disassembly error: {}", e))?
            .data;

        if insns.is_empty() {
            return Err(format!("No instructions decoded at 0x{:08x}", address));
        }

        // 1. Instantiate architecture-specific lifter
        let mut lifter: Box<dyn InstructionLifter> = match self.arch {
            ArchKind::AArch64 => Box::new(Arm64Lifter::new()),
            ArchKind::Arm32 => Box::new(Arm32Lifter::new()),
            ArchKind::X86_64 => Box::new(X86_64Lifter::new()),
            ArchKind::X86_32 => Box::new(X86_32Lifter::new()),
            _ => Box::new(Arm64Lifter::new()),
        };

        // 2. Identify basic block leaders
        let mut block_starts = HashSet::new();
        block_starts.insert(insns[0].address);

        for (i, ins) in insns.iter().enumerate() {
            let mnem = ins.mnemonic.as_str();
            let is_branch = mnem.starts_with('b')
                || mnem.starts_with('j')
                || mnem.starts_with("cb")
                || mnem.starts_with("tb");
            let is_ret = mnem == "ret" || mnem == "leave" || (mnem == "bx" && ins.op_str == "lr");

            if is_branch {
                if let Some(target) = parse_target_addr(&ins.op_str) {
                    if target >= address && target < address + size {
                        block_starts.insert(target);
                    }
                }
                if i + 1 < insns.len() {
                    block_starts.insert(insns[i + 1].address);
                }
            } else if is_ret && i + 1 < insns.len() {
                block_starts.insert(insns[i + 1].address);
            }
        }

        // 3. Lift instructions into shared IR statements partitioned by blocks
        let mut blocks = Vec::new();
        let mut current_block_id = 0;
        let mut current_stmts = Vec::new();
        let mut current_start = insns[0].address;
        let mut current_end = insns[0].address;

        for ins in &insns {
            if block_starts.contains(&ins.address) && !current_stmts.is_empty() {
                blocks.push(IrBlock {
                    id: current_block_id,
                    start_address: current_start,
                    end_address: current_end,
                    stmts: current_stmts,
                });
                current_block_id += 1;
                current_stmts = Vec::new();
                current_start = ins.address;
                lifter.reset_state();
            }
            current_end = ins.address;

            let lifted = lifter.lift(ctx, ins.address, &ins.mnemonic, &ins.op_str, &ins.bytes);
            current_stmts.extend(lifted);
        }

        if !current_stmts.is_empty() {
            blocks.push(IrBlock {
                id: current_block_id,
                start_address: current_start,
                end_address: current_end,
                stmts: current_stmts,
            });
        }

        // 4. Def-Use Analysis: Infer actual function parameters used
        let arg_candidates = self.arch.argument_registers();
        let mut read_before_def = HashSet::new();
        let mut raw_reads = HashSet::new();
        let mut defined = HashSet::new();
        let mut assigned_regs = HashSet::new();

        for block in &blocks {
            for stmt in &block.stmts {
                match stmt {
                    IrStmt::Assign { dst, src } => {
                        collect_reads(
                            src,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                        if let IrExpr::Reg(r, _) = dst {
                            assigned_regs.insert(r.to_lowercase());
                            defined.insert(self.arch.normalize_sub_register(r));
                        }
                    }
                    IrStmt::Store { ptr, val, .. } => {
                        collect_reads(
                            ptr,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                        collect_reads(
                            val,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                    }
                    IrStmt::DivRem {
                        quot_dst,
                        rem_dst,
                        dividend_high,
                        dividend_low,
                        divisor,
                        ..
                    } => {
                        collect_reads(
                            dividend_high,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                        collect_reads(
                            dividend_low,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                        collect_reads(
                            divisor,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                        if let IrExpr::Reg(r, _) = quot_dst {
                            assigned_regs.insert(r.to_lowercase());
                            defined.insert(self.arch.normalize_sub_register(r));
                        }
                        if let IrExpr::Reg(r, _) = rem_dst {
                            assigned_regs.insert(r.to_lowercase());
                            defined.insert(self.arch.normalize_sub_register(r));
                        }
                    }
                    IrStmt::Call {
                        ret_dst: Some(IrExpr::Reg(r, _)),
                        ..
                    } => {
                        assigned_regs.insert(r.to_lowercase());
                        defined.insert(self.arch.normalize_sub_register(r));
                    }
                    IrStmt::Branch { cond: Some(c), .. } => {
                        collect_reads(c, &defined, &mut read_before_def, &mut raw_reads, self.arch);
                    }
                    IrStmt::IndirectBranch { target } => {
                        collect_reads(
                            target,
                            &defined,
                            &mut read_before_def,
                            &mut raw_reads,
                            self.arch,
                        );
                    }
                    IrStmt::Return(Some(v)) => {
                        collect_reads(v, &defined, &mut read_before_def, &mut raw_reads, self.arch);
                    }
                    _ => {}
                }
            }
        }

        // Track pointer dereferences and register aliases
        let mut ptr_params: HashMap<String, IrType> = HashMap::new();
        let mut fn_ptr_params: HashSet<String> = HashSet::new();
        let mut reg_aliases: HashMap<String, String> = HashMap::new();

        let pushed_bytes = if self.arch == ArchKind::X86_32 {
            insns
                .iter()
                .take(4)
                .filter(|ins| ins.mnemonic == "push")
                .count() as u64
                * 4
        } else {
            0
        };
        let base_stack_offset = 4 + pushed_bytes;

        for block in &blocks {
            for stmt in &block.stmts {
                match stmt {
                    IrStmt::Assign { dst, src } => {
                        if let (IrExpr::Reg(d, _), IrExpr::Reg(s, _)) = (dst, src) {
                            let s_norm = self.arch.normalize_sub_register(s);
                            let d_norm = self.arch.normalize_sub_register(d);
                            reg_aliases.insert(d_norm, s_norm);
                        } else if let (IrExpr::Reg(d, _), IrExpr::Load { ptr, .. }) = (dst, src) {
                            if let Some(arg_idx) = resolve_x86_stack_arg(ptr, base_stack_offset) {
                                let d_norm = self.arch.normalize_sub_register(d);
                                reg_aliases.insert(d_norm, format!("a{}", arg_idx));
                            }
                        }
                        if let IrExpr::Load { ptr, ty } = src {
                            check_ptr_access(ptr, *ty, &mut ptr_params, &reg_aliases, self.arch);
                        }
                    }
                    IrStmt::Store { ptr, ty, .. } => {
                        check_ptr_access(ptr, *ty, &mut ptr_params, &reg_aliases, self.arch);
                    }
                    IrStmt::Call {
                        target: IrExpr::Reg(target_reg, _),
                        name,
                        ..
                    } if name.is_none() => {
                        let norm = self.arch.normalize_sub_register(target_reg);
                        let root = reg_aliases.get(&norm).cloned().unwrap_or(norm);
                        fn_ptr_params.insert(root);
                    }
                    _ => {}
                }
            }
        }

        // Infer contiguous positional parameters up to the maximum argument register read
        let mut max_arg_idx: Option<usize> = None;
        for (idx, &arg_reg) in arg_candidates.iter().enumerate() {
            let norm = self.arch.normalize_sub_register(arg_reg);
            if read_before_def.contains(&norm) {
                max_arg_idx = Some(idx);
            }
        }

        let mut inferred_params = Vec::new();
        if let Some(max_i) = max_arg_idx {
            for (i, &arg_reg) in arg_candidates.iter().enumerate().take(max_i + 1) {
                let norm = self.arch.normalize_sub_register(arg_reg);
                let is_fn_ptr = fn_ptr_params.contains(&norm);
                let is_ptr = ptr_params.contains_key(&norm) || is_fn_ptr;
                let ty = if let Some(&deref_ty) = ptr_params.get(&norm) {
                    deref_ty
                } else {
                    match self.arch {
                        ArchKind::AArch64 => {
                            let w_name = format!("w{}", &norm[1..]);
                            if raw_reads.contains(&w_name) {
                                IrType::Int32
                            } else {
                                IrType::Int64
                            }
                        }
                        ArchKind::X86_64 => {
                            let is_32 = raw_reads.iter().any(|r| {
                                (r.starts_with('e') || r.ends_with('d'))
                                    && self.arch.normalize_sub_register(r) == norm
                            });
                            if is_32 {
                                IrType::Int32
                            } else {
                                IrType::Int64
                            }
                        }
                        _ => self.arch.pointer_type(),
                    }
                };
                inferred_params.push(ParamInfo {
                    name: format!("a{}", i),
                    ty,
                    is_ptr,
                    is_fn_ptr,
                });
            }
        }

        // x86_32: Recover stack parameters [esp + ...] or [ebp + ...]
        if self.arch == ArchKind::X86_32 && inferred_params.is_empty() {
            let stack_arg_count = count_x86_stack_args(&blocks, base_stack_offset);
            for i in 0..stack_arg_count {
                let p_name = format!("a{}", i);
                let is_fn_ptr = fn_ptr_params.contains(&p_name);
                let is_ptr = ptr_params.contains_key(&p_name) || is_fn_ptr;
                let ty = ptr_params.get(&p_name).copied().unwrap_or(IrType::Int32);
                inferred_params.push(ParamInfo {
                    name: p_name,
                    ty,
                    is_ptr,
                    is_fn_ptr,
                });
            }
        }

        // Fallback for JNI functions
        let is_jni = name.contains("JNI_OnLoad") || name.starts_with("Java_");
        if inferred_params.is_empty() && is_jni {
            inferred_params = vec![
                ParamInfo {
                    name: "a0".to_string(),
                    ty: self.arch.pointer_type(),
                    is_ptr: true,
                    is_fn_ptr: false,
                },
                ParamInfo {
                    name: "a1".to_string(),
                    ty: self.arch.pointer_type(),
                    is_ptr: true,
                    is_fn_ptr: false,
                },
                ParamInfo {
                    name: "a2".to_string(),
                    ty: self.arch.pointer_type(),
                    is_ptr: false,
                    is_fn_ptr: false,
                },
                ParamInfo {
                    name: "a3".to_string(),
                    ty: self.arch.pointer_type(),
                    is_ptr: false,
                    is_fn_ptr: false,
                },
            ];
        }

        // 5. Accurate Return Type and Return Register Inference
        let (ret_type, ret_reg) = infer_return_info(self.arch, &assigned_regs);

        Ok(IrFunction {
            name,
            start_address: address,
            size,
            blocks,
            ret_type,
            ret_reg,
            base_stack_offset,
            inferred_params,
        })
    }
}

fn infer_return_info(arch: ArchKind, assigned_regs: &HashSet<String>) -> (IrType, String) {
    match arch {
        ArchKind::AArch64 => {
            if assigned_regs.contains("d0") {
                (IrType::Float64, "d0".to_string())
            } else if assigned_regs.contains("s0") {
                (IrType::Float32, "s0".to_string())
            } else if assigned_regs.contains("w0") && !assigned_regs.contains("x0") {
                (IrType::Int32, "w0".to_string())
            } else if assigned_regs.contains("x0") {
                (IrType::Int64, "x0".to_string())
            } else {
                (IrType::Void, String::new())
            }
        }
        ArchKind::X86_64 => {
            if assigned_regs.contains("eax") && !assigned_regs.contains("rax") {
                (IrType::Int32, "eax".to_string())
            } else if assigned_regs.contains("al")
                && !assigned_regs.contains("rax")
                && !assigned_regs.contains("eax")
            {
                (IrType::Int8, "al".to_string())
            } else if assigned_regs.contains("rax") {
                (IrType::Int64, "rax".to_string())
            } else {
                (IrType::Void, String::new())
            }
        }
        ArchKind::X86_32 => {
            if assigned_regs.contains("al") && !assigned_regs.contains("eax") {
                (IrType::Int8, "al".to_string())
            } else if assigned_regs.contains("eax") {
                (IrType::Int32, "eax".to_string())
            } else {
                (IrType::Void, String::new())
            }
        }
        ArchKind::Arm32 => {
            if assigned_regs.contains("r0") {
                (IrType::Int32, "r0".to_string())
            } else {
                (IrType::Void, String::new())
            }
        }
        _ => (
            arch.pointer_type(),
            arch.default_return_register().to_string(),
        ),
    }
}

fn count_x86_stack_args(blocks: &[IrBlock], base_arg_offset: u64) -> usize {
    let mut max_arg_idx = 0;
    let mut found = false;
    for b in blocks {
        for s in &b.stmts {
            if let IrStmt::Assign { src, .. } = s {
                check_stack_load(src, &mut max_arg_idx, &mut found, base_arg_offset);
            }
            if let IrStmt::DivRem { divisor, .. } = s {
                check_stack_load(divisor, &mut max_arg_idx, &mut found, base_arg_offset);
            }
        }
    }
    if found {
        max_arg_idx + 1
    } else {
        0
    }
}

fn check_stack_load(expr: &IrExpr, max_idx: &mut usize, found: &mut bool, base_arg_offset: u64) {
    if let IrExpr::Load { ptr, .. } = expr {
        if let Some(idx) = resolve_x86_stack_arg(ptr.as_ref(), base_arg_offset) {
            if idx < 16 {
                if idx >= *max_idx {
                    *max_idx = idx;
                }
                *found = true;
            }
        }
    }
}

pub fn resolve_x86_stack_arg(expr: &IrExpr, base_offset: u64) -> Option<usize> {
    match expr {
        IrExpr::Binary(BinaryOp::Add, lhs, rhs, _) => {
            if let (IrExpr::Reg(r, _), IrExpr::Const(off)) = (lhs.as_ref(), rhs.as_ref()) {
                let r_lower = r.to_lowercase();
                if r_lower == "ebp" && *off >= 8 {
                    return Some(((*off - 8) / 4) as usize);
                } else if r_lower == "esp" && *off >= base_offset {
                    return Some(((*off - base_offset) / 4) as usize);
                }
            }
        }
        IrExpr::Reg(r, _) => {
            let r_lower = r.to_lowercase();
            if r_lower.contains("ebp +") {
                let off_str = r_lower.split('+').nth(1)?.trim().trim_end_matches(')');
                let off = u64::from_str_radix(
                    off_str.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .ok()?;
                if off >= 8 {
                    return Some(((off - 8) / 4) as usize);
                }
            } else if r_lower.contains("esp +") {
                let off_str = r_lower.split('+').nth(1)?.trim().trim_end_matches(')');
                let off = u64::from_str_radix(
                    off_str.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .ok()?;
                if off >= base_offset {
                    return Some(((off - base_offset) / 4) as usize);
                }
            }
        }
        _ => {}
    }
    None
}

fn collect_reads(
    expr: &IrExpr,
    defined: &HashSet<String>,
    reads: &mut HashSet<String>,
    raw_reads: &mut HashSet<String>,
    arch: ArchKind,
) {
    match expr {
        IrExpr::Reg(r, _) => {
            let r_lower = r.to_lowercase();
            raw_reads.insert(r_lower.clone());
            let norm = arch.normalize_sub_register(&r_lower);
            if !defined.contains(&norm) {
                reads.insert(norm);
            }
        }
        IrExpr::Unary(_, inner, _) => collect_reads(inner, defined, reads, raw_reads, arch),
        IrExpr::Binary(_, lhs, rhs, _) => {
            collect_reads(lhs, defined, reads, raw_reads, arch);
            collect_reads(rhs, defined, reads, raw_reads, arch);
        }
        IrExpr::Load { ptr, .. } => collect_reads(ptr, defined, reads, raw_reads, arch),
        IrExpr::Ternary {
            cond,
            true_val,
            false_val,
            ..
        } => {
            collect_reads(cond, defined, reads, raw_reads, arch);
            collect_reads(true_val, defined, reads, raw_reads, arch);
            collect_reads(false_val, defined, reads, raw_reads, arch);
        }
        IrExpr::Call { args, .. } => {
            for a in args {
                collect_reads(a, defined, reads, raw_reads, arch);
            }
        }
        _ => {}
    }
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

fn check_ptr_access(
    expr: &IrExpr,
    ty: IrType,
    ptr_params: &mut HashMap<String, IrType>,
    aliases: &HashMap<String, String>,
    arch: ArchKind,
) {
    match expr {
        IrExpr::Reg(r, _) => {
            let norm = arch.normalize_sub_register(r);
            let root = aliases.get(&norm).cloned().unwrap_or(norm);
            ptr_params.insert(root, ty);
        }
        IrExpr::Binary(_, lhs, _, _) => {
            check_ptr_access(lhs, ty, ptr_params, aliases, arch);
        }
        _ => {}
    }
}
