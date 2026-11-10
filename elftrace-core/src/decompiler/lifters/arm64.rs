//! AArch64 (ARM64) Instruction Lifter into Architecture-Independent IR.

use crate::decompiler::ir::{BinaryOp, IrExpr, IrStmt, IrType, UnaryOp};
use crate::decompiler::lifters::InstructionLifter;
use crate::elf_parser::ElfContext;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Default)]
pub struct ArgLiveness {
    pub written: u8,
}

pub struct Arm64Lifter {
    pub last_cmp: Option<IrExpr>,
    pub adrp_pages: HashMap<String, u64>,
    pub prologue_done: bool,
    pub arg_live: ArgLiveness,
}

impl Arm64Lifter {
    pub fn new() -> Self {
        Self {
            last_cmp: None,
            adrp_pages: HashMap::new(),
            prologue_done: false,
            arg_live: ArgLiveness::default(),
        }
    }
}

impl Default for Arm64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionLifter for Arm64Lifter {
    fn reset_state(&mut self) {
        self.last_cmp = None;
        self.prologue_done = false;
        self.arg_live.written = 0;
    }

    fn lift(
        &mut self,
        ctx: &ElfContext,
        _address: u64,
        mnemonic: &str,
        op_str: &str,
        _insn_bytes: &[u8],
    ) -> Vec<IrStmt> {
        let mnem = mnemonic.trim();
        let ops = op_str.trim();

        // Check if any branch/jump/call terminates the prologue region
        let is_branch_or_call = mnem.starts_with('b')
            || mnem.starts_with("cb")
            || mnem.starts_with("tb")
            || mnem == "ret";

        // 1. Prologue / Epilogue / Frame Filter (Scoped to prologue region only)
        if !self.prologue_done {
            if (mnem == "sub" || mnem == "add") && ops.starts_with("sp, sp") {
                return Vec::new();
            }
            if (mnem == "stp" || mnem == "ldp")
                && (ops.contains("x29, x30")
                    || ops.contains("x19, x20")
                    || ops.contains("x21, x22"))
            {
                return Vec::new();
            }
            if mnem == "add" && ops.starts_with("x29, sp") {
                return Vec::new();
            }
            if mnem == "paciasp" || mnem == "autiasp" {
                return Vec::new();
            }
            if (mnem == "str" || mnem == "ldr" || mnem == "stur" || mnem == "ldur")
                && (ops.starts_with("x28,") || ops.starts_with("x27,") || ops.starts_with("x26,"))
                && ops.contains("[sp")
            {
                return Vec::new();
            }
            // Stack canary setup in prologue
            if mnem == "mrs" && ops.contains("tpidr_el0") {
                return Vec::new();
            }
            if (mnem.starts_with("ldr") || mnem.starts_with("ldur"))
                && ops.contains("0x28]")
                && (ops.contains("x21,") || ops.contains("x8,"))
            {
                return Vec::new();
            }
            if (mnem == "str" || mnem == "stur")
                && (ops.contains("[x29, #-8]")
                    || ops.contains("[x29, #-0x8]")
                    || ops.contains("[x29, -8]")
                    || ops.contains("[x29, -0x8]"))
            {
                return Vec::new();
            }
            if (mnem == "ldr" || mnem == "ldur")
                && (ops.contains("[x29, #-8]")
                    || ops.contains("[x29, #-0x8]")
                    || ops.contains("[x29, -8]")
                    || ops.contains("[x29, -0x8]"))
            {
                return Vec::new();
            }
            if mnem == "cmp" && ops.contains("x8, x9") {
                return Vec::new();
            }
        }

        if is_branch_or_call {
            self.prologue_done = true;
        }

        let stmts = match mnem {
            // Control Flow
            "ret" | "bx" if ops == "lr" || ops.is_empty() => {
                vec![IrStmt::Return(None)]
            }
            "brk" | "ud2" => {
                vec![IrStmt::Trap]
            }
            "b" => {
                if let Some(target) = parse_target_addr(ops) {
                    if let Some(sym) = ctx.syms_map.get(&target) {
                        let name = sym.demangled.as_deref().unwrap_or(sym.sym.as_str());
                        vec![
                            IrStmt::Call {
                                target: IrExpr::Const(target),
                                name: Some(name.to_string()),
                                args: Vec::new(),
                                ret_dst: None,
                            },
                            IrStmt::Return(None),
                        ]
                    } else {
                        vec![IrStmt::Branch { cond: None, target }]
                    }
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "br" => {
                vec![IrStmt::IndirectBranch {
                    target: IrExpr::reg(ops.trim(), IrType::Int64),
                }]
            }
            "bl" | "blx" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                let name = ctx
                    .syms_map
                    .get(&target)
                    .map(|s| s.demangled.as_deref().unwrap_or(s.sym.as_str()).to_string());
                self.last_cmp = None;
                let arg_regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
                let mut args = Vec::new();
                for (i, &r) in arg_regs.iter().enumerate() {
                    if (self.arg_live.written & (1 << i)) != 0 {
                        args.push(IrExpr::reg(r, IrType::Int64));
                    } else {
                        break;
                    }
                }
                self.arg_live.written = 0;
                let ret_dst = match (&name, ctx.syms_map.get(&target)) {
                    (Some(n), _) if is_void_callee(n) => None,
                    (_, Some(sym)) if sym.size > 0 && is_void_callee(&sym.sym) => None,
                    (None, None) => None,
                    _ => Some(IrExpr::reg("x0", IrType::Int64)),
                };
                vec![IrStmt::Call {
                    target: IrExpr::Const(target),
                    name,
                    args,
                    ret_dst,
                }]
            }
            "blr" => {
                let call_reg = ops.trim();
                self.last_cmp = None;
                let arg_regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
                let mut written_count = 0;
                for (i, &_r) in arg_regs.iter().enumerate() {
                    if (self.arg_live.written & (1 << i)) != 0 {
                        written_count = i + 1;
                    } else {
                        break;
                    }
                }
                // Indirect call: callee signature unknown, but on ARM64 AAPCS
                // the standard argument registers are x0-x3. If the caller
                // wrote nothing, it is forwarding its own parameters. Emit at
                // least 4 arg slots so the incoming registers appear in the
                // call site. Extend if the caller wrote more than 4.
                let arg_count = if written_count == 0 { 4 } else { written_count };
                let args: Vec<IrExpr> = arg_regs
                    .iter()
                    .take(arg_count)
                    .map(|&r| IrExpr::reg(r, IrType::Int64))
                    .collect();
                self.arg_live.written = 0;
                // Always assign the return value to x0. Dropping it causes
                // callers that read x0/w0 afterward to see stale data and take
                // wrong branches (e.g. env->RegisterNatives returns a status
                // code that the caller checks immediately).
                vec![IrStmt::Call {
                    target: IrExpr::reg(call_reg, IrType::Int64),
                    name: None,
                    args,
                    ret_dst: Some(IrExpr::reg("x0", IrType::Int64)),
                }]
            }

            // Comparisons
            "cmp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = IrExpr::reg(parts[0], IrType::Int64);
                    let r2 = parse_operand(parts[1], IrType::Int64);
                    self.last_cmp = Some(IrExpr::Binary(
                        BinaryOp::Eq,
                        Box::new(r1),
                        Box::new(r2),
                        IrType::Int8,
                    ));
                }
                Vec::new()
            }
            "cmn" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = IrExpr::reg(parts[0], IrType::Int64);
                    let r2_val = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                    let r2 = IrExpr::Const(r2_val.wrapping_neg());
                    self.last_cmp = Some(IrExpr::Binary(
                        BinaryOp::Eq,
                        Box::new(r1),
                        Box::new(r2),
                        IrType::Int8,
                    ));
                }
                Vec::new()
            }
            "tst" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = IrExpr::reg(parts[0], IrType::Int64);
                    let r2 = parse_operand(parts[1], IrType::Int64);
                    let band =
                        IrExpr::Binary(BinaryOp::And, Box::new(r1), Box::new(r2), IrType::Int64);
                    self.last_cmp = Some(IrExpr::Binary(
                        BinaryOp::Eq,
                        Box::new(band),
                        Box::new(IrExpr::Const(0)),
                        IrType::Int8,
                    ));
                }
                Vec::new()
            }

            // Conditional Branches
            "b.eq" | "beq" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    vec![IrStmt::Branch {
                        cond: Some(last),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.ne" | "bne" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::Ne, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.lt" | "blt" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::LtS, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.lo" | "b.cc" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::LtU, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.le" | "ble" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::LeS, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.ls" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::LeU, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.gt" | "bgt" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::GtS, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.hi" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::GtU, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.ge" | "bge" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::GeS, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "b.hs" | "b.cs" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::GeU, l, r, ty)
                        }
                        other => other,
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "cbz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let reg = IrExpr::reg(parts[0], IrType::Int64);
                    let target = parse_target_addr(parts[1]).unwrap_or(0);
                    let cond = IrExpr::Binary(
                        BinaryOp::Eq,
                        Box::new(reg),
                        Box::new(IrExpr::Const(0)),
                        IrType::Int8,
                    );
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    Vec::new()
                }
            }
            "cbnz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let reg = IrExpr::reg(parts[0], IrType::Int64);
                    let target = parse_target_addr(parts[1]).unwrap_or(0);
                    let cond = IrExpr::Binary(
                        BinaryOp::Ne,
                        Box::new(reg),
                        Box::new(IrExpr::Const(0)),
                        IrType::Int8,
                    );
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    Vec::new()
                }
            }
            "tbz" | "tbnz" => {
                let is_tbnz = mnem == "tbnz";
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let reg = IrExpr::reg(parts[0], IrType::Int64);
                    let bit = clean_imm(parts[1]).parse::<u64>().unwrap_or(0);
                    let target = parse_target_addr(parts[2]).unwrap_or(0);
                    let mask = 1u64 << bit;
                    let bit_and = IrExpr::Binary(
                        BinaryOp::And,
                        Box::new(reg),
                        Box::new(IrExpr::Const(mask)),
                        IrType::Int64,
                    );
                    let op = if is_tbnz { BinaryOp::Ne } else { BinaryOp::Eq };
                    let cond = IrExpr::Binary(
                        op,
                        Box::new(bit_and),
                        Box::new(IrExpr::Const(0)),
                        IrType::Int8,
                    );
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    Vec::new()
                }
            }

            // Conditional Selects (CSEL, CSET, CINC, CSINC, CSINV, CSNEG, CSETM)
            "csel" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[3], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            // parse_operand handles wzr/xzr → Const(0); IrExpr::reg does not.
                            let t_val = parse_operand(parts[1], ty);
                            let f_val = parse_operand(parts[2], ty);
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(t_val),
                                    false_val: Box::new(f_val),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "cset" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[1], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(IrExpr::Const(1)),
                                    false_val: Box::new(IrExpr::Const(0)),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "cinc" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[2], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            let src = IrExpr::reg(parts[1], ty);
                            let incremented = IrExpr::Binary(
                                BinaryOp::Add,
                                Box::new(src.clone()),
                                Box::new(IrExpr::Const(1)),
                                ty,
                            );
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(incremented),
                                    false_val: Box::new(src),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "csinc" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[3], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            let t_val = IrExpr::reg(parts[1], ty);
                            let f_src = IrExpr::reg(parts[2], ty);
                            let f_val = IrExpr::Binary(
                                BinaryOp::Add,
                                Box::new(f_src),
                                Box::new(IrExpr::Const(1)),
                                ty,
                            );
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(t_val),
                                    false_val: Box::new(f_val),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "csinv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[3], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            let t_val = IrExpr::reg(parts[1], ty);
                            let f_src = IrExpr::reg(parts[2], ty);
                            let f_val = IrExpr::Unary(UnaryOp::Not, Box::new(f_src), ty);
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(t_val),
                                    false_val: Box::new(f_val),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "csneg" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[3], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            let t_val = IrExpr::reg(parts[1], ty);
                            let f_src = IrExpr::reg(parts[2], ty);
                            let f_val = IrExpr::Unary(UnaryOp::Neg, Box::new(f_src), ty);
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(t_val),
                                    false_val: Box::new(f_val),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "csetm" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    match resolve_cond_arm64(&self.last_cmp, parts[1], ty) {
                        Some(cond) => {
                            let dst = IrExpr::reg(parts[0], ty);
                            let all_ones = match ty {
                                IrType::Int32 => IrExpr::Const(0xffff_ffff),
                                _ => IrExpr::Const(0xffff_ffff_ffff_ffff),
                            };
                            vec![IrStmt::Assign {
                                dst,
                                src: IrExpr::Ternary {
                                    cond: Box::new(cond),
                                    true_val: Box::new(all_ones),
                                    false_val: Box::new(IrExpr::Const(0)),
                                    ty,
                                },
                            }]
                        }
                        None => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
                    }
                } else {
                    Vec::new()
                }
            }
            "mul" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = parse_operand(parts[2], ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty),
                    }]
                } else {
                    Vec::new()
                }
            }

            // ADRP + ADD / Constant Folding
            "adrp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let reg = parts[0].to_lowercase();
                    if let Some(page) = parse_target_addr(parts[1]) {
                        self.adrp_pages.insert(reg, page);
                    }
                }
                Vec::new()
            }
            "adr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = if let Some(target) = parse_target_addr(parts[1]) {
                        if let Some(str_val) = resolve_rodata_string(ctx, target) {
                            IrExpr::StringLit(str_val)
                        } else {
                            IrExpr::Const(target)
                        }
                    } else {
                        parse_operand(parts[1], IrType::Int64)
                    };
                    vec![IrStmt::Assign { dst, src }]
                } else {
                    Vec::new()
                }
            }

            // Arithmetic & Logic
            "add" | "adds" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst_ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src_name = parts[1].to_lowercase();
                    let imm = clean_imm(parts[2]);

                    let dst_lower = parts[0].to_lowercase();
                    if let Some(&page) = self.adrp_pages.get(&src_name) {
                        if let Ok(offset_val) = parse_imm_num(&imm) {
                            let resolved = page + offset_val;
                            if src_name == dst_lower {
                                self.adrp_pages.remove(&src_name);
                            }
                            let src_expr = if let Some(s) = resolve_rodata_string(ctx, resolved) {
                                IrExpr::StringLit(s)
                            } else {
                                IrExpr::Const(resolved)
                            };
                            return vec![IrStmt::Assign { dst, src: src_expr }];
                        }
                    }

                    let lhs = IrExpr::reg(parts[1], dst_ty);
                    let rhs = parse_operand(parts[2], dst_ty);
                    if mnem == "adds" {
                        self.last_cmp = Some(IrExpr::Binary(
                            BinaryOp::Eq,
                            Box::new(lhs.clone()),
                            Box::new(rhs.clone()),
                            IrType::Int8,
                        ));
                    }
                    self.adrp_pages.remove(&parts[0].to_lowercase());
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Add, Box::new(lhs), Box::new(rhs), dst_ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sub" | "subs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst_ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let lhs = IrExpr::reg(parts[1], dst_ty);
                    let rhs = parse_operand(parts[2], dst_ty);
                    if mnem == "subs" {
                        self.last_cmp = Some(IrExpr::Binary(
                            BinaryOp::Eq,
                            Box::new(lhs.clone()),
                            Box::new(rhs.clone()),
                            IrType::Int8,
                        ));
                    }
                    self.adrp_pages.remove(&parts[0].to_lowercase());
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Sub, Box::new(lhs), Box::new(rhs), dst_ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "neg" | "negs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_operand(parts[1], dst_ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Unary(UnaryOp::Neg, Box::new(src), dst_ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "mvn" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_operand(parts[1], dst_ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Unary(UnaryOp::Not, Box::new(src), dst_ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "madd" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = IrExpr::reg(parts[2], ty);
                    let r3 = parse_operand(parts[3], ty);
                    let mul = IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Add, Box::new(mul), Box::new(r3), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "msub" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = IrExpr::reg(parts[2], ty);
                    let r3 = parse_operand(parts[3], ty);
                    let mul = IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Sub, Box::new(r3), Box::new(mul), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sdiv" | "udiv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let lhs = IrExpr::reg(parts[1], ty);
                    let rhs = parse_operand(parts[2], ty);
                    let op = if mnem == "sdiv" {
                        BinaryOp::DivS
                    } else {
                        BinaryOp::DivU
                    };
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(op, Box::new(lhs), Box::new(rhs), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "and" | "orr" | "eor" | "lsl" | "lsr" | "asr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let lhs = IrExpr::reg(parts[1], ty);
                    let rhs = parse_operand(parts[2], ty);
                    let op = match mnem {
                        "and" => BinaryOp::And,
                        "orr" => BinaryOp::Or,
                        "eor" => BinaryOp::Xor,
                        "lsl" => BinaryOp::Shl,
                        "lsr" => BinaryOp::ShrU,
                        "asr" => BinaryOp::ShrS,
                        _ => BinaryOp::And,
                    };
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(op, Box::new(lhs), Box::new(rhs), ty),
                    }]
                } else {
                    Vec::new()
                }
            }

            // Register Moves & Constant Loading
            "mov" | "fmov" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_operand(parts[1], dst_ty);
                    self.adrp_pages.remove(&parts[0].to_lowercase());
                    vec![IrStmt::Assign { dst, src }]
                } else {
                    Vec::new()
                }
            }
            "fadd" | "fsub" | "fmul" | "fdiv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let lhs = IrExpr::reg(parts[1], ty);
                    let rhs = IrExpr::reg(parts[2], ty);
                    let op = match mnem {
                        "fadd" => BinaryOp::Add,
                        "fsub" => BinaryOp::Sub,
                        "fmul" => BinaryOp::Mul,
                        "fdiv" => BinaryOp::DivS,
                        _ => BinaryOp::Add,
                    };
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(op, Box::new(lhs), Box::new(rhs), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "fcmp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let r1 = IrExpr::reg(parts[0], ty);
                    let r2 = parse_operand(parts[1], ty);
                    self.last_cmp =
                        Some(IrExpr::Binary(BinaryOp::Eq, Box::new(r1), Box::new(r2), ty));
                }
                Vec::new()
            }
            "fmadd" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = IrExpr::reg(parts[2], ty);
                    let r3 = IrExpr::reg(parts[3], ty);
                    let mul = IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Add, Box::new(mul), Box::new(r3), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "fmsub" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = IrExpr::reg(parts[2], ty);
                    let r3 = IrExpr::reg(parts[3], ty);
                    let mul = IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(BinaryOp::Sub, Box::new(r3), Box::new(mul), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "movi" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    // SIMD/FP vector destinations (v0.2d, q0, d0, s0 lanes) can't be modeled as scalar C.
                    // The '.' in 'v0.2d' would produce an invalid C identifier if emitted as a variable.
                    if parts[0].starts_with('v')
                        || parts[0].starts_with('q')
                        || parts[0].contains('.')
                    {
                        return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                    }
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let val = clean_imm(parts[1]);
                    if val.chars().all(|c| c == '0' || c == '#') {
                        vec![IrStmt::Assign {
                            dst,
                            src: IrExpr::Const(0),
                        }]
                    } else {
                        vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                    }
                } else {
                    Vec::new()
                }
            }
            "movk" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let val = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                    let shift = if parts.len() >= 3 && parts[2].contains("lsl") {
                        clean_imm(parts[2].trim_start_matches("lsl").trim())
                            .parse::<u64>()
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    let shifted_val = val << shift;
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Or,
                            Box::new(dst),
                            Box::new(IrExpr::Const(shifted_val)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }

            // Type Extensions (UXTB, UXTH, UXTW, SXTB, SXTH, SXTW, SBFIZ, UBFIZ)
            "uxtb" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = IrExpr::reg(parts[1], IrType::Int64);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(src),
                            Box::new(IrExpr::Const(0xff)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "uxth" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = IrExpr::reg(parts[1], IrType::Int64);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(src),
                            Box::new(IrExpr::Const(0xffff)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "uxtw" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = IrExpr::reg(parts[1], IrType::Int64);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(src),
                            Box::new(IrExpr::Const(0xffff_ffff)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sxtb" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = IrExpr::reg(parts[1], IrType::Int64);
                    let shl = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(src),
                        Box::new(IrExpr::Const(56)),
                        IrType::Int64,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(shl),
                            Box::new(IrExpr::Const(56)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sxth" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = IrExpr::reg(parts[1], IrType::Int64);
                    let shl = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(src),
                        Box::new(IrExpr::Const(48)),
                        IrType::Int64,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(shl),
                            Box::new(IrExpr::Const(48)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sxtw" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = IrExpr::reg(parts[1], IrType::Int64);
                    let shl = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(src),
                        Box::new(IrExpr::Const(32)),
                        IrType::Int64,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(shl),
                            Box::new(IrExpr::Const(32)),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "ubfiz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let src = parse_operand(parts[1], ty);
                    let lsb = parse_imm_num(clean_imm(parts[2]).as_str()).unwrap_or(0);
                    let width = parse_imm_num(clean_imm(parts[3]).as_str()).unwrap_or(0);
                    let mask = if width >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << width).saturating_sub(1)
                    };
                    let masked = IrExpr::Binary(
                        BinaryOp::And,
                        Box::new(src),
                        Box::new(IrExpr::Const(mask)),
                        ty,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Shl,
                            Box::new(masked),
                            Box::new(IrExpr::Const(lsb)),
                            ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sbfiz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let ty = infer_arm64_reg_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    let src = parse_operand(parts[1], ty);
                    let lsb = parse_imm_num(clean_imm(parts[2]).as_str()).unwrap_or(0);
                    let width = parse_imm_num(clean_imm(parts[3]).as_str()).unwrap_or(0);
                    let bit_size = ty.size_bytes() as u64 * 8;
                    let shift_amt = bit_size.saturating_sub(width);
                    let shl = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(src),
                        Box::new(IrExpr::Const(shift_amt)),
                        ty,
                    );
                    let s_ext = IrExpr::Binary(
                        BinaryOp::ShrS,
                        Box::new(shl),
                        Box::new(IrExpr::Const(shift_amt)),
                        ty,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Shl,
                            Box::new(s_ext),
                            Box::new(IrExpr::Const(lsb)),
                            ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }

            // Memory Loads & Stores
            "ldr" | "ldrb" | "ldrh" | "ldur" | "ldurb" | "ldurh" | "ldar" | "ldarb" | "ldarh" => {
                if ops.starts_with('q') {
                    return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                }
                let ty = match mnem {
                    "ldrb" | "ldurb" | "ldarb" => IrType::Int8,
                    "ldrh" | "ldurh" | "ldarh" => IrType::Int16,
                    _ if ops.starts_with('d') => IrType::Float64,
                    _ if ops.starts_with('s') => IrType::Float32,
                    _ if ops.starts_with('w') => IrType::Int32,
                    _ => IrType::Int64,
                };

                // Post-indexed: ldr rd, [base], #imm
                if ops.contains("], #") {
                    let parts: Vec<&str> = ops.split("], #").collect();
                    if parts.len() == 2 {
                        let post_imm = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                        let left_parts: Vec<&str> = parts[0].split(", [").collect();
                        if left_parts.len() == 2 {
                            let dst = IrExpr::reg(left_parts[0].trim(), ty);
                            let base = IrExpr::reg(left_parts[1].trim(), IrType::Int64);
                            return vec![
                                IrStmt::Assign {
                                    dst,
                                    src: IrExpr::Load {
                                        ptr: Box::new(base.clone()),
                                        ty,
                                    },
                                },
                                IrStmt::Assign {
                                    dst: base.clone(),
                                    src: IrExpr::Binary(
                                        BinaryOp::Add,
                                        Box::new(base),
                                        Box::new(IrExpr::Const(post_imm)),
                                        IrType::Int64,
                                    ),
                                },
                            ];
                        }
                    }
                }

                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], ty);
                    let ptr_expr = parse_mem_expr(parts[1], &self.adrp_pages);
                    self.adrp_pages.remove(&parts[0].to_lowercase());
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Load {
                            ptr: Box::new(ptr_expr),
                            ty,
                        },
                    }]
                } else {
                    Vec::new()
                }
            }
            "str" | "strb" | "strh" | "stur" | "sturb" | "sturh" | "stlr" | "stlrb" | "stlrh" => {
                if ops.starts_with('q') {
                    return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                }
                let ty = match mnem {
                    "strb" | "sturb" | "stlrb" => IrType::Int8,
                    "strh" | "sturh" | "stlrh" => IrType::Int16,
                    _ if ops.starts_with('d') => IrType::Float64,
                    _ if ops.starts_with('s') => IrType::Float32,
                    _ if ops.starts_with('w') => IrType::Int32,
                    _ => IrType::Int64,
                };

                // Post-indexed: str rs, [base], #imm
                if ops.contains("], #") {
                    let parts: Vec<&str> = ops.split("], #").collect();
                    if parts.len() == 2 {
                        let post_imm = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                        let left_parts: Vec<&str> = parts[0].split(", [").collect();
                        if left_parts.len() == 2 {
                            let src = parse_operand(left_parts[0].trim(), ty);
                            let base = IrExpr::reg(left_parts[1].trim(), IrType::Int64);
                            return vec![
                                IrStmt::Store {
                                    ptr: base.clone(),
                                    val: src,
                                    ty,
                                },
                                IrStmt::Assign {
                                    dst: base.clone(),
                                    src: IrExpr::Binary(
                                        BinaryOp::Add,
                                        Box::new(base),
                                        Box::new(IrExpr::Const(post_imm)),
                                        IrType::Int64,
                                    ),
                                },
                            ];
                        }
                    }
                }

                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let src = parse_operand(parts[0], ty);
                    let ptr_expr = parse_mem_expr(parts[1], &self.adrp_pages);
                    vec![IrStmt::Store {
                        ptr: ptr_expr,
                        val: src,
                        ty,
                    }]
                } else {
                    Vec::new()
                }
            }
            "ldp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    if parts[0].starts_with('q') || parts[1].starts_with('q') {
                        return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                    }
                    let is_w = parts[0].starts_with('w');
                    let ty = if is_w { IrType::Int32 } else { IrType::Int64 };
                    let step = ty.size_bytes() as u64;

                    let r1 = IrExpr::reg(parts[0], ty);
                    let r2 = IrExpr::reg(parts[1], ty);
                    let mem_raw = parts[2..].join(",");
                    let ptr_expr = parse_mem_expr(&mem_raw, &self.adrp_pages);

                    let ptr2 = IrExpr::Binary(
                        BinaryOp::Add,
                        Box::new(ptr_expr.clone()),
                        Box::new(IrExpr::Const(step)),
                        IrType::Int64,
                    );
                    vec![
                        IrStmt::Assign {
                            dst: r1,
                            src: IrExpr::Load {
                                ptr: Box::new(ptr_expr),
                                ty,
                            },
                        },
                        IrStmt::Assign {
                            dst: r2,
                            src: IrExpr::Load {
                                ptr: Box::new(ptr2),
                                ty,
                            },
                        },
                    ]
                } else {
                    Vec::new()
                }
            }
            "stp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    if parts[0].starts_with('q') || parts[1].starts_with('q') {
                        return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                    }
                    let is_w = parts[0].starts_with('w');
                    let ty = if is_w { IrType::Int32 } else { IrType::Int64 };
                    let step = ty.size_bytes() as u64;

                    let r1 = parse_operand(parts[0], ty);
                    let r2 = parse_operand(parts[1], ty);
                    let mem_raw = parts[2..].join(",");
                    let ptr_expr = parse_mem_expr(&mem_raw, &self.adrp_pages);

                    let ptr2 = IrExpr::Binary(
                        BinaryOp::Add,
                        Box::new(ptr_expr.clone()),
                        Box::new(IrExpr::Const(step)),
                        IrType::Int64,
                    );
                    vec![
                        IrStmt::Store {
                            ptr: ptr_expr,
                            val: r1,
                            ty,
                        },
                        IrStmt::Store {
                            ptr: ptr2,
                            val: r2,
                            ty,
                        },
                    ]
                } else {
                    Vec::new()
                }
            }

            "nop" => Vec::new(),
            _ => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
        };

        for s in &stmts {
            if let IrStmt::Assign {
                dst: IrExpr::Reg(r, _),
                ..
            } = s
            {
                mark_arm64_arg_written(r.as_str(), &mut self.arg_live);
            }
        }

        stmts
    }
}

// Helpers
fn resolve_cond_arm64(last_cmp: &Option<IrExpr>, suffix: &str, _ty: IrType) -> Option<IrExpr> {
    let last = last_cmp.as_ref()?;
    let (l, r, cmp_ty) = match last {
        IrExpr::Binary(BinaryOp::Eq, l, r, t) => (l.clone(), r.clone(), *t),
        _ => return Some(last.clone()),
    };
    let signed = |op| IrExpr::Binary(op, l.clone(), r.clone(), cmp_ty);
    let unsigned = |op| IrExpr::Binary(op, l.clone(), r.clone(), cmp_ty);
    Some(match suffix {
        "eq" => signed(BinaryOp::Eq),
        "ne" => signed(BinaryOp::Ne),
        "gt" => signed(BinaryOp::GtS),
        "ge" => signed(BinaryOp::GeS),
        "lt" => signed(BinaryOp::LtS),
        "le" => signed(BinaryOp::LeS),
        "hi" => unsigned(BinaryOp::GtU),
        "hs" | "cs" => unsigned(BinaryOp::GeU),
        "lo" | "cc" => unsigned(BinaryOp::LtU),
        "ls" => unsigned(BinaryOp::LeU),
        "mi" => IrExpr::Binary(BinaryOp::LtS, l.clone(), Box::new(IrExpr::Const(0)), cmp_ty),
        "pl" => IrExpr::Binary(BinaryOp::GeS, l.clone(), Box::new(IrExpr::Const(0)), cmp_ty),
        _ => return None,
    })
}

fn clean_imm(s: &str) -> String {
    let t = s.trim();
    if let Some(stripped) = t.strip_prefix('#') {
        stripped.to_string()
    } else {
        t.to_string()
    }
}

fn parse_imm_num(s: &str) -> Result<u64, ()> {
    let t = s.trim().trim_start_matches('#');
    if t.starts_with("0x") || t.starts_with("0X") {
        u64::from_str_radix(&t[2..], 16).map_err(|_| ())
    } else {
        t.parse::<u64>().map_err(|_| ())
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

fn parse_operand(s: &str, ty: IrType) -> IrExpr {
    let t = clean_imm(s);
    if t == "xzr" || t == "wzr" {
        return IrExpr::Const(0);
    }
    if let Ok(c) = parse_imm_num(&t) {
        return IrExpr::Const(c);
    }
    if t.parse::<f64>().is_ok() {
        return IrExpr::StringLit(t);
    }
    IrExpr::reg(&t, ty)
}

fn mark_arm64_arg_written(r: &str, arg_live: &mut ArgLiveness) {
    let r_lower = r.to_lowercase();
    match r_lower.as_str() {
        "x0" | "w0" => arg_live.written |= 1 << 0,
        "x1" | "w1" => arg_live.written |= 1 << 1,
        "x2" | "w2" => arg_live.written |= 1 << 2,
        "x3" | "w3" => arg_live.written |= 1 << 3,
        "x4" | "w4" => arg_live.written |= 1 << 4,
        "x5" | "w5" => arg_live.written |= 1 << 5,
        "x6" | "w6" => arg_live.written |= 1 << 6,
        "x7" | "w7" => arg_live.written |= 1 << 7,
        _ => {}
    }
}

fn is_void_callee(sym: &str) -> bool {
    matches!(
        sym,
        "free"
            | "abort"
            | "__stack_chk_fail"
            | "pthread_mutex_lock"
            | "pthread_mutex_unlock"
            | "__cxa_finalize"
            | "__android_log_print"
            | "dummy_callee"
    ) || sym.contains("void")
}

fn parse_mem_expr(ops: &str, adrp_pages: &HashMap<String, u64>) -> IrExpr {
    let t = ops.trim().trim_end_matches('!');
    if t.starts_with('[') && t.ends_with(']') {
        let inner = &t[1..t.len() - 1];
        let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
        let base_name = parts[0].to_lowercase();

        let base_expr = if let Some(&page) = adrp_pages.get(&base_name) {
            IrExpr::Const(page)
        } else {
            IrExpr::reg(parts[0], IrType::Int64)
        };

        if parts.len() == 1 {
            base_expr
        } else if parts.len() == 3 {
            let idx_reg = parts[1].trim();
            let idx_ty = infer_arm64_reg_type(idx_reg);
            let idx_expr = IrExpr::reg(idx_reg, idx_ty);
            let shift = if parts[2].contains('#') {
                parse_imm_num(clean_imm(parts[2].split('#').nth(1).unwrap_or("0")).as_str())
                    .unwrap_or(0)
            } else {
                0
            };
            let scaled_idx = if shift > 0 {
                IrExpr::Binary(
                    BinaryOp::Shl,
                    Box::new(idx_expr),
                    Box::new(IrExpr::Const(shift)),
                    IrType::Int64,
                )
            } else {
                idx_expr
            };
            IrExpr::Binary(
                BinaryOp::Add,
                Box::new(base_expr),
                Box::new(scaled_idx),
                IrType::Int64,
            )
        } else {
            let off_str = clean_imm(parts[1]);
            let (is_neg, mag_str) = match off_str.strip_prefix('-') {
                Some(rest) => (true, rest.to_string()),
                None => (false, off_str.clone()),
            };
            let mag = parse_imm_num(&mag_str).unwrap_or(0);
            if is_neg {
                IrExpr::Binary(
                    BinaryOp::Sub,
                    Box::new(base_expr),
                    Box::new(IrExpr::Const(mag)),
                    IrType::Int64,
                )
            } else {
                IrExpr::Binary(
                    BinaryOp::Add,
                    Box::new(base_expr),
                    Box::new(IrExpr::Const(mag)),
                    IrType::Int64,
                )
            }
        }
    } else {
        IrExpr::reg(ops, IrType::Int64)
    }
}

fn resolve_rodata_string(ctx: &ElfContext, vaddr: u64) -> Option<String> {
    let offset = ctx.vaddr_to_offset(vaddr)? as usize;
    if offset >= ctx.raw.len() {
        return None;
    }
    let slice = &ctx.raw[offset..];
    let null_pos = slice.iter().position(|&b| b == 0)?;
    if !(2..=80).contains(&null_pos) {
        return None;
    }
    let candidate = &slice[..null_pos];
    if candidate.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        let s = std::str::from_utf8(candidate).ok()?;
        let escaped = s.replace('\"', "\\\"");
        return Some(format!("\"{}\"", escaped));
    }
    None
}

fn infer_arm64_reg_type(reg: &str) -> IrType {
    let r = reg.to_lowercase();
    if r.starts_with('w') {
        IrType::Int32
    } else if r.starts_with('x') {
        IrType::Int64
    } else if r.starts_with('s') {
        IrType::Float32
    } else if r.starts_with('d') {
        IrType::Float64
    } else if r.starts_with('q') {
        IrType::Int128
    } else {
        IrType::Int64
    }
}
