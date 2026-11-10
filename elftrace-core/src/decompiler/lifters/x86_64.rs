//! x86-64 / AMD64 (64-bit PC) Instruction Lifter into Architecture-Independent IR.

use crate::decompiler::ir::{BinaryOp, IrExpr, IrStmt, IrType, UnaryOp};
use crate::decompiler::lifters::InstructionLifter;
use crate::elf_parser::ElfContext;

#[derive(Debug, Clone, Copy, Default)]
pub struct ArgLiveness {
    pub written: u8,
}

pub struct X86_64Lifter {
    pub last_cmp: Option<IrExpr>,
    pub arg_live: ArgLiveness,
    pub prologue_done: bool,
}

impl X86_64Lifter {
    pub fn new() -> Self {
        Self {
            last_cmp: None,
            arg_live: ArgLiveness::default(),
            prologue_done: false,
        }
    }
}

impl Default for X86_64Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionLifter for X86_64Lifter {
    fn reset_state(&mut self) {
        self.last_cmp = None;
        self.arg_live.written = 0;
        self.prologue_done = false;
    }

    fn lift(
        &mut self,
        ctx: &ElfContext,
        address: u64,
        mnemonic: &str,
        op_str: &str,
        insn_bytes: &[u8],
    ) -> Vec<IrStmt> {
        let mnem = mnemonic.trim();
        let ops = op_str.trim();
        let next_pc = address + insn_bytes.len() as u64;

        let is_branch_or_call = mnem.starts_with('b')
            || mnem.starts_with('j')
            || mnem.starts_with("cb")
            || mnem.starts_with("tb")
            || mnem == "call"
            || mnem == "ret"
            || mnem == "leave";

        // 1. Prologue / Epilogue / Frame Filter
        if !self.prologue_done {
            if mnem == "push"
                && (ops.contains("rbp")
                    || ops.contains("r12")
                    || ops.contains("r13")
                    || ops.contains("r14")
                    || ops.contains("r15")
                    || ops.contains("rbx")
                    || ops.contains("rax"))
            {
                return Vec::new();
            }
            if mnem == "pop"
                && (ops.contains("rbp")
                    || ops.contains("r12")
                    || ops.contains("r13")
                    || ops.contains("r14")
                    || ops.contains("r15")
                    || ops.contains("rbx")
                    || ops.contains("rax"))
            {
                return Vec::new();
            }
            if mnem == "mov" && ops == "rbp, rsp" {
                return Vec::new();
            }
            if mnem == "sub" && ops.starts_with("rsp,") {
                return Vec::new();
            }
            if mnem == "add" && ops.starts_with("rsp,") {
                return Vec::new();
            }
        }

        if is_branch_or_call {
            self.prologue_done = true;
        }

        let stmts = match mnem {
            // Control Flow
            "ret" | "leave" => {
                vec![IrStmt::Return(None)]
            }
            "ud2" => {
                vec![IrStmt::Trap]
            }
            "jmp" => {
                if let Some(target) = parse_x86_target(ops, next_pc) {
                    vec![IrStmt::Branch { cond: None, target }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "call" => {
                self.last_cmp = None;
                let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                let mut args = Vec::new();
                for (i, &r) in arg_regs.iter().enumerate() {
                    if (self.arg_live.written & (1 << i)) != 0 {
                        args.push(IrExpr::reg(r, IrType::Int64));
                    } else {
                        break;
                    }
                }
                self.arg_live.written = 0;

                if let Some(target) = parse_x86_target(ops, next_pc) {
                    let name = ctx
                        .syms_map
                        .get(&target)
                        .map(|s| s.demangled.as_deref().unwrap_or(s.sym.as_str()).to_string());
                    vec![IrStmt::Call {
                        target: IrExpr::Const(target),
                        name,
                        args,
                        ret_dst: Some(IrExpr::reg("rax", IrType::Int64)),
                    }]
                } else {
                    let target_expr = parse_x86_operand(ops, next_pc, ctx);
                    vec![IrStmt::Call {
                        target: target_expr,
                        name: None,
                        args,
                        ret_dst: Some(IrExpr::reg("rax", IrType::Int64)),
                    }]
                }
            }

            // Comparisons
            "cmp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = parse_x86_operand(parts[0], next_pc, ctx);
                    let r2 = parse_x86_operand(parts[1], next_pc, ctx);
                    self.last_cmp = Some(IrExpr::Binary(
                        BinaryOp::Eq,
                        Box::new(r1),
                        Box::new(r2),
                        IrType::Int8,
                    ));
                }
                Vec::new()
            }
            "test" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = parse_x86_operand(parts[0], next_pc, ctx);
                    let r2 = parse_x86_operand(parts[1], next_pc, ctx);
                    if parts[0] == parts[1] {
                        self.last_cmp = Some(IrExpr::Binary(
                            BinaryOp::Ne,
                            Box::new(r1),
                            Box::new(IrExpr::Const(0)),
                            IrType::Int8,
                        ));
                    } else {
                        let band = IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(r1),
                            Box::new(r2),
                            IrType::Int64,
                        );
                        self.last_cmp = Some(IrExpr::Binary(
                            BinaryOp::Ne,
                            Box::new(band),
                            Box::new(IrExpr::Const(0)),
                            IrType::Int8,
                        ));
                    }
                }
                Vec::new()
            }

            // Jumps / Branches
            "je" | "jz" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
                if let Some(cond) = self.last_cmp.take() {
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "jne" | "jnz" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
                if let Some(last) = self.last_cmp.take() {
                    let cond = match last {
                        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => {
                            IrExpr::Binary(BinaryOp::Ne, l, r, ty)
                        }
                        other => IrExpr::Unary(UnaryOp::Not, Box::new(other), IrType::Int8),
                    };
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "jl" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "jb" | "jc" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "jle" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "jbe" | "jna" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "jg" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "ja" | "jnbe" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "jge" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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
            "jae" | "jnb" => {
                let target = parse_x86_target(ops, next_pc).unwrap_or(0);
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

            // LEA (Load Effective Address - PC-Relative String / Variable Resolution)
            "lea" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = parse_x86_lea(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign { dst, src }]
                } else {
                    Vec::new()
                }
            }

            // Conditional Move (CMOVcc)
            m if m.starts_with("cmov") => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let src = parse_x86_operand(parts[1], next_pc, ctx);
                    let cond_suffix = &m[4..];
                    let cond = match (&self.last_cmp, cond_suffix) {
                        (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "l" | "b") => {
                            IrExpr::Binary(BinaryOp::LtS, l.clone(), r.clone(), *ty)
                        }
                        (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "le" | "be") => {
                            IrExpr::Binary(BinaryOp::LeS, l.clone(), r.clone(), *ty)
                        }
                        (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "g" | "a") => {
                            IrExpr::Binary(BinaryOp::GtS, l.clone(), r.clone(), *ty)
                        }
                        (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ge" | "ae") => {
                            IrExpr::Binary(BinaryOp::GeS, l.clone(), r.clone(), *ty)
                        }
                        (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ne" | "nz") => {
                            IrExpr::Binary(BinaryOp::Ne, l.clone(), r.clone(), *ty)
                        }
                        (Some(other), _) => other.clone(),
                        (None, _) => {
                            IrExpr::reg(format!("flag_{}", cond_suffix).as_str(), IrType::Int8)
                        }
                    };
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Ternary {
                            cond: Box::new(cond),
                            true_val: Box::new(src),
                            false_val: Box::new(dst),
                            ty: IrType::Int64,
                        },
                    }]
                } else {
                    Vec::new()
                }
            }
            m if m.starts_with("set") => {
                let dst = parse_x86_operand(ops, next_pc, ctx);
                let cond_suffix = &m[3..];
                let cond = match (&self.last_cmp, cond_suffix) {
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "l") => {
                        IrExpr::Binary(BinaryOp::LtS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "b" | "c") => {
                        IrExpr::Binary(BinaryOp::LtU, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "le") => {
                        IrExpr::Binary(BinaryOp::LeS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "be" | "na") => {
                        IrExpr::Binary(BinaryOp::LeU, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "g") => {
                        IrExpr::Binary(BinaryOp::GtS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "a" | "nbe") => {
                        IrExpr::Binary(BinaryOp::GtU, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ge") => {
                        IrExpr::Binary(BinaryOp::GeS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ae" | "nb") => {
                        IrExpr::Binary(BinaryOp::GeU, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "e" | "z") => {
                        IrExpr::Binary(BinaryOp::Eq, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ne" | "nz") => {
                        IrExpr::Binary(BinaryOp::Ne, l.clone(), r.clone(), *ty)
                    }
                    (Some(other), _) => other.clone(),
                    (None, _) => IrExpr::Const(1),
                };
                vec![IrStmt::Assign {
                    dst,
                    src: IrExpr::Ternary {
                        cond: Box::new(cond),
                        true_val: Box::new(IrExpr::Const(1)),
                        false_val: Box::new(IrExpr::Const(0)),
                        ty: IrType::Int8,
                    },
                }]
            }

            // Zeroing Idioms & Logic
            "xor" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    if parts[0] == parts[1] {
                        vec![IrStmt::Assign {
                            dst,
                            src: IrExpr::Const(0),
                        }]
                    } else {
                        let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                        vec![IrStmt::Assign {
                            dst: dst.clone(),
                            src: IrExpr::Binary(
                                BinaryOp::Xor,
                                Box::new(dst),
                                Box::new(rhs),
                                IrType::Int64,
                            ),
                        }]
                    }
                } else {
                    Vec::new()
                }
            }
            "mov" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_raw = parts[0];
                    let src_raw = parts[1];
                    let dst_ty = infer_x86_operand_type(dst_raw);
                    let src_ty = infer_x86_operand_type(src_raw);
                    let op_ty = if dst_raw.contains('[') {
                        dst_ty
                    } else {
                        src_ty
                    };

                    if dst_raw.contains('[') {
                        let ptr = parse_x86_mem_ptr(dst_raw, next_pc);
                        let val = parse_x86_operand(src_raw, next_pc, ctx);
                        vec![IrStmt::Store {
                            ptr,
                            val,
                            ty: op_ty,
                        }]
                    } else if src_raw.contains('[') {
                        let dst = IrExpr::reg(dst_raw, op_ty);
                        let ptr = parse_x86_mem_ptr(src_raw, next_pc);
                        vec![IrStmt::Assign {
                            dst,
                            src: IrExpr::Load {
                                ptr: Box::new(ptr),
                                ty: op_ty,
                            },
                        }]
                    } else {
                        let dst = IrExpr::reg(dst_raw, dst_ty);
                        let src = parse_x86_operand(src_raw, next_pc, ctx);
                        vec![IrStmt::Assign { dst, src }]
                    }
                } else {
                    Vec::new()
                }
            }
            "add" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_raw = parts[0];
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    let ty = infer_x86_operand_type(dst_raw);
                    if dst_raw.contains('[') {
                        let ptr = parse_x86_mem_ptr(dst_raw, next_pc);
                        let load = IrExpr::Load {
                            ptr: Box::new(ptr.clone()),
                            ty,
                        };
                        let val = IrExpr::Binary(BinaryOp::Add, Box::new(load), Box::new(rhs), ty);
                        vec![IrStmt::Store { ptr, val, ty }]
                    } else {
                        let dst = IrExpr::reg(dst_raw, ty);
                        vec![IrStmt::Assign {
                            dst: dst.clone(),
                            src: IrExpr::Binary(BinaryOp::Add, Box::new(dst), Box::new(rhs), ty),
                        }]
                    }
                } else {
                    Vec::new()
                }
            }
            "sub" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_raw = parts[0];
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    let ty = infer_x86_operand_type(dst_raw);
                    if dst_raw.contains('[') {
                        let ptr = parse_x86_mem_ptr(dst_raw, next_pc);
                        let load = IrExpr::Load {
                            ptr: Box::new(ptr.clone()),
                            ty,
                        };
                        let val = IrExpr::Binary(BinaryOp::Sub, Box::new(load), Box::new(rhs), ty);
                        vec![IrStmt::Store { ptr, val, ty }]
                    } else {
                        let dst = IrExpr::reg(dst_raw, ty);
                        vec![IrStmt::Assign {
                            dst: dst.clone(),
                            src: IrExpr::Binary(BinaryOp::Sub, Box::new(dst), Box::new(rhs), ty),
                        }]
                    }
                } else {
                    Vec::new()
                }
            }
            "inc" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 1 {
                    let ty = infer_x86_operand_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Add,
                            Box::new(dst),
                            Box::new(IrExpr::Const(1)),
                            ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "dec" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 1 {
                    let ty = infer_x86_operand_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], ty);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Sub,
                            Box::new(dst),
                            Box::new(IrExpr::Const(1)),
                            ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "imul" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Mul,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int64,
                        ),
                    }]
                } else if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let r1 = parse_x86_operand(parts[1], next_pc, ctx);
                    let r2 = parse_x86_operand(parts[2], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Mul,
                            Box::new(r1),
                            Box::new(r2),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "and" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "or" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Or,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "shl" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Shl,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "shr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::ShrU,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "addsd" | "addss" | "subsd" | "subss" | "mulsd" | "mulss" | "divsd" | "divss" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_double = mnem.ends_with("sd");
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let dst = IrExpr::reg(parts[0], ty);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    let op = match &mnem[..3] {
                        "add" => BinaryOp::Add,
                        "sub" => BinaryOp::Sub,
                        "mul" => BinaryOp::Mul,
                        "div" => BinaryOp::DivS,
                        _ => BinaryOp::Add,
                    };
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(op, Box::new(dst), Box::new(rhs), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            "ucomisd" | "ucomiss" | "comisd" | "comiss" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_double = mnem.ends_with("sd");
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let r1 = parse_x86_operand(parts[0], next_pc, ctx);
                    let r2 = parse_x86_operand(parts[1], next_pc, ctx);
                    self.last_cmp =
                        Some(IrExpr::Binary(BinaryOp::Eq, Box::new(r1), Box::new(r2), ty));
                }
                Vec::new()
            }
            "movsd" | "movss" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_double = mnem == "movsd";
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let dst_raw = parts[0];
                    let src_raw = parts[1];

                    if dst_raw.contains('[') {
                        let ptr = parse_x86_mem_ptr(dst_raw, next_pc);
                        let val = parse_x86_operand(src_raw, next_pc, ctx);
                        vec![IrStmt::Store { ptr, val, ty }]
                    } else if src_raw.contains('[') {
                        let dst = IrExpr::reg(dst_raw, ty);
                        let ptr = parse_x86_mem_ptr(src_raw, next_pc);
                        vec![IrStmt::Assign {
                            dst,
                            src: IrExpr::Load {
                                ptr: Box::new(ptr),
                                ty,
                            },
                        }]
                    } else {
                        let dst = IrExpr::reg(dst_raw, ty);
                        let src = parse_x86_operand(src_raw, next_pc, ctx);
                        vec![IrStmt::Assign { dst, src }]
                    }
                } else {
                    Vec::new()
                }
            }
            "sar" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int64);
                    let rhs = parse_x86_operand(parts[1], next_pc, ctx);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int64,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "movzx" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_x86_operand_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_x86_operand(parts[1], next_pc, ctx);
                    let src_ty = infer_x86_operand_type(parts[1]);
                    let mask = match src_ty {
                        IrType::Int8 => 0xff,
                        IrType::Int16 => 0xffff,
                        _ => 0xffff_ffff,
                    };
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(src),
                            Box::new(IrExpr::Const(mask)),
                            dst_ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "movsx" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_x86_operand_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_x86_operand(parts[1], next_pc, ctx);
                    let src_ty = infer_x86_operand_type(parts[1]);
                    let shift = match src_ty {
                        IrType::Int8 => 56,
                        IrType::Int16 => 48,
                        _ => 32,
                    };
                    let shl = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(src),
                        Box::new(IrExpr::Const(shift)),
                        dst_ty,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(shl),
                            Box::new(IrExpr::Const(shift)),
                            dst_ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "movsxd" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_x86_operand_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_x86_operand(parts[1], next_pc, ctx);
                    let shl = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(src),
                        Box::new(IrExpr::Const(32)),
                        dst_ty,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(shl),
                            Box::new(IrExpr::Const(32)),
                            dst_ty,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "cdq" => {
                let edx = IrExpr::reg("edx", IrType::Int32);
                let eax = IrExpr::reg("eax", IrType::Int32);
                vec![IrStmt::Assign {
                    dst: edx,
                    src: IrExpr::Binary(
                        BinaryOp::ShrS,
                        Box::new(eax),
                        Box::new(IrExpr::Const(31)),
                        IrType::Int32,
                    ),
                }]
            }
            "cqo" => {
                let rdx = IrExpr::reg("rdx", IrType::Int64);
                let rax = IrExpr::reg("rax", IrType::Int64);
                vec![IrStmt::Assign {
                    dst: rdx,
                    src: IrExpr::Binary(
                        BinaryOp::ShrS,
                        Box::new(rax),
                        Box::new(IrExpr::Const(63)),
                        IrType::Int64,
                    ),
                }]
            }
            "cwd" => {
                let dx = IrExpr::reg("dx", IrType::Int16);
                let ax = IrExpr::reg("ax", IrType::Int16);
                vec![IrStmt::Assign {
                    dst: dx,
                    src: IrExpr::Binary(
                        BinaryOp::ShrS,
                        Box::new(ax),
                        Box::new(IrExpr::Const(15)),
                        IrType::Int16,
                    ),
                }]
            }
            "cdqe" => {
                let rax = IrExpr::reg("rax", IrType::Int64);
                let eax = IrExpr::reg("eax", IrType::Int32);
                vec![IrStmt::Assign { dst: rax, src: eax }]
            }
            "idiv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                let op_ty = infer_x86_operand_type(parts[0]);
                if op_ty == IrType::Int64 {
                    return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                }
                let divisor = parse_x86_operand(parts[0], next_pc, ctx);
                match op_ty {
                    IrType::Int8 => {
                        let ax = IrExpr::reg("ax", IrType::Int16);
                        let al = IrExpr::reg("al", IrType::Int8);
                        let ah = IrExpr::reg("ah", IrType::Int8);
                        vec![
                            IrStmt::Assign {
                                dst: al,
                                src: IrExpr::Binary(
                                    BinaryOp::DivS,
                                    Box::new(ax.clone()),
                                    Box::new(divisor.clone()),
                                    IrType::Int8,
                                ),
                            },
                            IrStmt::Assign {
                                dst: ah,
                                src: IrExpr::Binary(
                                    BinaryOp::Mod,
                                    Box::new(ax),
                                    Box::new(divisor),
                                    IrType::Int8,
                                ),
                            },
                        ]
                    }
                    IrType::Int16 => {
                        vec![IrStmt::DivRem {
                            quot_dst: IrExpr::reg("ax", IrType::Int16),
                            rem_dst: IrExpr::reg("dx", IrType::Int16),
                            dividend_high: IrExpr::reg("dx", IrType::Int16),
                            dividend_low: IrExpr::reg("ax", IrType::Int16),
                            divisor,
                            is_signed: true,
                            ty: IrType::Int16,
                        }]
                    }
                    IrType::Int32 => {
                        vec![IrStmt::DivRem {
                            quot_dst: IrExpr::reg("eax", IrType::Int32),
                            rem_dst: IrExpr::reg("edx", IrType::Int32),
                            dividend_high: IrExpr::reg("edx", IrType::Int32),
                            dividend_low: IrExpr::reg("eax", IrType::Int32),
                            divisor,
                            is_signed: true,
                            ty: IrType::Int32,
                        }]
                    }
                    _ => {
                        vec![IrStmt::DivRem {
                            quot_dst: IrExpr::reg("rax", IrType::Int64),
                            rem_dst: IrExpr::reg("rdx", IrType::Int64),
                            dividend_high: IrExpr::reg("rdx", IrType::Int64),
                            dividend_low: IrExpr::reg("rax", IrType::Int64),
                            divisor,
                            is_signed: true,
                            ty: IrType::Int64,
                        }]
                    }
                }
            }
            "div" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                let op_ty = infer_x86_operand_type(parts[0]);
                if op_ty == IrType::Int64 {
                    return vec![IrStmt::Asm(format!("{} {}", mnem, ops))];
                }
                let divisor = parse_x86_operand(parts[0], next_pc, ctx);
                match op_ty {
                    IrType::Int8 => {
                        let ax = IrExpr::reg("ax", IrType::Int16);
                        let al = IrExpr::reg("al", IrType::Int8);
                        let ah = IrExpr::reg("ah", IrType::Int8);
                        vec![
                            IrStmt::Assign {
                                dst: al,
                                src: IrExpr::Binary(
                                    BinaryOp::DivU,
                                    Box::new(ax.clone()),
                                    Box::new(divisor.clone()),
                                    IrType::Int8,
                                ),
                            },
                            IrStmt::Assign {
                                dst: ah,
                                src: IrExpr::Binary(
                                    BinaryOp::Mod,
                                    Box::new(ax),
                                    Box::new(divisor),
                                    IrType::Int8,
                                ),
                            },
                        ]
                    }
                    IrType::Int16 => {
                        vec![IrStmt::DivRem {
                            quot_dst: IrExpr::reg("ax", IrType::Int16),
                            rem_dst: IrExpr::reg("dx", IrType::Int16),
                            dividend_high: IrExpr::reg("dx", IrType::Int16),
                            dividend_low: IrExpr::reg("ax", IrType::Int16),
                            divisor,
                            is_signed: false,
                            ty: IrType::Int16,
                        }]
                    }
                    IrType::Int32 => {
                        vec![IrStmt::DivRem {
                            quot_dst: IrExpr::reg("eax", IrType::Int32),
                            rem_dst: IrExpr::reg("edx", IrType::Int32),
                            dividend_high: IrExpr::reg("edx", IrType::Int32),
                            dividend_low: IrExpr::reg("eax", IrType::Int32),
                            divisor,
                            is_signed: false,
                            ty: IrType::Int32,
                        }]
                    }
                    _ => {
                        vec![IrStmt::DivRem {
                            quot_dst: IrExpr::reg("rax", IrType::Int64),
                            rem_dst: IrExpr::reg("rdx", IrType::Int64),
                            dividend_high: IrExpr::reg("rdx", IrType::Int64),
                            dividend_low: IrExpr::reg("rax", IrType::Int64),
                            divisor,
                            is_signed: false,
                            ty: IrType::Int64,
                        }]
                    }
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
                mark_x86_64_arg_written(r.as_str(), &mut self.arg_live);
            }
        }

        stmts
    }
}

// Helpers
fn parse_x86_target(ops: &str, _next_pc: u64) -> Option<u64> {
    let t = ops.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok()
}

fn parse_x86_rip_relative(s: &str, next_pc: u64) -> Option<u64> {
    let t = s
        .trim()
        .trim_start_matches('&')
        .trim_matches(|c| c == '[' || c == ']');
    if let Some(rip_idx) = t.find("rip") {
        let after = t[rip_idx + 3..].trim();
        if let Some(num_str) = after.strip_prefix('+') {
            let num_str = num_str
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            let offset = u64::from_str_radix(num_str, 16).ok()?;
            return Some(next_pc.wrapping_add(offset));
        } else if let Some(num_str) = after.strip_prefix('-') {
            let num_str = num_str
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            let offset = u64::from_str_radix(num_str, 16).ok()?;
            return Some(next_pc.wrapping_sub(offset));
        }
    }
    None
}

fn parse_x86_lea(src_raw: &str, next_pc: u64, ctx: &ElfContext) -> IrExpr {
    if let Some(target) = parse_x86_rip_relative(src_raw, next_pc) {
        if let Some(s) = resolve_rodata_string(ctx, target) {
            return IrExpr::StringLit(s);
        }
        if let Some(sym) = ctx.syms_map.get(&target) {
            let name = sym.demangled.as_deref().unwrap_or(sym.sym.as_str());
            return IrExpr::reg(format!("&{}", name).as_str(), IrType::Int64);
        }
        return IrExpr::Const(target);
    }
    if src_raw.contains('[') && src_raw.contains(']') {
        return parse_x86_mem_ptr(src_raw, next_pc);
    }
    IrExpr::reg(src_raw, IrType::Int64)
}

fn parse_imm_num(s: &str) -> Result<u64, ()> {
    let t = s.trim().trim_start_matches('#');
    if t.starts_with("0x") || t.starts_with("0X") {
        u64::from_str_radix(&t[2..], 16).map_err(|_| ())
    } else {
        t.parse::<u64>().map_err(|_| ())
    }
}

fn parse_x86_mem_ptr(mem_raw: &str, next_pc: u64) -> IrExpr {
    let clean = mem_raw
        .replace("qword ptr ", "")
        .replace("dword ptr ", "")
        .replace("word ptr ", "")
        .replace("byte ptr ", "");
    let t = clean.trim();
    if let Some(target) = parse_x86_rip_relative(t, next_pc) {
        return IrExpr::Const(target);
    }
    if !t.starts_with('[') || !t.ends_with(']') {
        return IrExpr::reg(t, IrType::Int64);
    }
    let inner = &t[1..t.len() - 1].trim();

    // Split into signed terms by scanning '+' and '-'
    let mut terms: Vec<(i64, &str)> = Vec::new();
    let mut current_sign = 1i64;
    let mut start = 0;
    let bytes = inner.as_bytes();
    for i in 0..bytes.len() {
        let c = bytes[i] as char;
        if c == '+' && i > 0 {
            terms.push((current_sign, &inner[start..i]));
            current_sign = 1;
            start = i + 1;
        } else if c == '-' && i > 0 {
            terms.push((current_sign, &inner[start..i]));
            current_sign = -1;
            start = i + 1;
        }
    }
    if start < inner.len() {
        terms.push((current_sign, &inner[start..]));
    }

    let ty = IrType::Int64;
    let mut acc: Option<IrExpr> = None;
    for (sign, raw_term) in terms {
        let term = raw_term.trim();
        if term.is_empty() {
            continue;
        }
        let expr = if term.contains('*') {
            let parts: Vec<&str> = term.split('*').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let reg_name = parts[0];
                let scale = parts[1].parse::<u64>().unwrap_or(1);
                let shift = scale.trailing_zeros() as u64;
                if shift > 0 {
                    IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(IrExpr::reg(reg_name, ty)),
                        Box::new(IrExpr::Const(shift)),
                        ty,
                    )
                } else {
                    IrExpr::reg(reg_name, ty)
                }
            } else {
                IrExpr::reg(term, ty)
            }
        } else if let Ok(c) = parse_imm_num(term) {
            IrExpr::Const(c)
        } else {
            IrExpr::reg(term, ty)
        };

        acc = Some(match acc {
            None => expr,
            Some(prev) => {
                let op = if sign < 0 {
                    BinaryOp::Sub
                } else {
                    BinaryOp::Add
                };
                IrExpr::Binary(op, Box::new(prev), Box::new(expr), ty)
            }
        });
    }

    acc.unwrap_or_else(|| IrExpr::reg(inner, ty))
}

pub fn infer_x86_operand_type(s: &str) -> IrType {
    let t = s.trim().to_lowercase();
    let name = t
        .replace("qword ptr ", "")
        .replace("dword ptr ", "")
        .replace("word ptr ", "")
        .replace("byte ptr ", "");
    let name = name.trim();

    if t.contains("qword ptr")
        || matches!(
            name,
            "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp"
        )
        || (name.starts_with('r') && name[1..].chars().all(|c| c.is_ascii_digit()))
    {
        IrType::Int64
    } else if t.contains("dword ptr")
        || matches!(
            name,
            "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
        )
        || (name.starts_with('r') && name.ends_with('d'))
    {
        IrType::Int32
    } else if t.contains("word ptr")
        || matches!(name, "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp")
        || (name.starts_with('r') && name.ends_with('w'))
    {
        IrType::Int16
    } else if t.contains("byte ptr")
        || matches!(
            name,
            "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh" | "sil" | "dil" | "bpl" | "spl"
        )
        || (name.starts_with('r') && name.ends_with('b'))
    {
        IrType::Int8
    } else {
        IrType::Int32
    }
}

fn parse_x86_operand(s: &str, next_pc: u64, _ctx: &ElfContext) -> IrExpr {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        if let Ok(c) = u64::from_str_radix(&t[2..], 16) {
            return IrExpr::Const(c);
        }
    }
    if let Ok(c) = t.parse::<u64>() {
        return IrExpr::Const(c);
    }
    let ty = infer_x86_operand_type(t);
    if t.contains("rip") {
        if let Some(target) = parse_x86_rip_relative(t, next_pc) {
            return IrExpr::Load {
                ptr: Box::new(IrExpr::Const(target)),
                ty,
            };
        }
    }
    if t.contains('[') && t.ends_with(']') {
        let ptr_expr = parse_x86_mem_ptr(t, next_pc);
        return IrExpr::Load {
            ptr: Box::new(ptr_expr),
            ty,
        };
    }
    IrExpr::reg(t, ty)
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
        let escaped = s.replace('"', "\\\"");
        return Some(format!("\"{}\"", escaped));
    }
    None
}

fn mark_x86_64_arg_written(r: &str, arg_live: &mut ArgLiveness) {
    let r_lower = r.to_lowercase();
    match r_lower.as_str() {
        "rdi" | "edi" => arg_live.written |= 1 << 0,
        "rsi" | "esi" => arg_live.written |= 1 << 1,
        "rdx" | "edx" => arg_live.written |= 1 << 2,
        "rcx" | "ecx" => arg_live.written |= 1 << 3,
        "r8" | "r8d" => arg_live.written |= 1 << 4,
        "r9" | "r9d" => arg_live.written |= 1 << 5,
        _ => {}
    }
}
