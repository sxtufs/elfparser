//! x86 / i386 (32-bit PC) Instruction Lifter into Architecture-Independent IR.

use crate::decompiler::ir::{BinaryOp, IrExpr, IrStmt, IrType, UnaryOp};
use crate::decompiler::lifters::x86_64::infer_x86_operand_type;
use crate::decompiler::lifters::InstructionLifter;
use crate::elf_parser::ElfContext;

pub struct X86_32Lifter {
    pub last_cmp: Option<IrExpr>,
    pub prologue_done: bool,
}

impl X86_32Lifter {
    pub fn new() -> Self {
        Self {
            last_cmp: None,
            prologue_done: false,
        }
    }
}

impl Default for X86_32Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionLifter for X86_32Lifter {
    fn reset_state(&mut self) {
        self.last_cmp = None;
        self.prologue_done = false;
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
                && (ops.contains("ebp")
                    || ops.contains("ebx")
                    || ops.contains("edi")
                    || ops.contains("esi")
                    || ops.contains("eax"))
            {
                return Vec::new();
            }
            if mnem == "pop"
                && (ops.contains("ebp")
                    || ops.contains("ebx")
                    || ops.contains("edi")
                    || ops.contains("esi")
                    || ops.contains("eax"))
            {
                return Vec::new();
            }
            if mnem == "mov" && ops == "ebp, esp" {
                return Vec::new();
            }
            if mnem == "sub" && ops.starts_with("esp,") {
                return Vec::new();
            }
            if mnem == "add" && ops.starts_with("esp,") {
                return Vec::new();
            }
        }

        if is_branch_or_call {
            self.prologue_done = true;
        }

        match mnem {
            // Control Flow
            "ret" | "leave" => {
                vec![IrStmt::Return(None)]
            }
            "ud2" => {
                vec![IrStmt::Trap]
            }
            "jmp" => {
                if let Some(target) = parse_x86_target(ops) {
                    vec![IrStmt::Branch { cond: None, target }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "call" => {
                let target = parse_x86_target(ops).unwrap_or(0);
                let name = ctx
                    .syms_map
                    .get(&target)
                    .map(|s| s.demangled.as_deref().unwrap_or(s.sym.as_str()).to_string());
                self.last_cmp = None;
                vec![IrStmt::Call {
                    target: IrExpr::Const(target),
                    name,
                    args: Vec::new(),
                    ret_dst: Some(IrExpr::reg("eax", IrType::Int32)),
                }]
            }

            // Comparisons
            "cmp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = parse_x86_operand(parts[0]);
                    let r2 = parse_x86_operand(parts[1]);
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
                    let r1 = parse_x86_operand(parts[0]);
                    let r2 = parse_x86_operand(parts[1]);
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
                            IrType::Int32,
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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
                let target = parse_x86_target(ops).unwrap_or(0);
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

            // LEA (Load Effective Address - ebx GOT offsets)
            "lea" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let src = if parts[1].contains('[') && parts[1].contains(']') {
                        parse_x86_mem_ptr(parts[1])
                    } else {
                        IrExpr::reg(parts[1], IrType::Int32)
                    };
                    vec![IrStmt::Assign { dst, src }]
                } else {
                    Vec::new()
                }
            }

            // Conditional Move (CMOVcc)
            m if m.starts_with("cmov") => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let src = parse_x86_operand(parts[1]);
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
                            ty: IrType::Int32,
                        },
                    }]
                } else {
                    Vec::new()
                }
            }
            m if m.starts_with("set") => {
                let dst = parse_x86_operand(ops);
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
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    if parts[0] == parts[1] {
                        vec![IrStmt::Assign {
                            dst,
                            src: IrExpr::Const(0),
                        }]
                    } else {
                        let rhs = parse_x86_operand(parts[1]);
                        vec![IrStmt::Assign {
                            dst: dst.clone(),
                            src: IrExpr::Binary(
                                BinaryOp::Xor,
                                Box::new(dst),
                                Box::new(rhs),
                                IrType::Int32,
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
                        let ptr = parse_x86_mem_ptr(dst_raw);
                        let val = parse_x86_operand(src_raw);
                        vec![IrStmt::Store {
                            ptr,
                            val,
                            ty: op_ty,
                        }]
                    } else if src_raw.contains('[') {
                        let dst = IrExpr::reg(dst_raw, op_ty);
                        let ptr = parse_x86_mem_ptr(src_raw);
                        vec![IrStmt::Assign {
                            dst,
                            src: IrExpr::Load {
                                ptr: Box::new(ptr),
                                ty: op_ty,
                            },
                        }]
                    } else {
                        let dst = IrExpr::reg(dst_raw, dst_ty);
                        let src = parse_x86_operand(src_raw);
                        vec![IrStmt::Assign { dst, src }]
                    }
                } else {
                    Vec::new()
                }
            }
            "add" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_x86_operand(parts[1]);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Add,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sub" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_x86_operand(parts[1]);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Sub,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
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
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_x86_operand(parts[1]);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Mul,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let r1 = parse_x86_operand(parts[1]);
                    let r2 = parse_x86_operand(parts[2]);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Mul,
                            Box::new(r1),
                            Box::new(r2),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "shr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_x86_operand(parts[1]);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::ShrU,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "sar" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_x86_operand(parts[1]);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(dst),
                            Box::new(rhs),
                            IrType::Int32,
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
                    let src = parse_x86_operand(parts[1]);
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
                    let src = parse_x86_operand(parts[1]);
                    let src_ty = infer_x86_operand_type(parts[1]);
                    let shift = match src_ty {
                        IrType::Int8 => 24,
                        IrType::Int16 => 16,
                        _ => 0,
                    };
                    if shift > 0 {
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
                        vec![IrStmt::Assign { dst, src }]
                    }
                } else {
                    Vec::new()
                }
            }
            "movsxd" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst_ty = infer_x86_operand_type(parts[0]);
                    let dst = IrExpr::reg(parts[0], dst_ty);
                    let src = parse_x86_operand(parts[1]);
                    vec![IrStmt::Assign { dst, src }]
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
            "idiv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                let divisor = parse_x86_operand(parts[0]);
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
            "div" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                let divisor = parse_x86_operand(parts[0]);
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

            "nop" => Vec::new(),
            _ => vec![IrStmt::Asm(format!("{} {}", mnem, ops))],
        }
    }
}

// Helpers
fn parse_x86_target(ops: &str) -> Option<u64> {
    let t = ops.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).ok()
}

fn parse_imm_num(s: &str) -> Result<u64, ()> {
    let t = s.trim().trim_start_matches('#');
    if t.starts_with("0x") || t.starts_with("0X") {
        u64::from_str_radix(&t[2..], 16).map_err(|_| ())
    } else {
        t.parse::<u64>().map_err(|_| ())
    }
}

fn parse_x86_mem_ptr(mem_raw: &str) -> IrExpr {
    let clean = mem_raw
        .replace("qword ptr ", "")
        .replace("dword ptr ", "")
        .replace("word ptr ", "")
        .replace("byte ptr ", "");
    let t = clean.trim();
    if !t.starts_with('[') || !t.ends_with(']') {
        return IrExpr::reg(t, IrType::Int32);
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

    let ty = IrType::Int32;
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

fn parse_x86_operand(s: &str) -> IrExpr {
    let t_clean = s
        .trim()
        .replace("dword ptr ", "")
        .replace("word ptr ", "")
        .replace("byte ptr ", "");
    let t = t_clean.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        if let Ok(c) = u64::from_str_radix(&t[2..], 16) {
            return IrExpr::Const(c);
        }
    }
    if let Ok(c) = t.parse::<u64>() {
        return IrExpr::Const(c);
    }
    let ty = infer_x86_operand_type(t);
    if t.contains('[') && t.ends_with(']') {
        let ptr_expr = parse_x86_mem_ptr(t);
        return IrExpr::Load {
            ptr: Box::new(ptr_expr),
            ty,
        };
    }
    IrExpr::reg(t, ty)
}
