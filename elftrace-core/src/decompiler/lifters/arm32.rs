//! ARMv7 / Thumb-2 (32-bit ARM) Instruction Lifter into Architecture-Independent IR.

use crate::decompiler::ir::{BinaryOp, IrExpr, IrStmt, IrType, UnaryOp};
use crate::decompiler::lifters::InstructionLifter;
use crate::elf_parser::ElfContext;

#[derive(Debug, Clone, Copy, Default)]
pub struct ArgLiveness {
    pub written: u8,
}

pub struct Arm32Lifter {
    pub last_cmp: Option<IrExpr>,
    pub arg_live: ArgLiveness,
    pub prologue_done: bool,
}

impl Arm32Lifter {
    pub fn new() -> Self {
        Self {
            last_cmp: None,
            arg_live: ArgLiveness::default(),
            prologue_done: false,
        }
    }
}

impl Default for Arm32Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl InstructionLifter for Arm32Lifter {
    fn reset_state(&mut self) {
        self.last_cmp = None;
        self.arg_live.written = 0;
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
        let mnem_raw = mnemonic.trim();
        // Normalize Thumb-2 wide (.w) and narrow (.n) suffixes
        let mnem_clean = mnem_raw
            .strip_suffix(".w")
            .or_else(|| mnem_raw.strip_suffix(".n"))
            .unwrap_or(mnem_raw);

        // Normalize ARM conditional instruction suffixes inside IT blocks (cmpne -> cmp, moveq -> mov, mlagt -> mla)
        let (mnem, cond_code) = if mnem_clean.len() == 5
            && !mnem_clean.starts_with("movk")
            && !mnem_clean.starts_with("movz")
            && !mnem_clean.starts_with("movt")
        {
            let cond = &mnem_clean[3..];
            match cond {
                "eq" | "ne" | "cs" | "cc" | "mi" | "pl" | "vs" | "vc" | "hi" | "ls" | "ge"
                | "lt" | "gt" | "le" | "hs" | "lo" => (&mnem_clean[..3], Some(cond)),
                _ => (mnem_clean, None),
            }
        } else {
            (mnem_clean, None)
        };

        let ops = op_str.trim();

        if mnem == "it" {
            return Vec::new();
        }

        let is_branch_or_call = mnem.starts_with('b')
            || mnem.starts_with('j')
            || mnem.starts_with("cb")
            || mnem.starts_with("tb")
            || mnem == "call"
            || mnem == "ret"
            || mnem == "leave";

        // 1. Prologue / Epilogue / Frame Filter
        if !self.prologue_done {
            if (mnem == "sub" || mnem == "add") && ops.starts_with("sp, sp") {
                return Vec::new();
            }
            if mnem == "push"
                && (ops.contains("lr")
                    || ops.contains("r7")
                    || ops.contains("r4")
                    || ops.contains("r5")
                    || ops.contains("r6")
                    || ops.contains("r8")
                    || ops.contains("r10")
                    || ops.contains("r11"))
            {
                return Vec::new();
            }
            if mnem == "pop"
                && (ops.contains("pc")
                    || ops.contains("r7")
                    || ops.contains("r4")
                    || ops.contains("r5")
                    || ops.contains("r6")
                    || ops.contains("r8")
                    || ops.contains("r10")
                    || ops.contains("r11"))
            {
                return Vec::new();
            }
            if mnem == "mov" && ops == "r7, sp" {
                return Vec::new();
            }
        }

        if is_branch_or_call {
            self.prologue_done = true;
        }

        let stmts = match mnem {
            // Control Flow
            "bx" if ops == "lr" => {
                vec![IrStmt::Return(None)]
            }
            "b" => {
                if let Some(target) = parse_target_addr(ops) {
                    vec![IrStmt::Branch { cond: None, target }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "bl" | "blx" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                let name = ctx
                    .syms_map
                    .get(&target)
                    .map(|s| s.demangled.as_deref().unwrap_or(s.sym.as_str()).to_string());
                self.last_cmp = None;
                let arg_regs = ["r0", "r1", "r2", "r3"];
                let mut args = Vec::new();
                for (i, &r) in arg_regs.iter().enumerate() {
                    if (self.arg_live.written & (1 << i)) != 0 {
                        args.push(IrExpr::reg(r, IrType::Int32));
                    } else {
                        break;
                    }
                }
                self.arg_live.written = 0;
                vec![IrStmt::Call {
                    target: IrExpr::Const(target),
                    name,
                    args,
                    ret_dst: Some(IrExpr::reg("r0", IrType::Int32)),
                }]
            }

            // Comparisons
            "cmp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let r1 = IrExpr::reg(parts[0], IrType::Int32);
                    let r2 = parse_operand(parts[1], IrType::Int32);
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
                    let r1 = IrExpr::reg(parts[0], IrType::Int32);
                    let r2_val = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                    let r2 = IrExpr::Const((r2_val as u32).wrapping_neg() as u64);
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
                    let r1 = IrExpr::reg(parts[0], IrType::Int32);
                    let r2 = parse_operand(parts[1], IrType::Int32);
                    let band =
                        IrExpr::Binary(BinaryOp::And, Box::new(r1), Box::new(r2), IrType::Int32);
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
            "beq" | "b.eq" => {
                let target = parse_target_addr(ops).unwrap_or(0);
                if let Some(cond) = self.last_cmp.take() {
                    vec![IrStmt::Branch {
                        cond: Some(cond),
                        target,
                    }]
                } else {
                    vec![IrStmt::Asm(format!("{} {}", mnem, ops))]
                }
            }
            "bne" | "b.ne" => {
                let target = parse_target_addr(ops).unwrap_or(0);
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
            "blt" | "b.lt" => {
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
            "blo" | "b.lo" | "bcc" | "b.cc" => {
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
            "ble" | "b.le" => {
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
            "bls" | "b.ls" => {
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
            "bgt" | "b.gt" => {
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
            "bhi" | "b.hi" => {
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
            "bge" | "b.ge" => {
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
            "bhs" | "b.hs" | "bcs" | "b.cs" => {
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
                    let reg = IrExpr::reg(parts[0], IrType::Int32);
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
                    let reg = IrExpr::reg(parts[0], IrType::Int32);
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

            // Register Moves & Arithmetic
            "mov" | "movs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let src = parse_operand(parts[1], IrType::Int32);
                    vec![IrStmt::Assign { dst, src }]
                } else {
                    Vec::new()
                }
            }
            "movt" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let val = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(
                            BinaryOp::Or,
                            Box::new(dst),
                            Box::new(IrExpr::Const((val << 16) & 0xFFFF0000)),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "mvn" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let src = parse_operand(parts[1], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Unary(UnaryOp::Not, Box::new(src), IrType::Int32),
                    }]
                } else {
                    Vec::new()
                }
            }
            "add" | "adds" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    if mnem == "adds" {
                        self.last_cmp = Some(IrExpr::Binary(
                            BinaryOp::Eq,
                            Box::new(lhs.clone()),
                            Box::new(rhs.clone()),
                            IrType::Int8,
                        ));
                    }
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Add,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_operand(parts[1], IrType::Int32);
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
            "sub" | "subs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    if mnem == "subs" {
                        self.last_cmp = Some(IrExpr::Binary(
                            BinaryOp::Eq,
                            Box::new(lhs.clone()),
                            Box::new(rhs.clone()),
                            IrType::Int8,
                        ));
                    }
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Sub,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_operand(parts[1], IrType::Int32);
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
            "mul" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Mul,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[0], IrType::Int32);
                    let rhs = parse_operand(parts[1], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Mul,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "mla" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let r1 = IrExpr::reg(parts[1], IrType::Int32);
                    let r2 = parse_operand(parts[2], IrType::Int32);
                    let r3 = parse_operand(parts[3], IrType::Int32);
                    let mul =
                        IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Add,
                            Box::new(mul),
                            Box::new(r3),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "mls" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let r1 = IrExpr::reg(parts[1], IrType::Int32);
                    let r2 = parse_operand(parts[2], IrType::Int32);
                    let r3 = parse_operand(parts[3], IrType::Int32);
                    let mul =
                        IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Sub,
                            Box::new(r3),
                            Box::new(mul),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "and" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::And,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "orr" | "orrs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Or,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "eor" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Xor,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "pkhbt" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let r1 = IrExpr::reg(parts[1], IrType::Int32);
                    let r2 = IrExpr::reg(parts[2], IrType::Int32);
                    let shift = if parts.len() >= 4 && parts[3].contains("lsl") {
                        parse_imm_num(clean_imm(parts[3].trim_start_matches("lsl").trim()).as_str())
                            .unwrap_or(16)
                    } else {
                        16
                    };
                    let r1_masked = IrExpr::Binary(
                        BinaryOp::And,
                        Box::new(r1),
                        Box::new(IrExpr::Const(0xFFFF)),
                        IrType::Int32,
                    );
                    let r2_shifted = IrExpr::Binary(
                        BinaryOp::Shl,
                        Box::new(r2),
                        Box::new(IrExpr::Const(shift)),
                        IrType::Int32,
                    );
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Or,
                            Box::new(r1_masked),
                            Box::new(r2_shifted),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "lsl" | "lsls" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::Shl,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "lsr" | "lsrs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrU,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            "asr" | "asrs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let dst = IrExpr::reg(parts[0], IrType::Int32);
                    let lhs = IrExpr::reg(parts[1], IrType::Int32);
                    let rhs = parse_operand(parts[2], IrType::Int32);
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(
                            BinaryOp::ShrS,
                            Box::new(lhs),
                            Box::new(rhs),
                            IrType::Int32,
                        ),
                    }]
                } else {
                    Vec::new()
                }
            }
            m if m.starts_with("vadd")
                || m.starts_with("vsub")
                || m.starts_with("vmul")
                || m.starts_with("vdiv") =>
            {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_double = m.contains("f64") || parts[0].starts_with('d');
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let dst = IrExpr::reg(parts[0], ty);
                    let lhs = IrExpr::reg(parts[1], ty);
                    let rhs = IrExpr::reg(parts[2], ty);
                    let op = if m.starts_with("vadd") {
                        BinaryOp::Add
                    } else if m.starts_with("vsub") {
                        BinaryOp::Sub
                    } else if m.starts_with("vmul") {
                        BinaryOp::Mul
                    } else {
                        BinaryOp::DivS
                    };
                    vec![IrStmt::Assign {
                        dst,
                        src: IrExpr::Binary(op, Box::new(lhs), Box::new(rhs), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            m if m.starts_with("vmla") => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_double = m.contains("f64") || parts[0].starts_with('d');
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = IrExpr::reg(parts[2], ty);
                    let mul = IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(BinaryOp::Add, Box::new(dst), Box::new(mul), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            m if m.starts_with("vmls") => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_double = m.contains("f64") || parts[0].starts_with('d');
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let dst = IrExpr::reg(parts[0], ty);
                    let r1 = IrExpr::reg(parts[1], ty);
                    let r2 = IrExpr::reg(parts[2], ty);
                    let mul = IrExpr::Binary(BinaryOp::Mul, Box::new(r1), Box::new(r2), ty);
                    vec![IrStmt::Assign {
                        dst: dst.clone(),
                        src: IrExpr::Binary(BinaryOp::Sub, Box::new(dst), Box::new(mul), ty),
                    }]
                } else {
                    Vec::new()
                }
            }
            m if m.starts_with("vcmp") => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_double = m.contains("f64") || parts[0].starts_with('d');
                    let ty = if is_double {
                        IrType::Float64
                    } else {
                        IrType::Float32
                    };
                    let r1 = IrExpr::reg(parts[0], ty);
                    let r2 = IrExpr::reg(parts[1], ty);
                    self.last_cmp =
                        Some(IrExpr::Binary(BinaryOp::Eq, Box::new(r1), Box::new(r2), ty));
                }
                Vec::new()
            }

            // Memory Loads & Stores
            "ldr" | "ldrb" | "ldrh" => {
                let ty = match mnem {
                    "ldrb" => IrType::Int8,
                    "ldrh" => IrType::Int16,
                    _ => IrType::Int32,
                };

                // Post-indexed: ldr rd, [base], #imm
                if ops.contains("], #") {
                    let parts: Vec<&str> = ops.split("], #").collect();
                    if parts.len() == 2 {
                        let post_imm = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                        let left_parts: Vec<&str> = parts[0].split(", [").collect();
                        if left_parts.len() == 2 {
                            let dst = IrExpr::reg(left_parts[0].trim(), ty);
                            let base = IrExpr::reg(left_parts[1].trim(), IrType::Int32);
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
                                        IrType::Int32,
                                    ),
                                },
                            ];
                        }
                    }
                }

                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let dst = IrExpr::reg(parts[0], ty);
                    let ptr_expr = parse_arm32_mem(parts[1]);
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
            "str" | "strb" | "strh" => {
                let ty = match mnem {
                    "strb" => IrType::Int8,
                    "strh" => IrType::Int16,
                    _ => IrType::Int32,
                };

                // Post-indexed: str rs, [base], #imm
                if ops.contains("], #") {
                    let parts: Vec<&str> = ops.split("], #").collect();
                    if parts.len() == 2 {
                        let post_imm = parse_imm_num(clean_imm(parts[1]).as_str()).unwrap_or(0);
                        let left_parts: Vec<&str> = parts[0].split(", [").collect();
                        if left_parts.len() == 2 {
                            let src = parse_operand(left_parts[0].trim(), ty);
                            let base = IrExpr::reg(left_parts[1].trim(), IrType::Int32);
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
                                        IrType::Int32,
                                    ),
                                },
                            ];
                        }
                    }
                }

                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let src = parse_operand(parts[0], ty);
                    let ptr_expr = parse_arm32_mem(parts[1]);
                    vec![IrStmt::Store {
                        ptr: ptr_expr,
                        val: src,
                        ty,
                    }]
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
                mark_arm32_arg_written(r, &mut self.arg_live);
            }
        }

        if let Some(cond_suffix) = cond_code {
            if !stmts.is_empty() {
                let cond = match (&self.last_cmp, cond_suffix) {
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "gt" | "hi") => {
                        IrExpr::Binary(BinaryOp::GtS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ge" | "cs" | "hs") => {
                        IrExpr::Binary(BinaryOp::GeS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "lt" | "cc" | "lo") => {
                        IrExpr::Binary(BinaryOp::LtS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "le" | "ls") => {
                        IrExpr::Binary(BinaryOp::LeS, l.clone(), r.clone(), *ty)
                    }
                    (Some(IrExpr::Binary(BinaryOp::Eq, l, r, ty)), "ne") => {
                        IrExpr::Binary(BinaryOp::Ne, l.clone(), r.clone(), *ty)
                    }
                    (Some(other), _) => other.clone(),
                    (None, _) => {
                        IrExpr::reg(format!("flag_{}", cond_suffix).as_str(), IrType::Int8)
                    }
                };

                let mut wrapped = Vec::with_capacity(stmts.len());
                for s in stmts {
                    if let IrStmt::Assign { dst, src } = s {
                        wrapped.push(IrStmt::Assign {
                            dst: dst.clone(),
                            src: IrExpr::Ternary {
                                cond: Box::new(cond.clone()),
                                true_val: Box::new(src),
                                false_val: Box::new(dst),
                                ty: IrType::Int32,
                            },
                        });
                    } else {
                        wrapped.push(s);
                    }
                }
                return wrapped;
            }
        }

        stmts
    }
}

// Helpers
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
    if let Ok(c) = parse_imm_num(&t) {
        return IrExpr::Const(c);
    }
    if t.parse::<f64>().is_ok() {
        return IrExpr::StringLit(t);
    }
    IrExpr::reg(&t, ty)
}

fn mark_arm32_arg_written(r: &str, arg_live: &mut ArgLiveness) {
    let r_lower = r.to_lowercase();
    match r_lower.as_str() {
        "r0" => arg_live.written |= 1 << 0,
        "r1" => arg_live.written |= 1 << 1,
        "r2" => arg_live.written |= 1 << 2,
        "r3" => arg_live.written |= 1 << 3,
        _ => {}
    }
}

fn parse_arm32_mem(ops: &str) -> IrExpr {
    let t = ops.trim().trim_end_matches('!');
    if t.starts_with('[') && t.ends_with(']') {
        let inner = &t[1..t.len() - 1];
        let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
        let base_expr = IrExpr::reg(parts[0], IrType::Int32);

        if parts.len() == 1 {
            base_expr
        } else if parts.len() == 3 {
            // [base, index, lsl #shift]
            let idx_reg = parts[1].trim();
            let idx_expr = IrExpr::reg(idx_reg, IrType::Int32);
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
                    IrType::Int32,
                )
            } else {
                idx_expr
            };
            IrExpr::Binary(
                BinaryOp::Add,
                Box::new(base_expr),
                Box::new(scaled_idx),
                IrType::Int32,
            )
        } else if parts.len() == 2 {
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
                    IrType::Int32,
                )
            } else {
                IrExpr::Binary(
                    BinaryOp::Add,
                    Box::new(base_expr),
                    Box::new(IrExpr::Const(mag)),
                    IrType::Int32,
                )
            }
        } else {
            base_expr
        }
    } else {
        IrExpr::reg(ops, IrType::Int32)
    }
}
