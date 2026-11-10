//! Virtual CPU Execution Tracer for ARM64 (AArch64).
//!
//! Provides single-step forward, backward history replay, flag tracking,
//! memory emulation, and register diffing for native disassembly debugging.

use crate::disasm::disassemble;
use crate::elf_parser::ElfContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterState {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
    pub mnemonic: String,
    pub op_str: String,
    pub current_insn: String,
    pub changed_regs: Vec<String>,
    pub changed_flags: Vec<String>,
}

pub struct VirtualCpu {
    pub state: RegisterState,
    pub history: Vec<RegisterState>,
    pub memory: HashMap<u64, u8>,
}

impl VirtualCpu {
    pub fn new(entry_pc: u64) -> Self {
        Self {
            state: RegisterState {
                x: [0; 31],
                sp: 0x7FFF_FFFF_0000,
                pc: entry_pc,
                n: false,
                z: false,
                c: false,
                v: false,
                mnemonic: String::new(),
                op_str: String::new(),
                current_insn: "Initial State".to_string(),
                changed_regs: Vec::new(),
                changed_flags: Vec::new(),
            },
            history: Vec::new(),
            memory: HashMap::new(),
        }
    }

    pub fn step(&mut self, ctx: &ElfContext) -> Result<RegisterState, String> {
        let pc = self.state.pc;
        let offset = match ctx.vaddr_to_offset(pc) {
            Some(off) => off as usize,
            None => return Err(format!("PC 0x{:08x} outside mapped ELF sections", pc)),
        };

        if offset >= ctx.raw.len() {
            return Err("Execution reached end of binary".to_string());
        }

        let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
        let slice = &ctx.raw[offset..std::cmp::min(ctx.raw.len(), offset + 4)];

        let insns = disassemble(slice, pc, 4, e_machine, false)
            .map_err(|e| format!("Disassembly error at 0x{:08x}: {}", pc, e))?;

        let ins = match insns.data.first() {
            Some(i) => i,
            None => return Err(format!("Could not decode instruction at 0x{:08x}", pc)),
        };

        // Save state to history for backward stepping (capped at 500 steps)
        if self.history.len() >= 500 {
            self.history.remove(0);
        }
        self.history.push(self.state.clone());
        let prev_state = self.state.clone();
        self.state.changed_regs.clear();

        self.state.mnemonic = ins.mnemonic.clone();
        self.state.op_str = ins.op_str.clone();
        self.state.current_insn = format!("{:<7} {}", ins.mnemonic, ins.op_str);

        let next_pc = pc + ins.bytes.len() as u64;
        self.execute_insn(ctx, pc, &ins.mnemonic, &ins.op_str, next_pc)?;

        // Detect changed registers for UI highlighting
        for i in 0..31 {
            if self.state.x[i] != prev_state.x[i] {
                self.state.changed_regs.push(format!("x{}", i));
            }
        }
        if self.state.sp != prev_state.sp {
            self.state.changed_regs.push("sp".to_string());
        }

        // Detect changed flags for UI illumination
        self.state.changed_flags.clear();
        if self.state.z != prev_state.z {
            self.state.changed_flags.push("z".to_string());
        }
        if self.state.n != prev_state.n {
            self.state.changed_flags.push("n".to_string());
        }
        if self.state.c != prev_state.c {
            self.state.changed_flags.push("c".to_string());
        }
        if self.state.v != prev_state.v {
            self.state.changed_flags.push("v".to_string());
        }

        Ok(self.state.clone())
    }

    /// Execute one instruction by mnemonic string.  is the address of this instruction,
    ///  is where execution continues if the instruction does not branch.
    /// Used by  after decoding, and by unit tests to verify semantics directly.
    pub fn execute_insn(
        &mut self,
        ctx: &ElfContext,
        pc: u64,
        mnem: &str,
        ops: &str,
        next_pc: u64,
    ) -> Result<(), String> {
        let mut target_pc = next_pc;

        match mnem {
            "mov" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let val = self.eval_operand(parts[1]);
                    self.set_reg(parts[0], val);
                }
            }
            "movk" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let val = self.eval_operand(parts[1]);
                    let shift = if parts.len() == 3 && parts[2].contains("lsl #16") {
                        16
                    } else if parts.len() == 3 && parts[2].contains("lsl #32") {
                        32
                    } else if parts.len() == 3 && parts[2].contains("lsl #48") {
                        48
                    } else {
                        0
                    };
                    let current = self.get_reg(parts[0]);
                    let mask = !(0xffffu64 << shift);
                    self.set_reg(parts[0], (current & mask) | (val << shift));
                }
            }
            "movz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let val = self.eval_operand(parts[1]);
                    let shift = if parts.len() == 3 && parts[2].contains("lsl #") {
                        let shift_str = parts[2].split("lsl #").nth(1).unwrap_or("0");
                        self.parse_imm(shift_str).unwrap_or(0)
                    } else {
                        0
                    };
                    self.set_reg(parts[0], val << shift);
                }
            }
            "movn" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 2 {
                    let val = self.eval_operand(parts[1]);
                    let shift = if parts.len() == 3 && parts[2].contains("lsl #") {
                        let shift_str = parts[2].split("lsl #").nth(1).unwrap_or("0");
                        self.parse_imm(shift_str).unwrap_or(0)
                    } else {
                        0
                    };
                    let shifted = val << shift;
                    if parts[0].starts_with('w') {
                        self.set_reg(parts[0], (!shifted) & 0xFFFF_FFFF);
                    } else {
                        self.set_reg(parts[0], !shifted);
                    }
                }
            }
            "add" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1.wrapping_add(v2));
                } else if parts.len() == 4 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_shifted_operand(parts[2], Some(parts[3]));
                    self.set_reg(parts[0], v1.wrapping_add(v2));
                }
            }
            "sub" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1.wrapping_sub(v2));
                } else if parts.len() == 4 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_shifted_operand(parts[2], Some(parts[3]));
                    self.set_reg(parts[0], v1.wrapping_sub(v2));
                }
            }
            "neg" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]);
                    self.set_reg(parts[0], 0u64.wrapping_sub(v));
                }
            }
            "mvn" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]);
                    self.set_reg(parts[0], !v);
                }
            }
            "mul" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1.wrapping_mul(v2));
                }
            }
            "madd" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    let v3 = self.eval_operand(parts[3]);
                    self.set_reg(parts[0], v1.wrapping_mul(v2).wrapping_add(v3));
                }
            }
            "msub" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    let v3 = self.eval_operand(parts[3]);
                    self.set_reg(parts[0], v3.wrapping_sub(v1.wrapping_mul(v2)));
                }
            }
            "sdiv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    if is_w {
                        let n = v1 as u32 as i32;
                        let d = v2 as u32 as i32;
                        let res = if d == 0 {
                            0
                        } else if n == i32::MIN && d == -1 {
                            n as u32 as u64
                        } else {
                            (n / d) as u32 as u64
                        };
                        self.set_reg(parts[0], res);
                    } else {
                        let n = v1 as i64;
                        let d = v2 as i64;
                        let res = if d == 0 {
                            0
                        } else if n == i64::MIN && d == -1 {
                            n as u64
                        } else {
                            (n / d) as u64
                        };
                        self.set_reg(parts[0], res);
                    }
                }
            }
            "udiv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    if is_w {
                        let n = v1 as u32;
                        let d = v2 as u32;
                        let res = n.checked_div(d).map(|r| r as u64).unwrap_or(0);
                        self.set_reg(parts[0], res);
                    } else {
                        let res = v1.checked_div(v2).unwrap_or(0);
                        self.set_reg(parts[0], res);
                    }
                }
            }
            "and" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1 & v2);
                }
            }
            "orr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1 | v2);
                }
            }
            "eor" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1 ^ v2);
                }
            }
            "bic" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let v1 = self.eval_operand(parts[1]);
                    let v2 = self.eval_operand(parts[2]);
                    self.set_reg(parts[0], v1 & (!v2));
                }
            }
            "lsl" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v1 = self.eval_operand(parts[1]);
                    let shift = self.eval_operand(parts[2]) & (if is_w { 31 } else { 63 });
                    self.set_reg(parts[0], v1 << shift);
                }
            }
            "lsr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v1 = self.eval_operand(parts[1]);
                    let shift = self.eval_operand(parts[2]) & (if is_w { 31 } else { 63 });
                    let res = if is_w {
                        ((v1 as u32) >> shift) as u64
                    } else {
                        v1 >> shift
                    };
                    self.set_reg(parts[0], res);
                }
            }
            "asr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v1 = self.eval_operand(parts[1]);
                    let shift = self.eval_operand(parts[2]) & (if is_w { 31 } else { 63 });
                    let res = if is_w {
                        ((v1 as u32 as i32) >> shift) as u64
                    } else {
                        ((v1 as i64) >> shift) as u64
                    };
                    self.set_reg(parts[0], res);
                }
            }
            "ror" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v1 = self.eval_operand(parts[1]);
                    let shift = self.eval_operand(parts[2]);
                    let res = if is_w {
                        (v1 as u32).rotate_right((shift & 31) as u32) as u64
                    } else {
                        v1.rotate_right((shift & 63) as u32)
                    };
                    self.set_reg(parts[0], res);
                }
            }
            "adr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    if let Some(target) = self.parse_addr(parts[1]) {
                        self.set_reg(parts[0], target);
                    } else {
                        return Err(format!("Bad adr: {} {}", mnem, ops));
                    }
                }
            }
            "adrp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    if let Some(target) = self.parse_addr(parts[1]) {
                        self.set_reg(parts[0], target & !0xFFF);
                    } else {
                        return Err(format!("Bad adrp: {} {}", mnem, ops));
                    }
                }
            }
            "ldr" | "ldur" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let width = if is_w { 4 } else { 8 };
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, width)?;
                    self.set_reg(parts[0], val);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "ldrb" | "ldurb" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, 1)?;
                    self.set_reg(parts[0], val & 0xFF);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "ldrh" | "ldurh" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, 2)?;
                    self.set_reg(parts[0], val & 0xFFFF);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "ldrsb" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, 1)?;
                    let s_ext = (val as u8 as i8) as i64 as u64;
                    self.set_reg(parts[0], s_ext);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "ldrsh" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, 2)?;
                    let s_ext = (val as u16 as i16) as i64 as u64;
                    self.set_reg(parts[0], s_ext);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "ldrsw" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, 4)?;
                    let s_ext = (val as u32 as i32) as i64 as u64;
                    self.set_reg(parts[0], s_ext);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "str" | "stur" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let width = if is_w { 4 } else { 8 };
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.get_reg(parts[0]);
                    self.write_mem(addr, val, width);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "strb" | "sturb" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.get_reg(parts[0]);
                    self.write_mem(addr, val & 0xFF, 1);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "strh" | "sturh" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let (addr, wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.get_reg(parts[0]);
                    self.write_mem(addr, val & 0xFFFF, 2);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "ldp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    let is_w = parts[0].starts_with('w');
                    let width = if is_w { 4 } else { 8 };
                    let step = width as u64;
                    let mem_raw = parts[2..].join(",");
                    let (addr, wb) = self
                        .eval_mem_address(&mem_raw)
                        .ok_or_else(|| format!("Invalid memory operand: {}", mem_raw))?;
                    let val1 = self.read_mem(ctx, addr, width)?;
                    let val2 = self.read_mem(ctx, addr + step, width)?;
                    self.set_reg(parts[0], val1);
                    self.set_reg(parts[1], val2);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "stp" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 3 {
                    let is_w = parts[0].starts_with('w');
                    let width = if is_w { 4 } else { 8 };
                    let step = width as u64;
                    let mem_raw = parts[2..].join(",");
                    let (addr, wb) = self
                        .eval_mem_address(&mem_raw)
                        .ok_or_else(|| format!("Invalid memory operand: {}", mem_raw))?;
                    let val1 = self.get_reg(parts[0]);
                    let val2 = self.get_reg(parts[1]);
                    self.write_mem(addr, val1, width);
                    self.write_mem(addr + step, val2, width);
                    if let Some((wb_reg, wb_val)) = wb {
                        self.set_reg(&wb_reg, wb_val);
                    }
                }
            }
            "cmp" | "subs" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 || parts.len() == 3 {
                    let (dst, s1, s2) = if parts.len() == 3 {
                        (Some(parts[0]), parts[1], parts[2])
                    } else {
                        (None, parts[0], parts[1])
                    };
                    let is_64 = s1.to_lowercase().starts_with('x');
                    let mask = if is_64 {
                        0xFFFF_FFFF_FFFF_FFFF
                    } else {
                        0xFFFF_FFFF
                    };
                    let sign_bit = if is_64 { 1u64 << 63 } else { 1u64 << 31 };

                    let v1 = self.eval_operand(s1) & mask;
                    let v2 = self.eval_operand(s2) & mask;
                    let res = v1.wrapping_sub(v2) & mask;

                    self.state.z = res == 0;
                    self.state.n = (res & sign_bit) != 0;
                    self.state.c = v1 >= v2;
                    let v1_s = (v1 & sign_bit) != 0;
                    let v2_s = (v2 & sign_bit) != 0;
                    let r_s = (res & sign_bit) != 0;
                    self.state.v = (v1_s != v2_s) && (v1_s != r_s);

                    if let Some(d) = dst {
                        self.set_reg(d, res);
                    }
                }
            }
            "cmn" | "adds" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 || parts.len() == 3 {
                    let (dst, s1, s2) = if parts.len() == 3 {
                        (Some(parts[0]), parts[1], parts[2])
                    } else {
                        (None, parts[0], parts[1])
                    };
                    let is_64 = s1.to_lowercase().starts_with('x');
                    let mask = if is_64 {
                        0xFFFF_FFFF_FFFF_FFFF
                    } else {
                        0xFFFF_FFFF
                    };
                    let sign_bit = if is_64 { 1u64 << 63 } else { 1u64 << 31 };

                    let v1 = self.eval_operand(s1) & mask;
                    let v2 = self.eval_operand(s2) & mask;
                    let res = v1.wrapping_add(v2) & mask;

                    self.state.z = res == 0;
                    self.state.n = (res & sign_bit) != 0;
                    self.state.c = res < v1;
                    let v1_s = (v1 & sign_bit) != 0;
                    let v2_s = (v2 & sign_bit) != 0;
                    let r_s = (res & sign_bit) != 0;
                    self.state.v = (v1_s == v2_s) && (v1_s != r_s);

                    if let Some(d) = dst {
                        self.set_reg(d, res);
                    }
                }
            }
            "tst" | "ands" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 || parts.len() == 3 {
                    let (dst, s1, s2) = if parts.len() == 3 {
                        (Some(parts[0]), parts[1], parts[2])
                    } else {
                        (None, parts[0], parts[1])
                    };
                    let is_64 = s1.to_lowercase().starts_with('x');
                    let mask = if is_64 {
                        0xFFFF_FFFF_FFFF_FFFF
                    } else {
                        0xFFFF_FFFF
                    };
                    let sign_bit = if is_64 { 1u64 << 63 } else { 1u64 << 31 };

                    let v1 = self.eval_operand(s1) & mask;
                    let v2 = self.eval_operand(s2) & mask;
                    let res = (v1 & v2) & mask;

                    self.state.z = res == 0;
                    self.state.n = (res & sign_bit) != 0;
                    self.state.c = false;
                    self.state.v = false;

                    if let Some(d) = dst {
                        self.set_reg(d, res);
                    }
                }
            }
            "cset" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let cond_met = self.eval_cond(parts[1])?;
                    self.set_reg(parts[0], if cond_met { 1 } else { 0 });
                }
            }
            "csel" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let cond_met = self.eval_cond(parts[3])?;
                    let val = if cond_met {
                        self.get_reg(parts[1])
                    } else {
                        self.get_reg(parts[2])
                    };
                    self.set_reg(parts[0], val);
                }
            }
            "cinc" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let cond_met = self.eval_cond(parts[2])?;
                    let s_val = self.get_reg(parts[1]);
                    let val = if cond_met {
                        s_val.wrapping_add(1)
                    } else {
                        s_val
                    };
                    self.set_reg(parts[0], val);
                }
            }
            "csinc" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let cond_met = self.eval_cond(parts[3])?;
                    let val = if cond_met {
                        self.get_reg(parts[1])
                    } else {
                        self.get_reg(parts[2]).wrapping_add(1)
                    };
                    self.set_reg(parts[0], val);
                }
            }
            "csinv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let cond_met = self.eval_cond(parts[3])?;
                    let val = if cond_met {
                        self.get_reg(parts[1])
                    } else {
                        !self.get_reg(parts[2])
                    };
                    self.set_reg(parts[0], val);
                }
            }
            "csneg" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let cond_met = self.eval_cond(parts[3])?;
                    let val = if cond_met {
                        self.get_reg(parts[1])
                    } else {
                        0u64.wrapping_sub(self.get_reg(parts[2]))
                    };
                    self.set_reg(parts[0], val);
                }
            }
            "csetm" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let cond_met = self.eval_cond(parts[1])?;
                    let all_ones = if parts[0].starts_with('w') {
                        0xFFFF_FFFF
                    } else {
                        0xFFFF_FFFF_FFFF_FFFF
                    };
                    self.set_reg(parts[0], if cond_met { all_ones } else { 0 });
                }
            }
            "b" => {
                if let Some(target) = self.parse_addr(ops) {
                    target_pc = target;
                }
            }
            "b.eq" | "beq" => {
                if self.state.z {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.ne" | "bne" => {
                if !self.state.z {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.lt" | "blt" => {
                if self.state.n != self.state.v {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.le" | "ble" => {
                if self.state.z || (self.state.n != self.state.v) {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.gt" | "bgt" => {
                if !self.state.z && (self.state.n == self.state.v) {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.ge" | "bge" => {
                if self.state.n == self.state.v {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.cs" | "b.hs" => {
                if self.state.c {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.cc" | "b.lo" => {
                if !self.state.c {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.mi" => {
                if self.state.n {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.pl" => {
                if !self.state.n {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "cbz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let val = self.eval_operand(parts[0]);
                    if val == 0 {
                        if let Some(target) = self.parse_addr(parts[1]) {
                            target_pc = target;
                        }
                    }
                }
            }
            "cbnz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let val = self.eval_operand(parts[0]);
                    if val != 0 {
                        if let Some(target) = self.parse_addr(parts[1]) {
                            target_pc = target;
                        }
                    }
                }
            }
            "ret" => {
                target_pc = self.state.x[30];
                self.state.current_insn = "ret (Function complete)".to_string();
            }
            "nop" => {}
            "sxtb" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]) as u8 as i8 as i64 as u64;
                    self.set_reg(parts[0], v);
                }
            }
            "sxth" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]) as u16 as i16 as i64 as u64;
                    self.set_reg(parts[0], v);
                }
            }
            "sxtw" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]) as u32 as i32 as i64 as u64;
                    self.set_reg(parts[0], v);
                }
            }
            "uxtb" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]) & 0xFF;
                    self.set_reg(parts[0], v);
                }
            }
            "uxth" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]) & 0xFFFF;
                    self.set_reg(parts[0], v);
                }
            }
            "uxtw" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let v = self.eval_operand(parts[1]) & 0xFFFF_FFFF;
                    self.set_reg(parts[0], v);
                }
            }
            "rev" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let v = self.eval_operand(parts[1]);
                    let res = if is_w {
                        (v as u32).swap_bytes() as u64
                    } else {
                        v.swap_bytes()
                    };
                    self.set_reg(parts[0], res);
                }
            }
            "bl" => {
                self.set_reg("x30", next_pc);
                if let Some(target) = self.parse_addr(ops) {
                    target_pc = target;
                }
            }
            "blr" => {
                self.set_reg("x30", next_pc);
                target_pc = self.get_reg(ops);
            }
            "br" => {
                target_pc = self.get_reg(ops);
            }
            "b.vs" | "bvs" => {
                if self.state.v {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.vc" | "bvc" => {
                if !self.state.v {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.hi" | "bhi" => {
                if self.state.c && !self.state.z {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "b.ls" | "bls" => {
                if !self.state.c || self.state.z {
                    if let Some(target) = self.parse_addr(ops) {
                        target_pc = target;
                    }
                }
            }
            "svc" => {
                // Syscall boundary: the kernel is not emulated, so we skip past the
                // instruction and annotate it.  x0 keeps its pre-call value as a
                // best-effort return; callers can inspect current_insn for context.
                let nr = self.state.x[8];
                self.state.current_insn = format!(
                    "svc #{} (syscall nr={}) [skipped]",
                    ops.trim_start_matches('#'),
                    nr
                );
            }
            "tbz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let val = self.eval_operand(parts[0]);
                    let bit = self.parse_imm(parts[1]).unwrap_or(64);
                    if bit < 64 && ((val >> bit) & 1) == 0 {
                        if let Some(target) = self.parse_addr(parts[2]) {
                            target_pc = target;
                        }
                    }
                }
            }
            "tbnz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let val = self.eval_operand(parts[0]);
                    let bit = self.parse_imm(parts[1]).unwrap_or(64);
                    if bit < 64 && ((val >> bit) & 1) != 0 {
                        if let Some(target) = self.parse_addr(parts[2]) {
                            target_pc = target;
                        }
                    }
                }
            }
            "mrs" => {
                // System register read (e.g. NZCV, TPIDR_EL0, CNTVCT_EL0).
                // We only model NZCV accurately; everything else reads as 0.
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let sys = parts[1].to_lowercase();
                    let val = if sys == "nzcv" {
                        ((self.state.n as u64) << 31)
                            | ((self.state.z as u64) << 30)
                            | ((self.state.c as u64) << 29)
                            | ((self.state.v as u64) << 28)
                    } else {
                        0
                    };
                    self.set_reg(parts[0], val);
                }
            }
            "msr" => {
                // System register write. Only NZCV is modelled; others are ignored.
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 && parts[0].trim().to_lowercase() == "nzcv" {
                    let val = self.eval_operand(parts[1]);
                    self.state.n = (val & (1 << 31)) != 0;
                    self.state.z = (val & (1 << 30)) != 0;
                    self.state.c = (val & (1 << 29)) != 0;
                    self.state.v = (val & (1 << 28)) != 0;
                }
            }
            "pacibsp" | "paciasp" | "autibsp" | "autiasp" | "bti" | "hint"
            | "paciza" | "autiza" => {
                // Pointer-authentication / branch-target / hint instructions: no-op
                // for emulation purposes (we don't track signing keys).
            }
            // ---- Bitfield insert / extract ----
            "sbfiz" | "ubfiz" | "sbfx" | "ubfx" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let src = self.eval_operand(parts[1]);
                    let a = self.parse_imm(parts[2]).unwrap_or(0);
                    let w = self.parse_imm(parts[3]).unwrap_or(0);
                    let maskw = |n: u64| -> u64 {
                        if n >= 64 { u64::MAX } else if n == 0 { 0 } else { (1u64 << n) - 1 }
                    };
                    if w > 0 && w <= 64 && a < 64 {
                        let (val, sbit) = match mnem {
                            "sbfiz" => { let f = (src & maskw(w)) << a; (f, Some(a + w - 1)) }
                            "ubfiz" => ((src & maskw(w)) << a, None),
                            "sbfx"  => { let f = (src >> a) & maskw(w); (f, Some(w - 1)) }
                            _       => ((src >> a) & maskw(w), None), // ubfx
                        };
                        let out = match sbit {
                            Some(sb) if sb < 63 && ((val >> sb) & 1) == 1 => val | !maskw(sb + 1),
                            _ => val,
                        };
                        self.set_reg(parts[0], out);
                    }
                }
            }
            "extr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let is_w = parts[0].starts_with('w');
                    let lo = self.eval_operand(parts[1]);
                    let hi = self.eval_operand(parts[2]);
                    let sh = self.parse_imm(parts[3]).unwrap_or(0);
                    let res = if is_w {
                        let sh = (sh & 31) as u32;
                        let lo = lo as u32;
                        let hi = hi as u32;
                        if sh == 0 { lo as u64 } else { (((hi << (32 - sh)) | (lo >> sh)) as u64) }
                    } else {
                        let sh = (sh & 63) as u32;
                        if sh == 0 { lo } else { (hi << (64 - sh)) | (lo >> sh) }
                    };
                    self.set_reg(parts[0], res);
                }
            }
            // ---- Bit manipulation ----
            "clz" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let v = self.eval_operand(parts[1]);
                    let res = if is_w { (v as u32).leading_zeros() as u64 } else { v.leading_zeros() as u64 };
                    self.set_reg(parts[0], res);
                }
            }
            "rbit" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let v = self.eval_operand(parts[1]);
                    let res = if is_w { (v as u32).reverse_bits() as u64 } else { v.reverse_bits() };
                    self.set_reg(parts[0], res);
                }
            }
            "rev16" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let v = self.eval_operand(parts[1]);
                    let res = if is_w {
                        let x = v as u32;
                        (((x & 0x00FF_00FF) << 8) | ((x & 0xFF00_FF00) >> 8)) as u64
                    } else {
                        ((v & 0x00FF_00FF_00FF_00FF) << 8) | ((v & 0xFF00_FF00_FF00_FF00) >> 8)
                    };
                    self.set_reg(parts[0], res);
                }
            }
            "rev32" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let is_w = parts[0].starts_with('w');
                    let v = self.eval_operand(parts[1]);
                    let res = if is_w {
                        (v as u32).swap_bytes() as u64
                    } else {
                        let lo = (v as u32).swap_bytes() as u64;
                        let hi = ((v >> 32) as u32).swap_bytes() as u64;
                        lo | (hi << 32)
                    };
                    self.set_reg(parts[0], res);
                }
            }
            // ---- Variable shifts (register amount) ----
            "lslv" | "lsrv" | "asrv" | "rorv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let is_w = parts[0].starts_with('w');
                    let v = self.eval_operand(parts[1]);
                    let amt = self.eval_operand(parts[2]);
                    let res = if is_w {
                        let v = v as u32;
                        let sh = (amt & 31) as u32;
                        match mnem {
                            "lslv" => v.wrapping_shl(sh) as u64,
                            "lsrv" => v.wrapping_shr(sh) as u64,
                            "asrv" => ((v as i32).wrapping_shr(sh)) as u32 as u64,
                            _      => v.rotate_right(sh) as u64,
                        }
                    } else {
                        let sh = (amt & 63) as u32;
                        match mnem {
                            "lslv" => v.wrapping_shl(sh),
                            "lsrv" => v.wrapping_shr(sh),
                            "asrv" => ((v as i64).wrapping_shr(sh)) as u64,
                            _      => v.rotate_right(sh),
                        }
                    };
                    self.set_reg(parts[0], res);
                }
            }
            // ---- Conditional invert / negate ----
            "cinv" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let cond_met = self.eval_cond(parts[2])?;
                    let v = self.get_reg(parts[1]);
                    self.set_reg(parts[0], if cond_met { v } else { !v });
                }
            }
            "cneg" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let cond_met = self.eval_cond(parts[2])?;
                    let v = self.get_reg(parts[1]);
                    self.set_reg(parts[0], if cond_met { v } else { 0u64.wrapping_sub(v) });
                }
            }
            // ---- Conditional compare (sets flags) ----
            "ccmp" | "ccmn" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let cond = self.eval_cond(parts[3])?;
                    if cond {
                        let a = self.eval_operand(parts[0]);
                        let b = self.eval_operand(parts[1]);
                        let (res, carry) = if mnem == "ccmn" {
                            (a.wrapping_add(b), a.checked_add(b).is_none() || a > u64::MAX - b)
                        } else {
                            (a.wrapping_sub(b), a >= b)
                        };
                        self.state.z = res == 0;
                        self.state.n = (res & (1u64 << 63)) != 0;
                        self.state.c = carry;
                        let as_ = (a & (1u64 << 63)) != 0;
                        let bs = (b & (1u64 << 63)) != 0;
                        let rs = (res & (1u64 << 63)) != 0;
                        self.state.v = if mnem == "ccmn" { (as_ == bs) && (as_ != rs) } else { (as_ != bs) && (as_ != rs) };
                    } else {
                        let nzcv = self.parse_imm(parts[2]).unwrap_or(0);
                        self.state.n = (nzcv & 0b1000) != 0;
                        self.state.z = (nzcv & 0b0100) != 0;
                        self.state.c = (nzcv & 0b0010) != 0;
                        self.state.v = (nzcv & 0b0001) != 0;
                    }
                }
            }
            // ---- 32x32 -> 64 multiplies ----
            "smull" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let a = self.eval_operand(parts[1]) as u32 as i32 as i64;
                    let b = self.eval_operand(parts[2]) as u32 as i32 as i64;
                    self.set_reg(parts[0], a.wrapping_mul(b) as u64);
                }
            }
            "umull" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let a = self.eval_operand(parts[1]) as u32 as u64;
                    let b = self.eval_operand(parts[2]) as u32 as u64;
                    self.set_reg(parts[0], a.wrapping_mul(b));
                }
            }
            "smaddl" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let a = self.eval_operand(parts[1]) as u32 as i32 as i64;
                    let b = self.eval_operand(parts[2]) as u32 as i32 as i64;
                    let acc = self.eval_operand(parts[3]);
                    self.set_reg(parts[0], (a.wrapping_mul(b) as u64).wrapping_add(acc));
                }
            }
            "umaddl" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 4 {
                    let a = self.eval_operand(parts[1]) as u32 as u64;
                    let b = self.eval_operand(parts[2]) as u32 as u64;
                    let acc = self.eval_operand(parts[3]);
                    self.set_reg(parts[0], a.wrapping_mul(b).wrapping_add(acc));
                }
            }
            // ---- Exclusive / ordered atomics (treated as plain load/store) ----
            "ldxr" | "ldaxr" | "ldar" | "ldlar" | "ldarb" | "ldarh" | "ldxrb" | "ldxrh" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let width = if mnem.ends_with('b') { 1 } else if mnem.ends_with('h') { 2 } else if parts[0].starts_with('w') { 4 } else { 8 };
                    let (addr, _wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.read_mem(ctx, addr, width)?;
                    self.set_reg(parts[0], val);
                }
            }
            "stxr" | "stlxr" => {
                let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 {
                    let width = if parts[1].starts_with('w') { 4 } else { 8 };
                    let (addr, _wb) = self
                        .eval_mem_address(parts[2])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[2]))?;
                    let val = self.get_reg(parts[1]);
                    self.write_mem(addr, val, width);
                    self.set_reg(parts[0], 0); // exclusive store always succeeds here
                }
            }
            "stlr" | "stllr" => {
                let parts: Vec<&str> = ops.splitn(2, ',').map(|s| s.trim()).collect();
                if parts.len() == 2 {
                    let width = if parts[0].starts_with('w') { 4 } else { 8 };
                    let (addr, _wb) = self
                        .eval_mem_address(parts[1])
                        .ok_or_else(|| format!("Invalid memory operand: {}", parts[1]))?;
                    let val = self.get_reg(parts[0]);
                    self.write_mem(addr, val, width);
                }
            }
            // ---- FP / SIMD: not bit-exactly emulated; skip with annotation so GPR
            //      control flow keeps going. GPR state is unaffected by these. ----
            "fmov" | "fadd" | "fsub" | "fmul" | "fdiv" | "fneg" | "fabs" | "fsqrt"
            | "fcmp" | "fcmpe" | "fccmp" | "fcsel" | "fcvt" | "fcvtzs" | "fcvtzu"
            | "fcvtas" | "fcvtms" | "fcvtns" | "fcvtps" | "scvtf" | "ucvtf"
            | "fmax" | "fmin" | "fmaxnm" | "fminnm" | "fmla" | "fmls" | "fmadd"
            | "fmsub" | "fnmadd" | "fnmsub" | "frinta" | "frintm" | "frintn"
            | "frintp" | "frintz" | "frintx" | "frinti"
            | "movi" | "mvni" | "dup" | "ins" | "umov" | "smov" | "addv" | "addp"
            | "zip1" | "zip2" | "uzp1" | "uzp2" | "trn1" | "trn2"
            | "xtn" | "xtn2" | "sxtl" | "sxtl2" | "uxtl" | "uxtl2"
            | "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4"
            | "shl" | "sshr" | "ushr" | "ssra" | "usra" | "sli" | "sri"
            | "cmtst" | "cmeq" | "cmge" | "cmgt" | "cmle" | "cmlt" | "bsl" | "bit" | "bif"
            | "tbl" | "tbx" | "ext" | "cnt" | "not" | "abs" => {
                self.state.current_insn = format!("{:<7} {} [simd/fp: skipped]", mnem, ops);
            }
            _ => {
                return Err(format!(
                    "Unhandled instruction at 0x{:08x}: {} {}",
                    pc, mnem, ops
                ));
            }
        }

        self.state.pc = target_pc;
        Ok(())
    }

    pub fn step_back(&mut self) -> Option<RegisterState> {
        if let Some(prev) = self.history.pop() {
            self.state = prev;
            Some(self.state.clone())
        } else {
            None
        }
    }

    /// Run up to `max_steps` instructions, or stop early when `stop` returns true
    /// for the state produced by a step. Returns the number of steps executed.
    /// Errors from any step are propagated and leave the CPU at the failing state.
    pub fn run_until<F>(
        &mut self,
        ctx: &ElfContext,
        max_steps: usize,
        mut stop: F,
    ) -> Result<usize, String>
    where
        F: FnMut(&RegisterState) -> bool,
    {
        for i in 0..max_steps {
            let state = self.step(ctx)?;
            if stop(&state) {
                return Ok(i + 1);
            }
        }
        Ok(max_steps)
    }

    /// Run exactly `n` instructions (bounded), returning the final state.
    pub fn run_steps(&mut self, ctx: &ElfContext, n: usize) -> Result<RegisterState, String> {
        for _ in 0..n {
            self.step(ctx)?;
        }
        Ok(self.state.clone())
    }

    /// Run until the current function returns, i.e. until the PC moves outside
    /// the half-open range [func_start, func_end). Bounded by `max_steps`.
    pub fn run_until_return(
        &mut self,
        ctx: &ElfContext,
        func_start: u64,
        func_end: u64,
        max_steps: usize,
    ) -> Result<usize, String> {
        self.run_until(ctx, max_steps, |s| s.pc < func_start || s.pc >= func_end)
    }

    fn eval_cond(&self, suffix: &str) -> Result<bool, String> {
        Ok(match suffix.to_lowercase().as_str() {
            "eq" => self.state.z,
            "ne" => !self.state.z,
            "cs" | "hs" => self.state.c,
            "cc" | "lo" => !self.state.c,
            "mi" => self.state.n,
            "pl" => !self.state.n,
            "vs" => self.state.v,
            "vc" => !self.state.v,
            "hi" => self.state.c && !self.state.z,
            "ls" => !self.state.c || self.state.z,
            "ge" => self.state.n == self.state.v,
            "lt" => self.state.n != self.state.v,
            "gt" => !self.state.z && (self.state.n == self.state.v),
            "le" => self.state.z || (self.state.n != self.state.v),
            _ => return Err(format!("Unknown condition code: {}", suffix)),
        })
    }

    fn eval_shifted_operand(&self, s: &str, shift_part: Option<&str>) -> u64 {
        let mut val = self.eval_operand(s);
        if let Some(sp) = shift_part {
            let trimmed = sp.trim();
            if let Some(imm_str) = trimmed.strip_prefix("lsl #") {
                let shift = self.parse_imm(imm_str).unwrap_or(0);
                val <<= shift;
            } else if let Some(imm_str) = trimmed.strip_prefix("lsr #") {
                let shift = self.parse_imm(imm_str).unwrap_or(0);
                val >>= shift;
            } else if let Some(imm_str) = trimmed.strip_prefix("asr #") {
                let shift = self.parse_imm(imm_str).unwrap_or(0);
                if s.starts_with('w') {
                    val = ((val as u32 as i32) >> (shift & 31)) as u64;
                } else {
                    val = ((val as i64) >> (shift & 63)) as u64;
                }
            }
        }
        val
    }

    fn parse_arm64_mem_operand(ops: &str) -> Option<(String, Option<String>, i64, bool, bool)> {
        let t = ops.trim();
        // Post-index: [xN], #imm or [xN], -#imm
        if let Some(idx) = t.find("],") {
            let base = t[..idx].trim().trim_start_matches('[').trim().to_string();
            let disp_str = t[idx + 2..].trim().trim_start_matches('#');
            let disp = if let Some(stripped) = disp_str.strip_prefix('-') {
                -(parse_imm_num(stripped).unwrap_or(0) as i64)
            } else {
                parse_imm_num(disp_str).unwrap_or(0) as i64
            };
            return Some((base, None, disp, false, true));
        }

        // Pre-index: [xN, #imm]! or [xN, #-imm]!
        if t.ends_with('!') {
            let inner = t
                .trim_end_matches('!')
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']');
            let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
            if parts.is_empty() {
                return None;
            }
            let base = parts[0].to_string();
            let disp = if parts.len() > 1 {
                let d_str = parts[1].trim_start_matches('#');
                if let Some(stripped) = d_str.strip_prefix('-') {
                    -(parse_imm_num(stripped).unwrap_or(0) as i64)
                } else {
                    parse_imm_num(d_str).unwrap_or(0) as i64
                }
            } else {
                0
            };
            return Some((base, None, disp, true, false));
        }

        // Normal: [base, ...]
        if t.starts_with('[') && t.ends_with(']') {
            let inner = &t[1..t.len() - 1];
            let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
            if parts.is_empty() {
                return None;
            }
            let base = parts[0].to_string();
            if parts.len() == 1 {
                return Some((base, None, 0, false, false));
            }
            if parts.len() == 2 {
                if parts[1].starts_with('#') || parts[1].starts_with("-#") {
                    let d_str = parts[1].trim_start_matches('#');
                    let disp = if let Some(stripped) = d_str.strip_prefix('-') {
                        -(parse_imm_num(stripped).unwrap_or(0) as i64)
                    } else {
                        parse_imm_num(d_str).unwrap_or(0) as i64
                    };
                    return Some((base, None, disp, false, false));
                } else {
                    return Some((base, Some(parts[1].to_string()), 0, false, false));
                }
            }
            if parts.len() == 3 {
                let idx_repr = format!("{}_{}", parts[1], parts[2].replace(' ', ""));
                return Some((base, Some(idx_repr), 0, false, false));
            }
        }
        None
    }

    fn eval_mem_address(&self, ops: &str) -> Option<(u64, Option<(String, u64)>)> {
        // Literal form: `ldr x0, 0x4000` (no brackets) — absolute address.
        let t = ops.trim();
        if !t.starts_with('[') {
            let lit = t.trim_start_matches('#');
            if let Some(addr) = if lit.starts_with("0x") || lit.starts_with("0X") {
                u64::from_str_radix(&lit[2..], 16).ok()
            } else {
                u64::from_str_radix(lit, 16).ok()
            } {
                return Some((addr, None));
            }
        }
        let (base_reg, idx_opt, disp, is_pre, is_post) = Self::parse_arm64_mem_operand(ops)?;
        let base_val = self.get_reg(&base_reg);
        let idx_val = if let Some(idx_str) = idx_opt {
            if idx_str.contains("_lsl#") {
                let p: Vec<&str> = idx_str.split("_lsl#").collect();
                let r_val = self.get_reg(p[0]);
                let shift = p[1].parse::<u32>().unwrap_or(0);
                r_val << shift
            } else {
                self.get_reg(&idx_str)
            }
        } else {
            0
        };

        if is_pre {
            let updated = (base_val as i64).wrapping_add(disp) as u64;
            Some((updated, Some((base_reg, updated))))
        } else if is_post {
            let updated = (base_val as i64).wrapping_add(disp) as u64;
            Some((base_val, Some((base_reg, updated))))
        } else {
            let access = (base_val as i64)
                .wrapping_add(disp)
                .wrapping_add(idx_val as i64) as u64;
            Some((access, None))
        }
    }

    fn read_mem(&self, ctx: &ElfContext, addr: u64, size_bytes: u8) -> Result<u64, String> {
        let mut val = 0u64;
        let mut all_present = true;
        for i in 0..size_bytes as u64 {
            match self.memory.get(&(addr + i)) {
                Some(&b) => val |= (b as u64) << (8 * i),
                None => {
                    all_present = false;
                    break;
                }
            }
        }
        if all_present {
            return Ok(val);
        }

        if let Some(off) = ctx.vaddr_to_offset(addr) {
            let off = off as usize;
            if off + size_bytes as usize <= ctx.raw.len() {
                val = 0;
                for i in 0..size_bytes as usize {
                    val |= (ctx.raw[off + i] as u64) << (8 * i);
                }
                return Ok(val);
            }
        }

        Err(format!(
            "Unmapped memory read at 0x{:016x} ({} bytes)",
            addr, size_bytes
        ))
    }

    fn write_mem(&mut self, addr: u64, val: u64, size_bytes: u8) {
        for i in 0..size_bytes as u64 {
            self.memory
                .insert(addr + i, ((val >> (8 * i)) & 0xFF) as u8);
        }
    }

    fn get_reg(&self, name: &str) -> u64 {
        let n = name.trim().to_lowercase();
        if n == "sp" {
            return self.state.sp;
        }
        if n == "pc" {
            return self.state.pc;
        }
        if n == "xzr" || n == "wzr" {
            return 0;
        }
        if let Some(idx_str) = n.strip_prefix('x') {
            if let Ok(idx) = idx_str.parse::<usize>() {
                if idx < 31 {
                    return self.state.x[idx];
                }
            }
        }
        if let Some(idx_str) = n.strip_prefix('w') {
            if let Ok(idx) = idx_str.parse::<usize>() {
                if idx < 31 {
                    return self.state.x[idx] & 0xFFFF_FFFF;
                }
            }
        }
        0
    }

    fn set_reg(&mut self, name: &str, val: u64) {
        let n = name.trim().to_lowercase();
        if n == "sp" {
            self.state.sp = val;
            return;
        }
        if let Some(idx_str) = n.strip_prefix('x') {
            if let Ok(idx) = idx_str.parse::<usize>() {
                if idx < 31 {
                    self.state.x[idx] = val;
                }
            }
        } else if let Some(idx_str) = n.strip_prefix('w') {
            if let Ok(idx) = idx_str.parse::<usize>() {
                if idx < 31 {
                    // W registers zero-extend into X registers
                    self.state.x[idx] = (val as u32) as u64;
                }
            }
        }
    }

    fn parse_imm(&self, s: &str) -> Option<u64> {
        let t = s.trim().trim_start_matches('#');
        if t.starts_with("0x") || t.starts_with("0X") {
            u64::from_str_radix(&t[2..], 16).ok()
        } else {
            t.parse::<u64>().ok()
        }
    }

    fn eval_operand(&self, s: &str) -> u64 {
        let t = s.trim().trim_start_matches('#');
        if t.starts_with("0x") || t.starts_with("0X") {
            u64::from_str_radix(&t[2..], 16).unwrap_or(0)
        } else if let Ok(n) = t.parse::<i64>() {
            n as u64
        } else {
            self.get_reg(t)
        }
    }

    fn parse_addr(&self, s: &str) -> Option<u64> {
        let t = s.trim().trim_start_matches('#');
        if t.starts_with("0x") || t.starts_with("0X") {
            u64::from_str_radix(&t[2..], 16).ok()
        } else {
            u64::from_str_radix(t, 16).ok()
        }
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
