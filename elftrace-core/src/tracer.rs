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
