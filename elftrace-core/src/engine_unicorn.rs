

//! Unicorn-backed execution tracer (compiled only with the `engine-unicorn`
//! feature).
//!
//! Multi-architecture: ARM64, ARM32 (ARM/Thumb), x86_64 and x86. The Unicorn
//! (QEMU) core executes; Capstone still renders the disassembly text so the UI
//! looks identical across engines.
//!
//! The public surface (`new`, `step`, `step_back`) matches `VirtualCpu`, so the
//! JNI layer is unchanged.

use crate::elf_parser::ElfContext;
use crate::tracer::{FlagEntry, RegEntry, RegisterState};
use object::{Object, ObjectSegment};
use std::collections::VecDeque;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{RegisterARM, RegisterARM64, RegisterX86, Unicorn};

const PAGE: u64 = 0x1000;
const HISTORY_CAP: usize = 500;

// X0..X30 in order (ARM64).
const X_REGS: [RegisterARM64; 31] = [
    RegisterARM64::X0, RegisterARM64::X1, RegisterARM64::X2, RegisterARM64::X3,
    RegisterARM64::X4, RegisterARM64::X5, RegisterARM64::X6, RegisterARM64::X7,
    RegisterARM64::X8, RegisterARM64::X9, RegisterARM64::X10, RegisterARM64::X11,
    RegisterARM64::X12, RegisterARM64::X13, RegisterARM64::X14, RegisterARM64::X15,
    RegisterARM64::X16, RegisterARM64::X17, RegisterARM64::X18, RegisterARM64::X19,
    RegisterARM64::X20, RegisterARM64::X21, RegisterARM64::X22, RegisterARM64::X23,
    RegisterARM64::X24, RegisterARM64::X25, RegisterARM64::X26, RegisterARM64::X27,
    RegisterARM64::X28, RegisterARM64::X29, RegisterARM64::X30,
];

fn arm32_table() -> [(&'static str, RegisterARM); 16] {
    [
        ("R0", RegisterARM::R0), ("R1", RegisterARM::R1), ("R2", RegisterARM::R2),
        ("R3", RegisterARM::R3), ("R4", RegisterARM::R4), ("R5", RegisterARM::R5),
        ("R6", RegisterARM::R6), ("R7", RegisterARM::R7), ("R8", RegisterARM::R8),
        ("R9", RegisterARM::R9), ("R10", RegisterARM::R10), ("R11", RegisterARM::R11),
        ("R12", RegisterARM::R12),
        ("SP", RegisterARM::SP), ("LR", RegisterARM::LR), ("PC", RegisterARM::PC),
    ]
}

fn x86_64_table() -> [(&'static str, RegisterX86); 17] {
    [
        ("RAX", RegisterX86::RAX), ("RBX", RegisterX86::RBX), ("RCX", RegisterX86::RCX),
        ("RDX", RegisterX86::RDX), ("RSI", RegisterX86::RSI), ("RDI", RegisterX86::RDI),
        ("RBP", RegisterX86::RBP), ("RSP", RegisterX86::RSP),
        ("R8", RegisterX86::R8), ("R9", RegisterX86::R9), ("R10", RegisterX86::R10),
        ("R11", RegisterX86::R11), ("R12", RegisterX86::R12), ("R13", RegisterX86::R13),
        ("R14", RegisterX86::R14), ("R15", RegisterX86::R15), ("RIP", RegisterX86::RIP),
    ]
}

fn x86_32_table() -> [(&'static str, RegisterX86); 9] {
    [
        ("EAX", RegisterX86::EAX), ("EBX", RegisterX86::EBX), ("ECX", RegisterX86::ECX),
        ("EDX", RegisterX86::EDX), ("ESI", RegisterX86::ESI), ("EDI", RegisterX86::EDI),
        ("EBP", RegisterX86::EBP), ("ESP", RegisterX86::ESP), ("EIP", RegisterX86::EIP),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Isa {
    Arm64,
    Arm32Thumb,
    Arm32,
    X86_64,
    X86,
}

impl Isa {
    fn label(&self) -> &'static str {
        match self {
            Isa::Arm64 => "arm64",
            Isa::Arm32 | Isa::Arm32Thumb => "arm",
            Isa::X86_64 => "x86_64",
            Isa::X86 => "x86",
        }
    }

    fn is_64(&self) -> bool {
        matches!(self, Isa::Arm64 | Isa::X86_64)
    }

    /// Map an ELF e_machine to an ISA, returning the normalized entry address
    /// (Thumb entry clears bit 0).
    fn from_elf(e_machine: u32, entry: u64) -> Option<(Isa, u64)> {
        match e_machine {
            183 => Some((Isa::Arm64, entry)),           // EM_AARCH64
            40 => {
                if entry & 1 != 0 {
                    Some((Isa::Arm32Thumb, entry & !1)) // EM_ARM, Thumb
                } else {
                    Some((Isa::Arm32, entry))
                }
            }
            62 => Some((Isa::X86_64, entry)),           // EM_X86_64
            3 => Some((Isa::X86, entry)),               // EM_386
            _ => None,
        }
    }

    fn arch_mode(&self) -> (Arch, Mode) {
        match self {
            Isa::Arm64 => (Arch::ARM64, Mode::LITTLE_ENDIAN),
            Isa::Arm32Thumb => (Arch::ARM, Mode::LITTLE_ENDIAN | Mode::THUMB),
            Isa::Arm32 => (Arch::ARM, Mode::LITTLE_ENDIAN),
            Isa::X86_64 => (Arch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_64),
            Isa::X86 => (Arch::X86, Mode::LITTLE_ENDIAN | Mode::MODE_32),
        }
    }

    fn thumb(&self) -> bool {
        matches!(self, Isa::Arm32Thumb)
    }
}

pub struct UnicornTracer {
    uc: Unicorn<'static, ()>,
    history: VecDeque<RegisterState>,
    isa: Isa,
    e_machine: u32,
}

// SAFETY: Unicorn is not thread-safe, but all trace operations are serialized
// through the JNI layer (one Java thread drives tracing). `ElfContext` is shared
// as `Arc<ElfContext>` only for read-only analysis paths that never touch `vcpu`.
unsafe impl Send for UnicornTracer {}
unsafe impl Sync for UnicornTracer {}

impl UnicornTracer {
    pub fn new(entry_pc: u64, ctx: &ElfContext) -> Result<Self, String> {
        let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
        let (isa, entry) = Isa::from_elf(e_machine, entry_pc).ok_or_else(|| {
            format!("Execution tracing is not supported for e_machine={} yet", e_machine)
        })?;

        let (arch, mode) = isa.arch_mode();
        let mut uc: Unicorn<'static, ()> =
            Unicorn::new(arch, mode).map_err(|e| format!("Unicorn init failed: {:?}", e))?;

        Self::map_image(&mut uc, &ctx.raw)?;

        // Emulated stack sized for the address width.
        let (stack_top, stack_size) = if isa.is_64() {
            (0x7FFF_FFFF_0000u64, 0x80_0000u64) // 8 MiB
        } else {
            (0x7FFE_0000u64, 0x40_0000u64)     // 4 MiB, within 32-bit range
        };
        let stack_start = stack_top - stack_size;
        uc.mem_map(stack_start, stack_size, Prot::ALL)
            .map_err(|e| format!("Stack mapping failed: {:?}", e))?;

        Self::write_sp(&mut uc, isa, stack_top)?;
        Self::write_pc(&mut uc, isa, entry)?;

        Ok(Self {
            uc,
            history: VecDeque::new(),
            isa,
            e_machine,
        })
    }

    fn write_sp(uc: &mut Unicorn<'static, ()>, isa: Isa, val: u64) -> Result<(), String> {
        let r = match isa {
            Isa::Arm64 => uc.reg_write(RegisterARM64::SP, val),
            Isa::Arm32 | Isa::Arm32Thumb => uc.reg_write(RegisterARM::SP, val),
            Isa::X86_64 => uc.reg_write(RegisterX86::RSP, val),
            Isa::X86 => uc.reg_write(RegisterX86::ESP, val),
        };
        r.map_err(|e| format!("SP init failed: {:?}", e))
    }

    fn write_pc(uc: &mut Unicorn<'static, ()>, isa: Isa, val: u64) -> Result<(), String> {
        let r = match isa {
            Isa::Arm64 => uc.reg_write(RegisterARM64::PC, val),
            Isa::Arm32 | Isa::Arm32Thumb => uc.reg_write(RegisterARM::PC, val),
            Isa::X86_64 => uc.reg_write(RegisterX86::RIP, val),
            Isa::X86 => uc.reg_write(RegisterX86::EIP, val),
        };
        r.map_err(|e| format!("PC init failed: {:?}", e))
    }

    fn read_pc(&self) -> Result<u64, String> {
        let r = match self.isa {
            Isa::Arm64 => self.uc.reg_read(RegisterARM64::PC),
            Isa::Arm32 | Isa::Arm32Thumb => self.uc.reg_read(RegisterARM::PC),
            Isa::X86_64 => self.uc.reg_read(RegisterX86::RIP),
            Isa::X86 => self.uc.reg_read(RegisterX86::EIP),
        };
        r.map_err(|e| format!("PC read failed: {:?}", e))
    }

    fn map_image(uc: &mut Unicorn<'static, ()>, raw: &[u8]) -> Result<(), String> {
        let file = object::File::parse(raw).map_err(|e| format!("ELF parse failed: {:?}", e))?;
        let mut lo = u64::MAX;
        let mut hi = 0u64;
        let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
        for seg in file.segments() {
            let addr = seg.address();
            let memsz = seg.size();
            if memsz == 0 {
                continue;
            }
            lo = lo.min(addr);
            hi = hi.max(addr.wrapping_add(memsz));
            let data = seg.data().map(|d| d.to_vec()).unwrap_or_default();
            chunks.push((addr, data));
        }
        if lo == u64::MAX {
            return Err("ELF has no loadable segments".to_string());
        }
        let start = lo & !(PAGE - 1);
        let end = (hi + PAGE - 1) & !(PAGE - 1);
        let size = end - start;
        if size == 0 {
            return Err("ELF image has zero size".to_string());
        }
        if size > 0x2000_0000 {
            return Err(format!(
                "Refusing to map {} MiB image (unexpected segment layout)",
                size / 0x10_0000
            ));
        }
        uc.mem_map(start, size, Prot::ALL)
            .map_err(|e| format!("Image mapping failed: {:?}", e))?;
        for (addr, data) in chunks {
            if !data.is_empty() {
                uc.mem_write(addr, &data)
                    .map_err(|e| format!("Image write at 0x{:x} failed: {:?}", addr, e))?;
            }
        }
        Ok(())
    }

    fn base_state(&self) -> RegisterState {
        RegisterState {
            x: [0u64; 31],
            sp: 0,
            pc: 0,
            n: false,
            z: false,
            c: false,
            v: false,
            arch: self.isa.label().to_string(),
            regs: Vec::new(),
            flags: Vec::new(),
            mnemonic: String::new(),
            op_str: String::new(),
            current_insn: String::new(),
            changed_regs: Vec::new(),
            changed_flags: Vec::new(),
        }
    }

    fn snapshot(&self) -> Result<RegisterState, String> {
        let mut st = self.base_state();
        match self.isa {
            Isa::Arm64 => self.snap_arm64(&mut st)?,
            Isa::Arm32 | Isa::Arm32Thumb => self.snap_arm32(&mut st)?,
            Isa::X86_64 => self.snap_x86(&mut st, true)?,
            Isa::X86 => self.snap_x86(&mut st, false)?,
        }
        Ok(st)
    }

    fn snap_arm64(&self, st: &mut RegisterState) -> Result<(), String> {
        let mut x = [0u64; 31];
        let mut regs = Vec::with_capacity(33);
        for (i, reg) in X_REGS.iter().enumerate() {
            let v = self.uc.reg_read(*reg).map_err(|e| format!("read X{}: {:?}", i, e))?;
            x[i] = v;
            regs.push(RegEntry { name: format!("X{}", i), value: v });
        }
        let sp = self.uc.reg_read(RegisterARM64::SP).map_err(|e| format!("read SP: {:?}", e))?;
        let pc = self.uc.reg_read(RegisterARM64::PC).map_err(|e| format!("read PC: {:?}", e))?;
        let nzcv = self.uc.reg_read(RegisterARM64::NZCV).map_err(|e| format!("read NZCV: {:?}", e))?;
        st.n = (nzcv >> 31) & 1 != 0;
        st.z = (nzcv >> 30) & 1 != 0;
        st.c = (nzcv >> 29) & 1 != 0;
        st.v = (nzcv >> 28) & 1 != 0;
        regs.push(RegEntry { name: "SP".to_string(), value: sp });
        regs.push(RegEntry { name: "PC".to_string(), value: pc });
        st.x = x;
        st.sp = sp;
        st.pc = pc;
        st.flags = vec![
            FlagEntry { name: "N".to_string(), value: st.n },
            FlagEntry { name: "Z".to_string(), value: st.z },
            FlagEntry { name: "C".to_string(), value: st.c },
            FlagEntry { name: "V".to_string(), value: st.v },
        ];
        st.regs = regs;
        Ok(())
    }

    fn snap_arm32(&self, st: &mut RegisterState) -> Result<(), String> {
        let mut regs = Vec::with_capacity(16);
        for (name, reg) in arm32_table() {
            let v = self.uc.reg_read(reg).map_err(|e| format!("read {}: {:?}", name, e))?;
            match name {
                "SP" => st.sp = v,
                "PC" => st.pc = v,
                _ => {}
            }
            regs.push(RegEntry { name: name.to_string(), value: v });
        }
        let cpsr = self.uc.reg_read(RegisterARM::CPSR).map_err(|e| format!("read CPSR: {:?}", e))?;
        st.n = (cpsr >> 31) & 1 != 0;
        st.z = (cpsr >> 30) & 1 != 0;
        st.c = (cpsr >> 29) & 1 != 0;
        st.v = (cpsr >> 28) & 1 != 0;
        st.flags = vec![
            FlagEntry { name: "N".to_string(), value: st.n },
            FlagEntry { name: "Z".to_string(), value: st.z },
            FlagEntry { name: "C".to_string(), value: st.c },
            FlagEntry { name: "V".to_string(), value: st.v },
        ];
        st.regs = regs;
        Ok(())
    }

    fn snap_x86(&self, st: &mut RegisterState, is64: bool) -> Result<(), String> {
        let mut regs = Vec::new();
        if is64 {
            for (name, reg) in x86_64_table() {
                let v = self.uc.reg_read(reg).map_err(|e| format!("read {}: {:?}", name, e))?;
                match name {
                    "RSP" => st.sp = v,
                    "RIP" => st.pc = v,
                    _ => {}
                }
                regs.push(RegEntry { name: name.to_string(), value: v });
            }
        } else {
            for (name, reg) in x86_32_table() {
                let v = self.uc.reg_read(reg).map_err(|e| format!("read {}: {:?}", name, e))?;
                match name {
                    "ESP" => st.sp = v,
                    "EIP" => st.pc = v,
                    _ => {}
                }
                regs.push(RegEntry { name: name.to_string(), value: v });
            }
        }
        let eflags = self.uc.reg_read(RegisterX86::EFLAGS).map_err(|e| format!("read EFLAGS: {:?}", e))?;
        st.c = (eflags >> 0) & 1 != 0;
        st.z = (eflags >> 6) & 1 != 0;
        st.n = (eflags >> 7) & 1 != 0;
        st.v = (eflags >> 11) & 1 != 0;
        st.flags = vec![
            FlagEntry { name: "CF".to_string(), value: st.c },
            FlagEntry { name: "ZF".to_string(), value: st.z },
            FlagEntry { name: "SF".to_string(), value: st.n },
            FlagEntry { name: "OF".to_string(), value: st.v },
        ];
        st.regs = regs;
        Ok(())
    }

    fn restore(&mut self, s: &RegisterState) -> Result<(), String> {
        match self.isa {
            Isa::Arm64 => {
                for (i, reg) in X_REGS.iter().enumerate() {
                    self.uc.reg_write(*reg, s.x[i]).map_err(|e| format!("write X{}: {:?}", i, e))?;
                }
                self.uc.reg_write(RegisterARM64::SP, s.sp).map_err(|e| format!("write SP: {:?}", e))?;
                self.uc.reg_write(RegisterARM64::PC, s.pc).map_err(|e| format!("write PC: {:?}", e))?;
                let nzcv = ((s.n as u64) << 31) | ((s.z as u64) << 30) | ((s.c as u64) << 29) | ((s.v as u64) << 28);
                self.uc.reg_write(RegisterARM64::NZCV, nzcv).map_err(|e| format!("write NZCV: {:?}", e))?;
            }
            Isa::Arm32 | Isa::Arm32Thumb => {
                for (i, (_, reg)) in arm32_table().iter().enumerate() {
                    if let Some(e) = s.regs.get(i) {
                        self.uc.reg_write(*reg, e.value).map_err(|er| format!("write reg {}: {:?}", i, er))?;
                    }
                }
                let cpsr = ((s.n as u64) << 31) | ((s.z as u64) << 30) | ((s.c as u64) << 29) | ((s.v as u64) << 28);
                self.uc.reg_write(RegisterARM::CPSR, cpsr).map_err(|e| format!("write CPSR: {:?}", e))?;
            }
            Isa::X86_64 => {
                for (i, (_, reg)) in x86_64_table().iter().enumerate() {
                    if let Some(e) = s.regs.get(i) {
                        self.uc.reg_write(*reg, e.value).map_err(|er| format!("write reg {}: {:?}", i, er))?;
                    }
                }
                self.restore_flags_x86(s)?;
            }
            Isa::X86 => {
                for (i, (_, reg)) in x86_32_table().iter().enumerate() {
                    if let Some(e) = s.regs.get(i) {
                        self.uc.reg_write(*reg, e.value).map_err(|er| format!("write reg {}: {:?}", i, er))?;
                    }
                }
                self.restore_flags_x86(s)?;
            }
        }
        Ok(())
    }

    fn restore_flags_x86(&mut self, s: &RegisterState) -> Result<(), String> {
        let mut eflags = 0u64;
        if s.c { eflags |= 1 << 0; }
        if s.z { eflags |= 1 << 6; }
        if s.n { eflags |= 1 << 7; }
        if s.v { eflags |= 1 << 11; }
        self.uc.reg_write(RegisterX86::EFLAGS, eflags).map_err(|e| format!("write EFLAGS: {:?}", e))?;
        Ok(())
    }

    fn read_len(&self) -> usize {
        match self.isa {
            Isa::X86_64 | Isa::X86 => 16, // variable-length x86 instructions
            _ => 4,
        }
    }

    pub fn step(&mut self, ctx: &ElfContext) -> Result<RegisterState, String> {
        let pc = self.read_pc()?;
        let read_len = self.read_len();
        let mut code = vec![0u8; read_len];
        let (mnem, ops) = if self.uc.mem_read(pc, &mut code).is_ok() {
            match crate::disasm::disassemble(&code, pc, read_len as u64, self.e_machine, self.isa.thumb()) {
                Ok(ins) => match ins.data.into_iter().next() {
                    Some(i) => (i.mnemonic, i.op_str),
                    None => (String::from(".word"), self.raw_word(&code)),
                },
                Err(_) => (String::from(".word"), self.raw_word(&code)),
            }
        } else {
            (String::from("?"), String::new())
        };

        let prev = self.snapshot()?;
        if self.history.len() >= HISTORY_CAP {
            self.history.pop_front();
        }
        self.history.push_back(prev.clone());

        self.uc.emu_start(pc, 0, 0, 1).map_err(|e| {
            format!("Execution stopped at 0x{:016x} (`{} {}`): {:?}", pc, mnem, ops, e)
        })?;

        let mut post = self.snapshot()?;

        let (changed_regs, changed_flags) = self.diff(&prev, &post);
        post.mnemonic = mnem.clone();
        post.op_str = ops.clone();
        post.current_insn = format!("{:<7} {}", mnem, ops);
        post.changed_regs = changed_regs;
        post.changed_flags = changed_flags;
        Ok(post)
    }

    fn raw_word(&self, code: &[u8]) -> String {
        let mut w = [0u8; 4];
        for (i, b) in code.iter().take(4).enumerate() {
            w[i] = *b;
        }
        format!("0x{:08x}", u32::from_le_bytes(w))
    }

    fn diff(&self, prev: &RegisterState, post: &RegisterState) -> (Vec<String>, Vec<String>) {
        let mut changed_regs = Vec::new();
        for (a, b) in prev.regs.iter().zip(post.regs.iter()) {
            if a.value != b.value {
                let lname = b.name.to_lowercase();
                // Don't flag the program counter as a "changed register".
                if lname != "pc" && lname != "rip" && lname != "eip" {
                    changed_regs.push(lname);
                }
            }
        }
        // Emit the *native* flag names that changed (e.g. "cf"/"zf" on x86,
        // "n"/"z"/"c"/"v" on ARM), matching the `flags` view the UI renders.
        let mut changed_flags = Vec::new();
        let set = [
            ("z", post.z != prev.z),
            ("n", post.n != prev.n),
            ("c", post.c != prev.c),
            ("v", post.v != prev.v),
        ];
        for f in &post.flags {
            let key = f.name.to_lowercase();
            // Map an x86 flag name to the legacy field it corresponds to.
            let legacy_key = match key.as_str() {
                "cf" => "c",
                "zf" => "z",
                "sf" => "n",
                "of" => "v",
                other => other,
            };
            if set.iter().any(|(k, changed)| *k == legacy_key && *changed) {
                changed_flags.push(key.clone());
            }
        }
        (changed_regs, changed_flags)
    }

    pub fn step_back(&mut self) -> Option<RegisterState> {
        let prev = self.history.pop_back()?;
        if self.restore(&prev).is_err() {
            return None;
        }
        Some(prev)
    }
}
