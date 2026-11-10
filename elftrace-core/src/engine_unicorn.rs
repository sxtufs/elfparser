

//! Unicorn-backed execution tracer (compiled only with the `engine-unicorn`
//! feature).
//!
//! Replaces the hand-written `VirtualCpu` with the QEMU-derived Unicorn CPU
//! core. Benefits over the hand-written engine:
//!   * Complete ARM64 ISA (no "unhandled instruction" halts).
//!   * Real memory mapping: every PT_LOAD segment is mapped, so `.bss` /
//!     NOBITS zero-fill and normal data reads just work.
//!   * An emulated 8 MiB stack.
//!
//! The public surface (`new`, `step`, `step_back`) matches `VirtualCpu`, so the
//! JNI layer and the Compose UI are unchanged.

use crate::elf_parser::ElfContext;
use crate::tracer::RegisterState;
use object::{Object, ObjectSegment};
use std::collections::VecDeque;
use unicorn_engine::unicorn_const::{Arch, Mode, Perm};
use unicorn_engine::{RegisterARM64, Unicorn};

const STACK_TOP: u64 = 0x7FFF_FFFF_0000;
const STACK_SIZE: u64 = 0x80_0000; // 8 MiB, Android default thread stack
const PAGE: u64 = 0x1000;
const HISTORY_CAP: usize = 500;

/// X0..X30 in order. X29 is the frame pointer and X30 the link register, but
/// they are ordinary GPRs here.
const X_REGS: [RegisterARM64; 31] = [
    RegisterARM64::X0,
    RegisterARM64::X1,
    RegisterARM64::X2,
    RegisterARM64::X3,
    RegisterARM64::X4,
    RegisterARM64::X5,
    RegisterARM64::X6,
    RegisterARM64::X7,
    RegisterARM64::X8,
    RegisterARM64::X9,
    RegisterARM64::X10,
    RegisterARM64::X11,
    RegisterARM64::X12,
    RegisterARM64::X13,
    RegisterARM64::X14,
    RegisterARM64::X15,
    RegisterARM64::X16,
    RegisterARM64::X17,
    RegisterARM64::X18,
    RegisterARM64::X19,
    RegisterARM64::X20,
    RegisterARM64::X21,
    RegisterARM64::X22,
    RegisterARM64::X23,
    RegisterARM64::X24,
    RegisterARM64::X25,
    RegisterARM64::X26,
    RegisterARM64::X27,
    RegisterARM64::X28,
    RegisterARM64::X29,
    RegisterARM64::X30,
];

pub struct UnicornTracer {
    uc: Unicorn<'static, ()>,
    history: VecDeque<RegisterState>,
}

// SAFETY: the Unicorn handle is not thread-safe, but every trace operation is
// serialized through the JNI layer (a single Java thread drives tracing) and
// `ElfContext` is shared as `Arc<ElfContext>` only for read-only analysis
// paths that never touch `vcpu`. We therefore assert Send + Sync so the engine
// can live inside `ElfContext::vcpu`.
unsafe impl Send for UnicornTracer {}
unsafe impl Sync for UnicornTracer {}

impl UnicornTracer {
    pub fn new(entry_pc: u64, ctx: &ElfContext) -> Result<Self, String> {
        let mut uc: Unicorn<'static, ()> = Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
            .map_err(|e| format!("Unicorn init failed: {:?}", e))?;

        Self::map_image(&mut uc, &ctx.raw)?;

        // Emulated stack.
        let stack_start = STACK_TOP - STACK_SIZE;
        uc.mem_map(stack_start, STACK_SIZE, Perm::ALL)
            .map_err(|e| format!("Stack mapping failed: {:?}", e))?;

        uc.reg_write(RegisterARM64::SP, STACK_TOP)
            .map_err(|e| format!("SP init failed: {:?}", e))?;
        uc.reg_write(RegisterARM64::PC, entry_pc)
            .map_err(|e| format!("PC init failed: {:?}", e))?;

        Ok(Self {
            uc,
            history: VecDeque::new(),
        })
    }

    /// Map every PT_LOAD segment of the ELF into one contiguous region and
    /// copy its file-backed bytes in. Regions between/after segments are zero
    /// by default, which correctly models `.bss` and `p_memsz > p_filesz`.
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
        // Guard against pathological layouts that would map gigabytes.
        if size > 0x2000_0000 {
            return Err(format!(
                "Refusing to map {} MiB image (unexpected segment layout)",
                size / 0x10_0000
            ));
        }

        uc.mem_map(start, size, Perm::ALL)
            .map_err(|e| format!("Image mapping failed: {:?}", e))?;

        for (addr, data) in chunks {
            if !data.is_empty() {
                uc.mem_write(addr, &data)
                    .map_err(|e| format!("Image write at 0x{:x} failed: {:?}", addr, e))?;
            }
        }

        Ok(())
    }

    fn snapshot(&self) -> Result<RegisterState, String> {
        let mut x = [0u64; 31];
        for (i, reg) in X_REGS.iter().enumerate() {
            x[i] = self
                .uc
                .reg_read(*reg)
                .map_err(|e| format!("register read failed: {:?}", e))?;
        }
        let sp = self
            .uc
            .reg_read(RegisterARM64::SP)
            .map_err(|e| format!("SP read failed: {:?}", e))?;
        let pc = self
            .uc
            .reg_read(RegisterARM64::PC)
            .map_err(|e| format!("PC read failed: {:?}", e))?;
        let nzcv = self
            .uc
            .reg_read(RegisterARM64::NZCV)
            .map_err(|e| format!("NZCV read failed: {:?}", e))?;

        Ok(RegisterState {
            x,
            sp,
            pc,
            n: (nzcv >> 31) & 1 != 0,
            z: (nzcv >> 30) & 1 != 0,
            c: (nzcv >> 29) & 1 != 0,
            v: (nzcv >> 28) & 1 != 0,
            mnemonic: String::new(),
            op_str: String::new(),
            current_insn: String::new(),
            changed_regs: Vec::new(),
            changed_flags: Vec::new(),
        })
    }

    fn restore(&mut self, s: &RegisterState) -> Result<(), String> {
        for (i, reg) in X_REGS.iter().enumerate() {
            self.uc
                .reg_write(*reg, s.x[i])
                .map_err(|e| format!("register write failed: {:?}", e))?;
        }
        self.uc
            .reg_write(RegisterARM64::SP, s.sp)
            .map_err(|e| format!("SP write failed: {:?}", e))?;
        self.uc
            .reg_write(RegisterARM64::PC, s.pc)
            .map_err(|e| format!("PC write failed: {:?}", e))?;
        let nzcv = ((s.n as u64) << 31)
            | ((s.z as u64) << 30)
            | ((s.c as u64) << 29)
            | ((s.v as u64) << 28);
        self.uc
            .reg_write(RegisterARM64::NZCV, nzcv)
            .map_err(|e| format!("NZCV write failed: {:?}", e))?;
        Ok(())
    }

    pub fn step(&mut self, ctx: &ElfContext) -> Result<RegisterState, String> {
        let pc = self
            .uc
            .reg_read(RegisterARM64::PC)
            .map_err(|e| format!("PC read failed: {:?}", e))?;

        // Decode the instruction at PC for display (read straight from emulated
        // memory, so it works for any mapped code region).
        let (mnem, ops) = match self.uc.mem_read(pc, 4) {
            Ok(code) => {
                let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
                match crate::disasm::disassemble(&code, pc, 4, e_machine, false) {
                    Ok(ins) => match ins.data.into_iter().next() {
                        Some(i) => (i.mnemonic, i.op_str),
                        None => (String::from("?"), String::new()),
                    },
                    Err(_) => (String::from("?"), String::new()),
                }
            }
            Err(_) => (String::from("?"), String::new()),
        };

        let prev = self.snapshot()?;
        if self.history.len() >= HISTORY_CAP {
            self.history.pop_front();
        }
        self.history.push_back(prev.clone());

        // Execute exactly one instruction.
        self.uc.emu_start(pc, 0, 0, 1).map_err(|e| {
            format!(
                "Execution stopped at 0x{:016x} (`{} {}`): {:?}",
                pc, mnem, ops, e
            )
        })?;

        let mut post = self.snapshot()?;

        // Register / flag diffs for UI highlighting.
        let mut changed_regs = Vec::new();
        for i in 0..31 {
            if post.x[i] != prev.x[i] {
                changed_regs.push(format!("x{}", i));
            }
        }
        if post.sp != prev.sp {
            changed_regs.push("sp".to_string());
        }
        let mut changed_flags = Vec::new();
        if post.z != prev.z {
            changed_flags.push("z".to_string());
        }
        if post.n != prev.n {
            changed_flags.push("n".to_string());
        }
        if post.c != prev.c {
            changed_flags.push("c".to_string());
        }
        if post.v != prev.v {
            changed_flags.push("v".to_string());
        }

        post.mnemonic = mnem.clone();
        post.op_str = ops.clone();
        post.current_insn = format!("{:<7} {}", mnem, ops);
        post.changed_regs = changed_regs;
        post.changed_flags = changed_flags;

        Ok(post)
    }

    pub fn step_back(&mut self) -> Option<RegisterState> {
        let prev = self.history.pop_back()?;
        if self.restore(&prev).is_err() {
            return None;
        }
        Some(prev)
    }
}
