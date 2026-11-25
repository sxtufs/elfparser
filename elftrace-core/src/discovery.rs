//! Function discovery for stripped binaries.
//!
//! A stripped Android `.so` usually exports a handful of symbols and nothing
//! else: the symbol table is gone, so every screen that is keyed on symbols
//! (disassembly list, xrefs, call hierarchy) is empty for the binaries people
//! actually open. This module recovers function starts from the code itself:
//!
//! 1. Seed with the ELF entry point, the PLT section start and every symbol
//!    that already exists in `syms_map`.
//! 2. Sweep every executable region for direct call instructions
//!    (`bl`/`blx` on AArch64 and ARM, `call rel32` on x86) and treat each
//!    branch target as a function start.
//! 3. Discard targets outside executable regions (literal-pool false
//!    positives), then synthesize `sub_XXXXXXXX` names and conservative sizes
//!    from the distance to the next known function start.
//!
//! The scan is bounded by `max_scanned` bytes and `MAX_FUNCTIONS` functions so
//! a huge or adversarial binary cannot exhaust the phone's memory or the
//! caller's patience.

use crate::elf_parser::ElfContext;
use crate::model::SymsDTO;
use crate::xref::decode_arm64_branch_insn;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Refuse to scan more than this many bytes of executable code per call.
pub const MAX_SCANNED_BYTES: u64 = 32 * 1024 * 1024;
/// Upper bound on the number of discovered functions (keeps the symbol table,
/// the JSON response and the UI list bounded).
pub const MAX_FUNCTIONS: usize = 40_000;
/// A function guessed only by the distance to the next start is never given a
/// span larger than this; real code is far smaller and a 32 KiB span would
/// swallow unrelated bytes.
pub const MAX_FUNCTION_SPAN: u64 = 0x8000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredFunction {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub thumb: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryReport {
    /// Newly synthesized functions (not previously named by any symbol table).
    pub added: usize,
    /// Function starts that already had a symbol (used as scan seeds).
    pub known: usize,
    /// Bytes of executable code actually decoded.
    pub scanned_bytes: u64,
    /// True when a bound was hit and discovery is partial.
    pub truncated: bool,
    pub functions: Vec<DiscoveredFunction>,
}

impl DiscoveryReport {
    /// Small JSON payload for the JNI boundary: the full function list is large
    /// for a big library and is already available through `get_info()` after
    /// the discovered symbols are installed.
    pub fn to_summary_json(&self) -> String {
        serde_json::json!({
            "added": self.added,
            "known": self.known,
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
        })
        .to_string()
    }
}

fn exec_regions<'a>(obj: &'a object::File<'a>) -> Vec<(u64, &'a [u8])> {
    use object::{Object, ObjectSection, ObjectSegment};

    let mut regions: Vec<(u64, &[u8])> = Vec::new();
    for seg in obj.segments() {
        if let object::SegmentFlags::Elf { p_flags, .. } = seg.flags() {
            if (p_flags.0 & 1) != 0 {
                if let Ok(data) = seg.data() {
                    if !data.is_empty() {
                        regions.push((seg.address(), data));
                    }
                }
            }
        }
    }
    // Packed binaries sometimes have unusable program headers; fall back to the
    // classic code sections.
    if regions.is_empty() {
        for sec in obj.sections() {
            let name = sec.name().unwrap_or("");
            if matches!(name, ".text" | ".plt" | ".init" | ".fini") {
                if let Ok(data) = sec.data() {
                    if !data.is_empty() {
                        regions.push((sec.address(), data));
                    }
                }
            }
        }
    }
    regions
}

pub fn in_exec_regions(regions: &[(u64, &[u8])], addr: u64) -> bool {
    regions
        .iter()
        .any(|(base, data)| addr >= *base && addr < base.saturating_add(data.len() as u64))
}

/// Decode one executable region and collect the targets of *direct calls*.
///
/// Pure function of (architecture, base address, bytes) so it can be tested
/// with hand-encoded instructions and no fixture binary.
pub fn scan_region_for_calls(
    e_machine: u64,
    base: u64,
    data: &[u8],
    out: &mut HashSet<u64>,
) {
    match e_machine {
        183 => {
            let mut i = 0usize;
            while i + 4 <= data.len() {
                let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
                if word != 0 {
                    if let Some((to, kind, _)) = decode_arm64_branch_insn(word, base + i as u64) {
                        if kind == "Call" {
                            out.insert(to);
                        }
                    }
                }
                i += 4;
            }
        }
        40 => {
            // Thumb-2 BL/BLX (16-bit halfwords) plus classic ARM BL/BLX.
            let mut i = 0usize;
            while i + 4 <= data.len() {
                let hw1 = u16::from_le_bytes(data[i..i + 2].try_into().unwrap());
                let hw2 = u16::from_le_bytes(data[i + 2..i + 4].try_into().unwrap());
                if (hw1 & 0xF800) == 0xF000 && (hw2 & 0xC000) == 0xC000 {
                    let from = base + i as u64;
                    let s = ((hw1 >> 10) & 1) as i64;
                    let imm10 = (hw1 & 0x03FF) as i64;
                    let j1 = ((hw2 >> 13) & 1) as i64;
                    let j2 = ((hw2 >> 11) & 1) as i64;
                    let i1 = (!(j1 ^ s)) & 1;
                    let i2 = (!(j2 ^ s)) & 1;
                    let imm11 = (hw2 & 0x07FF) as i64;
                    let mut imm = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
                    if s != 0 {
                        imm |= !0x01FF_FFFF;
                    }
                    out.insert((from + 4).wrapping_add(imm as u64));
                }
                // ARM-mode instructions are 4-byte aligned; decoding them on the
                // 2-byte halfword walk would read misaligned garbage.
                let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
                let is_bl = (word & 0x0F00_0000) == 0x0B00_0000
                    && (word & 0xF000_0000) != 0xF000_0000;
                let is_blx = (word & 0xFE00_0000) == 0xFA00_0000;
                if (is_bl || is_blx) && i % 4 == 0 {
                    let from = base + i as u64;
                    let mut imm24 = (word & 0x00FF_FFFF) as i64;
                    if (imm24 & 0x0080_0000) != 0 {
                        imm24 |= !0x00FF_FFFF;
                    }
                    let h = if is_blx {
                        (((word >> 24) & 1) as i64) << 1
                    } else {
                        0
                    };
                    out.insert((from + 8).wrapping_add(((imm24 << 2) | h) as u64));
                }
                i += 2;
            }
        }
        _ => {
            // x86 / x86-64: let Capstone decode so variable-length instructions
            // cannot desync the sweep.
            use capstone::prelude::*;
            let cs = if e_machine == 62 {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .build()
            } else {
                Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode32)
                    .build()
            };
            let cs = match cs {
                Ok(c) => c,
                Err(_) => return,
            };
            const CHUNK: usize = 1 << 16;
            let mut off = 0usize;
            while off < data.len() {
                let end = (off + CHUNK).min(data.len());
                let chunk = &data[off..end];
                if let Ok(insns) = cs.disasm_all(chunk, base + off as u64) {
                    for ins in insns.iter() {
                        if ins.mnemonic() != Some("call") {
                            continue;
                        }
                        let Some(ops) = ins.op_str() else { continue };
                        let ops = ops.trim();
                        let imm = ops.strip_prefix('#').unwrap_or(ops);
                        if let Some(hex) = imm.strip_prefix("0x") {
                            if let Ok(target) = u64::from_str_radix(hex, 16) {
                                out.insert(target);
                            }
                        }
                    }
                }
                off = end;
            }
        }
    }
}

fn synthesized_name(addr: u64) -> String {
    format!("sub_{:08X}", addr)
}

/// Discover function starts without mutating the context.
pub fn discover(ctx: &ElfContext, max_scanned: u64) -> DiscoveryReport {
    use object::{Object, ObjectSection};

    let mut report = DiscoveryReport::default();
    let obj_file = match object::File::parse(&*ctx.raw) {
        Ok(f) => f,
        Err(_) => return report,
    };
    let e_machine = match obj_file.architecture() {
        object::Architecture::Arm => 40u64,
        object::Architecture::Aarch64 => 183,
        object::Architecture::X86_64 => 62,
        object::Architecture::I386 => 3,
        _ => return report,
    };
    let regions = exec_regions(&obj_file);
    if regions.is_empty() {
        return report;
    }

    let align = |addr: u64| -> u64 {
        if e_machine == 40 {
            addr & !1
        } else {
            addr
        }
    };

    // Seeds: everything already named that is executable code.
    let mut seeds: HashSet<u64> = HashSet::new();
    let entry = align(obj_file.entry());
    if in_exec_regions(&regions, entry) {
        seeds.insert(entry);
    }
    for (&addr, sym) in &ctx.syms_map {
        let a = align(addr);
        let _ = sym;
        if in_exec_regions(&regions, a) {
            seeds.insert(a);
        }
    }
    for sec in obj_file.sections() {
        if sec.name().unwrap_or("") == ".plt" {
            let a = align(sec.address());
            if in_exec_regions(&regions, a) {
                seeds.insert(a);
            }
        }
    }
    report.known = seeds.len();

    // Sweep for call targets.
    let mut targets: HashSet<u64> = HashSet::new();
    let mut budget = max_scanned;
    for (base, data) in &regions {
        if budget == 0 {
            report.truncated = true;
            break;
        }
        let slice_len = (*data).len().min(budget as usize);
        scan_region_for_calls(e_machine, *base, &data[..slice_len], &mut targets);
        report.scanned_bytes += slice_len as u64;
        budget = budget.saturating_sub(slice_len as u64);
        if slice_len < (*data).len() {
            report.truncated = true;
        }
    }

    let mut new_starts: std::collections::HashMap<u64, bool> = std::collections::HashMap::new();
    for t in targets {
        let a = align(t);
        if a == 0 || seeds.contains(&a) || !in_exec_regions(&regions, a) {
            continue;
        }
        let thumb = e_machine == 40 && (t & 1) != 0;
        new_starts
            .entry(a)
            .and_modify(|prev| *prev = *prev || thumb)
            .or_insert(thumb);
        if seeds.len() + new_starts.len() >= MAX_FUNCTIONS {
            report.truncated = true;
            break;
        }
    }

    // Sizes: the distance to the next known start, clamped.
    let mut all_starts: Vec<u64> = seeds
        .iter()
        .copied()
        .chain(new_starts.keys().copied())
        .collect();
    all_starts.sort_unstable();
    all_starts.dedup();
    let next_start = |addr: u64| -> Option<u64> {
        let idx = all_starts.partition_point(|s| *s <= addr);
        all_starts.get(idx).copied()
    };
    let region_end = |addr: u64| -> Option<u64> {
        regions
            .iter()
            .find(|(base, data)| addr >= *base && addr < base.saturating_add(data.len() as u64))
            .map(|(base, data)| base.saturating_add(data.len() as u64))
    };

    let mut functions: Vec<DiscoveredFunction> = new_starts
        .iter()
        .map(|(&addr, &thumb)| {
            let size = next_start(addr)
                .or_else(|| region_end(addr))
                .map(|next| next.saturating_sub(addr))
                .filter(|s| *s >= 4)
                .map(|s| s.min(MAX_FUNCTION_SPAN))
                .unwrap_or(0);
            DiscoveredFunction {
                address: addr,
                name: synthesized_name(addr),
                size,
                thumb,
            }
        })
        .collect();
    functions.sort_by_key(|f| f.address);
    report.added = functions.len();
    report.functions = functions;
    report
}

impl ElfContext {
    /// Discover function starts and install them as `sub_XXXXXXXX` symbols.
    /// Existing symbols are never overwritten. Returns the report (which lists
    /// only the newly added functions).
    pub fn discover_functions(&mut self, max_scanned: u64) -> DiscoveryReport {
        let report = discover(self, max_scanned);
        if report.functions.is_empty() {
            return report;
        }
        for f in &report.functions {
            self.syms_map.entry(f.address).or_insert(SymsDTO {
                sym: f.name.clone(),
                value: f.address,
                size: f.size,
                thumb: f.thumb,
                demangled: None,
                jni_class: None,
                jni_method: None,
                json: None,
            });
        }
        self.invalidate_symbol_caches();
        report
    }
}
