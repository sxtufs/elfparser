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
use std::collections::{HashMap, HashSet};

/// Refuse to scan more than this many bytes of executable code per call.
pub const MAX_SCANNED_BYTES: u64 = 32 * 1024 * 1024;
/// Upper bound on the number of discovered functions (keeps the symbol table,
/// the JSON response and the UI list bounded).
pub const MAX_FUNCTIONS: usize = 40_000;
/// Hard cap on recovered string references. A packed 100+ MB binary can
/// otherwise produce millions of adrp/add pairs, and the report JSON (and the
/// Kotlin-side list built from it) grows past the phone's heap and kills the
/// process. The cap keeps the Recover Functions pass bounded on any input.
pub const MAX_STRING_REFS: usize = 100_000;
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
    /// Exact sizes from `.eh_frame` FDEs, keyed by function start. Used to
    /// backfill sizes onto pre-existing symbols.
    pub fde_sizes: std::collections::HashMap<u64, u64>,
    /// PLT imports, as (stub address, resolved import name).
    pub plt_imports: Vec<(u64, String)>,
    /// (rodata string address, code address referencing it) from AArch64
    /// `adrp+add/ldr` scanning over executable regions.
    pub string_refs: Vec<(u64, u64)>,
    /// C++ vtable slots and class symbols recovered from `.data.rel.ro`
    /// (Itanium ABI: typeinfo/type-string header + run of code pointers).
    pub vtables: Vec<(u64, String)>,
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
            "string_refs": self.string_refs.iter()
                .map(|(s, c)| serde_json::json!({"str": s, "code": c}))
                .collect::<Vec<_>>(),
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

/// Detect one AArch64 frame-pointer prologue: `stp x29, x30, [sp, #imm]!`
/// (pre-index) or `stp x29, x30, [sp, #imm]` (signed offset). This is the
/// canonical first instruction of a frame-setting function on ARM64, so its
/// presence at a candidate start marks a real function beginning.
pub fn is_aarch64_fp_prologue(word: u32) -> bool {
    // STP (64-bit): opc 10 = pre-index, 01 = signed offset; Rt=29 (x29),
    // Rt2=30 (x30), Rn=31 (sp).
    let rt = word & 0x1F;
    let rn = (word >> 5) & 0x1F;
    let rt2 = (word >> 10) & 0x1F;
    let opc = (word >> 22) & 0x3;
    rt == 29 && rt2 == 30 && rn == 31 && (opc == 0b10 || opc == 0b01)
}

/// Bound the function that starts at `start`: scan forward to the first `ret`
/// (D65F03C0) at instruction granularity, never past `next_start`. Returns
/// the end address (exclusive), or `None` when no `ret` appears first.
pub fn scan_for_function_end_aarch64(
    base: u64,
    data: &[u8],
    start: u64,
    next_start: Option<u64>,
) -> Option<u64> {
    let limit = next_start
        .map(|n| n.min(base + data.len() as u64))
        .unwrap_or(base + data.len() as u64);
    let mut addr = start;
    while addr + 4 <= limit {
        let i = (addr - base) as usize;
        let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if word == 0xD65F_03C0 {
            return Some((addr + 4).min(limit));
        }
        addr += 4;
    }
    None
}

/// Scan an executable region for references into `rodata`, decoding the
/// canonical AArch64 `adrp Xn, #page` + `add Xn, Xn, #off` (and
/// `ldr Xn, [Xn, #off]`) idiom. Returns `(string_addr, code_addr)` pairs —
/// the code address is the `add`/`ldr` instruction that completes the
/// reference, which the UI can attribute to the function containing it.
/// `is_string` decides whether a rodata address holds a printable string.
pub fn scan_string_refs_aarch64(
    base: u64,
    data: &[u8],
    rodata: (u64, u64),
    is_string: impl Fn(u64) -> bool,
) -> Vec<(u64, u64)> {
    use std::collections::HashMap;
    let mut out = Vec::new();
    let mut adrp_regs: HashMap<u32, u64> = HashMap::new();
    let (ro_lo, ro_hi) = rodata;
    let mut addr = base & !3;
    let end = base + data.len() as u64;
    while addr + 8 <= end {
        let i = (addr - base) as usize;
        let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());

        // ADRP Xn, #imm: opc=1 (bit 31), bits 28-24 = 10000
        if (word >> 31) == 1 && ((word >> 24) & 0x1F) == 0b10000 {
            let rd = word & 0x1F;
            let immlo = (word >> 29) & 0x3;
            let immhi = (word >> 5) & 0x7_FFFF;
            let imm = ((immhi << 2) | immlo) as i64;
            let imm = if imm & (1 << 20) != 0 {
                imm - (1 << 21)
            } else {
                imm
            };
            let page = (addr & !0xFFF).wrapping_add((imm << 12) as u64);
            adrp_regs.insert(rd, page);
            addr += 4;
            continue;
        }

        // ADD Xd, Xn, #imm (M=0, shift=00): sf 00 100010
        if (word >> 23) == 0b0_0010_0010 && (word >> 22) & 1 == 0 {
            let rd = word & 0x1F;
            let rn = (word >> 5) & 0x1F;
            let imm12 = (word >> 10) & 0xFFF;
            if let Some(&page) = adrp_regs.get(&rn) {
                let target = page + imm12 as u64;
                if target >= ro_lo && target < ro_hi && is_string(target) {
                    out.push((target, addr));
                }
            }
            adrp_regs.remove(&rd); // conservative: rd overwritten
                                   // rd now holds page+off; keep mapping for ldr Xt,[rd] usage:
            let combined = adrp_regs.get(&rn).map(|p| p + imm12 as u64);
            adrp_regs.remove(&rd);
            if let Some(c) = combined {
                adrp_regs.insert(rd, c);
            }
            addr += 4;
            continue;
        }

        // LDR Xt, [Xn, #imm12] (size=11, V=0, opc=01, imm12 scaled by 8)
        if (word >> 22) == 0b1_1111_0101 {
            let rt = word & 0x1F;
            let rn = (word >> 5) & 0x1F;
            let imm12 = ((word >> 10) & 0xFFF) as u64 * 8;
            if let Some(&page) = adrp_regs.get(&rn) {
                let target = page + imm12;
                if target >= ro_lo && target < ro_hi && is_string(target) {
                    out.push((target, addr));
                }
            }
            adrp_regs.remove(&rt);
            addr += 4;
            continue;
        }

        // Unknown instruction: assume it may clobber tracked registers is too
        // aggressive; branch/ret targets rarely reuse adrp scratch regs. Keep.
        addr += 4;
    }
    out
}

/// Recover C++ vtables and class names from `.data.rel.ro`.
///
/// Itanium ABI layout: a `-8` from a vtable pointer sits a `typeinfo` pointer,
/// and before that a pointer to a `_ZTS<N>ClassName...` type-string in
/// `.rodata` (or `.data.rel.ro`). A run of 2+ consecutive pointers into
/// executable sections after that header is a vtable; each entry becomes a
/// named virtual function `ClassName::vfN`, and the class name is recovered
/// from the type string. Returns (address, name) pairs for both the vtable
/// slots and the class symbol at the vtable base.
pub fn scan_vtables(
    data_rel_ro: (u64, &[u8]),
    exec: &[(u64, u64)],
    rodata: (u64, &[u8]),
    relocs: &HashMap<u64, u64>,
) -> Vec<(u64, String)> {
    use std::collections::HashMap;
    let (base, data) = data_rel_ro;
    let (ro_base, ro_data) = rodata;
    let in_exec = |a: u64| exec.iter().any(|(b, len)| a >= *b && a < b + *len);
    let read_ptr = |off: usize| -> Option<u64> {
        if off + 8 <= data.len() {
            let raw = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            if raw == 0 {
                // Unloaded file image: RELATIVE relocations carry the real
                // pointer values in their addends.
                return relocs.get(&(base + off as u64)).copied();
            }
            Some(raw)
        } else {
            None
        }
    };
    // typeinfo type-string name: "_ZTS" prefix, class name up to ".." or NUL.
    let class_name_from_ts = |addr: u64| -> Option<String> {
        if addr < ro_base || addr >= ro_base + ro_data.len() as u64 {
            return None;
        }
        let bytes = &ro_data[(addr - ro_base) as usize..];
        let take = bytes.len().min(256);
        let end = bytes[..take].iter().position(|&b| b == 0).unwrap_or(take);
        let s = std::str::from_utf8(&bytes[..end]).ok()?;
        let rest = s.strip_prefix("_ZTS")?;
        let name_len: Option<usize> = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .try_fold(0usize, |acc, c| {
                c.to_digit(10).map(|d| acc * 10 + d as usize)
            });
        let name_len = name_len?;
        Some(
            rest.chars()
                .skip_while(|c| c.is_ascii_digit())
                .take(name_len)
                .collect(),
        )
    };

    let mut out = Vec::new();
    let mut seen_classes: HashMap<u64, String> = HashMap::new();
    let n = data.len() / 8;
    for i in 0..n {
        let off = i * 8;
        // Candidate vtable header: [i-2] = type-string ptr, [i-1] = typeinfo
        // ptr (skip: unknown pointee), [i..] = fn pointers.
        if i < 2 {
            continue;
        }
        // Class name: try the direct _ZTS pointer at [i-16] first, then the
        // standard Itanium layout where [i-8] is a typeinfo pointer whose
        // first word points at the _ZTS string.
        let class = read_ptr(off - 16)
            .and_then(&class_name_from_ts)
            .or_else(|| {
                read_ptr(off - 8).and_then(|ti| {
                    let ti_off = (ti as usize).checked_sub(base as usize)?;
                    let zts = if ti_off + 8 <= data.len() {
                        let raw = u64::from_le_bytes(data[ti_off..ti_off + 8].try_into().ok()?);
                        if raw != 0 {
                            Some(raw)
                        } else {
                            relocs.get(&ti).copied()
                        }
                    } else {
                        None
                    }?;
                    class_name_from_ts(zts)
                })
            });
        let class = match class {
            Some(c) => c,
            None => continue,
        };
        // Count consecutive exec pointers from slot i.
        let mut slots = 0usize;
        while let Some(p) = read_ptr(off + slots * 8) {
            if p != 0 && in_exec(p) {
                slots += 1;
            } else {
                break;
            }
        }
        if slots < 2 {
            continue;
        }
        let vt_addr = base + off as u64;
        seen_classes.insert(vt_addr, class.clone());
        out.push((vt_addr.wrapping_sub(16), format!("vtable for {}", class)));
        for s in 0..slots {
            out.push((base + (off + s * 8) as u64, format!("{}::vf{}", class, s)));
        }
    }
    out
}

/// Decode one executable region and collect the targets of *direct calls*.
///
/// Pure function of (architecture, base address, bytes) so it can be tested
/// with hand-encoded instructions and no fixture binary.
pub fn scan_region_for_calls(e_machine: u64, base: u64, data: &[u8], out: &mut HashSet<u64>) {
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
                    let mut imm =
                        (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
                    if s != 0 {
                        imm |= !0x01FF_FFFF;
                    }
                    out.insert((from + 4).wrapping_add(imm as u64));
                }
                // ARM-mode instructions are 4-byte aligned; decoding them on the
                // 2-byte halfword walk would read misaligned garbage.
                let word = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
                let is_bl =
                    (word & 0x0F00_0000) == 0x0B00_0000 && (word & 0xF000_0000) != 0xF000_0000;
                let is_blx = (word & 0xFE00_0000) == 0xFA00_0000;
                if (is_bl || is_blx) && i.is_multiple_of(4) {
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

/// Recover function starts from `.eh_frame` FDEs.
///
/// Release builds keep `.eh_frame` for stack unwinding, and every FDE's
/// `pc_begin` is the exact start of a real function — no heuristic, no
/// false positives. The FDE also encodes the function's size (`pc_range`),
/// so a function recovered here gets a precise span instead of the
/// distance-to-next-start guess. Returns `(pc_begin, size)` pairs.
/// Only the DWARF32, 64-bit little-endian layout Android ships is parsed;
/// anything else stops the walk cleanly.
pub fn scan_eh_frame(data: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 12 <= data.len() {
        let length = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as u64;
        if length == 0 {
            break; // terminator
        }
        if length == 0xFFFF_FFFF {
            break; // DWARF64: not shipped on Android, stop parsing
        }
        let entry_len = length as usize;
        if i + 4 + entry_len > data.len() {
            break;
        }
        let entry = &data[i + 4..i + 4 + entry_len];
        let cie_id = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        if cie_id != 0 {
            // FDE: pc_begin is a 4-byte pcrel sdata4 right after the id,
            // pc_range the 4 bytes after it. The pcrel base is the file
            // offset of the pc_begin field itself.
            if entry.len() >= 12 {
                let off = i32::from_le_bytes(entry[4..8].try_into().unwrap());
                let range = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
                let field_pos = (i + 4 + 4) as i64;
                let pc_begin = field_pos.wrapping_add(off as i64);
                if pc_begin >= 0 && range > 0 {
                    out.push((pc_begin as u64, range));
                }
            }
        }
        i += 4 + entry_len;
    }
    out
}

/// Bounds of the `.eh_frame` FDE that covers `address`, as `(start, size)`.
///
/// Cheap on purpose: it parses section headers and scans only `.eh_frame`
/// instead of running the full discovery pass. Returns `None` when the file has
/// no `.eh_frame`, when no FDE covers the address, or when the addressing is a
/// form this scanner does not decode.
pub fn fde_bounds_for(ctx: &ElfContext, address: u64) -> Option<(u64, u64)> {
    use object::{Object, ObjectSection};

    let obj_file = object::File::parse(&*ctx.raw).ok()?;
    let sec = obj_file.section_by_name(".eh_frame")?;
    let data = sec.data().ok()?;
    let mut best: Option<(u64, u64)> = None;
    for (start, size) in scan_eh_frame(data) {
        if address >= start && address < start.saturating_add(size) {
            // Nested/duplicate FDEs: keep the innermost, i.e. the latest start.
            if best.is_none_or(|(prev, _)| start >= prev) {
                best = Some((start, size));
            }
        }
    }
    best
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

    // `.eh_frame` FDEs: exact function starts and sizes, no heuristics. These
    // are trusted over anything the call scan infers.
    let mut fde_sizes: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for sec in obj_file.sections() {
        if sec.name().unwrap_or("") == ".eh_frame" {
            if let Ok(data) = sec.data() {
                for (start, size) in scan_eh_frame(data) {
                    if in_exec_regions(&regions, start) {
                        fde_sizes.insert(align(start), size);
                    }
                }
            }
        }
    }
    for &start in fde_sizes.keys() {
        seeds.insert(start);
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
            // Priority: FDE size (exact) > prologue-bounded scan (good) >
            // distance-to-next-start guess (last resort).
            let size = fde_sizes
                .get(&addr)
                .copied()
                .or_else(|| {
                    next_start(addr).and_then(|next| {
                        let region = regions
                            .iter()
                            .find(|(b, d)| addr >= *b && addr < b.saturating_add(d.len() as u64));
                        region
                            .and_then(|(b, d)| {
                                scan_for_function_end_aarch64(*b, d, addr, Some(next))
                            })
                            .filter(|end| end > &addr)
                            .map(|end| end - addr)
                    })
                })
                .or_else(|| {
                    next_start(addr)
                        .or_else(|| region_end(addr))
                        .map(|next| next.saturating_sub(addr))
                        .filter(|s| *s >= 4)
                })
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
    report.fde_sizes = fde_sizes;
    // PLT imports: every named stub in .plt range, sorted by address.
    if let Some(plt) = obj_file.section_by_name(".plt") {
        let plt_lo = plt.address();
        let plt_hi = plt_lo + plt.size();
        report.plt_imports = ctx
            .syms_map
            .iter()
            .filter(|(a, s)| {
                **a >= plt_lo && **a < plt_hi && !s.sym.starts_with('.') && !s.sym.is_empty()
            })
            .map(|(a, s)| (*a, s.sym.clone()))
            .collect();
        report.plt_imports.sort_by_key(|(a, _)| *a);
    }
    // String refs: adrp+add/ldr into .rodata (and .data.rel.ro) where a
    // NUL-terminated printable string lives.
    let ro_sections: Vec<(u64, &[u8])> = obj_file
        .sections()
        .filter_map(|s| {
            let n = s.name().unwrap_or("");
            if matches!(n, ".rodata" | ".data.rel.ro" | ".data") {
                s.data().ok().map(|d| (s.address(), d))
            } else {
                None
            }
        })
        .collect();
    let looks_like_string = |addr: u64| -> bool {
        for (base, data) in &ro_sections {
            if addr >= *base && addr < base + data.len() as u64 {
                let off = (addr - base) as usize;
                let bytes = &data[off..];
                if bytes.len() < 2 {
                    return false;
                }
                let take = bytes.len().min(256);
                let s = &bytes[..take];
                let nul = s.iter().position(|&b| b == 0);
                let len = nul.unwrap_or(take);
                return len >= 2
                    && s[..len]
                        .iter()
                        .all(|&b| (0x20..0x7F).contains(&b) || b == b'\t' || b == b'\n');
            }
        }
        false
    };
    let mut string_refs = Vec::new();
    'refs: for (base, data) in &regions {
        if *base as usize + data.len() > u32::MAX as usize {
            continue; // bound 32-bit decoding to 32-bit address spaces
        }
        for r in scan_string_refs_aarch64(
            *base,
            data,
            (
                ro_sections.first().map(|(b, _)| *b).unwrap_or(0),
                ro_sections
                    .last()
                    .map(|(b, d)| b + d.len() as u64)
                    .unwrap_or(0),
            ),
            looks_like_string,
        ) {
            if string_refs.len() >= MAX_STRING_REFS {
                break 'refs;
            }
            string_refs.push(r);
        }
    }
    string_refs.sort();
    string_refs.dedup();
    report.string_refs = string_refs;
    // Vtables: `.data.rel.ro` + `.rodata` for the _ZTS type strings.
    if let (Some(drr), Some(ro)) = (
        obj_file
            .sections()
            .find(|s| s.name().unwrap_or("") == ".data.rel.ro")
            .and_then(|s| s.data().ok().map(|d| (s.address(), d))),
        obj_file
            .sections()
            .find(|s| s.name().unwrap_or("") == ".rodata")
            .and_then(|s| s.data().ok().map(|d| (s.address(), d))),
    ) {
        let exec: Vec<(u64, u64)> = regions.iter().map(|(b, d)| (*b, d.len() as u64)).collect();
        // RELATIVE relocation addends: in the file image .data.rel.ro pointers
        // are zero; the loader fills them from these addends at load time.
        let mut relocs: HashMap<u64, u64> = HashMap::new();
        for sec in obj_file.sections() {
            if sec.name().unwrap_or("") == ".rela.dyn" {
                if let Ok(data) = sec.data() {
                    for chunk in data.chunks_exact(24) {
                        let r_off = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                        let r_info = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
                        let r_add = i64::from_le_bytes(chunk[16..24].try_into().unwrap());
                        // R_AARCH64_RELATIVE = 1027; addend-based, type must be RELATIVE
                        if r_info & 0xffffffff == 1027 && r_add > 0 {
                            relocs.insert(r_off, r_add as u64);
                        }
                    }
                }
            }
        }
        report.vtables = scan_vtables(drr, &exec, ro, &relocs);
    }
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
        // FDE functions that were already symbol-named still get their exact
        // size backfilled when the existing entry has none.
        for (addr, size) in &report.fde_sizes {
            if let Some(sym) = self.syms_map.get_mut(addr) {
                if sym.size == 0 {
                    sym.size = *size;
                }
            }
        }
        self.invalidate_symbol_caches();
        report
    }
}
