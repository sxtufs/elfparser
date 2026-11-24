//! Patch Propagation Engine (MVP: exact-clone + caller propagation).
//!
//! A real reversing job means: find the check at one address, then neutralise
//! *every copy / every caller / every inlined instance*. With `-O2`/LTO hot
//! functions are frequently duplicated inline, so a single `quickPatch`
//! "doesn't stick" — the check reappears from a clone a few hundred bytes away.
//!
//! SAFETY: every propagated write goes through the exact same validation as
//! `apply_quick_patch` (see `write_at_dispatch`): the address must map into an
//! executable segment and be instruction-aligned.

use crate::elf_parser::ElfContext;
use crate::patcher::{PatchResult, QuickPatchType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationMode {
    ExactClone = 1,
    Callers = 2,
}

impl PropagationMode {
    pub fn from_i32(v: i32) -> Option<PropagationMode> {
        match v {
            1 => Some(PropagationMode::ExactClone),
            2 => Some(PropagationMode::Callers),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            PropagationMode::ExactClone => "ExactClone",
            PropagationMode::Callers => "Callers",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PropagateOptions {
    pub max_results: usize,
    pub operand_wildcard: bool,
    pub dry_run: bool,
}

impl Default for PropagateOptions {
    fn default() -> Self {
        PropagateOptions {
            max_results: 256,
            operand_wildcard: true,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagatedPatch {
    pub address: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub original_bytes: Vec<u8>,
    #[serde(default)]
    pub patched_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPropagationReport {
    pub seed_address: u64,
    pub mode: String,
    pub dry_run: bool,
    pub total_candidates: usize,
    pub applied: usize,
    pub skipped: usize,
    pub truncated: bool,
    #[serde(default)]
    pub entries: Vec<PropagatedPatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PatchPropagationReport {
    fn error(seed: u64, mode: PropagationMode, dry_run: bool, msg: String) -> Self {
        PatchPropagationReport {
            seed_address: seed,
            mode: mode.name().to_string(),
            dry_run,
            total_candidates: 0,
            applied: 0,
            skipped: 0,
            truncated: false,
            entries: Vec::new(),
            error: Some(msg),
        }
    }
}

/// Encode a seed patch into raw bytes WITHOUT writing anything.
pub fn resolve_seed_patch(
    ctx: &ElfContext,
    mode: &str,
    value: &str,
    address: u64,
    is_thumb: bool,
) -> Result<Vec<u8>, String> {
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    match mode.to_lowercase().as_str() {
        "quick" => {
            let ptype = match value.trim().to_lowercase().as_str() {
                "nop" => QuickPatchType::Nop,
                "ret_true" | "return_true" | "true" => QuickPatchType::ReturnTrue,
                "ret_false" | "return_false" | "false" => QuickPatchType::ReturnFalse,
                "ret_void" | "return_void" | "void" => QuickPatchType::ReturnVoid,
                _ => return Err(format!("Unknown quick patch type: {}", value)),
            };
            crate::patcher::quick_patch_bytes(e_machine, ptype, is_thumb)
                .ok_or_else(|| format!("Unsupported e_machine: {}", e_machine))
        }
        "asm" | "hex" => {
            let first = value
                .split(';')
                .map(|s| s.trim())
                .find(|s| !s.is_empty())
                .ok_or_else(|| "Empty patch value".to_string())?;
            crate::patcher::assemble_instruction(first, address)
        }
        _ => Err(format!("Unsupported patch mode: {}", mode)),
    }
}

/// Apply (or, in dry-run, validate) at one address. Returns Ok(original) on
/// success or Err(reason). In dry-run the buffer is not mutated.
fn write_at_dispatch(
    ctx: &mut ElfContext,
    addr: u64,
    bytes: &[u8],
    dry_run: bool,
) -> Result<Vec<u8>, String> {
    let offset = ctx
        .vaddr_to_offset(addr)
        .ok_or_else(|| format!("Address 0x{:08x} not mapped", addr))? as usize;
    crate::patcher::validate_patch_target_public(ctx, addr, offset, bytes)?;
    if offset + bytes.len() > ctx.raw.len() {
        return Err("Patch exceeds file size".to_string());
    }
    let orig = ctx.raw[offset..offset + bytes.len()].to_vec();
    if !dry_run {
        ctx.raw[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    Ok(orig)
}

fn exec_regions(ctx: &ElfContext) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let obj = match object::File::parse(&*ctx.raw) {
        Ok(o) => o,
        Err(_) => return out,
    };
    use object::{Object, ObjectSection, ObjectSegment};
    for segment in obj.segments() {
        if let object::SegmentFlags::Elf { p_flags } = segment.flags() {
            if (p_flags & 1) != 0 {
                if let Ok(data) = segment.data() {
                    if !data.is_empty() {
                        out.push((segment.address(), data.to_vec()));
                    }
                }
            }
        }
    }
    if out.is_empty() {
        for section in obj.sections() {
            let name = section.name().unwrap_or("");
            if name == ".text" || name == ".plt" {
                if let Ok(data) = section.data() {
                    if !data.is_empty() {
                        out.push((section.address(), data.to_vec()));
                    }
                }
            }
        }
    }
    out
}

fn align_of(e_machine: u32) -> usize {
    match e_machine {
        183 => 4,
        40 => 2,
        _ => 1,
    }
}

/// True when `data[i..i+template.len()]` equals `template` under `mask`
/// (mask byte 0x00 = ignored, 0xFF = exact). Pure and side-effect-free so it
/// can be unit-tested without an ELF context.
pub fn template_matches_at(data: &[u8], template: &[u8], mask: &[u8], i: usize) -> bool {
    if mask.len() != template.len() || i + template.len() > data.len() {
        return false;
    }
    for k in 0..template.len() {
        if mask[k] != 0 && (data[i + k] & mask[k]) != (template[k] & mask[k]) {
            return false;
        }
    }
    true
}

pub fn seed_word_mask(e_machine: u32, word: u32) -> (u32, u32) {
    if e_machine == 183 {
        let operand_bits: u32 = 0x00FF_FFE0;
        (word & !operand_bits, !operand_bits)
    } else {
        (word, 0xFFFF_FFFF)
    }
}

fn make_entry(
    ctx: &mut ElfContext,
    addr: u64,
    seed_patch: &[u8],
    applied: &mut usize,
    skipped: &mut usize,
) -> PropagatedPatch {
    match write_at_dispatch(ctx, addr, seed_patch, false) {
        Ok(orig) => {
            *applied += 1;
            PropagatedPatch {
                address: addr,
                status: "applied".into(),
                reason: None,
                original_bytes: orig,
                patched_bytes: seed_patch.to_vec(),
            }
        }
        Err(r) => {
            *skipped += 1;
            PropagatedPatch {
                address: addr,
                status: "skipped".into(),
                reason: Some(r),
                original_bytes: vec![],
                patched_bytes: vec![],
            }
        }
    }
}

fn candidate_entry(
    ctx: &mut ElfContext,
    addr: u64,
    seed_patch: &[u8],
    skipped: &mut usize,
) -> PropagatedPatch {
    match write_at_dispatch(ctx, addr, seed_patch, true) {
        Ok(orig) => PropagatedPatch {
            address: addr,
            status: "candidate".into(),
            reason: None,
            original_bytes: orig,
            patched_bytes: seed_patch.to_vec(),
        },
        Err(r) => {
            *skipped += 1;
            PropagatedPatch {
                address: addr,
                status: "skipped".into(),
                reason: Some(r),
                original_bytes: vec![],
                patched_bytes: vec![],
            }
        }
    }
}

pub fn propagate_exact(
    ctx: &mut ElfContext,
    seed_addr: u64,
    seed_patch: &[u8],
    opts: &PropagateOptions,
) -> PatchPropagationReport {
    let mode = PropagationMode::ExactClone;
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    let align = align_of(e_machine) as u64;

    if seed_patch.is_empty() {
        return PatchPropagationReport::error(seed_addr, mode, opts.dry_run, "Empty seed patch".into());
    }
    // Multi-instruction seeds (e.g. `ret_true` = mov+ret, 8 bytes on AArch64)
    // are allowed: the first instruction word is operand-wildcarded, the rest
    // of the seed must match the clone exactly. Only the alignment rule below
    // constrains the length (it must be a whole number of instructions).
    if e_machine == 183 && seed_patch.len() % 4 != 0 {
        return PatchPropagationReport::error(
            seed_addr,
            mode,
            opts.dry_run,
            format!("AArch64 seed patch must be a multiple of 4 bytes, got {}", seed_patch.len()),
        );
    }

    let seed_off = match ctx.vaddr_to_offset(seed_addr) {
        Some(o) => o as usize,
        None => {
            return PatchPropagationReport::error(
                seed_addr,
                mode,
                opts.dry_run,
                format!("Seed 0x{:08x} not mapped", seed_addr),
            )
        }
    };
    if seed_off + seed_patch.len() > ctx.raw.len() {
        return PatchPropagationReport::error(seed_addr, mode, opts.dry_run, "Seed patch out of bounds".into());
    }

    let fn_range = crate::decompiler::find_function_range(ctx, seed_addr);
    let (tpl_start_vaddr, tpl_end_vaddr) = if fn_range.size >= 8 {
        (fn_range.start, fn_range.start.saturating_add(fn_range.size))
    } else {
        (seed_addr.saturating_sub(64), seed_addr.saturating_add(64))
    };
    let tpl_start_off = match ctx.vaddr_to_offset(tpl_start_vaddr & !1) {
        Some(o) => o as usize,
        None => {
            return PatchPropagationReport::error(
                seed_addr,
                mode,
                opts.dry_run,
                "Could not map template start".into(),
            )
        }
    };
    let tpl_end_off = match ctx.vaddr_to_offset(tpl_end_vaddr & !1) {
        Some(o) => o as usize,
        None => ctx.raw.len(),
    };
    let tpl_end_off = tpl_end_off.min(ctx.raw.len());
    if tpl_start_off >= tpl_end_off {
        return PatchPropagationReport::error(seed_addr, mode, opts.dry_run, "Empty template range".into());
    }

    let mut template: Vec<u8> = ctx.raw[tpl_start_off..tpl_end_off].to_vec();
    let seed_in_tpl = seed_off - tpl_start_off;
    if seed_in_tpl + seed_patch.len() > template.len() {
        return PatchPropagationReport::error(seed_addr, mode, opts.dry_run, "Seed outside template".into());
    }
    template[seed_in_tpl..seed_in_tpl + seed_patch.len()].copy_from_slice(seed_patch);

    let mut mask: Vec<u8> = vec![0xFF; template.len()];
    if opts.operand_wildcard && e_machine == 183 && seed_patch.len() >= 4 {
        let patched_word = u32::from_le_bytes([
            template[seed_in_tpl],
            template[seed_in_tpl + 1],
            template[seed_in_tpl + 2],
            template[seed_in_tpl + 3],
        ]);
        let (val, m) = seed_word_mask(e_machine, patched_word);
        let val_b = val.to_le_bytes();
        let m_b = m.to_le_bytes();
        for i in 0..4 {
            template[seed_in_tpl + i] = val_b[i];
            mask[seed_in_tpl + i] = m_b[i];
        }
    }

    let regions = exec_regions(ctx);
    let mut hits: Vec<u64> = Vec::new();
    let mut truncated = false;

    'outer: for (base_vaddr, data) in &regions {
        if data.len() < template.len() {
            continue;
        }
        let mut i = 0usize;
        while i + template.len() <= data.len() {
            if template_matches_at(data, &template, &mask, i) {
                let hit_vaddr = base_vaddr + i as u64;
                let target = hit_vaddr
                    .wrapping_add(seed_in_tpl as u64)
                    .wrapping_add(seed_addr & 1);
                let aligned_target = target & !(align - 1);
                if aligned_target != (seed_addr & !(align - 1)) {
                    if hits.len() >= opts.max_results {
                        truncated = true;
                        break 'outer;
                    }
                    hits.push(aligned_target);
                }
            }
            i += align as usize;
        }
    }

    hits.sort_unstable();
    hits.dedup();

    let mut entries: Vec<PropagatedPatch> = Vec::with_capacity(hits.len());
    let mut applied = 0usize;
    let mut skipped = 0usize;

    for addr in hits {
        if opts.dry_run {
            entries.push(candidate_entry(ctx, addr, seed_patch, &mut skipped));
        } else {
            entries.push(make_entry(ctx, addr, seed_patch, &mut applied, &mut skipped));
        }
    }

    let total = entries.len();
    PatchPropagationReport {
        seed_address: seed_addr,
        mode: mode.name().to_string(),
        dry_run: opts.dry_run,
        total_candidates: total,
        applied,
        skipped,
        truncated,
        entries,
        error: None,
    }
}

pub fn propagate_callers(
    ctx: &mut ElfContext,
    seed_addr: u64,
    seed_patch: &[u8],
    opts: &PropagateOptions,
) -> PatchPropagationReport {
    let mode = PropagationMode::Callers;
    if seed_patch.is_empty() {
        return PatchPropagationReport::error(seed_addr, mode, opts.dry_run, "Empty seed patch".into());
    }

    let refs = crate::xref::find_callers_to(ctx, seed_addr & !1);
    let mut entries: Vec<PropagatedPatch> = Vec::new();
    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut truncated = false;

    for r in refs.into_iter() {
        if entries.len() >= opts.max_results {
            truncated = true;
            break;
        }
        let addr = r.from_address;
        if opts.dry_run {
            entries.push(candidate_entry(ctx, addr, seed_patch, &mut skipped));
        } else {
            entries.push(make_entry(ctx, addr, seed_patch, &mut applied, &mut skipped));
        }
    }

    let total = entries.len();
    PatchPropagationReport {
        seed_address: seed_addr,
        mode: mode.name().to_string(),
        dry_run: opts.dry_run,
        total_candidates: total,
        applied,
        skipped,
        truncated,
        entries,
        error: None,
    }
}
