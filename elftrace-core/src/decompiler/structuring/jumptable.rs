//! AArch64 jump-table (switch dispatch) recovery.
//!
//! GCC/Clang lower a `switch` with a dense case range into a "jump table":
//! a bounds check against the number of cases, then a load of a relative
//! offset from a table indexed by the selector, then an indirect branch to
//! `table_base + offset`. The IR only sees a bare `br <reg>` (`IndirectBranch`),
//! so without recovery the structurer bails to goto-soup for the whole function
//! and the CFG conservatively treats every later block as reachable.
//!
//! This pass re-disassembles the instruction window that ends in the indirect
//! branch and recognizes the canonical idioms, then reads the case offsets from
//! the file and computes absolute targets. When it succeeds, the caller can:
//!   1. add real case edges to the CFG, and
//!   2. mark the block as a resolved `switch` so `has_indirect_branch` no longer
//!      forces the goto fallback for an otherwise-structured function.
//!
//! Everything here is best-effort: any ambiguity returns `None` and the caller
//! keeps today's conservative behavior. This pass can therefore only ADD
//! structure — never regress a function it cannot fully resolve.

use crate::disasm::disassemble;
use crate::elf_parser::ElfContext;

/// A recovered switch dispatch.
#[derive(Debug, Clone)]
pub struct JumpTable {
    /// Address of the indirect-branch block's first instruction.
    pub block_start: u64,
    /// Selector register (lowercased), e.g. "x0".
    pub selector_reg: String,
    /// Recovered (case_value, target_addr) pairs, sorted by case_value.
    pub cases: Vec<(i64, u64)>,
    /// Out-of-range / default target (the bound-check fall-through), if known.
    pub default_target: Option<u64>,
}

impl JumpTable {
    /// Distinct absolute targets across all cases (for CFG edge insertion).
    pub fn target_set(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.cases.iter().map(|(_, t)| *t).collect();
        v.sort_unstable();
        v.dedup();
        if let Some(d) = self.default_target {
            if !v.contains(&d) {
                v.push(d);
            }
        }
        v
    }
}

/// Parse a register operand token like "x0" / "w0" to its index.
fn reg_index(tok: &str) -> Option<u32> {
    let t = tok.trim().to_lowercase();
    let rest = t.strip_prefix('x').or_else(|| t.strip_prefix('w'))?;
    rest.parse::<u32>().ok()
}

/// Parse an immediate like "#0x10" / "0x10" / "#16" / "16" to i64.
fn parse_imm(s: &str) -> Option<i64> {
    let t = s.trim().trim_start_matches('#');
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()
    } else if let Some(h) = t.strip_prefix("-0x").or_else(|| t.strip_prefix("-0X")) {
        i64::from_str_radix(h, 16).ok().map(|v| -v)
    } else {
        t.parse::<i64>().ok()
    }
}

/// Resolve the table base address produced by an `adrp` (page) + `add` (offset)
/// pair, or a single `adr`. Returns the effective VA and the destination reg.
fn track_adr(
    mnem: &str,
    ops: &str,
    pc: u64,
    pages: &mut std::collections::HashMap<String, u64>,
) -> Option<String> {
    let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
    match mnem {
        "adrp" if parts.len() == 2 => {
            let reg = parts[0].to_lowercase();
            // Capstone renders adrp's target as an absolute page address already.
            let page = parse_imm(parts[1])? as u64;
            pages.insert(reg.clone(), page);
            Some(reg)
        }
        "add" if parts.len() == 3 => {
            let dst = parts[0].to_lowercase();
            let src = parts[1].to_lowercase();
            if let Some(&page) = pages.get(&src) {
                let off = parse_imm(parts[2])? as u64;
                pages.insert(dst.clone(), page.wrapping_add(off));
                Some(dst)
            } else {
                None
            }
        }
        "adr" if parts.len() == 2 => {
            let reg = parts[0].to_lowercase();
            let _ = pc; // Capstone gives absolute target for adr too.
            let va = parse_imm(parts[1])? as u64;
            pages.insert(reg.clone(), va);
            Some(reg)
        }
        _ => None,
    }
}

/// Try to recover a jump table for the block starting at `block_start` that
/// ends in an indirect branch. `block_end` is the address just past the last
/// instruction (used to bound the re-disassembly window's look-back).
pub fn recover(ctx: &ElfContext, block_start: u64, block_end: u64) -> Option<JumpTable> {
    // Re-disassemble a slightly-wider window so we can see the `subs`/`cmp`
    // bound check and the `adrp/add` base setup, which may live a few
    // instructions before the `br`. We start at the block and cap at 256 bytes.
    let off = ctx.vaddr_to_offset(block_start)? as usize;
    if off >= ctx.raw.len() {
        return None;
    }
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    if e_machine != 183 {
        return None; // AArch64 only for now.
    }
    let slice = &ctx.raw[off..];
    let want = 256u64.min((block_end.saturating_sub(block_start)).max(64));
    let code = disassemble(slice, block_start, want, e_machine, false).ok()?;
    let insns = code.data;
    if insns.is_empty() {
        return None;
    }

    // Walk the window tracking adrp/adr-derived table bases. When we reach a
    // `br <reg>`, look for the immediately-preceding load that read the case
    // offset using a base we tracked.
    let mut pages: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    // Remember the last few loads: (dest_reg, base_reg, scale_shift, is_signed)
    let mut last_load: Option<(String, String, u32)> = None;
    let mut last_bound: Option<u64> = None; // max case value + 1 from the bound check
    let mut selector: Option<String> = None;

    for ins in &insns {
        let mnem = ins.mnemonic.to_lowercase();
        let ops = ins.op_str.as_str();

        if let Some(_r) = track_adr(&mnem, ops, ins.address, &mut pages) {
            continue;
        }

        // Bound check: `cmp <sel>, #N` followed (somewhere) by `b.hi`/`b.cs`
        // to the default case. Clang emits `cmp w8, #N` or `subs w8, w8, #N`.
        if (mnem == "cmp" || mnem == "subs") && last_bound.is_none() {
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                if let (Some(_), Some(imm)) = (reg_index(parts[0]), parse_imm(parts[1])) {
                    if imm >= 0 {
                        // For `cmp sel, #N`, valid cases are 0..=N → count N+1.
                        // For `subs sel, sel, #N`, count is N (case 0 is the
                        // fall-through). We record the raw bound and resolve
                        // the exact count from the table length later.
                        last_bound = Some((imm as u64) + 1);
                        selector = Some(parts[0].to_lowercase());
                    }
                }
            }
            continue;
        }

        // Scaled offset load: ldrb / ldrh / ldrsw / ldr from [base, index]
        if (mnem == "ldrb" || mnem == "ldrh" || mnem == "ldrsw" || mnem == "ldr")
            && ops.contains('[')
        {
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let dst = parts[0].to_lowercase();
                // The memory operand looks like "[x9, x0]" or "[x9, w0, sxtw #2]".
                let mem = parts[1].trim_start_matches('[');
                let base = mem
                    .split([',', ']'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();
                let scale_shift = if mnem == "ldrb" {
                    0
                } else if mnem == "ldrh" {
                    1
                } else if mnem == "ldrsw" || mnem == "ldr" {
                    // ldrsw/ldr of a word table: 4-byte entries.
                    2
                } else {
                    0
                };
                last_load = Some((dst, base, scale_shift));
            }
            continue;
        }

        // The indirect branch itself.
        if mnem == "br" {
            let br_reg = ops.trim().to_lowercase();
            let (load_dst, load_base, shift) = last_load.clone()?;
            // The branch register should be the loaded offset's destination
            // (or a register derived from it — we only handle the direct case).
            if br_reg != load_dst {
                // Some compilers `add tmp, base, offset; br tmp`. Try to see if
                // the previous instruction was such an add; otherwise bail.
                return None;
            }
            let table_base = *pages.get(&load_base)?;
            let count = last_bound.unwrap_or(0);
            if count == 0 || count > 4096 {
                return None;
            }

            // Read `count` entries. The load width determines stride/encoding:
            //   ldrb  → u8  relative offset
            //   ldrh  → u16 relative offset
            //   ldrsw → i32 relative byte offset
            let width = match shift {
                0 => 1usize,
                1 => 2usize,
                _ => 4usize,
            };

            let mut cases = Vec::new();
            for i in 0..count {
                let entry_va = table_base.wrapping_add(i * width as u64);
                let ent_off = match ctx.vaddr_to_offset(entry_va) {
                    Some(o) => o as usize,
                    None => break,
                };
                if ent_off + width > ctx.raw.len() {
                    break;
                }
                let raw = &ctx.raw[ent_off..ent_off + width];
                let rel: i64 = match width {
                    1 => raw[0] as i8 as i64,
                    2 => i16::from_le_bytes([raw[0], raw[1]]) as i64,
                    _ => i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as i64,
                };
                // Target = table_base + rel  (AArch64 jump tables store offsets
                // relative to the table base; some toolchains use the adr pc).
                // Clang/GCC on AArch64 default to base-relative.
                let target = table_base.wrapping_add(rel as u64);
                if target == 0 {
                    break;
                }
                cases.push((i as i64, target));
            }

            if cases.is_empty() {
                return None;
            }

            // Safety rail: every recovered target must be a mapped, executable
            // address. A wrong table-offset interpretation (toolchain variance:
            // byte-relative vs scaled, base-relative vs pc-relative) produces
            // plausible-looking but WRONG targets. Emitting a switch to garbage
            // is worse than the goto fallback, so reject the whole table unless
            // ALL targets validate. This makes misinterpretation fail safe.
            for (_, tgt) in &cases {
                if *tgt == 0
                    || !ctx.is_executable_address(*tgt)
                    || ctx.vaddr_to_offset(*tgt).is_none()
                {
                    return None;
                }
            }

            // The default target is the fall-through of the bound check. We
            // don't have the exact block here; the caller fills it in from the
            // `b.hi`/`b.cs` edge if present. Leave it None for now.
            return Some(JumpTable {
                block_start,
                selector_reg: selector.unwrap_or_else(|| "x0".to_string()),
                cases,
                default_target: None,
            });
        }
    }

    None
}
