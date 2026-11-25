use crate::model::{ElfInfo, ElfSectionDTO, ElfSegmentDTO, SData, SDataItem, SymsDTO};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

struct DynamicTables<'a> {
    dynamic: &'a [u8],
    dynstr: &'a [u8],
    dynsym: &'a [u8],
    jmprel: &'a [u8],
    rela_dyn: &'a [u8],
    init_array: &'a [u8],
    init_array_va: u64,
    pltgot_va: u64,
    is_rela: bool,
    exec_segments: Vec<(u64, &'a [u8])>,
}

fn extract_dynamic_tables<'a>(raw: &'a [u8], is_64: bool) -> DynamicTables<'a> {
    let mut out = DynamicTables {
        dynamic: &[],
        dynstr: &[],
        dynsym: &[],
        jmprel: &[],
        rela_dyn: &[],
        init_array: &[],
        init_array_va: 0,
        pltgot_va: 0,
        is_rela: is_64,
        exec_segments: Vec::new(),
    };

    let (phoff, phentsize, phnum) = if is_64 {
        if raw.len() < 64 {
            return out;
        }
        (
            u64::from_le_bytes(raw[32..40].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[54..56].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[56..58].try_into().unwrap()) as usize,
        )
    } else {
        if raw.len() < 52 {
            return out;
        }
        (
            u32::from_le_bytes(raw[28..32].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[42..44].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[44..46].try_into().unwrap()) as usize,
        )
    };

    let mut loads: Vec<(u64, usize, usize)> = Vec::new();
    for i in 0..phnum {
        let off = phoff.saturating_add(i.saturating_mul(phentsize));
        if off + phentsize > raw.len() {
            break;
        }
        let ph = &raw[off..off + phentsize];
        let (p_type, p_flags, p_offset, p_vaddr, p_filesz) = if is_64 && phentsize >= 56 {
            (
                u32::from_le_bytes(ph[0..4].try_into().unwrap()),
                u32::from_le_bytes(ph[4..8].try_into().unwrap()),
                u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize,
                u64::from_le_bytes(ph[16..24].try_into().unwrap()),
                u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize,
            )
        } else if !is_64 && phentsize >= 32 {
            (
                u32::from_le_bytes(ph[0..4].try_into().unwrap()),
                u32::from_le_bytes(ph[24..28].try_into().unwrap()),
                u32::from_le_bytes(ph[4..8].try_into().unwrap()) as usize,
                u32::from_le_bytes(ph[8..12].try_into().unwrap()) as u64,
                u32::from_le_bytes(ph[16..20].try_into().unwrap()) as usize,
            )
        } else {
            continue;
        };

        if p_type == 1 && p_filesz > 0 && p_offset < raw.len() {
            let avail = p_filesz.min(raw.len() - p_offset);
            loads.push((p_vaddr, p_offset, avail));
            if (p_flags & 1) != 0 {
                out.exec_segments.push((p_vaddr, &raw[p_offset..p_offset + avail]));
            }
        } else if p_type == 2 && p_filesz > 0 && p_offset < raw.len() {
            let avail = p_filesz.min(raw.len() - p_offset);
            out.dynamic = &raw[p_offset..p_offset + avail];
        }
    }

    let va_to_off = |va: u64| -> Option<(usize, usize)> {
        for &(seg_va, seg_off, seg_sz) in &loads {
            if va >= seg_va && va < seg_va.saturating_add(seg_sz as u64) {
                let delta = (va - seg_va) as usize;
                return Some((seg_off + delta, seg_sz - delta));
            }
        }
        None
    };

    let mut dt_strtab = 0u64;
    let mut dt_strsz = 0usize;
    let mut dt_symtab = 0u64;
    let mut dt_jmprel = 0u64;
    let mut dt_pltrelsz = 0usize;
    let mut dt_pltrel = if is_64 { 7u64 } else { 17u64 };
    let mut dt_rela = 0u64;
    let mut dt_relasz = 0usize;
    let mut dt_init_array = 0u64;
    let mut dt_init_arraysz = 0usize;

    let dyn_entry_sz = if is_64 { 16 } else { 8 };
    let mut pos = 0usize;
    while pos + dyn_entry_sz <= out.dynamic.len() {
        let (tag, val) = if is_64 {
            (
                u64::from_le_bytes(out.dynamic[pos..pos + 8].try_into().unwrap()),
                u64::from_le_bytes(out.dynamic[pos + 8..pos + 16].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(out.dynamic[pos..pos + 4].try_into().unwrap()) as u64,
                u32::from_le_bytes(out.dynamic[pos + 4..pos + 8].try_into().unwrap()) as u64,
            )
        };
        pos += dyn_entry_sz;
        if tag == 0 {
            break;
        }
        match tag {
            2 => dt_pltrelsz = val as usize,
            3 => out.pltgot_va = val,
            5 => dt_strtab = val,
            6 => dt_symtab = val,
            7 => dt_rela = val,
            8 => dt_relasz = val as usize,
            10 => dt_strsz = val as usize,
            20 => dt_pltrel = val,
            23 => dt_jmprel = val,
            25 => dt_init_array = val,
            27 => dt_init_arraysz = val as usize,
            _ => {}
        }
    }

    out.is_rela = dt_pltrel == 7;
    if dt_strtab != 0 {
        if let Some((off, max_sz)) = va_to_off(dt_strtab) {
            let sz = if dt_strsz > 0 { dt_strsz.min(max_sz) } else { max_sz };
            out.dynstr = &raw[off..off + sz];
        }
    }
    if dt_symtab != 0 {
        if let Some((off, max_sz)) = va_to_off(dt_symtab) {
            let end_off = if dt_strtab > dt_symtab {
                ((dt_strtab - dt_symtab) as usize).min(max_sz)
            } else {
                max_sz
            };
            out.dynsym = &raw[off..off + end_off];
        }
    }
    if dt_jmprel != 0 && dt_pltrelsz > 0 {
        if let Some((off, max_sz)) = va_to_off(dt_jmprel) {
            let sz = dt_pltrelsz.min(max_sz);
            out.jmprel = &raw[off..off + sz];
        }
    }
    if dt_rela != 0 && dt_relasz > 0 {
        if let Some((off, max_sz)) = va_to_off(dt_rela) {
            let sz = dt_relasz.min(max_sz);
            out.rela_dyn = &raw[off..off + sz];
        }
    }
    if dt_init_array != 0 && dt_init_arraysz > 0 {
        out.init_array_va = dt_init_array;
        if let Some((off, max_sz)) = va_to_off(dt_init_array) {
            let sz = dt_init_arraysz.min(max_sz);
            out.init_array = &raw[off..off + sz];
        }
    }

    out
}

fn extract_elf_segments(raw: &[u8], is_64: bool) -> Vec<ElfSegmentDTO> {
    let mut out = Vec::new();
    let (phoff, phentsize, phnum) = if is_64 {
        if raw.len() < 64 {
            return out;
        }
        (
            u64::from_le_bytes(raw[32..40].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[54..56].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[56..58].try_into().unwrap()) as usize,
        )
    } else {
        if raw.len() < 52 {
            return out;
        }
        (
            u32::from_le_bytes(raw[28..32].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[42..44].try_into().unwrap()) as usize,
            u16::from_le_bytes(raw[44..46].try_into().unwrap()) as usize,
        )
    };

    for i in 0..phnum {
        let off = phoff.saturating_add(i.saturating_mul(phentsize));
        let end = match off.checked_add(phentsize) {
            Some(e) if e <= raw.len() => e,
            _ => break,
        };
        let ph = &raw[off..end];
        let (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz) = if is_64 && phentsize >= 56 {
            (
                u32::from_le_bytes(ph[0..4].try_into().unwrap()),
                u32::from_le_bytes(ph[4..8].try_into().unwrap()),
                u64::from_le_bytes(ph[8..16].try_into().unwrap()),
                u64::from_le_bytes(ph[16..24].try_into().unwrap()),
                u64::from_le_bytes(ph[32..40].try_into().unwrap()),
                u64::from_le_bytes(ph[40..48].try_into().unwrap()),
            )
        } else if !is_64 && phentsize >= 32 {
            (
                u32::from_le_bytes(ph[0..4].try_into().unwrap()),
                u32::from_le_bytes(ph[24..28].try_into().unwrap()),
                u32::from_le_bytes(ph[4..8].try_into().unwrap()) as u64,
                u32::from_le_bytes(ph[8..12].try_into().unwrap()) as u64,
                u32::from_le_bytes(ph[16..20].try_into().unwrap()) as u64,
                u32::from_le_bytes(ph[20..24].try_into().unwrap()) as u64,
            )
        } else {
            continue;
        };

        let type_name = match p_type {
            0 => "PT_NULL".to_string(),
            1 => "PT_LOAD".to_string(),
            2 => "PT_DYNAMIC".to_string(),
            3 => "PT_INTERP".to_string(),
            4 => "PT_NOTE".to_string(),
            6 => "PT_PHDR".to_string(),
            7 => "PT_TLS".to_string(),
            0x6474_e550 => "GNU_EH_FRAME".to_string(),
            0x6474_e551 => "GNU_STACK".to_string(),
            0x6474_e552 => "GNU_RELRO".to_string(),
            0x7000_0001 => "ARM_EXIDX".to_string(),
            other => format!("0x{:x}", other),
        };
        let flags = format!(
            "{}{}{}",
            if (p_flags & 4) != 0 { "R" } else { "-" },
            if (p_flags & 2) != 0 { "W" } else { "-" },
            if (p_flags & 1) != 0 { "X" } else { "-" }
        );
        out.push(ElfSegmentDTO {
            p_type: type_name,
            flags,
            vaddr: p_vaddr,
            offset: p_offset,
            filesz: p_filesz,
            memsz: p_memsz,
        });
    }
    out
}

pub struct ElfContext {
    pub path: String,
    pub raw: Vec<u8>,
    pub syms_map: HashMap<u64, SymsDTO>,
    /// Memoized result of `get_info()`. `get_info` re-parses the whole ELF and
    /// rebuilds the symbol/section/segment tables on every call; the UI used to
    /// trigger 4+ of these per function selection. A RwLock-backed Option makes it
    /// a one-time cost while still allowing invalidation when `syms_map` mutates
    /// (rename_function, Il2Cpp symbol injection). A OnceLock could not be reset,
    /// which previously left the UI showing stale symbol names after a rename.
    info_cache: std::sync::RwLock<Option<ElfInfo>>,
    /// Sorted (start, end, name) symbol bounds for O(log n) enclosing-symbol
    /// lookups. Built lazily on first use; invalidated together with info_cache.
    symbol_index: std::sync::RwLock<Option<Vec<(u64, u64, String)>>>,
    /// LIFO undo log: (address, original bytes) pushed before every in-place
    /// patch. `undo_last`/`undo_all` restore them. Shared by every patch path
    /// (quick, assemble, plugin, propagation, hex) so a single Undo covers all.
    undo_stack: Vec<(u64, Vec<u8>)>,
}

impl ElfContext {
    /// A minimal `ElfContext` with no file backing. Use this for tests that only
    /// exercise lifter and codegen logic where the context is passed but never
    /// actually read for ELF data. Avoids requiring committed fixture binaries
    /// in CI environments that can't ship .so files alongside the source.
    ///
    /// Panics if any test using the stub tries to read `raw`, `syms_map`,
    /// `path`, or any other field that would hold real data — the stub's raw
    /// is empty, syms_map is empty, so those reads silently return defaults.
    /// Do NOT use this for tests that decompile or disassemble real code.
    pub fn stub() -> Self {
        Self {
            path: String::from("<stub>"),
            raw: Vec::new(),
            syms_map: HashMap::new(),
            info_cache: std::sync::RwLock::new(None),
            symbol_index: std::sync::RwLock::new(None),
            undo_stack: Vec::new(),
        }
    }

    pub fn open(path: &str) -> Result<Self, String> {
        let raw = fs::read(Path::new(path)).map_err(|e| format!("Failed to read file: {}", e))?;
        if raw.len() < 4 || &raw[0..4] != b"\x7fELF" {
            return Err("Not a valid ELF file".to_string());
        }

        let mut syms_map = HashMap::new();
        if let Ok(obj_file) = object::File::parse(&*raw) {
            let e_machine = match obj_file.architecture() {
                object::Architecture::Arm => 40,
                object::Architecture::Aarch64 => 183,
                object::Architecture::X86_64 => 62,
                object::Architecture::I386 => 3,
                _ => 0,
            };

            for sym in obj_file.dynamic_symbols() {
                if let Ok(name) = sym.name() {
                    if !name.is_empty() && !name.starts_with('$') {
                        let addr = sym.address();
                        let size = sym.size();
                        let is_thumb = if e_machine == 40 {
                            (addr & 1) != 0
                        } else {
                            false
                        };
                        let clean_addr = if e_machine == 40 { addr & !1 } else { addr };
                        let demangled = demangle_name(name);
                        let (jni_class, jni_method) = parse_jni_name(name);
                        syms_map.insert(
                            clean_addr,
                            SymsDTO {
                                sym: name.to_string(),
                                value: clean_addr,
                                size,
                                thumb: is_thumb,
                                demangled,
                                jni_class,
                                jni_method,
                                json: None,
                            },
                        );
                    }
                }
            }
            for sym in obj_file.symbols() {
                if let Ok(name) = sym.name() {
                    if !name.is_empty() && !name.starts_with('$') {
                        let addr = sym.address();
                        let size = sym.size();
                        let is_thumb = if e_machine == 40 {
                            (addr & 1) != 0
                        } else {
                            false
                        };
                        let clean_addr = if e_machine == 40 { addr & !1 } else { addr };
                        let demangled = demangle_name(name);
                        let (jni_class, jni_method) = parse_jni_name(name);
                        syms_map.entry(clean_addr).or_insert(SymsDTO {
                            sym: name.to_string(),
                            value: clean_addr,
                            size,
                            thumb: is_thumb,
                            demangled,
                            jni_class,
                            jni_method,
                            json: None,
                        });
                    }
                }
            }

            // Resolve PLT stub names so imported functions (malloc, free, strlen, __android_log_print)
            // appear with real names in Disassembly, Decompiler, and Call Hierarchy!
            // Falls back to PT_DYNAMIC + PT_LOAD when section headers are stripped/corrupted (e.g. LIAPP).
            let is_64 = matches!(
                obj_file.architecture(),
                object::Architecture::Aarch64
                    | object::Architecture::X86_64
                    | object::Architecture::Riscv64
            );
            let dyn_tables = extract_dynamic_tables(&raw, is_64);

            let plt_section = obj_file.section_by_name(".plt");
            let rela_plt_section = obj_file
                .section_by_name(".rela.plt")
                .or_else(|| obj_file.section_by_name(".rel.plt"));

            let sec_dynstr = obj_file
                .section_by_name(".dynstr")
                .and_then(|s| s.data().ok())
                .unwrap_or(&[]);
            let sec_dynsym = obj_file
                .section_by_name(".dynsym")
                .and_then(|s| s.data().ok())
                .unwrap_or(&[]);

            let dynstr_data = if sec_dynstr.len() > 1 {
                sec_dynstr
            } else {
                dyn_tables.dynstr
            };
            let dynsym_data = if sec_dynsym.len() > dyn_tables.dynsym.len() && sec_dynsym.len() > 256 {
                sec_dynsym
            } else if !dyn_tables.dynsym.is_empty() {
                dyn_tables.dynsym
            } else {
                sec_dynsym
            };

            let (rel_data, is_rela, plt_start, plt_regions): (&[u8], bool, u64, Vec<(u64, &[u8])>) =
                if let (Some(plt), Some(rela_plt)) = (plt_section, rela_plt_section) {
                    let p_bytes = plt.data().unwrap_or(&[]);
                    let r_bytes = rela_plt.data().unwrap_or(&[]);
                    if p_bytes.len() > 16 && r_bytes.len() > 8 {
                        (
                            r_bytes,
                            rela_plt.name().unwrap_or("").contains("rela"),
                            plt.address(),
                            vec![(plt.address(), p_bytes)],
                        )
                    } else {
                        (
                            dyn_tables.jmprel,
                            dyn_tables.is_rela,
                            0,
                            dyn_tables.exec_segments.clone(),
                        )
                    }
                } else {
                    (
                        dyn_tables.jmprel,
                        dyn_tables.is_rela,
                        0,
                        dyn_tables.exec_segments.clone(),
                    )
                };

            if !rel_data.is_empty() && !dynstr_data.is_empty() && !dynsym_data.is_empty() {
                let (header_size, stub_size) = match e_machine {
                    183 => (32u64, 16u64), // AArch64: 32B header, 16B per stub
                    62 => (16u64, 16u64),  // x86_64: 16B header, 16B per stub
                    3 => (16u64, 16u64),   // i386: 16B header, 16B per stub
                    40 => (20u64, 12u64),  // ARM32: 20B header, 12B per stub
                    _ => (16u64, 16u64),
                };

                let get_dynsym_name = |sym_idx: usize| -> Option<String> {
                    let sym_entry_size = if is_64 { 24 } else { 16 };
                    let off = sym_idx * sym_entry_size;
                    if off + 4 <= dynsym_data.len() {
                        let st_name =
                            u32::from_le_bytes(dynsym_data[off..off + 4].try_into().ok()?) as usize;
                        if st_name < dynstr_data.len() {
                            let slice = &dynstr_data[st_name..];
                            if let Some(nul) = slice.iter().position(|&b| b == 0) {
                                return std::str::from_utf8(&slice[..nul])
                                    .ok()
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                    None
                };

                // Decode .plt stubs for AArch64 and ARM32 to map each GOT slot (r_offset)
                // to its exact PLT stub address.
                let mut got_to_stub: HashMap<u64, u64> = HashMap::new();
                if e_machine == 183 {
                    for &(region_va, plt_bytes) in &plt_regions {
                        let mut off = 0usize;
                        while off + 12 <= plt_bytes.len() {
                            let w0 = u32::from_le_bytes(plt_bytes[off..off + 4].try_into().unwrap());
                            let w1 = u32::from_le_bytes(plt_bytes[off + 4..off + 8].try_into().unwrap());
                            let w2 = u32::from_le_bytes(plt_bytes[off + 8..off + 12].try_into().unwrap());
                            let w3 = if off + 16 <= plt_bytes.len() {
                                u32::from_le_bytes(plt_bytes[off + 12..off + 16].try_into().unwrap())
                            } else {
                                0
                            };
                            if (w0 & 0x9F00_001F) == 0x9000_0010
                                && (w1 & 0xFFC0_03FF) == 0xF940_0211
                                && (w2 == 0xD61F_0220 || w3 == 0xD61F_0220)
                            {
                                let pc = region_va + off as u64;
                                let immlo = ((w0 >> 29) & 0x3) as i64;
                                let immhi = ((w0 >> 5) & 0x7_FFFF) as i64;
                                let mut imm21 = (immhi << 2) | immlo;
                                if (imm21 & (1 << 20)) != 0 {
                                    imm21 |= !0x1F_FFFF;
                                }
                                let page = ((pc & !0xFFF) as i64).wrapping_add(imm21 << 12) as u64;
                                let uimm12 = (((w1 >> 10) & 0xFFF) as u64) * 8;
                                let got_addr = page.wrapping_add(uimm12);
                                let stub_start = if off >= 4 {
                                    let prev = u32::from_le_bytes(plt_bytes[off - 4..off].try_into().unwrap());
                                    if prev == 0xD503_245F { pc - 4 } else { pc }
                                } else {
                                    pc
                                };
                                got_to_stub.entry(got_addr).or_insert(stub_start);
                            }
                            off += 4;
                        }
                    }
                } else if e_machine == 40 {
                    for &(region_va, plt_bytes) in &plt_regions {
                        let mut off = 0usize;
                        while off + 12 <= plt_bytes.len() {
                            let w0 = u32::from_le_bytes(plt_bytes[off..off + 4].try_into().unwrap());
                            let w1 = u32::from_le_bytes(plt_bytes[off + 4..off + 8].try_into().unwrap());
                            let w2 = u32::from_le_bytes(plt_bytes[off + 8..off + 12].try_into().unwrap());
                            if (w0 & 0xFFFF_F000) == 0xE28F_C000
                                && (w1 & 0xFFFF_F000) == 0xE28C_C000
                                && (w2 & 0xFFFF_F000) == 0xE5BC_F000
                            {
                                let pc = region_va + off as u64;
                                let imm0 = (w0 & 0xFF).rotate_right(((w0 >> 8) & 0xF) * 2) as u64;
                                let imm1 = (w1 & 0xFF).rotate_right(((w1 >> 8) & 0xF) * 2) as u64;
                                let imm2 = (w2 & 0xFFF) as u64;
                                let got_addr = (pc + 8).wrapping_add(imm0).wrapping_add(imm1).wrapping_add(imm2);
                                got_to_stub.entry(got_addr).or_insert(pc);
                            }
                            off += 4;
                        }
                    }
                } else if e_machine == 62 {
                    for &(region_va, plt_bytes) in &plt_regions {
                        let mut off = 0usize;
                        while off + 12 <= plt_bytes.len() {
                            if plt_bytes[off] == 0xFF
                                && plt_bytes[off + 1] == 0x25
                                && plt_bytes[off + 6] == 0x68
                                && plt_bytes[off + 11] == 0xE9
                            {
                                let pc = region_va + off as u64;
                                let disp = i32::from_le_bytes(
                                    plt_bytes[off + 2..off + 6].try_into().unwrap(),
                                ) as i64;
                                let got_addr = (pc + 6).wrapping_add(disp as u64);
                                let stub_start = if off >= 4
                                    && plt_bytes[off - 4..off] == [0xF3, 0x0F, 0x1E, 0xFA]
                                {
                                    pc - 4
                                } else {
                                    pc
                                };
                                got_to_stub.entry(got_addr).or_insert(stub_start);
                                off += 16;
                                continue;
                            }
                            off += 1;
                        }
                    }
                } else if e_machine == 3 {
                    for &(region_va, plt_bytes) in &plt_regions {
                        let mut off = 0usize;
                        while off + 12 <= plt_bytes.len() {
                            if plt_bytes[off] == 0xFF
                                && (plt_bytes[off + 1] == 0xA3 || plt_bytes[off + 1] == 0x25)
                                && plt_bytes[off + 6] == 0x68
                                && plt_bytes[off + 11] == 0xE9
                            {
                                let pc = region_va + off as u64;
                                let disp = u32::from_le_bytes(
                                    plt_bytes[off + 2..off + 6].try_into().unwrap(),
                                ) as u64;
                                let got_addr = if plt_bytes[off + 1] == 0xA3 {
                                    dyn_tables.pltgot_va.wrapping_add(disp)
                                } else {
                                    disp
                                };
                                got_to_stub.entry(got_addr).or_insert(pc);
                                off += 16;
                                continue;
                            }
                            off += 1;
                        }
                    }
                }

                let entry_size = if is_64 {
                    if is_rela { 24 } else { 16 }
                } else {
                    if is_rela { 12 } else { 8 }
                };

                let count = rel_data.len() / entry_size;
                for idx in 0..count {
                    let entry = &rel_data[idx * entry_size..(idx + 1) * entry_size];
                    let r_offset = if is_64 {
                        u64::from_le_bytes(entry[0..8].try_into().unwrap_or([0; 8]))
                    } else {
                        u32::from_le_bytes(entry[0..4].try_into().unwrap_or([0; 4])) as u64
                    };
                    let sym_idx = if is_64 {
                        let r_info =
                            u64::from_le_bytes(entry[8..16].try_into().unwrap_or([0; 8]));
                        (r_info >> 32) as usize
                    } else {
                        let r_info =
                            u32::from_le_bytes(entry[4..8].try_into().unwrap_or([0; 4]));
                        (r_info >> 8) as usize
                    };

                    if let Some(raw_name) = get_dynsym_name(sym_idx) {
                        let clean_name = raw_name.split('@').next().unwrap_or(&raw_name);
                        if !clean_name.is_empty() {
                            let stub_addr = got_to_stub.get(&r_offset).copied().or_else(|| {
                                if plt_start > 0 {
                                    Some(plt_start + header_size + (idx as u64 * stub_size))
                                } else {
                                    None
                                }
                            });
                            if let Some(stub_addr) = stub_addr {
                                let demangled = demangle_name(clean_name);
                                syms_map.entry(stub_addr).or_insert(SymsDTO {
                                    sym: clean_name.to_string(),
                                    value: stub_addr,
                                    size: stub_size,
                                    thumb: false,
                                    demangled,
                                    jni_class: None,
                                    jni_method: None,
                                    json: None,
                                });
                            }
                        }
                    }
                }
            }

            // Inject .init_array constructors from PT_DYNAMIC only when section headers are
            // stripped/corrupted (e.g. LIAPP), so normal ELFs with hundreds of C++ ctors stay clean.
            let sections_corrupted = obj_file.section_by_name(".text").is_none()
                || obj_file
                    .section_by_name(".init_array")
                    .map(|s| s.size() <= 16)
                    .unwrap_or(true);
            let ptr_sz = if is_64 { 8 } else { 4 };
            if sections_corrupted && !dyn_tables.init_array.is_empty() {
                let mut rela_addends: HashMap<u64, u64> = HashMap::new();
                if is_64 && !dyn_tables.rela_dyn.is_empty() {
                    for chunk in dyn_tables.rela_dyn.chunks_exact(24) {
                        let r_off = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                        let r_add = i64::from_le_bytes(chunk[16..24].try_into().unwrap());
                        if r_add > 0 {
                            rela_addends.insert(r_off, r_add as u64);
                        }
                    }
                }
                let n_init = dyn_tables.init_array.len() / ptr_sz;
                for idx in 0..n_init {
                    let slot_va = dyn_tables.init_array_va + (idx * ptr_sz) as u64;
                    let slot = &dyn_tables.init_array[idx * ptr_sz..(idx + 1) * ptr_sz];
                    let mut raw_ptr = if is_64 {
                        u64::from_le_bytes(slot.try_into().unwrap_or([0; 8]))
                    } else {
                        u32::from_le_bytes(slot.try_into().unwrap_or([0; 4])) as u64
                    };
                    if raw_ptr == 0 {
                        if let Some(&addend) = rela_addends.get(&slot_va) {
                            raw_ptr = addend;
                        }
                    }
                    if raw_ptr != 0 && raw_ptr != u64::MAX {
                        let is_thumb = !is_64 && (raw_ptr & 1) != 0;
                        let clean_ptr = if is_64 { raw_ptr } else { raw_ptr & !1 };
                        syms_map.entry(clean_ptr).or_insert(SymsDTO {
                            sym: format!("init_array_{}", idx),
                            value: clean_ptr,
                            size: 0,
                            thumb: is_thumb,
                            demangled: None,
                            jni_class: None,
                            jni_method: None,
                            json: None,
                        });
                    }
                }
            }
        }

        let mut ctx = Self {
            path: path.to_string(),
            raw,
            syms_map,
            info_cache: std::sync::RwLock::new(None),
            symbol_index: std::sync::RwLock::new(None),
            undo_stack: Vec::new(),
        };
        ctx.scan_dynamic_jni();
        Ok(ctx)
    }

    pub fn get_info(&self) -> Result<ElfInfo, String> {
        // Fast path: return the memoized result instead of re-parsing the ELF.
        if let Ok(guard) = self.info_cache.read() {
            if let Some(cached) = guard.as_ref() {
                return Ok(cached.clone());
            }
        }
        let obj_file =
            object::File::parse(&*self.raw).map_err(|e| format!("Failed to parse ELF: {}", e))?;

        let is_64 = obj_file.is_64();
        let entry = obj_file.entry();

        // Determine e_machine value
        let e_machine = match obj_file.architecture() {
            object::Architecture::Aarch64 => 183, // EM_AARCH64
            object::Architecture::Arm => 40,      // EM_ARM
            object::Architecture::X86_64 => 62,   // EM_X86_64
            object::Architecture::I386 => 3,      // EM_386
            object::Architecture::Riscv64 => 243, // EM_RISCV
            _ => 0,
        };

        let mut soname = String::new();
        let mut libraries = Vec::new();
        let interpreter = None;

        // Extract soname and DT_NEEDED from dynamic section
        let mut dynstr_data = Vec::new();
        let mut dynamic_data = Vec::new();

        for section in obj_file.sections() {
            if let Ok(name) = section.name() {
                if name == ".dynstr" {
                    if let Ok(data) = section.data() {
                        dynstr_data = data.to_vec();
                    }
                } else if name == ".dynamic" {
                    if let Ok(data) = section.data() {
                        dynamic_data = data.to_vec();
                    }
                }
            }
        }

        if dynstr_data.len() <= 1 || dynamic_data.len() <= 1 {
            let dyn_tables = extract_dynamic_tables(&self.raw, is_64);
            if dynstr_data.len() <= 1 && !dyn_tables.dynstr.is_empty() {
                dynstr_data = dyn_tables.dynstr.to_vec();
            }
            if dynamic_data.len() <= 1 && !dyn_tables.dynamic.is_empty() {
                dynamic_data = dyn_tables.dynamic.to_vec();
            }
        }

        if !dynstr_data.is_empty() && !dynamic_data.is_empty() {
            let read_dyn_str = |off: usize| -> Option<String> {
                if off < dynstr_data.len() {
                    let slice = &dynstr_data[off..];
                    if let Some(nul) = slice.iter().position(|&b| b == 0) {
                        return Some(String::from_utf8_lossy(&slice[..nul]).to_string());
                    }
                }
                None
            };

            if is_64 {
                for chunk in dynamic_data.as_chunks::<16>().0 {
                    let tag = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                    let val = u64::from_le_bytes(chunk[8..16].try_into().unwrap()) as usize;
                    if tag == 1 {
                        // DT_NEEDED
                        if let Some(lib_name) = read_dyn_str(val) {
                            libraries.push(lib_name);
                        }
                    } else if tag == 14 {
                        // DT_SONAME
                        if let Some(s) = read_dyn_str(val) {
                            soname = s;
                        }
                    }
                }
            } else {
                for chunk in dynamic_data.as_chunks::<8>().0 {
                    let tag = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as u64;
                    let val = u32::from_le_bytes(chunk[4..8].try_into().unwrap()) as usize;
                    if tag == 1 {
                        // DT_NEEDED
                        if let Some(lib_name) = read_dyn_str(val) {
                            libraries.push(lib_name);
                        }
                    } else if tag == 14 {
                        // DT_SONAME
                        if let Some(s) = read_dyn_str(val) {
                            soname = s;
                        }
                    }
                }
            }
        }

        // Extract symbols (.dynsym and .symtab)
        let mut syms_map = std::collections::HashMap::new();

        // 1. Dynamic symbols
        for sym in obj_file.dynamic_symbols() {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    let addr = sym.address();
                    let size = sym.size();
                    let is_thumb = (addr & 1) != 0;
                    let clean_addr = addr & !1;
                    let demangled = demangle_name(name);
                    let (jni_class, jni_method) = parse_jni_name(name);
                    syms_map.insert(
                        clean_addr,
                        SymsDTO {
                            sym: name.to_string(),
                            value: clean_addr,
                            size,
                            thumb: is_thumb,
                            demangled,
                            jni_class,
                            jni_method,
                            json: None,
                        },
                    );
                }
            }
        }

        let mut syms: Vec<SymsDTO> = self.syms_map.values().cloned().collect();
        syms.sort_by_key(|s| s.value);

        let segments = extract_elf_segments(&self.raw, is_64);
        let mut sections = Vec::new();
        for sec in obj_file.sections() {
            let name = sec.name().unwrap_or("").to_string();
            let (offset, _) = sec.file_range().unwrap_or((0, 0));
            let flags = if let object::SectionFlags::Elf { sh_flags, .. } = sec.flags() {
                let sh_flags = sh_flags.0;
                format!(
                    "{}{}{}",
                    if (sh_flags & 0x2) != 0 { "A" } else { "-" },
                    if (sh_flags & 0x1) != 0 { "W" } else { "-" },
                    if (sh_flags & 0x4) != 0 { "X" } else { "-" }
                )
            } else {
                "---".to_string()
            };
            let sh_type = format!("{:?}", sec.kind());
            sections.push(ElfSectionDTO {
                name,
                sh_type,
                flags,
                vaddr: sec.address(),
                offset,
                size: sec.size(),
            });
        }

        let info = ElfInfo {
            e_machine,
            entry,
            is_64,
            soname,
            interpreter,
            libraries,
            syms,
            yara: Vec::new(),
            segments,
            sections,
        };
        // Cache the successful build. If another thread raced us, keep whichever
        // value landed first; both are identical in content.
        if let Ok(mut guard) = self.info_cache.write() {
            if guard.is_none() {
                *guard = Some(info.clone());
            }
        }
        Ok(info)
    }

    /// Return the name of the symbol whose address range encloses `vaddr`.
    /// Uses an exact-match fast path, then a binary search over a lazily-built
    /// sorted (start, end, name) table. This replaces the previous O(n) linear
    /// scan that `plugins::find_enclosing_symbol` did for every finding.
    pub fn enclosing_symbol(&self, vaddr: u64) -> Option<String> {
        if let Some(sym) = self.syms_map.get(&vaddr) {
            return Some(sym.demangled.clone().unwrap_or_else(|| sym.sym.clone()));
        }
        // Lazily build the sorted symbol index under a write lock, then read it
        // back under a read lock for the binary search. The index is invalidated
        // (reset to None) whenever syms_map mutates, so it is rebuilt on demand.
        if let Ok(mut guard) = self.symbol_index.write() {
            if guard.is_none() {
                let mut v: Vec<(u64, u64, String)> = self
                    .syms_map
                    .iter()
                    .filter(|(addr, _)| **addr != 0)
                    .map(|(&addr, sym)| {
                        let end = if sym.size > 0 {
                            addr.saturating_add(sym.size)
                        } else {
                            addr.saturating_add(0x1000)
                        };
                        (addr, end, sym.demangled.clone().unwrap_or_else(|| sym.sym.clone()))
                    })
                    .collect();
                v.sort_by_key(|e| e.0);
                *guard = Some(v);
            }
        }
        let index_guard = match self.symbol_index.read() {
            Ok(g) => g,
            Err(_) => return None,
        };
        let index = match index_guard.as_ref() {
            Some(v) => v,
            None => return None,
        };
        // Find the greatest start <= vaddr, then verify vaddr < its end.
        match index.binary_search_by(|e| {
            if e.0 <= vaddr {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        }) {
            Ok(_) => None, // exact start handled above; should not reach here
            Err(0) => None,
            Err(pos) => {
                let (_, end, name) = &index[pos - 1];
                if vaddr < *end {
                    Some(name.clone())
                } else {
                    None
                }
            }
        }
    }

    /// Return the smallest symbol start address strictly greater than `vaddr`.
    /// Used to bound a function's extent so a size-0 / unknown symbol cannot
    /// decode into the following function before hitting a terminator.
    /// Reuses the same lazily-built sorted symbol index as `enclosing_symbol`.
    pub fn next_symbol_start(&self, vaddr: u64) -> Option<u64> {
        if let Ok(mut guard) = self.symbol_index.write() {
            if guard.is_none() {
                let mut v: Vec<(u64, u64, String)> = self
                    .syms_map
                    .iter()
                    .filter(|(addr, _)| **addr != 0)
                    .map(|(&addr, sym)| {
                        let end = if sym.size > 0 {
                            addr.saturating_add(sym.size)
                        } else {
                            addr.saturating_add(0x1000)
                        };
                        (addr, end, sym.demangled.clone().unwrap_or_else(|| sym.sym.clone()))
                    })
                    .collect();
                v.sort_by_key(|e| e.0);
                *guard = Some(v);
            }
        }
        let index_guard = self.symbol_index.read().ok()?;
        let index = index_guard.as_ref()?;
        // First entry whose start is strictly greater than vaddr.
        let pos = index.partition_point(|e| e.0 <= vaddr);
        index.get(pos).map(|e| e.0)
    }

    /// Invalidate the memoized `get_info()` result and the sorted symbol index.
    /// MUST be called after any mutation of `syms_map` (rename_function, Il2Cpp
    /// symbol injection) so the next `get_info()` / `enclosing_symbol()` rebuild
    /// from the current symbol table instead of returning stale data.
    pub fn invalidate_symbol_caches(&self) {
        if let Ok(mut g) = self.info_cache.write() {
            *g = None;
        }
        if let Ok(mut g) = self.symbol_index.write() {
            *g = None;
        }
    }

    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<u64> {
        if vaddr == 0 {
            return None;
        }
        let obj_file = object::File::parse(&*self.raw).ok()?;

        // 1. Try Section Headers first
        for section in obj_file.sections() {
            let sec_addr = section.address();
            let sec_size = section.size();
            // In ELF, sections not loaded into memory have VMA 0; only allocated sections have valid VMA
            if sec_addr == 0 || sec_size == 0 {
                continue;
            }
            if let Some(sec_end) = sec_addr.checked_add(sec_size) {
                if vaddr >= sec_addr && vaddr < sec_end {
                    if let Some((file_off, _)) = section.file_range() {
                        return Some(file_off + (vaddr - sec_addr));
                    }
                }
            }
        }

        // 2. Program Headers (PT_LOAD Segments) Fallback for stripped / packed binaries
        for segment in obj_file.segments() {
            let seg_addr = segment.address();
            let seg_size = segment.size();
            if seg_size == 0 {
                continue;
            }
            if let Some(seg_end) = seg_addr.checked_add(seg_size) {
                if vaddr >= seg_addr && vaddr < seg_end {
                    let (file_off, file_size) = segment.file_range();
                    let delta = vaddr - seg_addr;
                    if delta < file_size {
                        return Some(file_off + delta);
                    }
                }
            }
        }

        None
    }

    /// True when `vaddr` lies inside a loadable segment's *memory* image but
    /// beyond its file-backed bytes — i.e. a `.bss` / `NOBITS` section or the
    /// zero-fill tail of a `PT_LOAD` segment (`p_memsz > p_filesz`). Such bytes
    /// read as 0 at runtime but have no backing bytes in `self.raw`.
    pub fn is_zero_fill_vaddr(&self, vaddr: u64) -> bool {
        if vaddr == 0 {
            return false;
        }
        let obj_file = match object::File::parse(&*self.raw) {
            Ok(f) => f,
            Err(_) => return false,
        };

        // NOBITS sections (.bss, .tbss) have an address+size but no file range.
        for section in obj_file.sections() {
            let sec_addr = section.address();
            let sec_size = section.size();
            if sec_addr == 0 || sec_size == 0 {
                continue;
            }
            if let Some(sec_end) = sec_addr.checked_add(sec_size) {
                if vaddr >= sec_addr && vaddr < sec_end {
                    match section.file_range() {
                        Some((_, fsize)) if (vaddr - sec_addr) < fsize => return false,
                        _ => return true,
                    }
                }
            }
        }

        // Segment tail: inside p_memsz but past p_filesz.
        for segment in obj_file.segments() {
            let seg_addr = segment.address();
            let seg_size = segment.size();
            if seg_size == 0 {
                continue;
            }
            if let Some(seg_end) = seg_addr.checked_add(seg_size) {
                if vaddr >= seg_addr && vaddr < seg_end {
                    let (_, file_size) = segment.file_range();
                    return (vaddr - seg_addr) >= file_size;
                }
            }
        }

        false
    }

    pub fn offset_to_vaddr(&self, offset: u64) -> Option<u64> {
        let obj_file = object::File::parse(&*self.raw).ok()?;

        for section in obj_file.sections() {
            if let Some((file_off, file_size)) = section.file_range() {
                if offset >= file_off && offset < file_off + file_size {
                    return Some(section.address() + (offset - file_off));
                }
            }
        }

        for segment in obj_file.segments() {
            let (file_off, file_size) = segment.file_range();
            if offset >= file_off && offset < file_off + file_size {
                return Some(segment.address() + (offset - file_off));
            }
        }

        None
    }

    pub fn get_string_at_vaddr(&self, vaddr: u64) -> Option<String> {
        let offset = self.vaddr_to_offset(vaddr)? as usize;
        if offset >= self.raw.len() {
            return None;
        }
        let slice = &self.raw[offset..];
        let end = slice.iter().position(|&b| b == 0)?;
        if (2..=80).contains(&end) {
            if let Ok(s) = std::str::from_utf8(&slice[..end]) {
                if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        // Correctness: an address only counts as executable if it provably falls
        // inside an executable section OR an executable PT_LOAD segment. The
        // previous fallback returned `true` for ANY address that matched no
        // region (and for any unparseable file), which let `validate_patch_target`
        // accept writes into .rodata/.data or into a completely bogus vaddr.
        //
        // Section-stripped/packed ELFs (e.g. LIAPP) are still handled: their
        // PT_LOAD segments carry the real PF_X flag, and the segment loop below
        // is authoritative when no section claims the address.
        let obj = match object::File::parse(&*self.raw) {
            Ok(o) => o,
            // Cannot prove executability without a parseable object; refuse.
            Err(_) => return false,
        };
        use object::{Object, ObjectSection};
        for section in obj.sections() {
            let start = section.address();
            let size = section.size();
            if size > 0 && address >= start && address < start.saturating_add(size) {
                let name = section.name().unwrap_or("");
                if name.contains("text")
                    || name.contains("plt")
                    || name.contains("init")
                    || name.contains("fini")
                {
                    return true;
                }
                if let object::SectionFlags::Elf { sh_flags, .. } = section.flags() {
                    let shf_execinstr = 0x4u64;
                    if (sh_flags.0 & shf_execinstr) != 0 {
                        return true;
                    }
                }
                // Address is inside a *known* non-executable section: definitively false.
                return false;
            }
        }
        use object::ObjectSegment;
        for segment in obj.segments() {
            let start = segment.address();
            let size = segment.size();
            if size > 0 && address >= start && address < start.saturating_add(size) {
                if let object::SegmentFlags::Elf { p_flags, .. } = segment.flags() {
                    return (p_flags.0 & 1) != 0; // PF_X = 1
                }
                // Segment found but flags are non-ELF: cannot prove executable.
                return false;
            }
        }
        // Not inside any section or segment: not executable.
        false
    }

    pub fn get_section_name_for_vaddr(&self, address: u64) -> Option<String> {
        if let Ok(obj) = object::File::parse(&*self.raw) {
            use object::{Object, ObjectSection};
            for section in obj.sections() {
                let start = section.address();
                let size = section.size();
                if address >= start && address < start + size {
                    return section.name().ok().map(|s| s.to_string());
                }
            }
        }
        None
    }

    pub fn scan_dynamic_jni(&mut self) -> usize {
        let is_64 = match object::File::parse(&*self.raw) {
            Ok(f) => f.is_64(),
            Err(_) => true,
        };

        let mut data_slices: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut text_range: Option<(u64, u64)> = None;

        if let Ok(obj_file) = object::File::parse(&*self.raw) {
            for sec in obj_file.sections() {
                let name = sec.name().unwrap_or("");
                if name == ".text" {
                    text_range = Some((sec.address(), sec.address() + sec.size()));
                } else if name == ".data" || name == ".rodata" || name == ".data.rel.ro" {
                    if let Ok(bytes) = sec.data() {
                        data_slices.push((sec.address(), bytes.to_vec()));
                    }
                }
            }
        }

        let (text_start, text_end) = match text_range {
            Some(r) => r,
            None => return 0,
        };

        let mut discovered = Vec::new();

        for (_sec_vaddr, sec_data) in data_slices {
            if is_64 {
                // 64-bit JNINativeMethod: 24 bytes (name: 8B, sig: 8B, fnPtr: 8B)
                for chunk in sec_data.as_chunks::<24>().0 {
                    let name_ptr = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
                    let sig_ptr = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
                    let fn_ptr = u64::from_le_bytes(chunk[16..24].try_into().unwrap());

                    if fn_ptr >= text_start && fn_ptr < text_end {
                        if let Some(sig) = self.get_string_at_vaddr(sig_ptr) {
                            if sig.starts_with('(') && sig.contains(')') {
                                if let Some(name) = self.get_string_at_vaddr(name_ptr) {
                                    if !name.is_empty()
                                        && name.len() < 64
                                        && name
                                            .chars()
                                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                                    {
                                        discovered.push((fn_ptr, name, sig));
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // 32-bit ARM (armeabi-v7a) JNINativeMethod: 12 bytes (name: 4B, sig: 4B, fnPtr: 4B)
                for chunk in sec_data.as_chunks::<12>().0 {
                    let name_ptr = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as u64;
                    let sig_ptr = u32::from_le_bytes(chunk[4..8].try_into().unwrap()) as u64;
                    let fn_ptr = u32::from_le_bytes(chunk[8..12].try_into().unwrap()) as u64;

                    let clean_fn = fn_ptr & !1;
                    if clean_fn >= text_start && clean_fn < text_end {
                        if let Some(sig) = self.get_string_at_vaddr(sig_ptr) {
                            if sig.starts_with('(') && sig.contains(')') {
                                if let Some(name) = self.get_string_at_vaddr(name_ptr) {
                                    if !name.is_empty()
                                        && name.len() < 64
                                        && name
                                            .chars()
                                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                                    {
                                        discovered.push((fn_ptr, name, sig));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let count = discovered.len();
        for (fn_ptr, name, sig) in discovered {
            let clean_addr = fn_ptr & !1;
            let display = format!("{} [Dynamic JNI]", name);
            self.syms_map.insert(
                clean_addr,
                SymsDTO {
                    sym: display.clone(),
                    value: clean_addr,
                    size: 0,
                    thumb: false,
                    demangled: Some(display),
                    jni_class: None,
                    jni_method: Some(name),
                    json: Some(sig),
                },
            );
        }

        count
    }

    pub fn rename_function(&mut self, address: u64, new_name: &str) -> bool {
        let clean_addr = address & !1;
        if let Some(sym) = self.syms_map.get_mut(&clean_addr) {
            sym.sym = new_name.to_string();
            sym.demangled = Some(new_name.to_string());
        } else {
            self.syms_map.insert(
                clean_addr,
                SymsDTO {
                    sym: new_name.to_string(),
                    value: clean_addr,
                    size: 0,
                    thumb: false,
                    demangled: Some(new_name.to_string()),
                    jni_class: None,
                    jni_method: Some(new_name.to_string()),
                    json: None,
                },
            );
        }
        // The memoized ElfInfo (get_info) and the enclosing-symbol index both
        // derive from syms_map; drop them so the next query reflects the rename.
        self.invalidate_symbol_caches();
        true
    }

    pub fn extract_strings(&self) -> Result<SData, String> {
        let obj_file =
            object::File::parse(&*self.raw).map_err(|e| format!("Failed to parse ELF: {}", e))?;

        let mut items = Vec::new();

        for section in obj_file.sections() {
            let name = section.name().unwrap_or("");
            // Scan data / string sections
            if name == ".rodata" || name == ".data" || name == ".data.rel.ro" || name == ".dynstr" {
                if let Ok(data) = section.data() {
                    let sec_vaddr = section.address();
                    let (sec_paddr, _) = section.file_range().unwrap_or((0, 0));

                    let mut i = 0;
                    while i < data.len() {
                        if data[i].is_ascii_graphic() {
                            let start = i;
                            while i < data.len() && data[i] >= 0x20 && data[i] <= 0x7e {
                                i += 1;
                            }
                            let len = i - start;
                            if len >= 4 {
                                // Minimum string length threshold
                                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                                    items.push(SDataItem {
                                        paddr: sec_paddr + start as u64,
                                        vaddr: sec_vaddr + start as u64,
                                        size: len,
                                        string: s.to_string(),
                                    });
                                }
                            }
                        }
                        i += 1;
                    }
                }
            }
        }

        // Fallback for section-stripped / section-corrupted ELFs (e.g. LIAPP):
        // scan PT_LOAD segments for NUL-terminated or >= 5-char printable ASCII strings.
        if items.is_empty() {
            for segment in obj_file.segments() {
                if let Ok(data) = segment.data() {
                    let seg_vaddr = segment.address();
                    let (seg_paddr, _) = segment.file_range();
                    let is_exec = matches!(
                        segment.flags(),
                        object::SegmentFlags::Elf { p_flags, .. } if (p_flags.0 & 1) != 0
                    );
                    let mut i = 0usize;
                    while i < data.len() {
                        if data[i].is_ascii_graphic() {
                            let start = i;
                            while i < data.len() && data[i] >= 0x20 && data[i] <= 0x7e {
                                i += 1;
                            }
                            let len = i - start;
                            let nul_term = data.get(i) == Some(&0);
                            let min_len = if is_exec && !nul_term { 6 } else { 4 };
                            if len >= min_len && (!is_exec || nul_term || len >= 6) {
                                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                                    items.push(SDataItem {
                                        paddr: seg_paddr + start as u64,
                                        vaddr: seg_vaddr + start as u64,
                                        size: len,
                                        string: s.to_string(),
                                    });
                                }
                            }
                        }
                        i += 1;
                    }
                }
            }
        }

        Ok(SData { data: items })
    }

    pub fn read_string_at(&self, address: u64, max_len: u64) -> String {
        if let Some(off) = self.vaddr_to_offset(address) {
            let off = off as usize;
            if off < self.raw.len() {
                let limit = std::cmp::min(self.raw.len(), off + max_len as usize);
                let slice = &self.raw[off..limit];
                if let Some(nul) = slice.iter().position(|&b| b == 0) {
                    return String::from_utf8_lossy(&slice[..nul]).to_string();
                } else {
                    return String::from_utf8_lossy(slice).to_string();
                }
            }
        }
        String::new()
    }

    pub fn patch_bytes(&mut self, address: u64, patch: &[u8]) -> Result<(), String> {
        let offset = self.vaddr_to_offset(address).ok_or_else(|| {
            format!(
                "Could not map virtual address 0x{:x} to file offset",
                address
            )
        })? as usize;

        if offset + patch.len() > self.raw.len() {
            return Err("Patch exceeds file boundary".to_string());
        }

        // Record undo before mutating, so this path is reversible too.
        self.undo_stack
            .push((address, self.raw[offset..offset + patch.len()].to_vec()));
        self.raw[offset..offset + patch.len()].copy_from_slice(patch);
        Ok(())
    }

    /// Record an undo entry for an in-place write that bypasses `patch_bytes`
    /// (quick/assemble/plugin/propagation write `raw` directly after their own
    /// validation). Call this immediately before such a write.
    pub fn push_undo(&mut self, address: u64, original: Vec<u8>) {
        self.undo_stack.push((address, original));
    }

    /// Number of reversible patches currently recorded.
    pub fn undo_len(&self) -> usize {
        self.undo_stack.len()
    }

    /// Revert the most recent patch. Returns Some(address) on success, None if
    /// the stack is empty or the address no longer maps.
    pub fn undo_last(&mut self) -> Option<u64> {
        let (address, original) = self.undo_stack.pop()?;
        let offset = self.vaddr_to_offset(address)? as usize;
        if offset + original.len() > self.raw.len() {
            return None;
        }
        self.raw[offset..offset + original.len()].copy_from_slice(&original);
        Some(address)
    }

    /// Revert every recorded patch, newest first. Returns how many were undone.
    #[allow(dead_code)]
    pub fn undo_all(&mut self) -> usize {
        let mut n = 0;
        while self.undo_last().is_some() {
            n += 1;
        }
        n
    }
}

fn parse_jni_name(sym: &str) -> (Option<String>, Option<String>) {
    if !sym.starts_with("Java_") {
        return (None, None);
    }
    let rest = &sym[5..];
    let parts: Vec<&str> = rest.split('_').collect();
    if parts.len() >= 2 {
        let method = parts.last().unwrap().to_string();
        let class = parts[..parts.len() - 1].join(".");
        (Some(class), Some(method))
    } else {
        (None, None)
    }
}

fn demangle_name(sym: &str) -> Option<String> {
    if sym.starts_with("_Z") {
        if let Ok(sym_obj) = cpp_demangle::Symbol::new(sym) {
            return Some(sym_obj.demangle().unwrap_or_else(|_| sym.to_string()));
        }
    }
    None
}
