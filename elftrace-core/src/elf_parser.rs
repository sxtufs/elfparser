use crate::model::{ElfInfo, SData, SDataItem, SymsDTO};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct ElfContext {
    pub path: String,
    pub raw: Vec<u8>,
    pub vcpu: Option<crate::tracer::Tracer>,
    pub syms_map: HashMap<u64, SymsDTO>,
    /// Last tracer-initialization failure, surfaced to the UI instead of being
    /// silently dropped when `Tracer::new` fails.
    pub trace_init_error: Option<String>,
    /// True once `traceInit` has been called, so the UI can distinguish
    /// "init never ran" from "init ran and failed/succeeded".
    pub trace_inited: bool,
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
            vcpu: None,
            syms_map: HashMap::new(),
            trace_init_error: None,
            trace_inited: false,
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
            let plt_section = obj_file.section_by_name(".plt");
            let rela_plt_section = obj_file
                .section_by_name(".rela.plt")
                .or_else(|| obj_file.section_by_name(".rel.plt"));
            let dynstr_data = obj_file
                .section_by_name(".dynstr")
                .and_then(|s| s.data().ok())
                .unwrap_or(&[]);
            let dynsym_data = obj_file
                .section_by_name(".dynsym")
                .and_then(|s| s.data().ok())
                .unwrap_or(&[]);

            if let (Some(plt), Some(rela_plt)) = (plt_section, rela_plt_section) {
                let plt_start = plt.address();
                let is_64 = matches!(
                    obj_file.architecture(),
                    object::Architecture::Aarch64
                        | object::Architecture::X86_64
                        | object::Architecture::Riscv64
                );
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

                if let Ok(rel_data) = rela_plt.data() {
                    let is_rela = rela_plt.name().unwrap_or("").contains("rela");
                    let entry_size = if is_64 {
                        if is_rela {
                            24
                        } else {
                            16
                        }
                    } else {
                        if is_rela {
                            12
                        } else {
                            8
                        }
                    };

                    let count = rel_data.len() / entry_size;
                    for idx in 0..count {
                        let entry = &rel_data[idx * entry_size..(idx + 1) * entry_size];
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
                                let stub_addr = plt_start + header_size + (idx as u64 * stub_size);
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
        }

        let mut ctx = Self {
            path: path.to_string(),
            raw,
            vcpu: None,
            syms_map,
            trace_init_error: None,
            trace_inited: false,
        };
        ctx.scan_dynamic_jni();
        Ok(ctx)
    }

    pub fn get_info(&self) -> Result<ElfInfo, String> {
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

        Ok(ElfInfo {
            e_machine,
            entry,
            is_64,
            soname,
            interpreter,
            libraries,
            syms,
            yara: Vec::new(),
        })
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
        if let Ok(obj) = object::File::parse(&*self.raw) {
            use object::{Object, ObjectSection};
            for section in obj.sections() {
                let start = section.address();
                let size = section.size();
                if address >= start && address < start + size {
                    let name = section.name().unwrap_or("");
                    if name.contains("text")
                        || name.contains("plt")
                        || name.contains("init")
                        || name.contains("fini")
                    {
                        return true;
                    }
                    if let object::SectionFlags::Elf { sh_flags } = section.flags() {
                        let shf_execinstr = 0x4u64;
                        if (sh_flags & shf_execinstr) != 0 {
                            return true;
                        }
                    }
                    return false;
                }
            }
            use object::ObjectSegment;
            for segment in obj.segments() {
                let start = segment.address();
                let size = segment.size();
                if address >= start && address < start + size {
                    if let object::SegmentFlags::Elf { p_flags } = segment.flags() {
                        return (p_flags & 1) != 0; // PF_X = 1
                    }
                }
            }
        }
        true
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
            true
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
            true
        }
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

        self.raw[offset..offset + patch.len()].copy_from_slice(patch);
        Ok(())
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
            return Some(sym_obj.to_string());
        }
    }
    None
}
