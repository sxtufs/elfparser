//! Fixture tests for the two ways symbols enter `ElfContext`:
//!
//! * `.symtab` — a local-only symbol that exists nowhere in `.dynsym` must
//!   still show up in `get_info().syms`. Regression guard for the shadowed
//!   symbol table that `get_info` used to build and throw away.
//! * discovery — a stripped function that is only reachable through a direct
//!   `bl` must be recovered as `sub_XXXXXXXX`.

use elftrace::discovery::scan_region_for_calls;
use elftrace::elf_parser::ElfContext;
use std::collections::HashSet;

/// Offsets in the synthetic ELF built by [`fixture_elf`].
const TEXT_ADDR: u64 = 0x1000;
const TEXT_OFF: usize = 0x40;
const TEXT_SIZE: usize = 0x20;
const SYMTAB_OFF: usize = 0x60;
const STRTAB_OFF: usize = 0x90;
const SHSTRTAB_OFF: usize = 0xa0;
const SHOFF: usize = 0xc8;

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Minimal ELF64 AArch64 object with:
/// * `.text` at 0x1000: `ret`, `bl 0x1010`, then `nop`s
/// * `.symtab` holding one LOCAL FUNC `local_helper` @ 0x1000 (not in .dynsym)
/// * no program headers (so discovery falls back to code sections)
fn fixture_elf() -> Vec<u8> {
    let mut buf = vec![0u8; SHOFF + 5 * 64];

    // e_ident
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    put_u32(&mut buf, 16, 3); // ET_DYN
    put_u16(&mut buf, 18, 183); // EM_AARCH64
    put_u32(&mut buf, 20, 1);
    put_u64(&mut buf, 24, TEXT_ADDR); // e_entry
    put_u64(&mut buf, 32, 0); // e_phoff
    put_u64(&mut buf, 40, SHOFF as u64); // e_shoff
    put_u32(&mut buf, 48, 0); // e_flags
    put_u16(&mut buf, 52, 64); // e_ehsize
    put_u16(&mut buf, 54, 0); // e_phentsize
    put_u16(&mut buf, 56, 0); // e_phnum
    put_u16(&mut buf, 58, 64); // e_shentsize
    put_u16(&mut buf, 60, 5); // e_shnum
    put_u16(&mut buf, 62, 4); // e_shstrndx

    // .text: ret; bl 0x1010 (offset 0xC => imm26 = 3); nop * 6
    let text = TEXT_OFF;
    put_u32(&mut buf, text, 0xd65f_03c0);
    put_u32(&mut buf, text + 4, 0x9400_0003);
    for i in 2..(TEXT_SIZE / 4) {
        put_u32(&mut buf, text + i * 4, 0xd503_201f);
    }

    // .symtab: null entry + local_helper
    put_u32(&mut buf, SYMTAB_OFF + 24, 1); // st_name -> "\0local_helper"
    buf[SYMTAB_OFF + 24 + 4] = 0x02; // STB_LOCAL | STT_FUNC
    put_u16(&mut buf, SYMTAB_OFF + 24 + 6, 1); // st_shndx = .text
    put_u64(&mut buf, SYMTAB_OFF + 24 + 8, TEXT_ADDR);
    put_u64(&mut buf, SYMTAB_OFF + 24 + 16, 0x10);

    // .strtab
    buf[STRTAB_OFF..STRTAB_OFF + 14].copy_from_slice(b"\0local_helper\0");
    // .shstrtab
    let shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    buf[SHSTRTAB_OFF..SHSTRTAB_OFF + shstr.len()].copy_from_slice(shstr);

    let sh = |i: usize| SHOFF + i * 64;
    // [1] .text
    put_u32(&mut buf, sh(1), 1); // sh_name
    put_u32(&mut buf, sh(1) + 4, 1); // SHT_PROGBITS
    put_u64(&mut buf, sh(1) + 8, 0x6); // SHF_ALLOC | SHF_EXECINSTR
    put_u64(&mut buf, sh(1) + 16, TEXT_ADDR);
    put_u64(&mut buf, sh(1) + 24, TEXT_OFF as u64);
    put_u64(&mut buf, sh(1) + 32, TEXT_SIZE as u64);
    put_u64(&mut buf, sh(1) + 48, 4);
    // [2] .symtab
    put_u32(&mut buf, sh(2), 7);
    put_u32(&mut buf, sh(2) + 4, 2); // SHT_SYMTAB
    put_u64(&mut buf, sh(2) + 24, SYMTAB_OFF as u64);
    put_u64(&mut buf, sh(2) + 32, 48);
    put_u32(&mut buf, sh(2) + 40, 3); // sh_link -> .strtab
    put_u32(&mut buf, sh(2) + 44, 2); // sh_info -> first global
    put_u64(&mut buf, sh(2) + 48, 8);
    put_u64(&mut buf, sh(2) + 56, 24);
    // [3] .strtab
    put_u32(&mut buf, sh(3), 15);
    put_u32(&mut buf, sh(3) + 4, 3); // SHT_STRTAB
    put_u64(&mut buf, sh(3) + 24, STRTAB_OFF as u64);
    put_u64(&mut buf, sh(3) + 32, 14);
    put_u64(&mut buf, sh(3) + 48, 1);
    // [4] .shstrtab
    put_u32(&mut buf, sh(4), 23);
    put_u32(&mut buf, sh(4) + 4, 3);
    put_u64(&mut buf, sh(4) + 24, SHSTRTAB_OFF as u64);
    put_u64(&mut buf, sh(4) + 32, shstr.len() as u64);
    put_u64(&mut buf, sh(4) + 48, 1);

    buf
}

fn write_fixture(name: &str) -> String {
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, fixture_elf()).unwrap();
    path.to_string_lossy().into_owned()
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn test_symtab_local_symbol_is_visible_in_info() {
    let path = write_fixture("elftrace_symtab_fixture.so");
    let ctx = ElfContext::open(&path).expect("fixture ELF should open");
    let info = ctx.get_info().expect("fixture ELF should parse");
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "local_helper")
        .unwrap_or_else(|| {
            panic!(
                "local .symtab symbol missing; symbols seen: {:?}",
                info.syms.iter().map(|s| &s.sym).collect::<Vec<_>>()
            )
        });
    assert_eq!(sym.value, TEXT_ADDR);
    assert_eq!(sym.size, 0x10);
}

#[test]
fn test_scan_aarch64_bl_is_collected() {
    let mut out = HashSet::new();
    // ret; bl 0x1100 (from 0x1004: +0xFC => imm26 = 0x3F)
    let mut code = Vec::new();
    code.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
    code.extend_from_slice(&0x9400_003fu32.to_le_bytes());
    scan_region_for_calls(183, 0x1000, &code, &mut out);
    assert_eq!(out.into_iter().collect::<Vec<_>>(), vec![0x1100u64]);
}

#[test]
fn test_scan_thumb_bl_is_collected() {
    let mut out = HashSet::new();
    // bl 0x2100 from 0x2000 (thumb target bit set on the branch)
    let code = [0x00u8, 0xf0, 0x7e, 0xf8];
    scan_region_for_calls(40, 0x2000, &code, &mut out);
    assert_eq!(out.into_iter().collect::<Vec<_>>(), vec![0x2100u64]);
}

#[test]
fn test_discover_functions_recovers_bl_target() {
    let path = write_fixture("elftrace_discovery_fixture.so");
    let mut ctx = ElfContext::open(&path).expect("fixture ELF should open");
    let report = ctx.discover_functions(1 << 20);

    assert_eq!(report.added, 1, "one unstripped call target expected");
    let f = &report.functions[0];
    assert_eq!(f.address, 0x1010);
    assert_eq!(f.name, "sub_00001010");
    assert_eq!(f.size, 0x10, "size is the distance to the end of .text");

    let info = ctx.get_info().expect("info after discovery");
    assert!(info.syms.iter().any(|s| s.sym == "local_helper"));
}

#[test]
fn test_scan_for_function_end_aarch64_bounds_at_ret() {
    use elftrace::discovery::{is_aarch64_fp_prologue, scan_for_function_end_aarch64};

    // Prologue check: stp x29, x30, [sp, #-16]! => 0xA9BF7BFD (little-endian
    // encoding: opc=10, imm7=-2, Rt2=30, Rn=31, Rt=29).
    assert!(is_aarch64_fp_prologue(0xA9BF_7BFD));
    assert!(!is_aarch64_fp_prologue(0xD65F_03C0)); // ret

    // Function at 0x1000: stp prologue, add, ret, then junk (another prologue).
    let mut code = Vec::new();
    code.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes()); // stp x29,x30
    code.extend_from_slice(&0x9100_4000u32.to_le_bytes()); // add x0, x0, #0x10
    code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
    code.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes()); // next prologue

    let end = scan_for_function_end_aarch64(0x1000, &code, 0x1000, None);
    assert_eq!(end, Some(0x1000 + 12), "end should be just past the ret");

    // With a next_start before the ret, no ret is seen in range: None, and
    // the caller falls back to the distance-to-next-start size.
    let end2 = scan_for_function_end_aarch64(0x1000, &code, 0x1000, Some(0x1008));
    assert_eq!(end2, None);
}

#[test]
fn test_scan_vtables_recovers_class_names_and_slots() {
    use elftrace::discovery::scan_vtables;

    // .data.rel.ro layout at 0x3000:
    //   0x2ff0: _ZTS8MyWidget string ptr -> 0x2040 (in .rodata)
    //   0x2ff8: typeinfo ptr (unknown, ignored)
    //   0x3000: fn ptr 1 -> 0x1000 (exec)
    //   0x3008: fn ptr 2 -> 0x2000 (exec)
    //   0x3010: 0 (ends the run)
    let ro = 0x2000u64;
    let mut rodata = vec![0u8; 0x100];
    let ts = b"_ZTS8MyWidget\0";
    rodata[0x40..0x40 + ts.len()].copy_from_slice(ts);
    let ts_addr = ro + 0x40;

    let mut drr = vec![0u8; 0x40];
    let drr_base = 0x3000u64;
    // i starts at 2, so slots live at offsets 0..; header at -16/-8.
    drr[0x00..0x08].copy_from_slice(&(drr_base + 0x10).to_le_bytes()); // fn1
    drr[0x08..0x10].copy_from_slice(&(drr_base + 0x20).to_le_bytes()); // fn2
    drr[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // end run
    drr[0x20..0x28].copy_from_slice(&ts_addr.to_le_bytes()); // _ZTS ptr (i=4? no—
                                                             // header must sit at vt_addr-16, so rewrite: put header right before slots.
    let mut drr2 = vec![0u8; 0x40];
    drr2[0x00..0x08].copy_from_slice(&ts_addr.to_le_bytes()); // _ZTS ptr
    drr2[0x08..0x10].copy_from_slice(&(ro + 0x80).to_le_bytes()); // typeinfo ptr
    drr2[0x10..0x18].copy_from_slice(&(0x1000u64).to_le_bytes()); // vf0
    drr2[0x18..0x20].copy_from_slice(&(0x2000u64).to_le_bytes()); // vf1
                                                                  // 0x20.. zeros end the run.

    // Same layout but with zeroed file-image pointers filled by RELATIVE
    // relocations — how real shared libraries look on disk (AArch64 RELA).
    let mut relocs = std::collections::HashMap::new();
    relocs.insert(drr_base, ts_addr);
    relocs.insert(drr_base + 0x08, ro + 0x80);
    relocs.insert(drr_base + 0x10, 0x1000u64);
    relocs.insert(drr_base + 0x18, 0x2000u64);
    let drr3 = vec![0u8; 0x40]; // all zeros in the file image
    let out3 = scan_vtables(
        (drr_base, &drr3),
        &[(0x1000, 0x2000)],
        (ro, &rodata),
        &relocs,
    );
    assert!(
        out3.contains(&(drr_base, "vtable for MyWidget".to_string())),
        "got {:?}",
        out3
    );
    assert!(out3.contains(&(drr_base + 0x10, "MyWidget::vf0".to_string())));

    let out = scan_vtables(
        (drr_base, &drr2),
        &[(0x1000, 0x2000)],
        (ro, &rodata),
        &std::collections::HashMap::new(),
    );
    assert!(
        out.contains(&(drr_base, "vtable for MyWidget".to_string())),
        "got {:?}",
        out
    );
    assert!(out.contains(&(drr_base + 0x10, "MyWidget::vf0".to_string())));
    assert!(out.contains(&(drr_base + 0x18, "MyWidget::vf1".to_string())));
    let _ = drr; // unused variant kept minimal
}

#[test]
fn test_scan_string_refs_aarch64_finds_rodata_reference() {
    use elftrace::discovery::scan_string_refs_aarch64;

    // Code at 0x1000:
    //   adrp x0, page(0x2000)   ; page of the string
    //   add  x0, x0, #0x34      ; -> 0x2034
    // then junk.
    // adrp x0, imm = ((0x2000>>12) - (0x1000>>12)) = 1 => immhi=0<<2|immlo=1
    let adrp_imm_lo = 1u32; // immlo bits 29-30
    let adrp: u32 = (1u32 << 31) | (adrp_imm_lo << 29) | (0b10000 << 24);
    let add: u32 = (0b0_0010_0010u32 << 23) | (0x34 << 10);

    let mut code = Vec::new();
    code.extend_from_slice(&adrp.to_le_bytes());
    code.extend_from_slice(&add.to_le_bytes());
    code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret

    // rodata range [0x2000, 0x2100): a string at 0x2034.
    let mut ro = vec![0u8; 0x100];
    ro[0x34..0x34 + 6].copy_from_slice(b"hello\0");

    let out = scan_string_refs_aarch64(0x1000, &code, (0x2000, 0x2100), |a| a == 0x2034);
    assert_eq!(out, vec![(0x2034u64, 0x1004u64)]);
}

#[test]
fn test_scan_eh_frame_extracts_fde_starts_and_sizes() {
    use elftrace::discovery::scan_eh_frame;

    // One CIE (length 0x10) then one FDE whose pc_begin is pcrel to its own
    // pc_begin field. Layout at section offset 0:
    //   CIE: len=0x10, id=0, version, aug, ...
    //   FDE at 0x14: len=0x0c, cie_ptr=0x14, pc_begin_pcrel, pc_range
    let cie_ptr = 0x14u32;
    let fde_field_pos: i64 = (cie_ptr + 4 + 4) as i64; // file offset of pc_begin field
    let func_start: i64 = 0x2000;
    let pcrel = (func_start - fde_field_pos) as i32;
    let range: u32 = 0x40;

    let mut data = Vec::new();
    // CIE
    data.extend_from_slice(&0x10u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // CIE id
    data.extend_from_slice(&[3u8, 0, 0, 0]); // version + aug
    data.extend_from_slice(&[0u8, 0, 0, 0]); // code align etc.
    data.extend_from_slice(&[0u8, 0, 0, 0]);
    // FDE
    data.extend_from_slice(&0x0cu32.to_le_bytes());
    data.extend_from_slice(&cie_ptr.to_le_bytes());
    data.extend_from_slice(&pcrel.to_le_bytes());
    data.extend_from_slice(&range.to_le_bytes());
    // terminator
    data.extend_from_slice(&0u32.to_le_bytes());

    let out = scan_eh_frame(&data);
    assert_eq!(out, vec![(0x2000u64, 0x40u64)]);
}
