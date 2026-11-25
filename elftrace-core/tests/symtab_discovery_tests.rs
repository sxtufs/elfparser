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
