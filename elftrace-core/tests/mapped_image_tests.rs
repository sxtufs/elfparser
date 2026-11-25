//! The ELF image is a private (copy-on-write) mapping rather than a heap copy.
//!
//! Guards two things at once:
//! * `ElfContext::open` maps instead of reading the whole file into RAM;
//! * patches stay in memory — the mapped pages are never flushed to the file.

use elftrace::elf_parser::{ElfContext, RawImage};

const TEXT_ADDR: u64 = 0x1000;
const TEXT_OFF: usize = 0x40;
const SHOFF: usize = 0xc8;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Minimal ELF64 AArch64 object with one executable `.text` section.
fn fixture_elf() -> Vec<u8> {
    let mut buf = vec![0u8; SHOFF + 3 * 64];

    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    put_u32(&mut buf, 16, 3);
    put_u16(&mut buf, 18, 183);
    put_u32(&mut buf, 20, 1);
    put_u64(&mut buf, 24, TEXT_ADDR);
    put_u64(&mut buf, 40, SHOFF as u64);
    put_u16(&mut buf, 52, 64);
    put_u16(&mut buf, 58, 64);
    put_u16(&mut buf, 60, 3);
    put_u16(&mut buf, 62, 2);

    put_u32(&mut buf, TEXT_OFF, 0xd65f_03c0); // ret
    put_u32(&mut buf, TEXT_OFF + 4, 0xd503_201f); // nop

    let shstr = b"\0.text\0.shstrtab\0";
    let shstr_off = 0xb0;
    buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

    let sh = |i: usize| SHOFF + i * 64;
    put_u32(&mut buf, sh(1), 1);
    put_u32(&mut buf, sh(1) + 4, 1);
    put_u64(&mut buf, sh(1) + 8, 0x6);
    put_u64(&mut buf, sh(1) + 16, TEXT_ADDR);
    put_u64(&mut buf, sh(1) + 24, TEXT_OFF as u64);
    put_u64(&mut buf, sh(1) + 32, 8);
    put_u64(&mut buf, sh(1) + 48, 4);

    put_u32(&mut buf, sh(2), 7);
    put_u32(&mut buf, sh(2) + 4, 3);
    put_u64(&mut buf, sh(2) + 24, shstr_off as u64);
    put_u64(&mut buf, sh(2) + 32, shstr.len() as u64);
    put_u64(&mut buf, sh(2) + 48, 1);

    buf
}

#[test]
fn elf_context_maps_and_keeps_patches_in_memory() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("elftrace_map_{}.so", std::process::id()));
    let original = fixture_elf();
    std::fs::write(&path, &original).unwrap();
    let path_str = path.to_string_lossy().into_owned();

    let mut ctx = ElfContext::open(&path_str).unwrap();
    assert!(
        matches!(ctx.raw, RawImage::Mapped(_)),
        "expected the release-size image to be a private mapping"
    );

    // Parsing works straight off the mapping.
    let info = ctx.get_info().unwrap();
    assert_eq!(info.e_machine, 183);

    // Patch `ret` -> `nop`: visible in the context, absent from the file.
    ctx.patch_bytes(TEXT_ADDR, &[0x1f, 0x20, 0x03, 0xd5])
        .unwrap();
    assert_eq!(&ctx.raw[TEXT_OFF..TEXT_OFF + 4], &[0x1f, 0x20, 0x03, 0xd5]);

    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(
        on_disk, original,
        "copy-on-write patch leaked into the file on disk"
    );

    // Undo restores the mapping, still without touching the file.
    assert_eq!(ctx.undo_last(), Some(TEXT_ADDR));
    assert_eq!(
        &ctx.raw[TEXT_OFF..TEXT_OFF + 4],
        &0xd65f_03c0u32.to_le_bytes()
    );
    assert_eq!(std::fs::read(&path).unwrap(), original);

    std::fs::remove_file(&path).unwrap();
}
