use elftrace::elf_parser::ElfContext;
use elftrace::patcher::assemble_and_patch;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = match args.get(1) {
        Some(p) => p,
        None => {
            eprintln!("Usage: {} <elf-path> [address-hex]", args[0]);
            eprintln!();
            eprintln!("Demo binary for the assemble-and-patch pipeline.");
            eprintln!("Example: {} /path/to/libfoo.so 0x1234", args[0]);
            std::process::exit(1);
        }
    };

    let addr = args
        .get(2)
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x1000);

    let mut ctx = match ElfContext::open(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open {}: {}", path, e);
            std::process::exit(1);
        }
    };

    println!("[*] Testing assemble_and_patch at 0x{:08x}:", addr);

    let res1 = assemble_and_patch(&mut ctx, addr, "nop");
    println!(
        "  'nop': success = {}, bytes = {:02X?}",
        res1.success, res1.patched_bytes
    );

    let res2 = assemble_and_patch(&mut ctx, addr, "ret");
    println!(
        "  'ret': success = {}, bytes = {:02X?}",
        res2.success, res2.patched_bytes
    );

    let res3 = assemble_and_patch(&mut ctx, addr, "1F 20 03 D5");
    println!(
        "  '1F 20 03 D5': success = {}, bytes = {:02X?}",
        res3.success, res3.patched_bytes
    );
}
