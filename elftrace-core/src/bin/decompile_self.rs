use elftrace::decompiler::decompile_to_c;
use elftrace::elf_parser::ElfContext;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: decompile_self <so> <addr>");
    let addr_str = std::env::args().nth(2).expect("addr");
    let clean = addr_str.trim_start_matches("0x").trim_start_matches("0X");
    let addr = u64::from_str_radix(clean, 16).unwrap();
    let ctx = ElfContext::open(&path).unwrap();
    print!("{}", decompile_to_c(&ctx, addr));
}
