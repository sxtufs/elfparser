use elftrace::disasm::resolve_aarch64_syscall;
use elftrace::elf_parser::ElfContext;
use elftrace::patcher::assemble_instruction;
use std::fs;
use std::sync::Arc;
use std::thread;

fn fixture(rel: &str) -> Option<String> {
    if let Ok(dir) = std::env::var("ELFTRACE_FIXTURES_DIR") {
        let p = format!("{}/{}", dir.trim_end_matches('/'), rel);
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    let candidates = [
        format!("../{}", rel),
        format!("./{}", rel),
        format!("../../{}", rel),
    ];
    for p in &candidates {
        if std::path::Path::new(p).exists() {
            return Some(p.clone());
        }
    }
    eprintln!("SKIP: fixture not found: {}", rel);
    None
}

fn get_sample_elf() -> Option<String> {
    if let Ok(path) = std::env::var("ELFTRACE_TEST_ELF") {
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    for rel in [
        "../app/src/main/jniLibs/arm64-v8a/libelftrace.so",
        "app/src/main/jniLibs/arm64-v8a/libelftrace.so",
        "test_fixtures/accuracy/fx_a64_O2.so",
        "test_fixtures/test_arm64.so",
    ] {
        if let Some(p) = fixture(rel) {
            return Some(p);
        }
    }
    None
}

#[test]
fn test_valid_elf_parsing() {
    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");
    assert!(!ctx.raw.is_empty());
    let info = ctx.get_info().expect("Should parse ELF info");
    assert_eq!(info.e_machine, 183); // AArch64
    assert!(info.is_64);
    assert!(!info.libraries.is_empty());
}

#[test]
fn test_malformed_and_truncated_elf() {
    // 1. Empty buffer
    let tmp_empty = "/tmp/test_empty.so";
    fs::write(tmp_empty, b"").unwrap();
    assert!(ElfContext::open(tmp_empty).is_err());

    // 2. Truncated magic (3 bytes)
    let tmp_trunc = "/tmp/test_trunc.so";
    fs::write(tmp_trunc, b"\x7fEL").unwrap();
    assert!(ElfContext::open(tmp_trunc).is_err());

    // 3. Invalid magic
    let tmp_bad = "/tmp/test_bad_magic.so";
    fs::write(tmp_bad, b"MZ\x90\x00not an elf file").unwrap();
    assert!(ElfContext::open(tmp_bad).is_err());

    // Cleanup
    let _ = fs::remove_file(tmp_empty);
    let _ = fs::remove_file(tmp_trunc);
    let _ = fs::remove_file(tmp_bad);
}

#[test]
fn test_address_translation_safety() {
    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");

    // Invalid virtual address should safely return None, never panic
    assert_eq!(ctx.vaddr_to_offset(0xFFFF_FFFF_FFFF_FFFF), None);
    assert_eq!(ctx.vaddr_to_offset(0x0), None);

    // String at invalid vaddr
    assert_eq!(ctx.get_string_at_vaddr(0xDEAD_BEEF), None);
}

#[test]
fn test_aarch64_branch_assembly_accuracy() {
    let addr = 0x2E248u64;

    // 1. b instruction
    let b_bytes = assemble_instruction("b #0x37d58", addr).expect("Should assemble b");
    assert_eq!(b_bytes, vec![0xC4, 0x26, 0x00, 0x14]);

    // 2. bl instruction
    let bl_bytes = assemble_instruction("bl #0x37d58", addr).expect("Should assemble bl");
    assert_eq!(bl_bytes, vec![0xC4, 0x26, 0x00, 0x94]);

    // 3. nop
    let nop_bytes = assemble_instruction("nop", addr).expect("Should assemble nop");
    assert_eq!(nop_bytes, vec![0x1F, 0x20, 0x03, 0xD5]);

    // 4. ret
    let ret_bytes = assemble_instruction("ret", addr).expect("Should assemble ret");
    assert_eq!(ret_bytes, vec![0xC0, 0x03, 0x5F, 0xD6]);

    // 5. Out-of-range branch target (> 128 MB)
    let too_far = addr + 200 * 1024 * 1024;
    let err = assemble_instruction(&format!("b #0x{:x}", too_far), addr);
    assert!(err.is_err(), "Should reject branch target exceeding 128 MB");
}

#[test]
fn test_syscall_resolver() {
    assert_eq!(resolve_aarch64_syscall(56), Some("openat"));
    assert_eq!(resolve_aarch64_syscall(63), Some("read"));
    assert_eq!(resolve_aarch64_syscall(64), Some("write"));
    assert_eq!(resolve_aarch64_syscall(117), Some("ptrace [Anti-Debug]"));
    assert_eq!(
        resolve_aarch64_syscall(226),
        Some("mprotect [Memory Hook/Unpack]")
    );
    assert_eq!(resolve_aarch64_syscall(9999), None);
}

#[test]
fn test_jni_offset_resolver() {
    use elftrace::resolve_jni_offset;
    // JNIEnv table: index 4 = GetVersion (0x20 in 64-bit, 0x10 in 32-bit)
    assert_eq!(resolve_jni_offset(0x020, true), Some("GetVersion"));
    assert_eq!(resolve_jni_offset(0x010, false), Some("GetVersion"));
    // index 5 = DefineClass
    assert_eq!(resolve_jni_offset(0x028, true), Some("DefineClass"));
    // index 6 = FindClass
    assert_eq!(resolve_jni_offset(0x030, true), Some("FindClass"));
    // index 33 = GetMethodID
    assert_eq!(resolve_jni_offset(0x108, true), Some("GetMethodID"));
    // index 215 = RegisterNatives
    assert_eq!(resolve_jni_offset(0x6b8, true), Some("RegisterNatives"));
    // index 219 = GetJavaVM
    assert_eq!(resolve_jni_offset(0x6d8, true), Some("GetJavaVM"));
    // reserved slots
    assert_eq!(resolve_jni_offset(0x000, true), None);
    assert_eq!(resolve_jni_offset(0x018, true), None); // reserved3, NOT DestroyJavaVM
    assert_eq!(resolve_jni_offset(0x99999, true), None);
}

#[test]
fn test_concurrent_analysis_thread_safety() {
    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = Arc::new(ElfContext::open(&elf_path).expect("Should open valid ELF"));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let ctx_clone = Arc::clone(&ctx);
        let handle = thread::spawn(move || {
            let info = ctx_clone.get_info().unwrap();
            assert!(!info.libraries.is_empty());
            let strings = ctx_clone.extract_strings().unwrap();
            assert!(!strings.data.is_empty());
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Thread should not panic");
    }
}

#[test]
fn test_callers_and_hierarchy_accuracy() {
    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");
    let info = ctx.get_info().unwrap();
    if let Some(first_sym) = info.syms.first() {
        let hierarchy = elftrace::get_hierarchy(&ctx, first_sym.value);
        assert_eq!(hierarchy.function_address, first_sym.value);
    }
}

#[test]
fn test_decompiler_aarch64_lifting() {
    use elftrace::decompiler::ir::{BinaryOp, IrExpr, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");
    let mut lifter = Arm64Lifter::new();

    // 1. Test TBZ: assert condition shape Eq(And(reg, mask), 0)
    let stmts = lifter.lift(&ctx, 0x1000, "tbz", "w0, #0, #0x2000", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Branch { cond: Some(c), .. } = &stmts[0] {
        if let IrExpr::Binary(op, lhs, rhs, _) = c {
            assert_eq!(*op, BinaryOp::Eq);
            assert_eq!(**rhs, IrExpr::Const(0));
            if let IrExpr::Binary(and_op, _, mask, _) = lhs.as_ref() {
                assert_eq!(*and_op, BinaryOp::And);
                assert_eq!(**mask, IrExpr::Const(1));
            } else {
                panic!("Expected and condition inside tbz");
            }
        } else {
            panic!("Expected binary condition");
        }
    } else {
        panic!("Expected conditional branch");
    }

    // 2. Test CSEL
    let _ = lifter.lift(&ctx, 0x1002, "cmp", "x10, x9", &[0; 4]);
    let stmts = lifter.lift(&ctx, 0x1004, "csel", "x0, x10, x9, eq", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Assign { .. }));

    // 3. Test TRAP
    let stmts = lifter.lift(&ctx, 0x1008, "brk", "1", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Trap));
}

#[test]
fn test_decompiler_arm32_thumb_lifting() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm32::Arm32Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");
    let mut lifter = Arm32Lifter::new();

    // 1. Test Wide instruction str.w
    let stmts = lifter.lift(&ctx, 0x1000, "str.w", "r8, [r4]", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Store { .. }));

    // 2. Test movt (high 16-bit constant loading)
    let stmts = lifter.lift(&ctx, 0x1004, "movt", "r0, #1", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Assign { .. }));

    // 3. Test BHI
    let _ = lifter.lift(&ctx, 0x1006, "cmp", "r0, r1", &[0; 4]);
    let stmts = lifter.lift(&ctx, 0x1008, "bhi", "0x2000", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Branch { .. }));
}

#[test]
fn test_decompiler_x86_64_lifting() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::x86_64::X86_64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");
    let mut lifter = X86_64Lifter::new();

    // 1. Test XOR zeroing idiom
    let stmts = lifter.lift(&ctx, 0x1000, "xor", "eax, eax", &[0; 2]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Assign { .. }));

    // 2. Test RET
    let stmts = lifter.lift(&ctx, 0x1002, "ret", "", &[0; 1]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Return(..)));
}

#[test]
fn test_decompiler_x86_32_lifting() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::x86_32::X86_32Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let ctx = ElfContext::open(&elf_path).expect("Should open valid ELF");
    let mut lifter = X86_32Lifter::new();

    // 1. Test 32-bit push/pop filtering (callee-saved registers)
    let stmts = lifter.lift(&ctx, 0x1000, "push", "ebx", &[0; 1]);
    assert!(stmts.is_empty()); // Filtered!

    // 2. Test 32-bit Return
    let stmts = lifter.lift(&ctx, 0x1001, "ret", "", &[0; 1]);
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], IrStmt::Return(..)));
}

#[test]
fn test_x86_division_quotient_remainder_accuracy() {
    use elftrace::decompiler::decompile_to_c;

    // 1. x86_64 signed division (idiv) with quotient & remainder
    let path_x64 = match fixture("test_fixtures/test_divrem_x64.so") {
        Some(p) => p,
        None => return,
    };
    let ctx_x64 = ElfContext::open(&path_x64).expect("open x64");
    let c_x64 = decompile_to_c(&ctx_x64, 0x1390);
    println!("=== x86_64 DIVREM DECOMPILED ===\n{}", c_x64);
    assert!(c_x64.contains("int32_t test_idiv_signed(int32_t a0, int32_t a1, int32_t* a2)"));
    assert!(c_x64.contains("int64_t dividend_64 ="));
    assert!(c_x64.contains("*(int32_t*)"));
    assert!(c_x64.contains("/ a1"));
    assert!(c_x64.contains("% a1"));

    // 2. x86_32 signed division (idiv) with quotient & remainder
    let path_x32 = match fixture("test_fixtures/test_divrem_x32.so") {
        Some(p) => p,
        None => return,
    };
    let ctx_x32 = ElfContext::open(&path_x32).expect("open x32");
    let c_x32 = decompile_to_c(&ctx_x32, 0x1300);
    println!("=== x86_32 DIVREM DECOMPILED ===\n{}", c_x32);
    assert!(c_x32.contains("int32_t test_idiv_signed(int32_t a0, int32_t a1, int32_t* a2)"));
    assert!(c_x32.contains("int64_t dividend_64 ="));
    assert!(c_x32.contains("*(int32_t*)"));
    assert!(c_x32.contains("/ a1"));
    assert!(c_x32.contains("% a1"));
}

#[test]
fn test_realworld_suite_all_architectures() {
    use elftrace::decompiler::decompile_to_c;

    for arch in ["aarch64", "armv7", "x86_64", "x86_32"] {
        for opt in ["O0", "O2", "Os"] {
            let rel = format!("test_fixtures/realworld_bins/rw_{}_{}.so", arch, opt);
            let path = match fixture(&rel) {
                Some(p) => p,
                None => {
                    eprintln!("SKIP: {}", rel);
                    continue;
                }
            };
            let ctx = match ElfContext::open(&path) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!("SKIP: unreadable {}", path);
                    continue;
                }
            };
            let info = ctx.get_info().unwrap();

            println!("\n=== RW ARCH: {}, OPT: {} ===", arch.to_uppercase(), opt);

            for sym in &info.syms {
                if sym.size > 0
                    && !sym.sym.starts_with('.')
                    && !sym.sym.starts_with('_')
                    && !sym.sym.starts_with('$')
                {
                    let code = decompile_to_c(&ctx, sym.value);
                    assert!(code.contains(&sym.sym), "Code should contain {}", sym.sym);
                }
            }
        }
    }
}

#[test]
fn test_function_pointer_and_float_typing() {
    use elftrace::decompiler::decompile_to_c;

    // 1. Function pointer parameter recovery (apply_callback on x86_64)
    let path_x64 = match fixture("test_fixtures/realworld_bins/rw_x86_64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx_x64 = ElfContext::open(&path_x64).unwrap();
    let info_x64 = ctx_x64.get_info().unwrap();
    let cb_sym = info_x64
        .syms
        .iter()
        .find(|s| s.sym == "apply_callback")
        .expect("find apply_callback");
    let c_cb = decompile_to_c(&ctx_x64, cb_sym.value);
    println!("=== apply_callback x86_64 ===\n{}", c_cb);
    assert!(c_cb.contains("(*a0)"));
    assert!(c_cb.contains("return rax;") || c_cb.contains("return eax;"));

    // 2. Double float register typing (traverse_linked_list on aarch64)
    let path_arm64 = match fixture("test_fixtures/realworld_bins/rw_aarch64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx_arm64 = ElfContext::open(&path_arm64).unwrap();
    let info_arm64 = ctx_arm64.get_info().unwrap();
    let ll_sym = info_arm64
        .syms
        .iter()
        .find(|s| s.sym == "traverse_linked_list")
        .expect("find traverse_linked_list");
    let c_ll = decompile_to_c(&ctx_arm64, ll_sym.value);
    println!("=== traverse_linked_list aarch64 ===\n{}", c_ll);
    assert!(c_ll.contains("traverse_linked_list"));
    assert!(c_ll.contains("double d0"));
    assert!(c_ll.contains("*(double*)"));
}

#[test]
fn test_il2cpp_metadata_honest_return() {
    use elftrace::elf_parser::ElfContext;
    use elftrace::il2cpp::load_global_metadata;

    let elf_path = match get_sample_elf() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: sample ELF not found");
            return;
        }
    };
    let mut ctx = ElfContext::open(&elf_path).unwrap();

    // Invalid magic → Err
    let tmp_bad = std::env::temp_dir().join("test_metadata_bad.dat");
    let mut bad = vec![0u8; 64];
    bad[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    std::fs::write(&tmp_bad, &bad).unwrap();
    assert!(load_global_metadata(&mut ctx, tmp_bad.to_str().unwrap()).is_err());
    let _ = std::fs::remove_file(&tmp_bad);

    // Valid magic → Ok(0), not Ok(N)
    let tmp_ok = std::env::temp_dir().join("test_metadata_ok.dat");
    let mut ok = vec![0u8; 64];
    ok[0..4].copy_from_slice(&0xFAB11BAFu32.to_le_bytes());
    std::fs::write(&tmp_ok, &ok).unwrap();
    assert_eq!(
        load_global_metadata(&mut ctx, tmp_ok.to_str().unwrap()),
        Ok(0)
    );
    let _ = std::fs::remove_file(&tmp_ok);
}
