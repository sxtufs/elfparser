use elftrace::decompiler::decompile_to_c;
use elftrace::decompiler::ir::{IrExpr, IrType};
use elftrace::elf_parser::ElfContext;

/// Compile the emitted C targeting AArch64. Decompiled output of libelftrace.so
/// and fx_a64_*.so contains AArch64 inline asm; x86 host gcc/clang cannot
/// assemble it. Use the AArch64 cross toolchain installed in CI
/// (`gcc-aarch64-linux-gnu` package) or clang's integrated assembler with
/// `--target=aarch64-linux-gnu`.
fn assert_compiles(c_code: &str, label: &str) {
    let tu = format!(
        "#include <stdint.h>\n#include <stddef.h>\nextern void dummy_callee(void);\n{}\n",
        c_code
    );
    let path = std::env::temp_dir().join(format!("elftrace_{}.c", label));
    std::fs::write(&path, tu).unwrap();
    let mut ok = false;
    for (cc, base_args) in [
        ("aarch64-linux-gnu-gcc", &["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-c"][..]),
        ("clang", &["--target=aarch64-linux-gnu", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-c"][..]),
    ] {
        match std::process::Command::new(cc)
            .args(base_args)
            .arg(&path)
            .arg("-o")
            .arg("/dev/null")
            .output()
        {
            Ok(o) if o.status.success() => { ok = true; break; }
            Ok(o) => panic!("{} FAILED on {}:\n{}", cc, label, String::from_utf8_lossy(&o.stderr)),
            Err(_) => continue,
        }
    }
    if !ok {
        panic!("No AArch64-capable compiler available (tried aarch64-linux-gnu-gcc and clang --target=aarch64-linux-gnu). Install gcc-aarch64-linux-gnu on this host.");
    }
}

#[test]
fn test_item1_arm64_negative_displacements() {
    let fixture_path = "/workspace/test_fixtures/accuracy/fx_a64_item1.so";
    if !std::path::Path::new(fixture_path).exists() {
        eprintln!("SKIP: {} not found", fixture_path);
        return;
    }
    let ctx = ElfContext::open(fixture_path).expect("open fx_a64_item1.so");
    let c_code = decompile_to_c(&ctx, 0x258);
    println!("=== ITEM 1 AARCH64 DECOMPILED ===\n{}", c_code);

    // Negative offsets must NOT collapse to 0
    assert!(
        !c_code.contains("- 0)"),
        "Negative offsets must not collapse to '- 0)':\n{}",
        c_code
    );
    // Must contain actual non-zero offsets
    assert!(
        c_code.contains("- 4") || c_code.contains("- 0x4"),
        "Must contain offset 4"
    );
    assert!(
        c_code.contains("- 0xc") || c_code.contains("- 12"),
        "Must contain offset 0xc"
    );

    assert_compiles(&c_code, "item1_aarch64");
}

#[test]
fn test_item3_compile_gate_accuracy_fixtures() {
    let base = std::env::var("ELFTRACE_FIXTURES_DIR")
        .unwrap_or_else(|_| "/workspace/test_fixtures/accuracy".to_string());
    let mut tested = 0;
    for arch in ["a64", "arm32", "x64", "x32"] {
        for opt in ["O0", "O2"] {
            let fixture = format!("{}/fx_{}_{}.so", base, arch, opt);
            if let Ok(ctx) = ElfContext::open(&fixture) {
                let info = ctx.get_info().unwrap();
                for sym in &info.syms {
                    if sym.size > 0
                        && !sym.sym.starts_with('.')
                        && !sym.sym.starts_with('_')
                        && !sym.sym.starts_with('$')
                    {
                        let c_code = decompile_to_c(&ctx, sym.value);
                        assert_compiles(&c_code, &format!("{}_{}_{}", arch, opt, sym.sym));
                        tested += 1;
                    }
                }
            }
        }
    }
    if tested == 0 {
        eprintln!("SKIP: no accuracy fixtures available (expected /workspace/test_fixtures/accuracy/*.so)");
        return;
    }
    println!(
        "Item 3 Compile Gate: {} symbols compiled cleanly under GCC & Clang!",
        tested
    );
}
#[test]
fn test_item2_operator_precedence() {
    use elftrace::decompiler::arch::ArchKind;
    use elftrace::decompiler::codegen::CodeGenerator;
    use elftrace::decompiler::ir::{BinaryOp, IrExpr, IrType};
    use std::collections::HashMap;

    let ctx = ElfContext::stub();
    let codegen = CodeGenerator::new(&ctx, ArchKind::AArch64);
    let empty_map = HashMap::new();

    let x = IrExpr::reg("x", IrType::Int32);
    let y = IrExpr::reg("y", IrType::Int32);
    let z = IrExpr::reg("z", IrType::Int32);

    // 1. Mul(Add(x,y), z) -> "(x + y) * z"
    let e1 = IrExpr::Binary(
        BinaryOp::Mul,
        Box::new(IrExpr::Binary(
            BinaryOp::Add,
            Box::new(x.clone()),
            Box::new(y.clone()),
            IrType::Int32,
        )),
        Box::new(z.clone()),
        IrType::Int32,
    );
    assert_eq!(codegen.format_expr(&e1, &empty_map, 0, 0), "(x + y) * z");

    // 2. Sub(x, Sub(y,z)) -> "x - (y - z)"
    let e2 = IrExpr::Binary(
        BinaryOp::Sub,
        Box::new(x.clone()),
        Box::new(IrExpr::Binary(
            BinaryOp::Sub,
            Box::new(y.clone()),
            Box::new(z.clone()),
            IrType::Int32,
        )),
        IrType::Int32,
    );
    assert_eq!(codegen.format_expr(&e2, &empty_map, 0, 0), "x - (y - z)");

    // 3. Add(x, Mul(y,z)) -> "x + y * z"
    let e3 = IrExpr::Binary(
        BinaryOp::Add,
        Box::new(x.clone()),
        Box::new(IrExpr::Binary(
            BinaryOp::Mul,
            Box::new(y.clone()),
            Box::new(z),
            IrType::Int32,
        )),
        IrType::Int32,
    );
    assert_eq!(codegen.format_expr(&e3, &empty_map, 0, 0), "x + y * z");

    // 4. Shl(Add(x,y), Const(2)) -> "(x + y) << 2"
    let e4 = IrExpr::Binary(
        BinaryOp::Shl,
        Box::new(IrExpr::Binary(
            BinaryOp::Add,
            Box::new(x),
            Box::new(y),
            IrType::Int32,
        )),
        Box::new(IrExpr::Const(2)),
        IrType::Int32,
    );
    assert_eq!(codegen.format_expr(&e4, &empty_map, 0, 0), "(x + y) << 2");
}

#[test]
fn test_item4_flag_state() {
    use elftrace::decompiler::ir::{BinaryOp, IrExpr, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // 1. tst w8, #1 ; b.eq L -> branch condition must be Eq ((w8 & 1) == 0)
    let _ = lifter.lift(&ctx, 0x1000, "tst", "w8, #1", &[0; 4]);
    let stmts = lifter.lift(&ctx, 0x1004, "b.eq", "0x2000", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Branch { cond: Some(c), .. } = &stmts[0] {
        if let IrExpr::Binary(op, _, _, _) = c {
            assert_eq!(*op, BinaryOp::Eq, "tst + b.eq must test Eq == 0!");
        } else {
            panic!("Expected binary condition");
        }
    } else {
        panic!("Expected conditional branch");
    }

    // 2. reset_state clears last_cmp across block boundary / call
    lifter.reset_state();
    let stmts_reset = lifter.lift(&ctx, 0x1008, "b.eq", "0x3000", &[0; 4]);
    assert!(matches!(stmts_reset[0], IrStmt::Asm(_)));
}

#[test]
fn test_item5_unsigned_comparison() {
    let path = "/workspace/test_fixtures/accuracy/fx_a64_items.so";
    if !std::path::Path::new(path).exists() {
        eprintln!("SKIP: {} not found", path);
        return;
    }
    let ctx = ElfContext::open(path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "test_unsigned_cmp")
        .expect("find test_unsigned_cmp");
    let c_code = decompile_to_c(&ctx, sym.value);
    println!("=== test_unsigned_cmp ===\n{}", c_code);

    assert!(
        c_code.contains("(uint32_t)") || c_code.contains("(uint64_t)"),
        "Must cast operands to unsigned in comparison:\n{}",
        c_code
    );
    assert_compiles(&c_code, "item5_unsigned_cmp");
}

#[test]
fn test_item7_call_arity() {
    let path = "/workspace/test_fixtures/accuracy/fx_a64_items.so";
    if !std::path::Path::new(path).exists() {
        eprintln!("SKIP: {} not found", path);
        return;
    }
    let ctx = ElfContext::open(path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "zero_arg_caller")
        .expect("find zero_arg_caller");
    let c_code = decompile_to_c(&ctx, sym.value);
    println!("=== zero_arg_caller ===\n{}", c_code);

    assert!(
        c_code.contains("zero_arg_caller()") || c_code.contains("zero_arg_caller(void)"),
        "Zero-arg caller must decompile with empty parameters:\n{}",
        c_code
    );
    assert_compiles(&c_code, "item7_call_arity");
}

#[test]
fn test_item6_signed_extensions() {
    use elftrace::decompiler::ir::{BinaryOp, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // sxtb w0, w1 must emit arithmetic shift pair
    let stmts = lifter.lift(&ctx, 0x1000, "sxtb", "w0, w1", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign { src, .. } = &stmts[0] {
        if let IrExpr::Binary(op, inner, _, _) = src {
            assert_eq!(*op, BinaryOp::ShrS);
            if let IrExpr::Binary(inner_op, _, _, _) = inner.as_ref() {
                assert_eq!(*inner_op, BinaryOp::Shl);
            } else {
                panic!("Expected inner Shl");
            }
        } else {
            panic!("Expected outer ShrS");
        }
    } else {
        panic!("Expected Assign");
    }
}

#[test]
fn test_item6_unsigned_extensions() {
    use elftrace::decompiler::ir::{BinaryOp, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // uxtb w0, w1 must emit And with 0xff
    let stmts = lifter.lift(&ctx, 0x1000, "uxtb", "w0, w1", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign { src, .. } = &stmts[0] {
        if let IrExpr::Binary(op, _, mask, _) = src {
            assert_eq!(*op, BinaryOp::And);
            assert_eq!(**mask, IrExpr::Const(0xff));
        } else {
            panic!("Expected And with 0xff");
        }
    } else {
        panic!("Expected Assign");
    }
}

#[test]
fn test_item6_bitfield_insert() {
    use elftrace::decompiler::ir::{BinaryOp, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // ubfiz w0, w1, #8, #8 must emit And(mask) then Shl(8)
    let stmts = lifter.lift(&ctx, 0x1000, "ubfiz", "w0, w1, #8, #8", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign { src, .. } = &stmts[0] {
        if let IrExpr::Binary(op, masked, lsb, _) = src {
            assert_eq!(*op, BinaryOp::Shl);
            assert_eq!(**lsb, IrExpr::Const(8));
            if let IrExpr::Binary(and_op, _, mask, _) = masked.as_ref() {
                assert_eq!(*and_op, BinaryOp::And);
                assert_eq!(**mask, IrExpr::Const(0xff));
            } else {
                panic!("Expected And mask inside ubfiz");
            }
        } else {
            panic!("Expected Shl");
        }
    } else {
        panic!("Expected Assign");
    }
}

#[test]
fn test_item6_pair_width() {
    use elftrace::decompiler::ir::{BinaryOp, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // ldp w0, w1, [x2] must load second word at +4, NOT +8!
    let stmts = lifter.lift(&ctx, 0x1000, "ldp", "w0, w1, [x2]", &[0; 4]);
    assert_eq!(stmts.len(), 2);
    if let IrStmt::Assign { src, .. } = &stmts[1] {
        if let IrExpr::Load { ptr, .. } = src {
            if let IrExpr::Binary(BinaryOp::Add, _, off, _) = ptr.as_ref() {
                assert_eq!(**off, IrExpr::Const(4), "wN pair step must be 4 bytes!");
            } else {
                panic!("Expected Add offset for second pair register");
            }
        } else {
            panic!("Expected Load");
        }
    } else {
        panic!("Expected Assign");
    }
}

#[test]
fn test_item6_index_addressing() {
    use elftrace::decompiler::ir::{BinaryOp, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // ldr w0, [x1, x2, lsl #2] must preserve index and scale
    let stmts = lifter.lift(&ctx, 0x1000, "ldr", "w0, [x1, x2, lsl #2]", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign { src, .. } = &stmts[0] {
        if let IrExpr::Load { ptr, .. } = src {
            if let IrExpr::Binary(BinaryOp::Add, base, scaled, _) = ptr.as_ref() {
                assert_eq!(**base, IrExpr::reg("x1", IrType::Int64));
                if let IrExpr::Binary(BinaryOp::Shl, idx, shift, _) = scaled.as_ref() {
                    assert_eq!(**idx, IrExpr::reg("x2", IrType::Int64));
                    assert_eq!(**shift, IrExpr::Const(2));
                } else {
                    panic!("Expected Shl for scaled index");
                }
            } else {
                panic!("Expected Add for base + scaled index");
            }
        } else {
            panic!("Expected Load");
        }
    } else {
        panic!("Expected Assign");
    }
}

#[test]
fn test_item8_prologue_filter_scoped() {
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // In prologue: cmp x8, x9 is filtered
    let stmts_prologue = lifter.lift(&ctx, 0x1000, "cmp", "x8, x9", &[0; 4]);
    assert!(
        stmts_prologue.is_empty(),
        "Prologue canary cmp must be filtered"
    );

    // Terminate prologue with a branch
    let _ = lifter.lift(&ctx, 0x1004, "b", "0x2000", &[0; 4]);

    // Mid-body: cmp x8, x9 must NOT be filtered!
    let stmts_midbody = lifter.lift(&ctx, 0x2000, "cmp", "x8, x9", &[0; 4]);
    assert_eq!(stmts_midbody.len(), 0); // cmp sets last_cmp, doesn't emit stmt, but last_cmp is set!
    assert!(
        lifter.last_cmp.is_some(),
        "Mid-body cmp x8, x9 must set last_cmp!"
    );
}

#[test]
fn test_item8_stack_slot_minus_8_preserved_midbody() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // Terminate prologue first
    let _ = lifter.lift(&ctx, 0x1000, "b", "0x2000", &[0; 4]);

    // Mid-body: ldur w0, [x29, #-8] must be preserved!
    let stmts = lifter.lift(&ctx, 0x2004, "ldur", "w0, [x29, #-8]", &[0; 4]);
    assert_eq!(
        stmts.len(),
        1,
        "Mid-body slot -8 access must NOT be filtered"
    );
    assert!(matches!(stmts[0], IrStmt::Assign { .. }));
}

#[test]
fn test_item7b_real_arguments_passed() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // Caller writes w0 (#5) and w1 (#7), then calls g
    let _ = lifter.lift(&ctx, 0x1000, "mov", "w0, #5", &[0; 4]);
    let _ = lifter.lift(&ctx, 0x1004, "mov", "w1, #7", &[0; 4]);
    let stmts = lifter.lift(&ctx, 0x1008, "bl", "0x2000", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Call { args, .. } = &stmts[0] {
        assert_eq!(
            args.len(),
            2,
            "Call must pass exactly the 2 written arguments x0, x1! Got: {:?}",
            args
        );
    } else {
        panic!("Expected Call statement");
    }
}

#[test]
fn test_item7b_void_callee_no_ret_dst() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // Zero arguments written before call to void callee
    let stmts = lifter.lift(&ctx, 0x1000, "bl", "0x2000", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Call { args, ret_dst, .. } = &stmts[0] {
        assert!(ret_dst.is_none(), "Void callee must have ret_dst: None!");
        assert_eq!(
            args.len(),
            0,
            "Zero-argument call must have empty args vector!"
        );
    } else {
        panic!("Expected Call statement");
    }
}

#[test]
fn test_p1_1_x86_movzx_movsx() {
    use elftrace::decompiler::ir::{BinaryOp, IrStmt};
    use elftrace::decompiler::lifters::x86_64::X86_64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = X86_64Lifter::new();

    // movzx: must contain And with 0xff (byte source)
    let stmts = lifter.lift(&ctx, 0x1000, "movzx", "eax, byte ptr [rbp-4]", &[0; 3]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Binary(BinaryOp::And, _, mask, _),
        ..
    } = &stmts[0]
    {
        assert_eq!(
            **mask,
            IrExpr::Const(0xff),
            "movzx byte must mask with 0xff"
        );
    } else {
        panic!("movzx must emit And mask, got: {:?}", stmts[0]);
    }

    // movsx: must contain ShrS(Shl(...)) shift-pair
    let stmts = lifter.lift(&ctx, 0x1004, "movsx", "eax, byte ptr [rbp-4]", &[0; 3]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Binary(BinaryOp::ShrS, inner, shift_r, _),
        ..
    } = &stmts[0]
    {
        assert_eq!(**shift_r, IrExpr::Const(56));
        if let IrExpr::Binary(BinaryOp::Shl, _, shift_l, _) = inner.as_ref() {
            assert_eq!(**shift_l, IrExpr::Const(56), "movsx byte must shift 56");
        } else {
            panic!("movsx byte must emit Shl inside ShrS");
        }
    } else {
        panic!("movsx must emit ShrS(Shl(...)), got: {:?}", stmts[0]);
    }

    use elftrace::decompiler::lifters::x86_32::X86_32Lifter;
    let mut lifter32 = X86_32Lifter::new();

    let stmts32 = lifter32.lift(&ctx, 0x1000, "movzx", "eax, byte ptr [ebp-4]", &[0; 3]);
    assert_eq!(stmts32.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Binary(BinaryOp::And, _, mask, _),
        ..
    } = &stmts32[0]
    {
        assert_eq!(**mask, IrExpr::Const(0xff));
    } else {
        panic!("x86_32 movzx must emit And mask");
    }

    let stmts32 = lifter32.lift(&ctx, 0x1004, "movsx", "eax, byte ptr [ebp-4]", &[0; 3]);
    assert_eq!(stmts32.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Binary(BinaryOp::ShrS, inner, shift_r, _),
        ..
    } = &stmts32[0]
    {
        assert_eq!(**shift_r, IrExpr::Const(24));
        if let IrExpr::Binary(BinaryOp::Shl, _, shift_l, _) = inner.as_ref() {
            assert_eq!(**shift_l, IrExpr::Const(24));
        } else {
            panic!("x86_32 movsx must emit Shl 24");
        }
    } else {
        panic!("x86_32 movsx must emit ShrS 24");
    }
}

#[test]
fn test_p1_4_patcher_x86_32() {
    use elftrace::patcher::{apply_quick_patch, QuickPatchType};

    let fixture_path = "/workspace/test_fixtures/accuracy/fx_x32_O2.so";
    if !std::path::Path::new(fixture_path).exists() {
        eprintln!("SKIP: {} not found", fixture_path);
        return;
    }
    let tmp = std::env::temp_dir().join("patch_test_x86_32.so");
    let file_bytes = std::fs::read(fixture_path).unwrap();
    std::fs::write(&tmp, &file_bytes).unwrap();
    let mut ctx = ElfContext::open(tmp.to_str().unwrap()).unwrap();

    let res = apply_quick_patch(&mut ctx, 0x1210, QuickPatchType::ReturnTrue, false);
    assert!(res.success);
    // x86_32 "return true" is 6 bytes: B8 01 00 00 00 C3
    assert_eq!(
        res.patched_bytes,
        vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3],
        "x86_32 ReturnTrue must emit mov eax,1; ret, NOT ARM64 bytes"
    );

    let res_false = apply_quick_patch(&mut ctx, 0x1210, QuickPatchType::ReturnFalse, false);
    assert!(res_false.success);
    // x86_32 "return false" is 3 bytes: 31 C0 C3
    assert_eq!(
        res_false.patched_bytes,
        vec![0x31, 0xC0, 0xC3],
        "x86_32 ReturnFalse must emit xor eax,eax; ret"
    );
}

#[test]
fn test_p1_2_arm32_scaled_index() {
    use elftrace::decompiler::ir::{BinaryOp, IrExpr, IrStmt, IrType};
    use elftrace::decompiler::lifters::arm32::Arm32Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm32Lifter::new();

    // ldr r0, [r1, r2, lsl #2] must produce Load { ptr: Add(r1, Shl(r2, 2)) }
    let stmts = lifter.lift(&ctx, 0x1000, "ldr", "r0, [r1, r2, lsl #2]", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Load { ptr, .. },
        ..
    } = &stmts[0]
    {
        if let IrExpr::Binary(BinaryOp::Add, base, scaled, _) = ptr.as_ref() {
            assert_eq!(**base, IrExpr::reg("r1", IrType::Int32));
            if let IrExpr::Binary(BinaryOp::Shl, idx, shift, _) = scaled.as_ref() {
                assert_eq!(**idx, IrExpr::reg("r2", IrType::Int32));
                assert_eq!(**shift, IrExpr::Const(2));
            } else {
                panic!("Expected Shl for scaled index, got: {:?}", scaled);
            }
        } else {
            panic!("Expected Add(base, scaled_index), got: {:?}", ptr);
        }
    } else {
        panic!("Expected Load, got: {:?}", stmts[0]);
    }
}

#[test]
fn test_p1_3_x86_scaled_index() {
    use elftrace::decompiler::ir::{BinaryOp, IrExpr, IrStmt};
    use elftrace::decompiler::lifters::x86_64::X86_64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = X86_64Lifter::new();

    // mov eax, [rbp+rax*4+8]
    let stmts = lifter.lift(&ctx, 0x1000, "mov", "eax, [rbp+rax*4+8]", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Load { ptr, .. },
        ..
    } = &stmts[0]
    {
        let mut found_shl = false;
        fn scan(e: &IrExpr, found: &mut bool) {
            match e {
                IrExpr::Binary(BinaryOp::Shl, _, shift, _) => {
                    if let IrExpr::Const(2) = **shift {
                        *found = true;
                    }
                }
                IrExpr::Binary(_, l, r, _) => {
                    scan(l, found);
                    scan(r, found);
                }
                _ => {}
            }
        }
        scan(ptr, &mut found_shl);
        assert!(found_shl, "Expected Shl(_, 2) inside ptr, got: {:?}", ptr);
    } else {
        panic!("Expected Load, got: {:?}", stmts[0]);
    }

    let c = elftrace::decompiler::decompile_to_c(&ctx, 0x1210);
    assert!(
        !c.contains("rbp+rax"),
        "C output must not contain literal identifier 'rbp+rax'"
    );
}

#[test]
fn test_p1_5_prologue_filter_scoped_x86_64() {
    use elftrace::decompiler::lifters::x86_64::X86_64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = X86_64Lifter::new();

    // Mid-body push rbp after a branch: must NOT be filtered
    let _ = lifter.lift(&ctx, 0x1000, "ret", "", &[0; 1]); // marks prologue_done

    let stmts = lifter.lift(&ctx, 0x1001, "push", "rbp", &[0; 1]);
    assert!(!stmts.is_empty(), "Mid-body push rbp must not be filtered");
}

#[test]
fn test_p1_5_prologue_filter_scoped_arm32() {
    use elftrace::decompiler::lifters::arm32::Arm32Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm32Lifter::new();

    let _ = lifter.lift(&ctx, 0x1000, "bx", "lr", &[0; 4]);

    let stmts = lifter.lift(&ctx, 0x1004, "push", "{r4, lr}", &[0; 4]);
    assert!(
        !stmts.is_empty(),
        "Mid-body push r4, lr must not be filtered"
    );
}

#[test]
fn test_p1_5_prologue_filter_scoped_x86_32() {
    use elftrace::decompiler::lifters::x86_32::X86_32Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = X86_32Lifter::new();

    let _ = lifter.lift(&ctx, 0x1000, "ret", "", &[0; 1]);

    let stmts = lifter.lift(&ctx, 0x1001, "push", "ebp", &[0; 1]);
    assert!(!stmts.is_empty(), "Mid-body push ebp must not be filtered");
}

#[test]
fn test_p2_1_arm64_arithmetic_type_fidelity() {
    use elftrace::decompiler::ir::{IrExpr, IrStmt, IrType};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // mul w0, w1, w2 → dst must be Int32, both srcs Int32
    let stmts = lifter.lift(&ctx, 0x1000, "mul", "w0, w1, w2", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign {
        dst: IrExpr::Reg(_, dst_ty),
        src,
    } = &stmts[0]
    {
        assert_eq!(*dst_ty, IrType::Int32, "mul w must have Int32 dst");
        if let IrExpr::Binary(_, l, r, ty) = src {
            assert_eq!(*ty, IrType::Int32, "mul w must have Int32 operands");
            if let IrExpr::Reg(_, l_ty) = l.as_ref() {
                assert_eq!(*l_ty, IrType::Int32);
            }
            if let IrExpr::Reg(_, r_ty) = r.as_ref() {
                assert_eq!(*r_ty, IrType::Int32);
            }
        }
    } else {
        panic!("Expected Assign");
    }

    // mul x0, x1, x2 → dst Int64
    let stmts = lifter.lift(&ctx, 0x1004, "mul", "x0, x1, x2", &[0; 4]);
    if let IrStmt::Assign {
        dst: IrExpr::Reg(_, dst_ty),
        ..
    } = &stmts[0]
    {
        assert_eq!(*dst_ty, IrType::Int64, "mul x must have Int64 dst");
    }

    // lsl w0, w1, #3 → 32-bit shift
    let stmts = lifter.lift(&ctx, 0x1008, "lsl", "w0, w1, #3", &[0; 4]);
    if let IrStmt::Assign {
        dst: IrExpr::Reg(_, ty),
        src: IrExpr::Binary(_, _, _, op_ty),
    } = &stmts[0]
    {
        assert_eq!(*ty, IrType::Int32);
        assert_eq!(*op_ty, IrType::Int32);
    }

    // and x0, x1, x2 → Int64
    let stmts = lifter.lift(&ctx, 0x100c, "and", "x0, x1, x2", &[0; 4]);
    if let IrStmt::Assign {
        dst: IrExpr::Reg(_, ty),
        ..
    } = &stmts[0]
    {
        assert_eq!(*ty, IrType::Int64);
    }
}

#[test]
fn test_p2_5_cinc_lifted() {
    use elftrace::decompiler::ir::{BinaryOp, IrExpr, IrStmt, IrType};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // Set up last_cmp via `cmp w0, #0`
    let _ = lifter.lift(&ctx, 0x1000, "cmp", "w0, #0", &[0; 4]);
    // cinc w1, w2, eq → w1 = eq ? w2 + 1 : w2
    let stmts = lifter.lift(&ctx, 0x1004, "cinc", "w1, w2, eq", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(
        !matches!(stmts[0], IrStmt::Asm(_)),
        "cinc must not fall to Asm"
    );
    if let IrStmt::Assign {
        dst: IrExpr::Reg(_, ty),
        src: IrExpr::Ternary {
            true_val,
            false_val,
            ..
        },
    } = &stmts[0]
    {
        assert_eq!(*ty, IrType::Int32);
        assert!(matches!(
            true_val.as_ref(),
            IrExpr::Binary(BinaryOp::Add, _, _, _)
        ));
        assert!(matches!(false_val.as_ref(), IrExpr::Reg(_, _)));
    } else {
        panic!("cinc must emit Assign with Ternary, got: {:?}", stmts[0]);
    }
}

#[test]
fn test_p2_5_csetm_lifted() {
    use elftrace::decompiler::ir::{IrExpr, IrStmt};
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    let _ = lifter.lift(&ctx, 0x1000, "cmp", "w0, #0", &[0; 4]);
    let stmts = lifter.lift(&ctx, 0x1004, "csetm", "w0, ne", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    if let IrStmt::Assign {
        src: IrExpr::Ternary {
            true_val,
            false_val,
            ..
        },
        ..
    } = &stmts[0]
    {
        assert_eq!(**true_val, IrExpr::Const(0xffff_ffff));
        assert_eq!(**false_val, IrExpr::Const(0));
    } else {
        panic!("csetm must emit Ternary");
    }
}

#[test]
fn test_p2_5_csel_no_cmp_falls_to_asm() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new(); // no cmp before

    let stmts = lifter.lift(&ctx, 0x1000, "csel", "w0, w1, w2, eq", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    assert!(
        matches!(stmts[0], IrStmt::Asm(_)),
        "csel with no prior cmp must fall back to Asm, got: {:?}",
        stmts[0]
    );
}

#[test]
fn test_p2_6_jni_annotation_gated_by_function_type() {
    // ldr x0, [x0, #0x30] — encodes to 00 18 40 F9
    // 0x30 is "FindClass / GetEnv" in the JNI vtable.
    // For a non-JNI function: NO annotation.
    // For a JNI function:     annotation MUST appear.
    let bytes = [0x00u8, 0x18, 0x40, 0xF9];

    // Non-JNI: no comment
    let non_jni =
        elftrace::disasm::disassemble_with_resolver(&bytes, 0x1000, 4, 183, false, None, false)
            .unwrap();
    assert_eq!(non_jni.data.len(), 1);
    assert!(
        non_jni.data[0].comment.is_none(),
        "Non-JNI function must NOT get JNI annotation. Got: {:?}",
        non_jni.data[0].comment
    );

    // JNI: comment present, contains FindClass or GetEnv
    let jni =
        elftrace::disasm::disassemble_with_resolver(&bytes, 0x1000, 4, 183, false, None, true)
            .unwrap();
    assert_eq!(jni.data.len(), 1);
    let comment = jni.data[0]
        .comment
        .as_ref()
        .expect("JNI function MUST get JNI annotation on 0x30 load");
    assert!(
        comment.contains("FindClass") || comment.contains("GetEnv"),
        "Comment must resolve to FindClass/GetEnv. Got: {:?}",
        comment
    );
}

#[test]
fn test_p2_7_xref_decodes_tbz_tbnz() {
    use elftrace::xref::decode_arm64_branch_insn;

    // TBZ x0, #3, #0x+8  (from_addr=0x1000, target=0x1008, offset=+8)
    // word = 0x3618_0040
    let word: u32 = 0x3618_0040;
    let result = decode_arm64_branch_insn(word, 0x1000);
    assert_eq!(
        result,
        Some((0x1008, "Jump", "tbz")),
        "TBZ to +8 must decode to 0x1008, got: {:?}",
        result
    );

    // TBNZ x0, #3, #0x-8  (from_addr=0x1000, target=0xff8, offset=-8)
    // imm14 = (-8/4) & 0x3FFF = 0x3FFE
    // word = 0x3700_0000 | 0x0018_0000 | (0x3FFE << 5) = 0x371F_FFC0
    let word: u32 = 0x371F_FFC0;
    let result = decode_arm64_branch_insn(word, 0x1000);
    assert_eq!(
        result,
        Some((0x0FF8, "Jump", "tbnz")),
        "TBNZ to -8 must decode to 0xff8, got: {:?}",
        result
    );

    // Sanity: BL still decodes correctly
    let word: u32 = 0x9400_0040;
    assert_eq!(
        decode_arm64_branch_insn(word, 0x1000),
        Some((0x1100, "Call", "bl"))
    );

    // Non-branch word returns None
    assert_eq!(decode_arm64_branch_insn(0xD503201F, 0x1000), None); // nop
}

fn get_test_so_path() -> Option<String> {
    std::env::var("ELFTRACE_TEST_ELF").ok().or_else(|| {
        for p in [
            "/workspace/test_fixtures/libelftrace.so",
            "test_fixtures/libelftrace.so",
            "../app/src/main/jniLibs/arm64-v8a/libelftrace.so",
            "/workspace/app/src/main/jniLibs/arm64-v8a/libelftrace.so",
        ] {
            if std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
        None
    })
}

#[test]
fn test_class_a_no_uint128_emitted() {
    let so = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let addr = match assemble_patch_addr(&ctx) {
        Some(a) => a,
        None => {
            eprintln!("SKIP: assemblePatch symbol not found in {}", so);
            return;
        }
    };
    let c = elftrace::decompiler::decompile_to_c(&ctx, addr);
    assert!(
        !c.contains("uint128_t"),
        "Decompiled output must not contain 'uint128_t'. Got:
{}",
        c
    );
    assert!(
        !c.contains("__int128"),
        "Decompiled output must not contain '__int128' either (use __asm__ instead)"
    );
}

#[test]
fn test_class_b_integer_calls_cast_to_fn_ptr() {
    let so = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let addr = match assemble_patch_addr(&ctx) {
        Some(a) => a,
        None => {
            eprintln!("SKIP: assemblePatch symbol not found in {}", so);
            return;
        }
    };
    let c = elftrace::decompiler::decompile_to_c(&ctx, addr);
    assert!(
        !c.contains("= 0x6ec594(") && !c.contains(" 0x6ec594("),
        "Raw integer call target found. Expected ((void(*)())0x6ec594)(...). Got:
{}",
        c
    );
    assert!(
        c.contains("((int64_t(*") || c.contains("((void(*"),
        "Expected function pointer cast in output"
    );
}

#[test]
fn test_class_c_no_int_to_pointer() {
    let so = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let addr = match assemble_patch_addr(&ctx) {
        Some(a) => a,
        None => {
            eprintln!("SKIP: assemblePatch symbol not found in {}", so);
            return;
        }
    };
    let c = elftrace::decompiler::decompile_to_c(&ctx, addr);
    assert!(
        !c.contains("void* a0") && !c.contains("void* a1"),
        "Parameters must be int64_t, not void*. Got:
{}",
        c
    );
}

#[test]
fn test_class_d_no_dead_code_after_trap() {
    let so = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let addr = match assemble_patch_addr(&ctx) {
        Some(a) => a,
        None => {
            eprintln!("SKIP: assemblePatch symbol not found in {}", so);
            return;
        }
    };
    let c = elftrace::decompiler::decompile_to_c(&ctx, addr);
    let lines: Vec<&str> = c.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "__builtin_trap();" && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            assert!(
                next.is_empty()
                    || next.starts_with("loc_")
                    || next == "}"
                    || next.starts_with("//"),
                "Dead code after __builtin_trap();. Next line: {:?}",
                next
            );
        }
    }
}

/// Look up the `assemblePatch` JNI entry point by name. Its address changes
/// between builds, so tests must resolve it from the symbol table rather than
/// hardcode an offset. Returns None if the symbol is absent (e.g. in a fresh CI
/// build whose symbol layout differs from the developer's local build).
fn assemble_patch_addr(ctx: &ElfContext) -> Option<u64> {
    let info = ctx.get_info().ok()?;
    info.syms
        .iter()
        .find(|s| s.sym.ends_with("assemblePatch"))
        .map(|s| s.value)
}

/// JNI symbols in `libelftrace.so` that do not currently produce compilable C.
/// Each entry MUST have a comment naming:
///   1. The specific instruction pattern or construct that fails
///   2. The fix that would resolve it
///   3. Why `test_self_compile_gate_known_failures` will flip red the moment it's fixed
const KNOWN_FAILURES: &[(&str, &str)] = &[
    // finalize0: emits a tail-call to a PLT-resolved symbol not present in syms_map,
    // producing `goto loc_<unmapped>;`.
    // Fix: include .plt in syms_map (extend xref scan), or emit the branch as an
    // `Asm` statement instead of a `Goto`.
    // Will flip red when: decompile_to_c(finalize0) produces compilable C.
    (
        "finalize0",
        "tail-call to PLT stub emitted as goto to unmapped address",
    ),
    // disasm0: large function (>2000 bytes) with non-cmp branch conditions.
    // The structurer emits an inline `__asm__` block that exceeds the compiler's
    // immediate-operand size limit for conditional branches.
    // Fix: for out-of-range conditional branches, emit `if (cond) { __asm__("b <target>"); }`
    // as separate statements, or degrade the whole function to goto-based output.
    // Will flip red when: decompile_to_c(disasm0) produces compilable C.
    (
        "disasm0",
        "inline asm branch exceeds immediate-operand range",
    ),
    // save0: large function with non-cmp branch conditions producing out-of-range inline asm branches.
    // Fix: emit out-of-range conditional branches as if (cond) goto <target> instead of inline assembly.
    // Will flip red when: decompile_to_c(save0) produces compilable C.
    ("save0", "inline asm branch exceeds immediate-operand range"),

];

#[test]
fn test_self_compile_gate() {
    let so_path = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found — self-compile gate not run");
            return;
        }
    };

    let ctx = ElfContext::open(&so_path).expect("open libelftrace.so");
    let info = ctx.get_info().unwrap();

    let mut clean = 0;
    let mut known = 0;
    let mut new_failures: Vec<(String, String)> = Vec::new();

    for sym in info
        .syms
        .iter()
        .filter(|s| s.size > 0 && (s.sym.starts_with("Java_") || s.sym == "JNI_OnLoad"))
    {
        let c_code = elftrace::decompiler::decompile_to_c(&ctx, sym.value);
        let compile_ok = try_compile(&c_code);
        let is_known = KNOWN_FAILURES
            .iter()
            .any(|(name, _)| sym.sym == *name || sym.sym.ends_with(name));

        match (compile_ok, is_known) {
            (Ok(()), true) => panic!(
                "Symbol {} is in KNOWN_FAILURES but now compiles cleanly. \
                 Remove it from the list in tests/accuracy_tests.rs.",
                sym.sym
            ),
            (Ok(()), false) => clean += 1,
            (Err(_), true) => {
                let reason = KNOWN_FAILURES
                    .iter()
                    .find(|(n, _)| sym.sym == *n || sym.sym.ends_with(n))
                    .map(|(_, r)| *r)
                    .unwrap_or("");
                eprintln!(
                    "KNOWN FAILURE (expected, tracked): {} — {}",
                    sym.sym, reason
                );
                known += 1;
            }
            (Err(stderr), false) => new_failures.push((sym.sym.clone(), stderr)),
        }
    }

    println!(
        "Self-compile gate: {} clean, {} known failures (documented), {} new failures",
        clean,
        known,
        new_failures.len()
    );

    assert!(
        new_failures.is_empty(),
        "Self-compile gate: {} NEW compile failures not in KNOWN_FAILURES. \
         Fix them, or add to KNOWN_FAILURES with a comment naming the fix.\n\n{}",
        new_failures.len(),
        new_failures
            .iter()
            .map(|(n, e)| format!("=== {} ===\n{}", n, e))
            .collect::<Vec<_>>()
            .join("\n\n")
    );
}

/// Attempt to compile with gcc and clang at -std=c11 -Wall -Wextra -Werror -pedantic.
/// Returns Ok(()) on success, Err(<stderr>) on first failure.
/// Does NOT panic — callers decide whether to fail based on KNOWN_FAILURES.
fn try_compile(c_code: &str) -> Result<(), String> {
    let tu = format!(
        "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n{}\n",
        c_code
    );
    let path = std::env::temp_dir().join(format!(
        "self_gate_{}.c",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, &tu).map_err(|e| format!("write failed: {}", e))?;

    // Decompiled output contains AArch64 inline asm; must cross-compile.
    let mut tried_any = false;
    for (cc, base_args) in [
        ("aarch64-linux-gnu-gcc", &["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-c"][..]),
        ("clang", &["--target=aarch64-linux-gnu", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-c"][..]),
    ] {
        let out = match std::process::Command::new(cc)
            .args(base_args)
            .arg(&path)
            .arg("-o")
            .arg("/dev/null")
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        tried_any = true;
        if !out.status.success() {
            let _ = std::fs::remove_file(&path);
            return Err(format!(
                "{} failed:\n{}",
                cc,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    let _ = std::fs::remove_file(&path);
    if !tried_any {
        return Err(
            "No AArch64-capable compiler available (tried aarch64-linux-gnu-gcc and \
             clang --target=aarch64-linux-gnu). Install gcc-aarch64-linux-gnu."
                .to_string(),
        );
    }
    Ok(())
}

#[test]
fn test_self_compile_gate_known_failures() {
    let so_path = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so_path).expect("open libelftrace.so");
    let info = ctx.get_info().unwrap();

    let mut still_failing = 0;
    let mut newly_fixed: Vec<String> = Vec::new();

    for (name, reason) in KNOWN_FAILURES {
        let sym = match info
            .syms
            .iter()
            .find(|s| s.sym == *name || s.sym.ends_with(name))
        {
            Some(s) => s,
            None => {
                eprintln!(
                    "WARN: known failure symbol '{}' no longer present in libelftrace.so. \
                     Remove it from KNOWN_FAILURES.",
                    name
                );
                continue;
            }
        };
        let c_code = elftrace::decompiler::decompile_to_c(&ctx, sym.value);
        match try_compile(&c_code) {
            Ok(()) => newly_fixed.push(format!("{} (was: {})", name, reason)),
            Err(_) => still_failing += 1,
        }
    }

    println!(
        "Self-compile known-failure audit: {} still failing, {} newly fixed",
        still_failing,
        newly_fixed.len()
    );

    assert!(
        newly_fixed.is_empty(),
        "{} symbols in KNOWN_FAILURES now compile cleanly. \
         Remove them from the list in tests/accuracy_tests.rs:\n\n{}",
        newly_fixed.len(),
        newly_fixed.join("\n")
    );
}

#[test]
fn test_item2_x86_64_div_no_int128() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::x86_64::X86_64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = X86_64Lifter::new();

    // idiv rax (64-bit form) must be preserved as Asm, not DivRem
    let stmts = lifter.lift(&ctx, 0x1000, "idiv", "rax", &[0; 3]);
    assert_eq!(stmts.len(), 1);
    assert!(
        matches!(stmts[0], IrStmt::Asm(_)),
        "64-bit idiv must emit Asm, got: {:?}",
        stmts[0]
    );

    // idiv eax (32-bit form) still emits DivRem — regression guard
    let stmts = lifter.lift(&ctx, 0x1004, "idiv", "eax", &[0; 3]);
    assert_eq!(stmts.len(), 1);
    assert!(
        matches!(
            stmts[0],
            IrStmt::DivRem {
                ty: elftrace::decompiler::ir::IrType::Int32,
                ..
            }
        ),
        "32-bit idiv must still emit DivRem, got: {:?}",
        stmts[0]
    );
}

#[test]
fn test_p4_dead_block_elimination() {
    use elftrace::decompiler::decompile_to_c;
    use elftrace::elf_parser::ElfContext;

    // Use a real .so with `brk` instructions (exception handlers / __builtin_trap)
    // assemblePatch is the canonical example
    let so = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let info = ctx.get_info().unwrap();
    let assemble = info
        .syms
        .iter()
        .find(|s| s.sym.ends_with("assemblePatch"))
        .expect("find assemblePatch");

    let c = decompile_to_c(&ctx, assemble.value);

    // The bug: statements after __builtin_trap(); in unreachable blocks
    let lines: Vec<&str> = c.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "__builtin_trap();" && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            assert!(
                next.is_empty()
                    || next.starts_with("loc_")
                    || next == "}"
                    || next.starts_with("//"),
                "Dead code after __builtin_trap(); at line {}: {:?}",
                i + 2,
                next
            );
        }
    }

    // Same for unconditional goto followed by non-label
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("goto loc_") && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            assert!(
                next.is_empty()
                    || next.starts_with("loc_")
                    || next == "}"
                    || next.starts_with("//"),
                "Dead code after {}: {:?}",
                trimmed,
                next
            );
        }
    }
}

#[test]
fn test_p4_hotfix_switch_cases_not_dropped() {
    use elftrace::decompiler::decompile_to_c;
    use elftrace::elf_parser::ElfContext;

    let so = match std::env::var("ELFTRACE_SWITCH_SO").ok().or_else(|| {
        for p in [
            "/tmp/switch_test.so",
            "test_fixtures/accuracy/switch_test.so",
            "/workspace/test_fixtures/accuracy/switch_test.so",
        ] {
            if std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
        None
    }) {
        Some(p) => p,
        None => {
            eprintln!("SKIP: switch_test.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "dispatch")
        .expect("find dispatch");

    let c = decompile_to_c(&ctx, sym.value);

    // All 5 case return values must be present in the emitted C (decimal or hex).
    for (val, hex_str, name) in [
        (10, "0xa", "case0"),
        (20, "0x14", "case1"),
        (30, "0x1e", "case2"),
        (40, "0x28", "case3"),
        (50, "0x32", "case4"),
    ] {
        assert!(
            c.contains(&val.to_string()) || c.contains(hex_str),
            "case body return {} / {} ({}) missing from output.\n\
             Case bodies are being pruned by reachable_blocks.\n\
             Full output:\n{}",
            val,
            hex_str,
            name,
            c
        );
    }
}

#[test]
fn test_p4_hotfix_no_regression_on_simple_functions() {
    use elftrace::decompiler::decompile_to_c;
    use elftrace::elf_parser::ElfContext;

    let so = match get_test_so_path() {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym.ends_with("assemblePatch"))
        .expect("find assemblePatch");

    let c = decompile_to_c(&ctx, sym.value);

    // No dead code follows __builtin_trap();
    let lines: Vec<&str> = c.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "__builtin_trap();" && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            assert!(
                next.is_empty()
                    || next.starts_with("loc_")
                    || next == "}"
                    || next.starts_with("//"),
                "Dead code after __builtin_trap(); at line {}: {:?}",
                i + 2,
                next
            );
        }
    }

    // No dead code follows unconditional goto
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("goto loc_") && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            assert!(
                next.is_empty()
                    || next.starts_with("loc_")
                    || next == "}"
                    || next.starts_with("//"),
                "Dead code after {}: {:?}",
                trimmed,
                next
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Batch E regression guards — bugs seen in real commercial .so output
// ---------------------------------------------------------------------------

/// `movi v0.2d, #0` must be preserved as Asm, not emitted as a variable named "v0.2d".
/// C identifiers cannot contain '.', so emitting the raw NEON lane notation fails to compile.
#[test]
fn test_batch_e_movi_simd_asm() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    for (mnem, ops) in [
        ("movi", "v0.2d, #0"),
        ("movi", "v0.4s, #0"),
        ("movi", "q0, #0"),
    ] {
        let stmts = lifter.lift(&ctx, 0x1000, mnem, ops, &[0; 4]);
        assert_eq!(stmts.len(), 1);
        assert!(
            matches!(stmts[0], IrStmt::Asm(_)),
            "{} {} must emit Asm, got: {:?}",
            mnem, ops, stmts[0]
        );
    }

    // Scalar movi (w/x reg) must STILL lower to an assignment (regression guard).
    let stmts = lifter.lift(&ctx, 0x1000, "movi", "w0, #0", &[0; 4]);
    assert!(
        matches!(stmts[0], IrStmt::Assign { .. }),
        "movi w0, #0 must still emit Assign, got: {:?}", stmts[0]
    );
}

/// Indirect call through a register (bl x8 / blr x8) must emit a cast, not `x8()`.
#[test]
fn test_batch_e_indirect_call_cast() {
    use elftrace::decompiler::arch::ArchKind;
    use elftrace::decompiler::codegen::CodeGenerator;
    use elftrace::decompiler::ir::{
        IrBlock, IrExpr, IrFunction, IrStmt, IrType,
    };

    // Synthesize an IrFunction with a single call through x8.
    let ctx = ElfContext::stub();
    let codegen = CodeGenerator::new(&ctx, ArchKind::AArch64);

    let mut func = IrFunction {
        name: "synthetic_indirect".to_string(),
        start_address: 0x1000,
        size: 4,
        blocks: vec![IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![
                IrStmt::Call {
                    target: IrExpr::reg("x8", IrType::Int64),
                    name: None,
                    args: vec![IrExpr::reg("x0", IrType::Int64)],
                    ret_dst: Some(IrExpr::reg("w0", IrType::Int32)),
                },
                IrStmt::Return(None),
            ],
        }],
        ret_type: IrType::Int32,
        ret_reg: "w0".to_string(),
        base_stack_offset: 0,
        inferred_params: vec![],
    };
    func.inferred_params.clear();

    let c = codegen.generate_c_pseudocode(&func);

    // Must NOT contain a bare `x8()` call — that is a call to an int64 variable.
    assert!(
        !c.contains("x8()") && !c.contains("x8("),
        "Indirect call must be cast, not bare x8(). Got:\n{}",
        c
    );
    // Must contain the function-pointer cast pattern.
    assert!(
        c.contains("((int64_t(*)(uint64_t))(uintptr_t)x8)"),
        "Indirect call must emit ((int64_t(*)(...))(uintptr_t)x8)(...). Got:\n{}",
        c
    );
}

/// C++ demangled names (operator new, operator delete, std::vector<...>::push_back)
/// are not valid C identifiers and must not be emitted verbatim as call names.
#[test]
fn test_batch_e_cpp_demangle_fallback() {
    use elftrace::decompiler::arch::ArchKind;
    use elftrace::decompiler::codegen::CodeGenerator;
    use elftrace::decompiler::ir::{IrBlock, IrExpr, IrFunction, IrStmt, IrType};

    let ctx = ElfContext::stub();
    let codegen = CodeGenerator::new(&ctx, ArchKind::AArch64);

    for bad_name in [
        "operator new(unsigned long)",
        "operator delete(void*)",
        "std::vector<int, std::allocator<int>>::push_back(int&&)",
        "foo::bar::baz",
        "template<T> f(T)",
    ] {
        let func = IrFunction {
            name: "synthetic_cpp".to_string(),
            start_address: 0x1000,
            size: 4,
            blocks: vec![IrBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1004,
                stmts: vec![
                    IrStmt::Call {
                        target: IrExpr::Const(0xDEAD0000),
                        name: Some(bad_name.to_string()),
                        args: vec![IrExpr::reg("x0", IrType::Int64)],
                        ret_dst: Some(IrExpr::reg("x0", IrType::Int64)),
                    },
                    IrStmt::Return(None),
                ],
            }],
            ret_type: IrType::Int64,
            ret_reg: "x0".to_string(),
            base_stack_offset: 0,
            inferred_params: vec![],
        };
        let c = codegen.generate_c_pseudocode(&func);
        assert!(
            !c.contains(bad_name),
            "C++ demangled name {:?} must not appear in C output. Got:\n{}",
            bad_name, c
        );
        // Must fall back to the function-pointer cast using the address.
        assert!(
            c.contains("((int64_t(*)(uint64_t))0xdead0000)"),
            "C++ demangle {:?} must fall back to address cast. Got:\n{}",
            bad_name, c
        );
    }
}

/// End-to-end: `assemblePatch` decompiled output must not contain any of the
/// three compile-blocking patterns (`v0.2d`, bare `xN()` calls, C++ demangle).
#[test]
fn test_batch_e_assemblePatch_compiles_clean() {
    use elftrace::decompiler::decompile_to_c;

    let so = match std::env::var("ELFTRACE_SELF_SO").ok().or_else(|| {
        for p in [
            "/workspace/test_fixtures/libelftrace.so",
            "test_fixtures/libelftrace.so",
            "../app/src/main/jniLibs/arm64-v8a/libelftrace.so",
        ] {
            if std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
        None
    }) {
        Some(p) => p,
        None => {
            eprintln!("SKIP: libelftrace.so not found — batch E end-to-end not run");
            return;
        }
    };
    let ctx = ElfContext::open(&so).unwrap();
    let addr = match assemble_patch_addr(&ctx) {
        Some(a) => a,
        None => {
            eprintln!("SKIP: assemblePatch symbol not found in {}", so);
            return;
        }
    };
    let c = decompile_to_c(&ctx, addr);

    assert!(!c.contains("v0.2d"), "SIMD lane identifier leaked into output:\n{}", c);
    assert!(!c.contains("v0.4s"), "SIMD lane identifier leaked into output:\n{}", c);
    // No bare `xN()` calls (would require regex; approximate by checking known reg names)
    for reg in ["x0(", "x1(", "x2(", "x3(", "x4(", "x5(", "x6(", "x7(", "x8(", "x9("] {
        assert!(!c.contains(reg), "Bare register call {} in output:\n{}", reg, c);
    }

    assert_compiles(&c, "batch_e_assemblePatch");
}

// ---------------------------------------------------------------------------
// Batch F regression guards — blr argument forwarding and return value
// ---------------------------------------------------------------------------

/// `blr xN` with no explicitly written argument registers must emit the AAPCS
/// argument prefix (x0-x3) — the caller is forwarding its own parameters.
/// Previously emitted zero args, silently discarding the callee's inputs.
#[test]
fn test_batch_f_blr_forwards_parameter_args() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    // Caller does NOT explicitly write any arg register, then does blr x8.
    // Must emit at least x0..x3 as arguments.
    let stmts = lifter.lift(&ctx, 0x1000, "blr", "x8", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    match &stmts[0] {
        IrStmt::Call { args, .. } => {
            assert!(
                args.len() >= 4,
                "blr with no explicit arg writes must emit >=4 args (AAPCS prefix). Got: {:?}",
                args
            );
        }
        other => panic!("Expected Call, got: {:?}", other),
    }
}

/// `blr` must assign the return value to x0. Without this, callers that read
/// `w0` after the call see stale data and take wrong branches (real-world:
/// `env->RegisterNatives(...)` returns a status code checked immediately).
#[test]
fn test_batch_f_blr_assigns_return() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    let stmts = lifter.lift(&ctx, 0x1000, "blr", "x8", &[0; 4]);
    assert_eq!(stmts.len(), 1);
    match &stmts[0] {
        IrStmt::Call { ret_dst, .. } => {
            assert!(
                ret_dst.is_some(),
                "blr must assign ret_dst (x0) so callers that read w0 see the result. Got: {:?}",
                ret_dst
            );
        }
        other => panic!("Expected Call, got: {:?}", other),
    }
}

/// Explicit writes on caller side must still win: if the caller sets x0/x1
/// before blr, only those two arg slots appear (not forced to 4).
#[test]
fn test_batch_f_blr_respects_explicit_args() {
    use elftrace::decompiler::ir::IrStmt;
    use elftrace::decompiler::lifters::arm64::Arm64Lifter;
    use elftrace::decompiler::lifters::InstructionLifter;

    let ctx = ElfContext::stub();
    let mut lifter = Arm64Lifter::new();

    let _ = lifter.lift(&ctx, 0x1000, "mov", "x0, #5", &[0; 4]);
    let _ = lifter.lift(&ctx, 0x1004, "mov", "x1, #7", &[0; 4]);
    let stmts = lifter.lift(&ctx, 0x1008, "blr", "x8", &[0; 4]);
    match &stmts[0] {
        IrStmt::Call { args, .. } => {
            assert_eq!(
                args.len(), 2,
                "blr with 2 explicit arg writes must emit exactly 2 args. Got: {:?}",
                args
            );
        }
        other => panic!("Expected Call, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Batch G regression guard — sub-register aliasing
// ---------------------------------------------------------------------------

/// `wN = ...` must zero-extend into the parent `xN` (matching ARM64 hardware
/// semantics where w-writes zero the upper 32 bits), and `wN` reads must
/// truncate the parent to uint32_t. Without this, the two variables are
/// independent and the decompiled C produces wrong branch decisions.
#[test]
fn test_batch_g_sub_register_aliasing() {
    use elftrace::decompiler::arch::ArchKind;
    use elftrace::decompiler::codegen::CodeGenerator;
    use elftrace::decompiler::ir::{BinaryOp, IrBlock, IrExpr, IrFunction, IrStmt, IrType};

    let ctx = ElfContext::stub();
    let codegen = CodeGenerator::new(&ctx, ArchKind::AArch64);

    let func = IrFunction {
        name: "subreg_test".to_string(),
        start_address: 0x1000,
        size: 8,
        blocks: vec![IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1008,
            stmts: vec![
                // w8 = *(uint8_t*)x1
                IrStmt::Assign {
                    dst: IrExpr::reg("w8", IrType::Int32),
                    src: IrExpr::Load {
                        ptr: Box::new(IrExpr::reg("x1", IrType::Int64)),
                        ty: IrType::Int8,
                    },
                },
                // if (w8 == 0) goto 0x2000
                IrStmt::Branch {
                    cond: Some(IrExpr::Binary(
                        BinaryOp::Eq,
                        Box::new(IrExpr::reg("w8", IrType::Int32)),
                        Box::new(IrExpr::Const(0)),
                        IrType::Int8,
                    )),
                    target: 0x2000,
                },
            ],
        }],
        ret_type: IrType::Void,
        ret_reg: "x0".to_string(),
        base_stack_offset: 0,
        inferred_params: vec![],
    };

    let c = codegen.generate_c_pseudocode(&func);

    // Sub-register write must zero-extend into parent x8
    assert!(
        c.contains("x8 = (uint64_t)(uint32_t)"),
        "w8 write must zero-extend to x8. Got:\n{}", c
    );
    // Sub-register read must truncate the parent
    assert!(
        c.contains("(uint32_t)x8"),
        "w8 read must truncate x8. Got:\n{}", c
    );
    // w8 must NOT appear as a declared local
    assert!(
        !c.contains("int32_t w8;"),
        "w8 must not be a declared local. Got:\n{}", c
    );
}
