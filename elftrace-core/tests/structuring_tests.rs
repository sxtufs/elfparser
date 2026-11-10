use elftrace::decompiler::decompile_to_c;
use elftrace::decompiler::decompile_to_c_structured;
use elftrace::decompiler::ir::{IrBlock, IrExpr, IrStmt};
use elftrace::decompiler::structuring::cfgraph::CfGraph;
use elftrace::decompiler::structuring::dominators::{dominators, idom, ipost_dom};
use elftrace::decompiler::structuring::loops::detect_loops;
use elftrace::elf_parser::ElfContext;
use std::collections::HashSet;

fn assert_compiles(c_code: &str, label: &str) {
    let tu = format!(
        "#include <stdint.h>\n#include <stddef.h>\nextern void dummy_callee(void);\n{}\n",
        c_code
    );
    let path = std::env::temp_dir().join(format!("elftrace_struct_{}.c", label));
    std::fs::write(&path, tu).unwrap();
    for cc in ["gcc", "clang"] {
        let out = std::process::Command::new(cc)
            .args([
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-c",
                path.to_str().unwrap(),
                "-o",
                "/dev/null",
            ])
            .output()
            .unwrap_or_else(|_| panic!("{cc} not runnable"));
        assert!(
            out.status.success(),
            "{} FAILED on {}:\n{}",
            cc,
            label,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

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

// ---------------------------------------------------------------------------
// Phase A: Pure Graph Dominators & Post-Dominators
// ---------------------------------------------------------------------------

#[test]
fn test_structuring_dominators_diamond() {
    // Graph: 0 -> 1, 2 ; 1 -> 3 ; 2 -> 3 ; 3 -> exit
    let blocks = vec![
        IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1010,
            }],
        },
        IrBlock {
            id: 1,
            start_address: 0x1008,
            end_address: 0x100c,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1018,
            }],
        },
        IrBlock {
            id: 2,
            start_address: 0x1010,
            end_address: 0x1014,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1018,
            }],
        },
        IrBlock {
            id: 3,
            start_address: 0x1018,
            end_address: 0x101c,
            stmts: vec![IrStmt::Return(None)],
        },
    ];

    let g = CfGraph::from_blocks(blocks);
    assert_eq!(g.succ[0], vec![2, 1]);
    assert_eq!(g.succ[1], vec![3]);
    assert_eq!(g.succ[2], vec![3]);
    assert_eq!(g.succ[3], Vec::<usize>::new());

    let idoms = idom(&g);
    assert_eq!(idoms[1], Some(0));
    assert_eq!(idoms[2], Some(0));
    assert_eq!(idoms[3], Some(0));

    let ipdoms = ipost_dom(&g);
    assert_eq!(ipdoms[0], Some(3));
    assert_eq!(ipdoms[1], Some(3));
    assert_eq!(ipdoms[2], Some(3));
}

#[test]
fn test_structuring_dominators_loop() {
    // Graph: 0 -> 1 ; 1 -> 2, 4 ; 2 -> 3 ; 3 -> 1 ; 4 -> exit
    let blocks = vec![
        IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1008,
            }],
        },
        IrBlock {
            id: 1,
            start_address: 0x1008,
            end_address: 0x100c,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1020,
            }],
        },
        IrBlock {
            id: 2,
            start_address: 0x1010,
            end_address: 0x1014,
            stmts: vec![],
        },
        IrBlock {
            id: 3,
            start_address: 0x1018,
            end_address: 0x101c,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1008,
            }],
        },
        IrBlock {
            id: 4,
            start_address: 0x1020,
            end_address: 0x1024,
            stmts: vec![IrStmt::Return(None)],
        },
    ];

    let g = CfGraph::from_blocks(blocks);
    let dom = dominators(&g);
    assert!(dom[1].contains(&0));
    assert!(dom[1].contains(&1));
    assert!(dom[2].contains(&1));
    assert!(dom[3].contains(&1));

    let loops = detect_loops(&g);
    assert_eq!(loops.loops.len(), 1);
    assert_eq!(loops.loops[0].header, 1);
    assert_eq!(loops.loops[0].back_edges, vec![(3, 1)]);
    assert!(loops.is_reducible);
}

// ---------------------------------------------------------------------------
// Phase B: Natural Loops Detection & Reducibility
// ---------------------------------------------------------------------------

#[test]
fn test_structuring_loop_simple_while() {
    // 0 -> 1 ; 1 -> 2, 5 ; 2 -> 3 ; 3 -> 4 ; 4 -> 1 ; 5 -> exit
    let blocks = vec![
        IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![],
        },
        IrBlock {
            id: 1,
            start_address: 0x1008,
            end_address: 0x100c,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1028,
            }],
        },
        IrBlock {
            id: 2,
            start_address: 0x1010,
            end_address: 0x1014,
            stmts: vec![],
        },
        IrBlock {
            id: 3,
            start_address: 0x1018,
            end_address: 0x101c,
            stmts: vec![],
        },
        IrBlock {
            id: 4,
            start_address: 0x1020,
            end_address: 0x1024,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1008,
            }],
        },
        IrBlock {
            id: 5,
            start_address: 0x1028,
            end_address: 0x102c,
            stmts: vec![IrStmt::Return(None)],
        },
    ];
    let g = CfGraph::from_blocks(blocks);
    let l_info = detect_loops(&g);
    assert_eq!(l_info.loops.len(), 1);
    let lp = &l_info.loops[0];
    assert_eq!(lp.header, 1);
    let expected_nodes: HashSet<usize> = [1, 2, 3, 4].iter().copied().collect();
    assert_eq!(lp.nodes, expected_nodes);
    assert_eq!(lp.back_edges, vec![(4, 1)]);
    assert_eq!(lp.exit_blocks, vec![1]);
    assert!(l_info.is_reducible);
}

#[test]
fn test_structuring_loop_do_while() {
    // 0 -> 1 ; 1 -> 2 ; 2 -> 3, 1 ; 3 -> exit
    let blocks = vec![
        IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![],
        },
        IrBlock {
            id: 1,
            start_address: 0x1008,
            end_address: 0x100c,
            stmts: vec![],
        },
        IrBlock {
            id: 2,
            start_address: 0x1010,
            end_address: 0x1014,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1008,
            }],
        },
        IrBlock {
            id: 3,
            start_address: 0x1018,
            end_address: 0x101c,
            stmts: vec![IrStmt::Return(None)],
        },
    ];
    let g = CfGraph::from_blocks(blocks);
    let l_info = detect_loops(&g);
    assert_eq!(l_info.loops.len(), 1);
    let lp = &l_info.loops[0];
    assert_eq!(lp.header, 1);
    let expected_nodes: HashSet<usize> = [1, 2].iter().copied().collect();
    assert_eq!(lp.nodes, expected_nodes);
    assert_eq!(lp.back_edges, vec![(2, 1)]);
    assert_eq!(lp.exit_blocks, vec![2]);
    assert!(l_info.is_reducible);
}

#[test]
fn test_structuring_loop_nested() {
    // Outer loop 1..4, inner loop 2..3
    let blocks = vec![
        IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![],
        },
        IrBlock {
            id: 1,
            start_address: 0x1008,
            end_address: 0x100c,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1028,
            }],
        },
        IrBlock {
            id: 2,
            start_address: 0x1010,
            end_address: 0x1014,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1020,
            }],
        },
        IrBlock {
            id: 3,
            start_address: 0x1018,
            end_address: 0x101c,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1010,
            }],
        },
        IrBlock {
            id: 4,
            start_address: 0x1020,
            end_address: 0x1024,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1008,
            }],
        },
        IrBlock {
            id: 5,
            start_address: 0x1028,
            end_address: 0x102c,
            stmts: vec![IrStmt::Return(None)],
        },
    ];
    let g = CfGraph::from_blocks(blocks);
    let l_info = detect_loops(&g);
    assert_eq!(l_info.loops.len(), 2);
    assert_eq!(l_info.loops[0].header, 2); // Inner loop first
    assert_eq!(l_info.loops[1].header, 1); // Outer loop second
    assert!(l_info.is_reducible);
}

#[test]
fn test_structuring_irreducible_rejected() {
    // Two-entry loop: 0 -> 1, 2 ; 1 -> 2 ; 2 -> 1
    let blocks = vec![
        IrBlock {
            id: 0,
            start_address: 0x1000,
            end_address: 0x1004,
            stmts: vec![IrStmt::Branch {
                cond: Some(IrExpr::Const(1)),
                target: 0x1010,
            }],
        },
        IrBlock {
            id: 1,
            start_address: 0x1008,
            end_address: 0x100c,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1010,
            }],
        },
        IrBlock {
            id: 2,
            start_address: 0x1010,
            end_address: 0x1014,
            stmts: vec![IrStmt::Branch {
                cond: None,
                target: 0x1008,
            }],
        },
    ];
    let g = CfGraph::from_blocks(blocks);
    let l_info = detect_loops(&g);
    assert!(
        !l_info.is_reducible,
        "Two-entry loop must be marked irreducible!"
    );
}

// ---------------------------------------------------------------------------
// Phase C & D: Structured Statements on Real Compiled Binaries
// ---------------------------------------------------------------------------

#[test]
fn test_structuring_if_simple() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_if")
        .expect("find f_if");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_if Structured ===\n{}", c_code);
    assert!(c_code.contains("if (") || c_code.contains("?"));
    assert_compiles(&c_code, "f_if");
}

#[test]
fn test_structuring_if_else() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_ifelse")
        .expect("find f_ifelse");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_ifelse Structured ===\n{}", c_code);
    assert!(c_code.contains("if (") && c_code.contains("} else {"));
    assert_compiles(&c_code, "f_ifelse");
}

#[test]
fn test_structuring_while_loop() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_while")
        .expect("find f_while");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_while Structured ===\n{}", c_code);
    assert!(c_code.contains("while ("));
    assert_compiles(&c_code, "f_while");
}

#[test]
fn test_structuring_do_while() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_dowhile")
        .expect("find f_dowhile");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_dowhile Structured ===\n{}", c_code);
    assert_compiles(&c_code, "f_dowhile");
}

#[test]
fn test_structuring_for_loop() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_for")
        .expect("find f_for");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_for Structured ===\n{}", c_code);
    assert!(c_code.contains("while ("));
    assert_compiles(&c_code, "f_for");
}

#[test]
fn test_structuring_while_break() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_break")
        .expect("find f_break");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_break Structured ===\n{}", c_code);
    assert_compiles(&c_code, "f_break");
}

#[test]
fn test_structuring_while_continue() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_continue")
        .expect("find f_continue");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_continue Structured ===\n{}", c_code);
    assert_compiles(&c_code, "f_continue");
}

// ---------------------------------------------------------------------------
// Phase F: Fallback Verification & Differential Equivalence
// ---------------------------------------------------------------------------

#[test]
fn test_structuring_irreducible_falls_back_to_goto() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_irreducible")
        .expect("find f_irreducible");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_irreducible Structured Fallback ===\n{}", c_code);
    assert!(c_code.contains("goto loc_") || c_code.contains("partial structure"));
    assert_compiles(&c_code, "f_irreducible");
}

#[test]
fn test_structuring_indirect_branch_falls_back_to_goto() {
    let path = match fixture("test_fixtures/accuracy/structuring/fx_struct_a64_O2.so") {
        Some(p) => p,
        None => return,
    };
    let ctx = ElfContext::open(&path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == "f_indirect")
        .expect("find f_indirect");
    let c_code = decompile_to_c_structured(&ctx, sym.value);
    println!("=== f_indirect Structured Fallback ===\n{}", c_code);
    assert_compiles(&c_code, "f_indirect");
}

fn assert_behaviorally_equivalent(fixture_path: &str, sym_name: &str, tests: &[(&str, &str)]) {
    let ctx = ElfContext::open(fixture_path).unwrap();
    let info = ctx.get_info().unwrap();
    let sym = info
        .syms
        .iter()
        .find(|s| s.sym == sym_name)
        .expect("find symbol");
    let structured = decompile_to_c_structured(&ctx, sym.value);
    let unstructured = decompile_to_c(&ctx, sym.value);

    for (i, (a1, a2)) in tests.iter().enumerate() {
        let make_tu = |code: &str, fn_name: &str| -> String {
            format!(
                r#"#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

struct Node {{
    int id;
    int flags;
    double weight;
    struct Node* next;
}};

static struct Node node3 = {{ 3, 1, 10.0, NULL }};
static struct Node node2 = {{ 2, 0, 5.0, &node3 }};
static struct Node node1 = {{ 1, 1, 2.5, &node2 }};

{}

int main(void) {{
    double res = {}((double*){}, {});
    printf("%.4f\n", res);
    return 0;
}}
"#,
                code.replace(
                    "double traverse_linked_list(",
                    &format!("double {}(", fn_name)
                ),
                fn_name,
                a1,
                a2
            )
        };

        let s_out = compile_and_run(&make_tu(&structured, "f_struct"), &format!("s_{}", i));
        let u_out = compile_and_run(&make_tu(&unstructured, "f_unstruct"), &format!("u_{}", i));
        println!(
            "Input ({}, {}):\n  structured:   {}\n  unstructured: {}",
            a1,
            a2,
            s_out.trim(),
            u_out.trim()
        );
        assert_eq!(
            s_out.trim(),
            u_out.trim(),
            "Behavioral mismatch on input ({}, {}):\n  structured:   {}\n  unstructured: {}",
            a1,
            a2,
            s_out,
            u_out
        );
    }
}

fn compile_and_run(c_tu: &str, label: &str) -> String {
    let src_path = std::env::temp_dir().join(format!("equiv_{}.c", label));
    let bin_path = std::env::temp_dir().join(format!("equiv_{}.bin", label));
    std::fs::write(&src_path, c_tu).expect("write c file");

    let cc_status = std::process::Command::new("gcc")
        .args([
            "-O0",
            src_path.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .output()
        .expect("run gcc");
    assert!(
        cc_status.status.success(),
        "GCC compilation failed for {}:\n{}",
        label,
        String::from_utf8_lossy(&cc_status.stderr)
    );

    let run_status = std::process::Command::new(&bin_path)
        .output()
        .expect("run binary");
    assert!(
        run_status.status.success(),
        "Binary execution failed for {}:\n{}",
        label,
        String::from_utf8_lossy(&run_status.stderr)
    );

    String::from_utf8_lossy(&run_status.stdout).to_string()
}

#[test]
fn test_structural_equivalence_traverse_linked_list() {
    let path = match fixture("test_fixtures/realworld_bins/rw_aarch64_O2.so") {
        Some(p) => p,
        None => return,
    };
    assert_behaviorally_equivalent(
        &path,
        "traverse_linked_list",
        &[
            ("NULL", "0"),
            ("(uintptr_t)&node3", "3"),
            ("(uintptr_t)&node1", "2"),
            ("(uintptr_t)&node1", "99"),
        ],
    );
}

#[test]
fn test_structural_equivalence_realworld_suite() {
    let mut structured_count = 0;
    let mut total_count = 0;

    for arch in ["aarch64"] {
        let rel = "test_fixtures/accuracy/structuring/fx_struct_a64_O2.so";
        if let Some(path) = fixture(rel) {
            let ctx = ElfContext::open(&path).unwrap();
            let info = ctx.get_info().unwrap();
            for sym in &info.syms {
                if sym.size > 0
                    && !sym.sym.starts_with('.')
                    && !sym.sym.starts_with('_')
                    && !sym.sym.starts_with('$')
                {
                    total_count += 1;
                    let s_code = decompile_to_c_structured(&ctx, sym.value);
                    assert_compiles(&s_code, &format!("{}_{}", arch, sym.sym));
                    if !s_code.contains("goto loc_") {
                        structured_count += 1;
                    }
                }
            }
        }
    }

    // Skip cleanly if no fixture was found (e.g. CI where the structuring
    // fixture .so files are not checked into the repo).
    if total_count == 0 {
        eprintln!("SKIP: no structuring fixtures available for realworld suite");
        return;
    }

    let pct = (structured_count * 100) / total_count;
    println!(
        "Realworld Structuring Coverage: {} / {} symbols ({}%)",
        structured_count, total_count, pct
    );
    assert!(
        pct >= 50,
        "At least 50% of reducible functions must structure cleanly! Got {}%",
        pct
    );
}
