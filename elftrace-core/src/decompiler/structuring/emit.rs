//! Structured C Pseudocode Emitter.

use super::StructuredNode;
use crate::decompiler::codegen::{is_valid_c_ident, CodeGenerator};
use crate::decompiler::ir::{IrBlock, IrExpr, IrFunction, IrStmt, IrType};
use std::collections::{HashMap, HashSet};

pub fn emit_structured_c(
    func: &IrFunction,
    nodes: &[StructuredNode],
    codegen: &CodeGenerator,
    helpers: &[super::regions::TailHelper],
) -> String {
    let mut out = String::new();

    // 1. Header & signature
    let mut goto_count = 0;
    count_gotos(nodes, &mut goto_count);

    out.push_str(&format!("// Function: {}\n", func.name));
    out.push_str(&format!(
        "// Address:  0x{:08x} - 0x{:08x} ({} bytes)\n",
        func.start_address,
        func.start_address + func.size,
        func.size
    ));
    if goto_count > 0 {
        // NOTE: gotos here usually mean shared-exit join points (a common log/
        // assert/return tail reached from many sites), NOT an irreducible CFG.
        // The wording reflects that: this is a partially-collapsed structure
        // that preserves correctness by keeping gotos to genuine joins.
        out.push_str(&format!(
            "// Note: {} goto(s) kept - shared exit/return tail not fully structured\n",
            goto_count
        ));
    }
    out.push('\n');

    // Build parameter register map
    let mut param_reg_map: HashMap<String, String> = HashMap::new();
    let arg_regs = codegen.arch.argument_registers();
    for (idx, p) in func.inferred_params.iter().enumerate() {
        if idx < arg_regs.len() {
            let reg = arg_regs[idx];
            param_reg_map.insert(reg.to_lowercase(), p.name.clone());
            match codegen.arch {
                crate::decompiler::arch::ArchKind::AArch64 => {
                    if reg.starts_with('x') && !p.is_ptr && !p.is_fn_ptr {
                        param_reg_map.insert(format!("w{}", &reg[1..]), p.name.clone());
                    }
                }
                crate::decompiler::arch::ArchKind::X86_64 if !p.is_ptr && !p.is_fn_ptr => match reg
                {
                    "rdi" => {
                        param_reg_map.insert("edi".to_string(), p.name.clone());
                    }
                    "rsi" => {
                        param_reg_map.insert("esi".to_string(), p.name.clone());
                    }
                    "rdx" => {
                        param_reg_map.insert("edx".to_string(), p.name.clone());
                    }
                    "rcx" => {
                        param_reg_map.insert("ecx".to_string(), p.name.clone());
                    }
                    "r8" => {
                        param_reg_map.insert("r8d".to_string(), p.name.clone());
                    }
                    "r9" => {
                        param_reg_map.insert("r9d".to_string(), p.name.clone());
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    // 2. Declare local variables
    // Extern declarations for every named function this decompiled function
    // calls. The emitted C only includes stdint.h/stddef.h, so without these
    // every external call is an implicit declaration (-Werror). Variadic
    // int64_t prototypes compile for any call shape; the libc-memory
    // denylist keeps gcc's built-in prototypes intact.
    let mut extern_calls: Vec<String> = Vec::new();
    collect_extern_calls(nodes, &mut extern_calls);
    for name in &extern_calls {
        match LIBC_PROTO.iter().find(|(n, _)| n == name) {
            Some((_, proto)) => out.push_str(&format!("extern {};\n", proto)),
            None => out.push_str(&format!("extern int64_t {}();\n", name)),
        }
    }
    if !extern_calls.is_empty() {
        out.push('\n');
    }

    // 2a. Static helper functions for shared exit tails. Each helper holds the
    // tail body ONCE (the inliner kept it because duplicating it per site
    // would blow up output size); goto sites became `return tail_...(...)` or
    // a call followed by return. Emitted before the main body so no forward
    // declaration is needed.
    for h in helpers {
        let mut h_param_map: HashMap<String, String> = HashMap::new();
        for (name, _is_ptr) in &h.params {
            h_param_map.insert(name.clone(), name.clone());
        }
        let h_sig = if h.params.is_empty() {
            "void".to_string()
        } else {
            h.params
                .iter()
                .map(|(name, is_ptr)| {
                    if *is_ptr {
                        format!("uint8_t* {}", name)
                    } else {
                        format!("int64_t {}", name)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!("static int64_t {}({}) {{\n", h.name, h_sig));
        for l in &h.locals {
            let ty = if super::regions::STACK_PTR_REGS.contains(&l.as_str()) {
                "uint8_t*"
            } else {
                "int64_t"
            };
            out.push_str(&format!("    {ty} {l} = 0;\n"));
        }
        // Same -Werror suppression the main body uses: a tail can write an
        // epilogue register it never reads (dead store kept for fidelity).
        for l in &h.locals {
            out.push_str(&format!("    (void){};\n", l));
        }
        emit_node_list(
            &h.body,
            1,
            &mut out,
            codegen,
            func,
            &h_param_map,
            &HashSet::new(),
            &mut HashSet::new(),
        );
        // A tail whose every path ends in a noreturn call (e.g. a bare
        // `__stack_chk_fail()`) has no explicit return; falling off the end of
        // a non-void helper trips -Wreturn-type, so give it a dead `return 0;`.
        if !super::regions::has_plain_return(&h.body) {
            out.push_str("    return 0;\n");
        }
        out.push_str("}\n");
    }
    if !helpers.is_empty() {
        out.push('\n');
    }

    let ret_c = func.ret_type.to_c_type();
    // JNI entrypoints (JNI_OnLoad, Java_*) reuse x0 freely across pointer and
    // integer values (JNIEnv*, then jint returns), so type params as int64_t —
    // same rule as the linear codegen path. Pointer-typed params in
    // general functions keep their pointer type.
    let is_jni = func.name.contains("JNI_OnLoad") || func.name.starts_with("Java_");
    let params_str = if is_jni {
        func.inferred_params
            .iter()
            .map(|p| format!("int64_t {}", p.name))
            .collect::<Vec<_>>()
            .join(", ")
    } else if func.inferred_params.is_empty() {
        "void".to_string()
    } else {
        func.inferred_params
            .iter()
            .map(|p| {
                if p.is_fn_ptr {
                    format!("int32_t (*{})(int32_t, int32_t)", p.name)
                } else if p.is_ptr {
                    format!("{}* {}", p.ty.to_c_type(), p.name)
                } else {
                    format!("{} {}", p.ty.to_c_type(), p.name)
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    out.push_str(&format!("{} {}({}) {{\n", ret_c, func.name, params_str));

    // 2. Declare local variables
    let mut assigned_regs: HashMap<String, IrType> = HashMap::new();
    collect_local_regs(nodes, &mut assigned_regs, &param_reg_map);
    // Registers passed as helper-call arguments must be declared in the
    // caller even if the rewrite moved their only assignment into a helper.
    collect_tail_call_arg_regs(nodes, &mut assigned_regs);

    let mut has_stack_mem = false;
    let mut stack_ptrs = Vec::new();
    for reg in assigned_regs.keys() {
        let r_lower = reg.to_lowercase();
        if matches!(
            r_lower.as_str(),
            "x29" | "sp" | "rbp" | "rsp" | "ebp" | "esp"
        ) {
            has_stack_mem = true;
            stack_ptrs.push(reg.clone());
        }
    }
    for r in &stack_ptrs {
        assigned_regs.remove(r);
    }

    if has_stack_mem {
        out.push_str("    uint8_t __stack_mem[512] = {0};\n");
        for ptr in stack_ptrs {
            out.push_str(&format!("    uint8_t* {} = __stack_mem + 256;\n", ptr));
        }
        out.push('\n');
    }

    if !assigned_regs.is_empty() {
        let mut by_type: HashMap<IrType, Vec<String>> = HashMap::new();
        for (reg, ty) in &assigned_regs {
            by_type.entry(*ty).or_default().push(reg.clone());
        }
        let mut types: Vec<_> = by_type.keys().copied().collect();
        types.sort_by_key(|t| std::cmp::Reverse(t.size_bytes()));

        for ty in types {
            let mut regs = by_type.remove(&ty).unwrap();
            regs.sort();
            let init = if ty == IrType::Float64 || ty == IrType::Float32 {
                " = 0.0"
            } else {
                " = 0"
            };
            let decl = regs.join(&format!("{}, ", init));
            out.push_str(&format!("    {} {}{};\n", ty.to_c_type(), decl, init));
        }
        out.push('\n');
    }

    // Silence unused parameter and variable warnings under -Werror
    for p in &func.inferred_params {
        out.push_str(&format!("    (void){};\n", p.name));
    }
    for reg in assigned_regs.keys() {
        out.push_str(&format!("    (void){};\n", reg));
    }
    out.push('\n');

    let mut jump_targets = HashSet::new();
    collect_all_jump_targets(nodes, &mut jump_targets);
    let mut emitted_labels = HashSet::new();

    // 3. Emit structured body
    emit_node_list(
        nodes,
        1,
        &mut out,
        codegen,
        func,
        &param_reg_map,
        &jump_targets,
        &mut emitted_labels,
    );

    // Post-pass: drop any `loc_XXXXXXXX:` label that no emitted `goto loc_XXXXXXXX;`
    // references. The structurer can label a block whose only referrer was a
    // branch that got absorbed into an if/while (or eliminated as dead code),
    // leaving a defined-but-unused label. That trips -Werror=unused-label in the
    // self-compile gate. Removing an unreferenced label is semantically inert.
    out = prune_unused_labels(out);

    // Ensure function returns
    if !has_explicit_return(nodes) {
        if func.ret_type != IrType::Void && !func.ret_reg.is_empty() {
            let mapped_ret = param_reg_map
                .get(&func.ret_reg.to_lowercase())
                .cloned()
                .unwrap_or_else(|| func.ret_reg.clone());
            out.push_str(&format!("    return {};\n", mapped_ret));
        } else if func.ret_type == IrType::Void {
            out.push_str("    return;\n");
        } else {
            out.push_str("    return 0;\n");
        }
    }

    out.push_str("}\n");
    out
}

#[allow(clippy::too_many_arguments)]
fn emit_node_list(
    nodes: &[StructuredNode],
    indent: usize,
    out: &mut String,
    codegen: &CodeGenerator,
    func: &IrFunction,
    param_map: &HashMap<String, String>,
    jump_targets: &HashSet<u64>,
    emitted_labels: &mut HashSet<u64>,
) {
    let ind_str = "    ".repeat(indent);
    for n in nodes {
        match n {
            StructuredNode::Block(b) => {
                emit_block_stmts(
                    b,
                    indent,
                    out,
                    codegen,
                    func,
                    param_map,
                    jump_targets,
                    emitted_labels,
                );
            }
            StructuredNode::If {
                cond,
                then,
                otherwise,
            } => {
                let cond_str = codegen.format_expr(
                    cond,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                if otherwise.is_empty() {
                    out.push_str(&format!("{}if ({}) {{\n", ind_str, cond_str));
                    emit_node_list(
                        then,
                        indent + 1,
                        out,
                        codegen,
                        func,
                        param_map,
                        jump_targets,
                        emitted_labels,
                    );
                    out.push_str(&format!("{}}}\n", ind_str));
                } else if then.is_empty() {
                    out.push_str(&format!("{}if (!({})) {{\n", ind_str, cond_str));
                    emit_node_list(
                        otherwise,
                        indent + 1,
                        out,
                        codegen,
                        func,
                        param_map,
                        jump_targets,
                        emitted_labels,
                    );
                    out.push_str(&format!("{}}}\n", ind_str));
                } else {
                    out.push_str(&format!("{}if ({}) {{\n", ind_str, cond_str));
                    emit_node_list(
                        then,
                        indent + 1,
                        out,
                        codegen,
                        func,
                        param_map,
                        jump_targets,
                        emitted_labels,
                    );
                    out.push_str(&format!("{}}} else {{\n", ind_str));
                    emit_node_list(
                        otherwise,
                        indent + 1,
                        out,
                        codegen,
                        func,
                        param_map,
                        jump_targets,
                        emitted_labels,
                    );
                    out.push_str(&format!("{}}}\n", ind_str));
                }
            }
            StructuredNode::While { cond, body } => {
                let cond_str = codegen.format_expr(
                    cond,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                out.push_str(&format!("{}while ({}) {{\n", ind_str, cond_str));
                emit_node_list(
                    body,
                    indent + 1,
                    out,
                    codegen,
                    func,
                    param_map,
                    jump_targets,
                    emitted_labels,
                );
                out.push_str(&format!("{}}}\n", ind_str));
            }
            StructuredNode::DoWhile { cond, body } => {
                let cond_str = codegen.format_expr(
                    cond,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                out.push_str(&format!("{}do {{\n", ind_str));
                emit_node_list(
                    body,
                    indent + 1,
                    out,
                    codegen,
                    func,
                    param_map,
                    jump_targets,
                    emitted_labels,
                );
                out.push_str(&format!("{}}} while ({});\n", ind_str, cond_str));
            }
            StructuredNode::Break => {
                out.push_str(&format!("{}break;\n", ind_str));
            }
            StructuredNode::Continue => {
                out.push_str(&format!("{}continue;\n", ind_str));
            }
            StructuredNode::Return(v) => {
                if let Some(val) = v {
                    let v_str = codegen.format_expr(
                        val,
                        param_map,
                        func.base_stack_offset,
                        func.inferred_params.len(),
                    );
                    out.push_str(&format!("{}return {};\n", ind_str, v_str));
                } else {
                    out.push_str(&format!("{}return;\n", ind_str));
                }
            }
            StructuredNode::Goto(tgt) => {
                out.push_str(&format!("{}goto loc_{:08x};\n", ind_str, tgt));
            }
            StructuredNode::Label(addr) => {
                if emitted_labels.insert(*addr) {
                    out.push_str(&format!("\nloc_{:08x}:\n", addr));
                }
            }
            StructuredNode::Switch {
                selector,
                cases,
                default,
            } => {
                let sel_str = codegen.format_expr(
                    selector,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                out.push_str(&format!("{}switch ({}) {{\n", ind_str, sel_str));
                for (val, tgt) in cases {
                    out.push_str(&format!(
                        "{}    case {}: goto loc_{:08x};\n",
                        ind_str, val, tgt
                    ));
                }
                if let Some(d) = default {
                    out.push_str(&format!("{}    default: goto loc_{:08x};\n", ind_str, d));
                } else {
                    out.push_str(&format!("{}    default: break;\n", ind_str));
                }
                out.push_str(&format!("{}}}\n", ind_str));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_block_stmts(
    b: &IrBlock,
    indent: usize,
    out: &mut String,
    codegen: &CodeGenerator,
    func: &IrFunction,
    param_map: &HashMap<String, String>,
    jump_targets: &HashSet<u64>,
    emitted_labels: &mut HashSet<u64>,
) {
    if jump_targets.contains(&b.start_address) && emitted_labels.insert(b.start_address) {
        out.push_str(&format!("\nloc_{:08x}:\n", b.start_address));
    }
    let ind_str = "    ".repeat(indent);
    for stmt in &b.stmts {
        match stmt {
            IrStmt::Assign { dst, src } => {
                // Sub-register destination (w0/eax/…) cannot be used as an C
                // lvalue: `format_expr` renders it as `(uint32_t)x0`, and
                // `(uint32_t)x0 = …;` is a compile error. Mirror codegen.rs:
                // assign the wider parent with a zero-extending truncation of
                // the source, matching ARM64 w-writes / x86-64 32-bit writes.
                if let IrExpr::Reg(dst_r, _) = dst {
                    let dst_lower = dst_r.to_lowercase();
                    if let Some((parent, _)) = crate::decompiler::codegen::sub_register_info(&dst_lower) {
                        let parent_name = param_map
                            .get(&parent)
                            .cloned()
                            .unwrap_or(parent);
                        let src_str = codegen.format_expr(
                            src,
                            param_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        out.push_str(&format!(
                            "{}{} = (uint64_t)(uint32_t)({});\n",
                            ind_str, parent_name, src_str
                        ));
                        continue;
                    }
                }

                let dst_str = codegen.format_expr(
                    dst,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                let mut src_str = codegen.format_expr(
                    src,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                if dst_str != src_str {
                    if let Some(p) = func
                        .inferred_params
                        .iter()
                        .find(|p| p.name == dst_str && p.is_ptr)
                    {
                        src_str = format!("({}*){}", p.ty.to_c_type(), src_str);
                    }
                    if (src_str.contains("sp")
                        || src_str.contains("x29")
                        || src_str.contains("esp")
                        || src_str.contains("ebp")
                        || src_str.contains("rsp")
                        || src_str.contains("rbp"))
                        && !dst_str.contains('*')
                    {
                        src_str = format!("(int64_t)(uintptr_t)({})", src_str);
                    }
                    // String literals assigned to an integer destination
                    // (e.g. adrp+add resolved to a .rodata address) must be
                    // cast to an integer, otherwise the C compiler rejects
                    // `x1 = "...";` as char* -> int64_t.
                    if matches!(src, IrExpr::StringLit(_)) && !dst_str.contains('*') {
                        src_str = format!("(int64_t)(uintptr_t)({})", src_str);
                    }
                    // A pointer-cast source (e.g. `(int64_t*)x20`, the JNIEnv
                    // vtable load) assigned to a scalar register must go
                    // through uintptr_t, or the C compiler rejects it as a
                    // pointer -> integer conversion.
                    if src_str.contains("*)(") || (src_str.contains("*)") && !src_str.contains(" *("))
                    {
                        if !dst_str.contains('*') {
                            src_str = format!("(int64_t)(uintptr_t)({})", src_str);
                        }
                    }
                    // A pointer-typed source register (a pointer param in a
                    // non-JNI function) assigned to a scalar local must be
                    // cast down, like `x20 = a0;`.
                    if !dst_str.contains('*') {
                        if let Some(p) = func
                            .inferred_params
                            .iter()
                            .find(|p| p.name == src_str && p.is_ptr)
                        {
                            src_str = format!("({})(uintptr_t){}", p.ty.to_c_type(), src_str);
                        }
                    }
                    out.push_str(&format!("{}{}{} = {};\n", ind_str, "", dst_str, src_str));
                }
            }
            IrStmt::Store { ptr, val, ty } => {
                let ptr_type = ty.to_c_type();
                let ptr_str = codegen.format_expr(
                    ptr,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                let val_str = codegen.format_expr(
                    val,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                let needs_paren = (ptr_str.contains('+')
                    || ptr_str.contains('-')
                    || ptr_str.contains(' ')
                    || ptr_str.contains('*'))
                    && !(ptr_str.starts_with('(') && ptr_str.ends_with(')'));
                if needs_paren {
                    if ptr_str.starts_with("a") && (ptr_str.contains('+') || ptr_str.contains('-'))
                    {
                        let op = if ptr_str.contains('+') { "+" } else { "-" };
                        let parts: Vec<&str> = ptr_str.splitn(2, ['+', '-']).collect();
                        out.push_str(&format!(
                            "{}*({}*)((uint8_t*)(uintptr_t){} {} {}) = {};\n",
                            ind_str,
                            ptr_type,
                            parts[0].trim(),
                            op,
                            parts[1].trim(),
                            val_str
                        ));
                    } else {
                        out.push_str(&format!(
                            "{}*({}*)({}) = {};\n",
                            ind_str, ptr_type, ptr_str, val_str
                        ));
                    }
                } else {
                    out.push_str(&format!(
                        "{}*({}*){} = {};\n",
                        ind_str, ptr_type, ptr_str, val_str
                    ));
                }
            }
            IrStmt::Call {
                target,
                name,
                args,
                ret_dst,
            } => {
                let proto_args = if args.is_empty() {
                    "void".to_string()
                } else {
                    vec!["uint64_t"; args.len()].join(", ")
                };
                let call_name = match (name.as_ref(), target) {
                    // A "name" that is really a local register (indirect call
                    // through a callee-saved register holding a vtable entry,
                    // e.g. `x8`) must become a function-pointer cast, not a
                    // direct call of a variable.
                    (Some(n), _) if !is_valid_c_ident(n) => match target {
                        IrExpr::Const(addr) => {
                            format!("((void(*)({}))0x{:x})", proto_args, addr)
                        }
                        other => {
                            let inner = codegen.format_expr(
                                other,
                                param_map,
                                func.base_stack_offset,
                                func.inferred_params.len(),
                            );
                            format!("((void(*)({}))(uintptr_t){})", proto_args, inner)
                        }
                    },
                    (Some(n), _) if looks_like_register_name(n) => {
                        let inner = n.clone();
                        format!("((int64_t(*)({}))(uintptr_t){})", proto_args, inner)
                    }
                    (Some(n), _) => n.clone(),
                    (None, IrExpr::Const(addr)) => {
                        format!("((void(*)({}))0x{:x})", proto_args, addr)
                    }
                    (None, other) => {
                        // Indirect call with no resolved name (e.g. the JNI
                        // vtable `x8` loaded from the JNIEnv): must become a
                        // function-pointer cast, a bare `x8(...)` is a
                        // "called object is not a function" error.
                        let inner = codegen.format_expr(
                            other,
                            param_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        format!("((int64_t(*)({}))(uintptr_t){})", proto_args, inner)
                    }
                };
                let formatted_args = args
                    .iter()
                    .map(|a| {
                        format!(
                            "(uint64_t)(uintptr_t){}",
                            codegen.format_expr(
                                a,
                                param_map,
                                func.base_stack_offset,
                                func.inferred_params.len(),
                            )
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Some(dst) = ret_dst {
                    out.push_str(&format!(
                        "{}{} = {}({});\n",
                        ind_str,
                        codegen.format_expr(
                            dst,
                            param_map,
                            func.base_stack_offset,
                            func.inferred_params.len()
                        ),
                        call_name,
                        formatted_args
                    ));
                } else {
                    out.push_str(&format!("{}{}({});\n", ind_str, call_name, formatted_args));
                }
            }
            IrStmt::Return(v) => {
                if let Some(val) = v {
                    let v_str = codegen.format_expr(
                        val,
                        param_map,
                        func.base_stack_offset,
                        func.inferred_params.len(),
                    );
                    out.push_str(&format!("{}return {};\n", ind_str, v_str));
                } else if func.ret_type != IrType::Void && !func.ret_reg.is_empty() {
                    let mapped_ret = param_map
                        .get(&func.ret_reg.to_lowercase())
                        .cloned()
                        .unwrap_or_else(|| func.ret_reg.clone());
                    out.push_str(&format!("{}return {};\n", ind_str, mapped_ret));
                } else if func.ret_type == IrType::Void {
                    out.push_str(&format!("{}return;\n", ind_str));
                } else {
                    out.push_str(&format!("{}return 0;\n", ind_str));
                }
                break;
            }
            IrStmt::Branch {
                cond: Some(c),
                target,
            } => {
                let c_str = codegen.format_expr(
                    c,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                out.push_str(&format!(
                    "{}if ({}) goto loc_{:08x};\n",
                    ind_str, c_str, target
                ));
            }
            IrStmt::Branch { cond: None, target } => {
                out.push_str(&format!("{}goto loc_{:08x};\n", ind_str, target));
                break;
            }
            IrStmt::Asm(s) => {
                out.push_str(&format!("{}__asm__(\"{}\");\n", ind_str, s));
            }
            IrStmt::Trap => {
                out.push_str(&format!("{}__builtin_trap();\n", ind_str));
            }
            IrStmt::IndirectBranch { target } => {
                // Unrecovered indirect branch (e.g. a tail-call `br x16` that is
                // a terminator, not a switch). We can't statically resolve the
                // destination, but dropping it silently would hide a real
                // control-flow transfer, so render it as an annotated asm line.
                let t = codegen.format_expr(
                    target,
                    param_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                out.push_str(&format!("{}/* indirect branch -> {} */\n", ind_str, t));
            }
            _ => {}
        }
    }
}

fn count_gotos(nodes: &[StructuredNode], count: &mut usize) {
    for n in nodes {
        match n {
            StructuredNode::Goto(_) => *count += 1,
            StructuredNode::Block(b) => {
                for s in &b.stmts {
                    if let IrStmt::Branch { .. } = s {
                        *count += 1;
                    }
                }
            }
            StructuredNode::If {
                then, otherwise, ..
            } => {
                count_gotos(then, count);
                count_gotos(otherwise, count);
            }
            StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                count_gotos(body, count);
            }
            _ => {}
        }
    }
}

fn has_explicit_return(nodes: &[StructuredNode]) -> bool {
    nodes.iter().any(|n| match n {
        StructuredNode::Return(_) => true,
        // The goto-fallback path puts Return inside a Block's stmt list rather
        // than as a StructuredNode::Return. Without this, emit_structured_c
        // appends a second implicit `return` after the fallback already ended
        // the function -> "return a0; return a0;".
        StructuredNode::Block(b) => b.stmts.iter().any(|s| matches!(s, IrStmt::Return(_))),
        StructuredNode::If {
            then, otherwise, ..
        } => has_explicit_return(then) && has_explicit_return(otherwise),
        // A loop containing a return does NOT guarantee the function returns,
        // so loops are intentionally excluded here (keeps the implicit
        // trailing return for such functions, avoiding C fall-off errors).
        _ => false,
    })
}

fn collect_local_regs(
    nodes: &[StructuredNode],
    assigned_regs: &mut HashMap<String, IrType>,
    param_map: &HashMap<String, String>,
) {
    for n in nodes {
        match n {
            StructuredNode::Block(b) => {
                for s in &b.stmts {
                    collect_stmt_regs(s, assigned_regs, param_map);
                }
            }
            StructuredNode::If {
                cond,
                then,
                otherwise,
            } => {
                collect_expr_regs(cond, assigned_regs, param_map);
                collect_local_regs(then, assigned_regs, param_map);
                collect_local_regs(otherwise, assigned_regs, param_map);
            }
            StructuredNode::While { cond, body } | StructuredNode::DoWhile { cond, body } => {
                collect_expr_regs(cond, assigned_regs, param_map);
                collect_local_regs(body, assigned_regs, param_map);
            }
            StructuredNode::Switch { selector, .. } => {
                collect_expr_regs(selector, assigned_regs, param_map);
            }
            _ => {}
        }
    }
}

fn collect_stmt_regs(
    stmt: &IrStmt,
    assigned_regs: &mut HashMap<String, IrType>,
    param_map: &HashMap<String, String>,
) {
    match stmt {
        IrStmt::Assign { dst, src } => {
            collect_expr_regs(dst, assigned_regs, param_map);
            collect_expr_regs(src, assigned_regs, param_map);
        }
        IrStmt::Store { ptr, val, .. } => {
            collect_expr_regs(ptr, assigned_regs, param_map);
            collect_expr_regs(val, assigned_regs, param_map);
        }
        IrStmt::Call {
            target,
            args,
            ret_dst,
            ..
        } => {
            collect_expr_regs(target, assigned_regs, param_map);
            for a in args {
                collect_expr_regs(a, assigned_regs, param_map);
            }
            if let Some(r) = ret_dst {
                collect_expr_regs(r, assigned_regs, param_map);
            }
        }
        IrStmt::Branch { cond: Some(c), .. } => {
            collect_expr_regs(c, assigned_regs, param_map);
        }
        IrStmt::Return(Some(v)) => {
            collect_expr_regs(v, assigned_regs, param_map);
        }
        _ => {}
    }
}

fn collect_expr_regs(
    expr: &IrExpr,
    assigned_regs: &mut HashMap<String, IrType>,
    param_map: &HashMap<String, String>,
) {
    match expr {
        IrExpr::Reg(r, ty) => {
            let r_lower = r.to_lowercase();
            let is_param = param_map.contains_key(&r_lower)
                || (r_lower.starts_with('a') && r_lower[1..].chars().all(|c| c.is_ascii_digit()));
            if r_lower.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && !r_lower.starts_with(|c: char| c.is_ascii_digit())
                && !r_lower.contains('.')
                && !r_lower.contains(' ')
                && !r_lower.contains('+')
                && !r_lower.contains('-')
                && !r_lower.contains('[')
                && !r_lower.contains(']')
                && !is_param
            {
                let exact_ty = CodeGenerator::infer_hardware_reg_type(&r_lower, *ty);
                assigned_regs.insert(r.clone(), exact_ty);
            }
        }
        IrExpr::Binary(_, lhs, rhs, _) => {
            collect_expr_regs(lhs, assigned_regs, param_map);
            collect_expr_regs(rhs, assigned_regs, param_map);
        }
        IrExpr::Unary(_, inner, _) => {
            collect_expr_regs(inner, assigned_regs, param_map);
        }
        IrExpr::Load { ptr, .. } => {
            collect_expr_regs(ptr, assigned_regs, param_map);
        }
        IrExpr::Ternary {
            cond,
            true_val,
            false_val,
            ..
        } => {
            collect_expr_regs(cond, assigned_regs, param_map);
            collect_expr_regs(true_val, assigned_regs, param_map);
            collect_expr_regs(false_val, assigned_regs, param_map);
        }
        _ => {}
    }
}

fn collect_all_jump_targets(nodes: &[StructuredNode], targets: &mut HashSet<u64>) {
    for n in nodes {
        match n {
            StructuredNode::Goto(tgt) => {
                targets.insert(*tgt);
            }
            StructuredNode::Block(b) => {
                for s in &b.stmts {
                    if let IrStmt::Branch { target, .. } = s {
                        targets.insert(*target);
                    }
                }
            }
            StructuredNode::If {
                then, otherwise, ..
            } => {
                collect_all_jump_targets(then, targets);
                collect_all_jump_targets(otherwise, targets);
            }
            StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                collect_all_jump_targets(body, targets);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, tgt) in cases {
                    targets.insert(*tgt);
                }
                if let Some(d) = default {
                    targets.insert(*d);
                }
            }
            _ => {}
        }
    }
}

/// Remove `loc_XXXXXXXX:` label lines that are not referenced by any emitted
/// `goto loc_XXXXXXXX;` statement.
///
/// Labels are collected in a first pass (`collect_all_jump_targets`) from the
/// structured node tree, but the structurer can absorb or eliminate the branch
/// that referenced a label while the label site itself survives. An unreferenced
/// C label is semantically inert but trips `-Werror=unused-label`, so we prune it.
pub fn prune_unused_labels(body: String) -> String {
    // 1. Collect every address that is the target of an emitted goto.
    let mut referenced: HashSet<u64> = HashSet::new();
    let needle = "goto loc_";
    let mut search_from = 0usize;
    while let Some(rel) = body[search_from..].find(needle) {
        let start = search_from + rel + needle.len();
        // Parse the 8+ hex digits that follow, up to a non-hex char.
        let rest = &body[start..];
        let hex_end = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        if hex_end > 0 {
            if let Ok(addr) = u64::from_str_radix(&rest[..hex_end], 16) {
                referenced.insert(addr);
            }
        }
        search_from = start;
    }

    // 2. Rebuild the body, dropping unreferenced label lines.
    let mut result = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if let Some(hexpart) = trimmed.strip_prefix("loc_") {
            // A label line looks like `loc_XXXXXXXX:` (possibly leading whitespace).
            if let Some(colon_idx) = hexpart.find(':') {
                let addr_str = &hexpart[..colon_idx];
                if !addr_str.is_empty() && addr_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        if !referenced.contains(&addr) {
                            // Drop this label line entirely.
                            continue;
                        }
                    }
                }
            }
        }
        result.push_str(line);
    }
    result
}

/// Names that gcc treats as built-ins: declaring them variadically would
/// conflict, so they get their real libc prototypes instead.
const LIBC_PROTO: &[(&str, &str)] = &[
    ("memcpy", "void *memcpy(void *, const void *, unsigned long)"),
    ("memmove", "void *memmove(void *, const void *, unsigned long)"),
    ("memset", "void *memset(void *, int, unsigned long)"),
    ("memcmp", "int memcmp(const void *, const void *, unsigned long)"),
    ("strlen", "unsigned long strlen(const char *)"),
    ("strcpy", "char *strcpy(char *, const char *)"),
    ("strncpy", "char *strncpy(char *, const char *, unsigned long)"),
    ("strcat", "char *strcat(char *, const char *)"),
    ("strcmp", "int strcmp(const char *, const char *)"),
    ("strncmp", "int strncmp(const char *, const char *, unsigned long)"),
];

/// True for plain register-shaped names (x0, w19, q8, v3): a call "name" like
/// this is an indirect call through a local register, not a symbol.
fn looks_like_register_name(s: &str) -> bool {
    let lower = s.to_lowercase();
    let b = lower.as_bytes();
    b.len() >= 2
        && matches!(b[0], b'x' | b'w' | b'q' | b'v' | b'd' | b's' | b'h' | b'b')
        && b[1..].iter().all(|c| c.is_ascii_digit())
        && s.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
}

/// Collect the names of every called function in the node tree, deduped in
/// first-appearance order, skipping register-shaped names (those are emitted
/// as function-pointer casts and need no declaration).
fn collect_extern_calls(nodes: &[StructuredNode], out: &mut Vec<String>) {
    for n in nodes {
        match n {
            StructuredNode::Block(b) => {
                for s in &b.stmts {
                    if let IrStmt::Call { name, .. } = s {
                        if let Some(nm) = name {
                            if is_valid_c_ident(nm)
                                && !looks_like_register_name(nm)
                                && !out.contains(nm)
                            {
                                out.push(nm.clone());
                            }
                        }
                    }
                }
            }
            StructuredNode::If { then, otherwise, .. } => {
                collect_extern_calls(then, out);
                collect_extern_calls(otherwise, out);
            }
            StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                collect_extern_calls(body, out);
            }
            _ => {}
        }
    }
}

/// Registers passed as arguments to tail-helper calls (`return
/// tail_XXXXXXXX(x19, ...)`): they must be declared in the caller even though
/// the assignments that produced them may have moved into the helper body.
fn collect_tail_call_arg_regs(nodes: &[StructuredNode], assigned_regs: &mut HashMap<String, IrType>) {
    fn expr_args(e: &IrExpr, out: &mut Vec<String>) {
        match e {
            IrExpr::Call { name: Some(n), args, .. } if n.starts_with("tail_") => {
                for a in args {
                    if let IrExpr::Reg(r, _) = a {
                        out.push(r.to_lowercase());
                    }
                }
            }
            IrExpr::Unary(_, inner, _) => expr_args(inner, out),
            IrExpr::Binary(_, l, r, _) => {
                expr_args(l, out);
                expr_args(r, out);
            }
            IrExpr::Ternary { cond, true_val, false_val, .. } => {
                expr_args(cond, out);
                expr_args(true_val, out);
                expr_args(false_val, out);
            }
            _ => {}
        }
    }
    fn walk(n: &StructuredNode, assigned_regs: &mut HashMap<String, IrType>) {
        match n {
            StructuredNode::Block(b) => {
                for s in &b.stmts {
                    let mut names: Vec<String> = Vec::new();
                    match s {
                        IrStmt::Return(Some(e)) => expr_args(e, &mut names),
                        IrStmt::Call { target, args, .. } => {
                            let mut push_call = |c: &IrExpr| {
                                if let IrExpr::Call { name: Some(cn), args: cargs, .. } = c {
                                    if cn.starts_with("tail_") {
                                        for ca in cargs {
                                            if let IrExpr::Reg(r, _) = ca {
                                                names.push(r.to_lowercase());
                                            }
                                        }
                                    }
                                }
                            };
                            push_call(target);
                            for a in args {
                                push_call(a);
                            }
                        }
                        _ => {}
                    }
                    for r in names {
                        if r != "sp" && !assigned_regs.contains_key(&r) {
                            assigned_regs.insert(r, IrType::Int64);
                        }
                    }
                }
            }
            StructuredNode::If { then, otherwise, .. } => {
                for n in then.iter().chain(otherwise.iter()) {
                    walk(n, assigned_regs);
                }
            }
            StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                for n in body.iter() {
                    walk(n, assigned_regs);
                }
            }
            _ => {}
        }
    }
    for n in nodes {
        walk(n, assigned_regs);
    }
}
