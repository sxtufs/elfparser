//! Structured C Pseudocode Emitter.

use super::StructuredNode;
use crate::decompiler::codegen::CodeGenerator;
use crate::decompiler::ir::{IrBlock, IrExpr, IrFunction, IrStmt, IrType};
use std::collections::{HashMap, HashSet};

pub fn emit_structured_c(
    func: &IrFunction,
    nodes: &[StructuredNode],
    codegen: &CodeGenerator,
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
        out.push_str(&format!(
            "// [partial structure: irreducible CFG, contains {} goto(s)]\n",
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

    let ret_c = func.ret_type.to_c_type();
    let params_str = if func.inferred_params.is_empty() {
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
                let call_name = match (name.as_ref(), target) {
                    (Some(n), _) => n.clone(),
                    (None, IrExpr::Const(addr)) => {
                        let proto_args = if args.is_empty() {
                            "void".to_string()
                        } else {
                            vec!["uint64_t"; args.len()].join(", ")
                        };
                        format!("((void(*)({}))0x{:x})", proto_args, addr)
                    }
                    (None, other) => codegen.format_expr(
                        other,
                        param_map,
                        func.base_stack_offset,
                        func.inferred_params.len(),
                    ),
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
            _ => {}
        }
    }
}

fn count_gotos(nodes: &[StructuredNode], count: &mut usize) {
    for n in nodes {
        match n {
            StructuredNode::Goto(_) | StructuredNode::Label(_) => *count += 1,
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
        StructuredNode::If {
            then, otherwise, ..
        } => has_explicit_return(then) && has_explicit_return(otherwise),
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
            _ => {}
        }
    }
}
