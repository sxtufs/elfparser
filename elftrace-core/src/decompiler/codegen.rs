//! Structured C/C++ Pseudocode Generator from Intermediate Representation (IR).

use super::arch::ArchKind;
use super::ir::{BinaryOp, IrExpr, IrFunction, IrStmt, IrType, UnaryOp};
use crate::elf_parser::ElfContext;
use std::collections::{HashMap, HashSet};

/// Compute reachable block indices via BFS from block 0, following:
///   - IrStmt::Branch { cond: Some, target }   → BOTH target and fallthrough
///   - IrStmt::Branch { cond: None, target }   → ONLY target
///   - IrStmt::Return | IrStmt::Trap           → no successors
///   - IrStmt::IndirectBranch                  → no successors
///   - fallthrough (last stmt is not a terminator) → next block index
fn reachable_blocks(func: &IrFunction) -> std::collections::HashSet<usize> {
    use std::collections::{HashSet, VecDeque};

    // map address → block index (start_address)
    let mut addr_to_idx: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, b) in func.blocks.iter().enumerate() {
        addr_to_idx.insert(b.start_address, i);
    }

    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();
    if !func.blocks.is_empty() {
        queue.push_back(0usize);
        reachable.insert(0);
    }

    while let Some(idx) = queue.pop_front() {
        let block = &func.blocks[idx];
        let mut succs: Vec<usize> = Vec::new();

        // Find terminator
        let mut has_terminator = false;
        for stmt in &block.stmts {
            match stmt {
                IrStmt::Branch { cond, target } => {
                    if let Some(&t) = addr_to_idx.get(target) {
                        succs.push(t);
                    }
                    if cond.is_some() {
                        // Fallthrough to next block
                        if idx + 1 < func.blocks.len() {
                            succs.push(idx + 1);
                        }
                    }
                    has_terminator = true;
                    break;
                }
                IrStmt::Return(_) | IrStmt::Trap => {
                    // Genuine terminators — no successors
                    has_terminator = true;
                    break;
                }
                IrStmt::IndirectBranch { .. } => {
                    // Indirect branches (jump tables, computed gotos, vtable dispatch) have
                    // successors that are not statically enumerable from the IR alone — the
                    // targets live in a data table referenced by the block's prior instructions.
                    //
                    // Conservative rule: every subsequent block is potentially reachable. This
                    // over-preserves (dead blocks after a switch will still be emitted), but it
                    // NEVER drops a live case body.
                    for i in (idx + 1)..func.blocks.len() {
                        succs.push(i);
                    }
                    has_terminator = true;
                    break;
                }
                _ => {}
            }
        }

        if !has_terminator && idx + 1 < func.blocks.len() {
            succs.push(idx + 1);
        }

        for s in succs {
            if reachable.insert(s) {
                queue.push_back(s);
            }
        }
    }

    reachable
}

pub struct CodeGenerator<'a> {
    pub ctx: &'a ElfContext,
    pub arch: ArchKind,
}

impl<'a> CodeGenerator<'a> {
    pub fn new(ctx: &'a ElfContext, arch: ArchKind) -> Self {
        Self { ctx, arch }
    }

    pub fn generate_c_pseudocode(&self, func: &IrFunction) -> String {
        let mut out = String::new();

        // 1. Header (Clean IDA Pro / Ghidra C comment style)
        out.push_str(&format!("// Function: {}\n", func.name));
        out.push_str(&format!(
            "// Address:  0x{:08x} - 0x{:08x} ({} bytes)\n\n",
            func.start_address,
            func.start_address + func.size,
            func.size
        ));

        // 2. Build parameter mapping from incoming ABI registers to parameter names
        // e.g. for ARM64: w0 -> a0, x0 -> a0, w1 -> a1, x1 -> a1
        // e.g. for x86_64: edi -> a0, rdi -> a0, esi -> a1, rsi -> a1, edx -> a2, rdx -> a2
        // e.g. for ARM32: r0 -> a0, r1 -> a1, r2 -> a2
        let mut param_reg_map: HashMap<String, String> = HashMap::new();
        let arg_regs = self.arch.argument_registers();
        for (idx, p) in func.inferred_params.iter().enumerate() {
            if idx < arg_regs.len() {
                let reg = arg_regs[idx];
                param_reg_map.insert(reg.to_lowercase(), p.name.clone());
                // Sub-register (w0/eax/…) → param name aliasing is INTENTIONALLY
                // not added here. Sub-register reads and writes are handled via
                // sub_register_info() in format_expr and the Assign arm, which
                // emit a (uint32_t) truncation cast against the parent's name.
                // Adding an alias here would shadow that path and produce
                // integer-width-inaccurate output.
            }
        }

        // Propagate aliases where a register is saved from an incoming argument register
        let mut reg_aliases: HashMap<String, String> = HashMap::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let IrStmt::Assign {
                    dst: IrExpr::Reg(d, _),
                    src,
                } = stmt
                {
                    let d_lower = d.to_lowercase();
                    if matches!(d_lower.as_str(), "rax" | "eax" | "x0" | "w0" | "r0") {
                        continue;
                    }
                    // Only track aliases for CALLEE-SAVED registers (AArch64 x19-x30,
                    // x86-64 rbx/rbp/r12-r15, ARM32 r4-r11/lr). Caller-saved registers
                    // (x0-x18 for AArch64, rax/rcx/rdx/rsi/rdi/r8-r11 for x86-64) are
                    // reused across calls; aliasing them to a parameter name produces
                    // WRONG output at call sites because the parameter's backing
                    // register may be reassigned before the alias is consumed.
                    //
                    // Example that motivates this: `x3 = x0` (alias x3 -> a0) followed
                    // by `x0 = malloc(...)` followed by `bl pthread_create(x0,...,x3)`.
                    // Without the fix, arg 4 renders as `a0` (malloc's value), not
                    // x3's actual value (the ORIGINAL a0 param).
                    if !self.arch.is_callee_saved(&d_lower) {
                        continue;
                    }
                    // Second check: drop the alias if the destination is reassigned
                    // anywhere else in the function. Callee-saved registers CAN be
                    // reassigned legitimately; when they are, they are no longer a
                    // pure copy of the parameter.
                    let already_aliased = reg_aliases.contains_key(&d_lower);
                    if already_aliased {
                        reg_aliases.remove(&d_lower);
                        continue;
                    }
                    if let IrExpr::Reg(s, _) = src {
                        let s_lower = s.to_lowercase();
                        if let Some(p) = param_reg_map.get(&s_lower) {
                            reg_aliases.insert(d_lower.clone(), p.clone());
                        }
                    }
                }
            }
        }
        param_reg_map.extend(reg_aliases);

        // 3. Signature
        let ret_c = func.ret_type.to_c_type();
        let is_jni = func.name.contains("JNI_OnLoad") || func.name.starts_with("Java_");

        let params_str = if is_jni {
            func.inferred_params
                .iter()
                .map(|p| format!("int64_t {}", p.name))
                .collect::<Vec<_>>()
                .join(", ")
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

        let params_decl = if params_str.is_empty() {
            "void".to_string()
        } else {
            params_str
        };

        out.push_str(&format!("{} {}({}) {{\n", ret_c, func.name, params_decl));

        // 4. Local variable declarations grouped by type (collect all referenced registers, excluding parameters)
        let mut assigned_regs: HashMap<String, IrType> = HashMap::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                collect_stmt_regs(stmt, &mut assigned_regs, &param_reg_map);
            }
        }

        let all_regs: Vec<String> = assigned_regs.keys().cloned().collect();
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
            for (reg, ty) in assigned_regs {
                by_type.entry(ty).or_default().push(reg);
            }
            let mut types: Vec<_> = by_type.keys().copied().collect();
            types.sort_by_key(|t| std::cmp::Reverse(t.size_bytes()));

            for ty in types {
                let mut regs = by_type.remove(&ty).unwrap();
                regs.sort();
                let init = if matches!(ty, IrType::Float32 | IrType::Float64) {
                    " = 0.0"
                } else {
                    " = 0"
                };
                let decl = regs
                    .iter()
                    .map(|r| format!("{}{}", r, init))
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!("    {} {};\n", ty.to_c_type(), decl));
            }
            out.push('\n');
        }

        // Silence unused parameter and variable warnings under -Werror
        for p in &func.inferred_params {
            out.push_str(&format!("    (void){};\n", p.name));
        }
        for r in &all_regs {
            out.push_str(&format!("    (void){};\n", r));
        }
        out.push('\n');

        // 5. Statements by basic block (only emit labels for blocks that are actually branch targets)
        let reachable = reachable_blocks(func);
        let mut jump_targets = HashSet::new();
        for block in &func.blocks {
            for stmt in &block.stmts {
                if let IrStmt::Branch { target, .. } = stmt {
                    jump_targets.insert(*target);
                }
            }
        }

        for (b_idx, block) in func.blocks.iter().enumerate() {
            if !reachable.contains(&b_idx) {
                continue;
            }
            if b_idx > 0 && jump_targets.contains(&block.start_address) {
                out.push_str(&format!("\nloc_{:08x}:\n", block.start_address));
            }

            for stmt in &block.stmts {
                match stmt {
                    IrStmt::Assign { dst, src } => {
                        // Special-case: writes to a sub-register (w0, eax, …) update
                        // the wider parent register with zero-extension semantics
                        // (matches ARM64 w-writes and x86-64 32-bit writes).
                        if let IrExpr::Reg(dst_r, _) = dst {
                            let dst_lower = dst_r.to_lowercase();
                            if let Some((parent, _)) = sub_register_info(&dst_lower) {
                                let parent_name = param_reg_map
                                    .get(&parent)
                                    .cloned()
                                    .unwrap_or(parent);
                                let src_str = self.format_expr(
                                    src,
                                    &param_reg_map,
                                    func.base_stack_offset,
                                    func.inferred_params.len(),
                                );
                                out.push_str(&format!(
                                    "    {} = (uint64_t)(uint32_t)({});\n",
                                    parent_name, src_str
                                ));
                                continue;
                            }
                        }

                        let dst_str = self.format_expr(
                            dst,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let mut src_str = self.format_expr(
                            src,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        if dst_str != src_str {
                            if !is_jni {
                                if let Some(p) = func
                                    .inferred_params
                                    .iter()
                                    .find(|p| p.name == dst_str && p.is_ptr)
                                {
                                    src_str = format!("({}*){}", p.ty.to_c_type(), src_str);
                                }
                            }
                            // Frame/stack pointer registers are declared as
                            // `uint8_t*` in the emitted C. When the source
                            // mentions a frame register, cast to uint8_t* so the
                            // assignment type-checks against the pointer-typed
                            // destination. For scalar destinations, cast to
                            // int64_t as before.
                            let dst_lower = dst_str.to_lowercase();
                            let dst_is_frame = matches!(
                                dst_lower.as_str(),
                                "sp" | "x29" | "rbp" | "rsp" | "ebp" | "esp"
                            );
                            let src_mentions_frame = src_str.contains("sp")
                                || src_str.contains("x29")
                                || src_str.contains("esp")
                                || src_str.contains("ebp")
                                || src_str.contains("rsp")
                                || src_str.contains("rbp");
                            if src_mentions_frame && dst_is_frame {
                                src_str = format!("(uint8_t*)(uintptr_t)({})", src_str);
                            } else if src_mentions_frame && !dst_str.contains('*') {
                                src_str = format!("(int64_t)(uintptr_t)({})", src_str);
                            }
                            // String literals assigned to an integer destination
                            // (e.g. adrp+add resolved to a .rodata address) must
                            // be cast to an integer, otherwise the C compiler
                            // rejects `a3 = "...";` as char* -> int64_t.
                            if matches!(src, IrExpr::StringLit(_)) && !dst_str.contains('*') {
                                src_str = format!("(int64_t)(uintptr_t)({})", src_str);
                            }
                            out.push_str(&format!("    {} = {};\n", dst_str, src_str));
                        }
                    }
                    IrStmt::Store { ptr, val, ty } => {
                        let ptr_type = ty.to_c_type();
                        let ptr_str = self.format_expr(
                            ptr,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let val_str = self.format_expr(
                            val,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let needs_paren = (ptr_str.contains('+')
                            || ptr_str.contains('-')
                            || ptr_str.contains(' ')
                            || ptr_str.contains('*'))
                            && !(ptr_str.starts_with('(') && ptr_str.ends_with(')'));
                        if needs_paren {
                            if ptr_str.starts_with("a")
                                && (ptr_str.contains('+') || ptr_str.contains('-'))
                            {
                                let op = if ptr_str.contains('+') { "+" } else { "-" };
                                let parts: Vec<&str> = ptr_str.splitn(2, ['+', '-']).collect();
                                out.push_str(&format!(
                                    "    *({}*)((uint8_t*)(uintptr_t){} {} {}) = {};\n",
                                    ptr_type,
                                    parts[0].trim(),
                                    op,
                                    parts[1].trim(),
                                    val_str
                                ));
                            } else {
                                out.push_str(&format!(
                                    "    *({}*)({}) = {};\n",
                                    ptr_type, ptr_str, val_str
                                ));
                            }
                        } else {
                            out.push_str(&format!(
                                "    *({}*){} = {};\n",
                                ptr_type, ptr_str, val_str
                            ));
                        }
                    }
                    IrStmt::DivRem {
                        quot_dst,
                        rem_dst,
                        dividend_high,
                        dividend_low,
                        divisor,
                        is_signed,
                        ty: _,
                    } => {
                        let q_str = self.format_expr(
                            quot_dst,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let r_str = self.format_expr(
                            rem_dst,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let dh_str = self.format_expr(
                            dividend_high,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let dl_str = self.format_expr(
                            dividend_low,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );
                        let div_str = self.format_expr(
                            divisor,
                            &param_reg_map,
                            func.base_stack_offset,
                            func.inferred_params.len(),
                        );

                        let cast_high = if *is_signed {
                            "(int64_t)"
                        } else {
                            "(uint64_t)"
                        };
                        let cast_ret = if *is_signed { "int32_t" } else { "uint32_t" };
                        out.push_str(&format!(
                            "    int64_t dividend_64 = ({})(((uint64_t)(uint32_t){} << 32) | (uint32_t){});\n\
                                 {} = ({})dividend_64 / {};\n\
                                 {} = ({})dividend_64 % {};\n",
                            cast_high, dh_str, dl_str,
                            q_str, cast_ret, div_str,
                            r_str, cast_ret, div_str
                        ));
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
                            // Use the symbol name only if it is a valid C identifier.
                            // C++ demangled names like "operator new(unsigned long)" contain
                            // characters that would be a compile error if emitted verbatim.
                            (Some(n), _) if is_valid_c_ident(n) => n.clone(),
                            // Invalid identifier (C++ demangle) but we know the address -> cast.
                            (Some(_), IrExpr::Const(addr)) => {
                                format!("((int64_t(*)({}))0x{:x})", proto_args, addr)
                            }
                            // Unresolved call to a literal address -> cast.
                            (None, IrExpr::Const(addr)) => {
                                format!("((int64_t(*)({}))0x{:x})", proto_args, addr)
                            }
                            // Indirect call through a register or expression -> cast.
                            // The 0x6d8 vtable dispatch in JNI code hits this path.
                            (_, other) => {
                                let inner = self.format_expr(
                                    other,
                                    &param_reg_map,
                                    func.base_stack_offset,
                                    func.inferred_params.len(),
                                );
                                format!("((int64_t(*)({}))(uintptr_t){})", proto_args, inner)
                            }
                        };
                        // libc memory/string functions have canonical C prototypes
                        // (memcpy(void*, const void*, size_t) etc). Wrapping the
                        // arguments in (uint64_t)(uintptr_t) produces
                        // integer-typed values that the compiler rejects as
                        // pointer args (-Wint-conversion). Skip the wrapper and
                        // cast the return value to int64_t if the destination is
                        // an integer register.
                        let is_libc_mem = name
                            .as_deref()
                            .map(is_libc_memory_fn)
                            .unwrap_or(false);
                        let formatted_args = args
                            .iter()
                            .enumerate()
                            .map(|(i, a)| {
                                let inner = self.format_expr(
                                    a,
                                    &param_reg_map,
                                    func.base_stack_offset,
                                    func.inferred_params.len(),
                                );
                                let cast = if is_libc_mem {
                                    libc_arg_cast(name.as_deref().unwrap_or(""), i)
                                } else {
                                    "(uint64_t)(uintptr_t)"
                                };
                                format!("{}{}", cast, inner)
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        let call_expr = if is_libc_mem {
                            format!("((int64_t)(uintptr_t){}({}))", call_name, formatted_args)
                        } else {
                            format!("{}({})", call_name, formatted_args)
                        };
                        if let Some(dst) = ret_dst {
                            out.push_str(&format!(
                                "    {} = {};\n",
                                self.format_expr(
                                    dst,
                                    &param_reg_map,
                                    func.base_stack_offset,
                                    func.inferred_params.len()
                                ),
                                call_expr
                            ));
                        } else if is_libc_mem {
                            out.push_str(&format!("    {}({});\n", call_name, formatted_args));
                        } else {
                            out.push_str(&format!("    {};\n", call_expr));
                        }
                    }
                    IrStmt::Branch { cond, target } => {
                        if let Some(c) = cond {
                            out.push_str(&format!(
                                "    if ({}) goto loc_{:08x};\n",
                                self.format_expr(
                                    c,
                                    &param_reg_map,
                                    func.base_stack_offset,
                                    func.inferred_params.len()
                                ),
                                target
                            ));
                        } else {
                            out.push_str(&format!("    goto loc_{:08x};\n", target));
                        }
                    }
                    IrStmt::IndirectBranch { target } => {
                        out.push_str(&format!(
                            "    goto *{}; // indirect jump / switch dispatch\n",
                            self.format_expr(
                                target,
                                &param_reg_map,
                                func.base_stack_offset,
                                func.inferred_params.len()
                            )
                        ));
                    }
                    IrStmt::Return(val) => {
                        if func.ret_type == IrType::Void {
                            out.push_str("    return;\n");
                        } else if let Some(v) = val {
                            out.push_str(&format!(
                                "    return {};\n",
                                self.format_expr(
                                    v,
                                    &param_reg_map,
                                    func.base_stack_offset,
                                    func.inferred_params.len()
                                )
                            ));
                        } else if func.ret_type != IrType::Void {
                            // Route through format_expr so sub-registers (w0) are
                            // emitted as `(uint32_t)parent` rather than the raw,
                            // undeclared sub-register name.
                            let ret_expr = IrExpr::reg(&func.ret_reg, func.ret_type);
                            let mapped_ret = self.format_expr(
                                &ret_expr,
                                &param_reg_map,
                                func.base_stack_offset,
                                func.inferred_params.len(),
                            );
                            out.push_str(&format!("    return {};\n", mapped_ret));
                        } else {
                            out.push_str("    return;\n");
                        }
                    }
                    IrStmt::Trap => {
                        out.push_str("    __builtin_trap();\n\n");
                        break;
                    }
                    IrStmt::Asm(s) => {
                        out.push_str(&format!("    __asm__(\"{}\");\n", s));
                    }
                    IrStmt::Comment(s) => {
                        out.push_str(&format!("    // {}\n", s));
                    }
                }
            }
        }

        // 6. Clean deduplicated return statement at exit.
        // Route the return value through format_expr so sub-registers
        // (e.g. `w0` return type) are emitted as `(uint32_t)x0` / `(uint32_t)a0`
        // rather than the raw, undeclared sub-register name.
        let last_line = out.lines().last().unwrap_or("").trim();
        if !last_line.starts_with("return") {
            if func.ret_type != IrType::Void {
                let ret_expr = IrExpr::reg(&func.ret_reg, func.ret_type);
                let mapped_ret = self.format_expr(
                    &ret_expr,
                    &param_reg_map,
                    func.base_stack_offset,
                    func.inferred_params.len(),
                );
                out.push_str(&format!("    return {};\n", mapped_ret));
            } else {
                out.push_str("    return;\n");
            }
        }

        out.push_str("}\n");
        out
    }

    pub fn format_expr(
        &self,
        expr: &IrExpr,
        param_map: &HashMap<String, String>,
        base_offset: u64,
        param_count: usize,
    ) -> String {
        match expr {
            IrExpr::Const(val) => {
                if *val > 9 {
                    format!("0x{:x}", val)
                } else {
                    val.to_string()
                }
            }
            IrExpr::StringLit(s) => s.clone(),
            IrExpr::Reg(r, _) => {
                let r_lower = r.to_lowercase();
                if let Some(p) = param_map.get(&r_lower) {
                    return p.clone();
                }
                // Sub-register (w0/eax/…) of a parent register. If the parent is a
                // parameter, emit a truncation cast from the parameter name; if the
                // parent is a local, emit a cast from the parent local's name.
                // Parent locals are always declared; sub-registers are never
                // declared as separate variables (see collect_expr_regs).
                if let Some((parent, cast)) = sub_register_info(&r_lower) {
                    if let Some(p) = param_map.get(&parent) {
                        return format!("{}{}", cast, p);
                    }
                    return format!("{}{}", cast, parent);
                }
                r.clone()
            }
            IrExpr::StackVar { offset, .. } => {
                if *offset < 0 {
                    format!("var_{:x}", -offset)
                } else {
                    format!("arg_{:x}", offset)
                }
            }
            IrExpr::Unary(op, inner, _) => {
                let op_str = match op {
                    UnaryOp::Neg => "-",
                    UnaryOp::Not => "~",
                };
                format!(
                    "{}{}",
                    op_str,
                    self.format_expr(inner, param_map, base_offset, param_count)
                )
            }
            IrExpr::Binary(op, lhs, rhs, _) => {
                let is_unsigned = matches!(
                    op,
                    BinaryOp::LtU
                        | BinaryOp::LeU
                        | BinaryOp::GtU
                        | BinaryOp::GeU
                        | BinaryOp::DivU
                        | BinaryOp::ShrU
                );
                let op_str = match op {
                    BinaryOp::Add => "+",
                    BinaryOp::Sub => "-",
                    BinaryOp::Mul => "*",
                    BinaryOp::DivS | BinaryOp::DivU => "/",
                    BinaryOp::Mod => "%",
                    BinaryOp::And => "&",
                    BinaryOp::Or => "|",
                    BinaryOp::Xor => "^",
                    BinaryOp::Shl => "<<",
                    BinaryOp::ShrU | BinaryOp::ShrS => ">>",
                    BinaryOp::Eq => "==",
                    BinaryOp::Ne => "!=",
                    BinaryOp::LtS | BinaryOp::LtU => "<",
                    BinaryOp::LeS | BinaryOp::LeU => "<=",
                    BinaryOp::GtS | BinaryOp::GtU => ">",
                    BinaryOp::GeS | BinaryOp::GeU => ">=",
                };
                let mut l_str = self.format_expr(lhs, param_map, base_offset, param_count);
                if child_needs_paren(lhs, *op, false) {
                    l_str = format!("({})", l_str);
                }
                let mut r_str = self.format_expr(rhs, param_map, base_offset, param_count);
                if child_needs_paren(rhs, *op, true) {
                    r_str = format!("({})", r_str);
                }
                if matches!(op, BinaryOp::Eq | BinaryOp::Ne) && r_str.starts_with("0x") {
                    if let IrExpr::Const(c) = **rhs {
                        if c > i64::MAX as u64 {
                            r_str = format!("(int64_t){}", r_str);
                        }
                    }
                }
                if is_unsigned {
                    let ucast = if self.arch.pointer_size() == 8 {
                        "(uint64_t)"
                    } else {
                        "(uint32_t)"
                    };
                    format!(
                        "{}{}{} {} {}{}{}",
                        ucast, l_str, "", op_str, ucast, r_str, ""
                    )
                } else {
                    format!("{} {} {}", l_str, op_str, r_str)
                }
            }
            IrExpr::Load { ptr, ty } => {
                let ptr_str = self.format_expr(ptr, param_map, base_offset, param_count);
                if self.arch == ArchKind::X86_32 {
                    if let Some(arg_idx) =
                        crate::decompiler::analysis::resolve_x86_stack_arg(ptr, base_offset)
                    {
                        if arg_idx < param_count {
                            return format!("a{}", arg_idx);
                        }
                    }
                }
                let ptr_type = ty.to_c_type();
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
                        format!(
                            "*({}*)((uint8_t*)(uintptr_t){} {} {})",
                            ptr_type,
                            parts[0].trim(),
                            op,
                            parts[1].trim()
                        )
                    } else {
                        format!("*({}*)({})", ptr_type, ptr_str)
                    }
                } else {
                    format!("*({}*){}", ptr_type, ptr_str)
                }
            }
            IrExpr::Ternary {
                cond,
                true_val,
                false_val,
                ..
            } => {
                let c_str = self.format_expr(cond, param_map, base_offset, param_count);
                let mut t_str = self.format_expr(true_val, param_map, base_offset, param_count);
                let mut f_str = self.format_expr(false_val, param_map, base_offset, param_count);
                // Under -Werror -Wextra, `cond ? (uint32_t)x : 0` triggers
                // -Wsign-compare because the two branches have different
                // signedness. Balance them by casting both sides to the same
                // type. The sub-register fix produces `(uint32_t)parent` on
                // one side and `Const(0)` on the other for csel to wzr —
                // exactly this pattern.
                let t_unsigned = t_str.contains("(uint32_t)") || t_str.contains("(uint64_t)");
                let f_unsigned = f_str.contains("(uint32_t)") || f_str.contains("(uint64_t)");
                if t_unsigned && !f_unsigned {
                    f_str = format!("(uint32_t){}", f_str);
                } else if f_unsigned && !t_unsigned {
                    t_str = format!("(uint32_t){}", t_str);
                }
                format!("({}) ? {} : {}", c_str, t_str, f_str)
            }
            IrExpr::Call {
                target, name, args, ..
            } => {
                let call_name = name.clone().unwrap_or_else(|| {
                    self.format_expr(target, param_map, base_offset, param_count)
                });
                let formatted_args = args
                    .iter()
                    .map(|a| self.format_expr(a, param_map, base_offset, param_count))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{}({})", call_name, formatted_args)
            }
        }
    }

    pub fn infer_hardware_reg_type(reg: &str, default_ty: IrType) -> IrType {
        let r = reg.to_lowercase();
        if (r.starts_with('d') && r[1..].chars().all(|c| c.is_ascii_digit()))
            || (r.starts_with("xmm") && default_ty == IrType::Float64)
        {
            IrType::Float64
        } else if (r.starts_with('s') && r[1..].chars().all(|c| c.is_ascii_digit()))
            || (r.starts_with("xmm") && default_ty == IrType::Float32)
        {
            IrType::Float32
        } else if r.starts_with('w') && r[1..].chars().all(|c| c.is_ascii_digit()) {
            IrType::Int32
        } else if r.starts_with('x') && r[1..].chars().all(|c| c.is_ascii_digit()) {
            IrType::Int64
        } else {
            default_ty
        }
    }

    pub fn generate_data_declaration(&self, name: &str, address: u64, size: u64) -> String {
        let sec_name = self
            .ctx
            .get_section_name_for_vaddr(address)
            .unwrap_or_else(|| "data".to_string());
        let demangled_str = self
            .ctx
            .syms_map
            .get(&address)
            .and_then(|s| s.demangled.clone());
        let mut out = String::new();

        if let Some(ref d) = demangled_str {
            out.push_str(&format!("// Data Symbol: {}\n", d));
            out.push_str(&format!("// Mangled:     {}\n", name));
        } else {
            out.push_str(&format!("// Data Symbol: {}\n", name));
        }
        out.push_str(&format!(
            "// Section:     {} (0x{:08x}, {} bytes)\n\n",
            sec_name, address, size
        ));

        let offset = match self.ctx.vaddr_to_offset(address) {
            Some(o) => o as usize,
            None => {
                return format!(
                    "// [Error] Failed to resolve address 0x{:08x} to file offset\n",
                    address
                )
            }
        };

        let max_data_len = std::cmp::min(size as usize, self.ctx.raw.len().saturating_sub(offset));
        let slice = &self.ctx.raw[offset..offset + max_data_len];

        // 1. Check if it is a printable C string (like _ZTS... typeinfo name)
        if let Some(nul) = slice.iter().position(|&b| b == 0) {
            let str_candidate = &slice[..nul];
            if !str_candidate.is_empty()
                && str_candidate.iter().all(|&b| (0x20..=0x7E).contains(&b))
            {
                let text = String::from_utf8_lossy(str_candidate);
                out.push_str(&format!(
                    "const char {}[{}] = \"{}\";\n",
                    name,
                    nul + 1,
                    text
                ));
                return out;
            }
        }

        // 2. Check if it is a VTable (_ZTV...) or array of pointers
        let is_64 = self.ctx.get_info().map(|i| i.is_64).unwrap_or(true);
        let ptr_size = if is_64 { 8 } else { 4 };
        if name.starts_with("_ZTV") || size >= (ptr_size as u64 * 2) {
            out.push_str(&format!("void* {}[] = {{\n", name));
            for (idx, chunk) in slice.chunks_exact(ptr_size).enumerate() {
                let ptr_val = if is_64 {
                    u64::from_le_bytes(chunk.try_into().unwrap())
                } else {
                    u32::from_le_bytes(chunk.try_into().unwrap()) as u64
                };
                if let Some(target_sym) = self.ctx.syms_map.get(&ptr_val) {
                    let t_name = target_sym
                        .demangled
                        .as_deref()
                        .unwrap_or(target_sym.sym.as_str());
                    out.push_str(&format!(
                        "    (void*){}, // [idx {}] -> 0x{:08x}\n",
                        t_name, idx, ptr_val
                    ));
                } else if ptr_val == 0 {
                    out.push_str("    (void*)0,\n");
                } else {
                    out.push_str(&format!("    (void*)0x{:08x},\n", ptr_val));
                }
            }
            out.push_str("};\n");
            return out;
        }

        // 3. Generic constant data array
        out.push_str(&format!(
            "const uint8_t {}[{}] = {{\n   ",
            name,
            slice.len()
        ));
        for (i, &b) in slice.iter().enumerate() {
            out.push_str(&format!(" 0x{:02x},", b));
            if (i + 1) % 16 == 0 && i + 1 < slice.len() {
                out.push_str("\n   ");
            }
        }
        out.push_str("\n};\n");
        out
    }
}

fn child_needs_paren(child: &IrExpr, parent_op: BinaryOp, is_right: bool) -> bool {
    match child {
        IrExpr::Binary(child_op, _, _, _) => {
            let cp = child_op.precedence();
            let pp = parent_op.precedence();
            if cp < pp {
                return true;
            }
            if cp == pp
                && is_right
                && matches!(
                    parent_op,
                    BinaryOp::Sub
                        | BinaryOp::DivS
                        | BinaryOp::DivU
                        | BinaryOp::Mod
                        | BinaryOp::Shl
                        | BinaryOp::ShrU
                        | BinaryOp::ShrS
                )
            {
                return true;
            }
            if matches!(parent_op, BinaryOp::Shl | BinaryOp::ShrU | BinaryOp::ShrS)
                && matches!(child_op, BinaryOp::Add | BinaryOp::Sub)
            {
                return true;
            }
            false
        }
        IrExpr::Ternary { .. } => true,
        _ => false,
    }
}

fn collect_stmt_regs(
    stmt: &IrStmt,
    assigned_regs: &mut HashMap<String, IrType>,
    param_reg_map: &HashMap<String, String>,
) {
    match stmt {
        IrStmt::Assign { dst, src } => {
            collect_expr_regs(dst, assigned_regs, param_reg_map);
            collect_expr_regs(src, assigned_regs, param_reg_map);
        }
        IrStmt::Store { ptr, val, .. } => {
            collect_expr_regs(ptr, assigned_regs, param_reg_map);
            collect_expr_regs(val, assigned_regs, param_reg_map);
        }
        IrStmt::DivRem {
            quot_dst,
            rem_dst,
            dividend_high,
            dividend_low,
            divisor,
            ..
        } => {
            collect_expr_regs(quot_dst, assigned_regs, param_reg_map);
            collect_expr_regs(rem_dst, assigned_regs, param_reg_map);
            collect_expr_regs(dividend_high, assigned_regs, param_reg_map);
            collect_expr_regs(dividend_low, assigned_regs, param_reg_map);
            collect_expr_regs(divisor, assigned_regs, param_reg_map);
        }
        IrStmt::Call {
            target,
            args,
            ret_dst,
            ..
        } => {
            collect_expr_regs(target, assigned_regs, param_reg_map);
            for a in args {
                collect_expr_regs(a, assigned_regs, param_reg_map);
            }
            if let Some(r) = ret_dst {
                collect_expr_regs(r, assigned_regs, param_reg_map);
            }
        }
        IrStmt::Branch { cond: Some(c), .. } => {
            collect_expr_regs(c, assigned_regs, param_reg_map);
        }
        IrStmt::IndirectBranch { target } => {
            collect_expr_regs(target, assigned_regs, param_reg_map);
        }
        IrStmt::Return(Some(v)) => {
            collect_expr_regs(v, assigned_regs, param_reg_map);
        }
        _ => {}
    }
}

fn collect_expr_regs(
    expr: &IrExpr,
    assigned_regs: &mut HashMap<String, IrType>,
    param_reg_map: &HashMap<String, String>,
) {
    match expr {
        IrExpr::Reg(r, ty) => {
            let r_lower = r.to_lowercase();

            // Sub-registers (w0, eax, …) are never declared as separate locals.
            // Their reads/writes go through the wider parent register with a
            // truncation cast (see format_expr and the Assign arm).
            if let Some((parent, _)) = sub_register_info(&r_lower) {
                if !param_reg_map.contains_key(&parent) && !parent.starts_with('a') {
                    let parent_ty = CodeGenerator::infer_hardware_reg_type(&parent, IrType::Int64);
                    assigned_regs.entry(parent).or_insert(parent_ty);
                }
                return;
            }

            if !r_lower.contains(' ')
                && !r_lower.contains('+')
                && !r_lower.contains('-')
                && !r_lower.contains('[')
                && !r_lower.contains(']')
                && !param_reg_map.contains_key(&r_lower)
                && !r_lower.starts_with('a')
            {
                let exact_ty = CodeGenerator::infer_hardware_reg_type(&r_lower, *ty);
                assigned_regs.insert(r.clone(), exact_ty);
            }
        }
        IrExpr::Binary(_, lhs, rhs, _) => {
            collect_expr_regs(lhs, assigned_regs, param_reg_map);
            collect_expr_regs(rhs, assigned_regs, param_reg_map);
        }
        IrExpr::Unary(_, inner, _) => {
            collect_expr_regs(inner, assigned_regs, param_reg_map);
        }
        IrExpr::Load { ptr, .. } => {
            collect_expr_regs(ptr, assigned_regs, param_reg_map);
        }
        IrExpr::Ternary {
            cond,
            true_val,
            false_val,
            ..
        } => {
            collect_expr_regs(cond, assigned_regs, param_reg_map);
            collect_expr_regs(true_val, assigned_regs, param_reg_map);
            collect_expr_regs(false_val, assigned_regs, param_reg_map);
        }
        _ => {}
    }
}

/// Returns true if `s` is a syntactically valid C identifier that can appear as a
/// function name in emitted C. Rejects C++ demangled names like
/// "operator new(unsigned long)" which contain characters invalid in C identifiers.
fn is_valid_c_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    true
}

/// C library memory and string functions whose canonical prototypes take
/// pointer arguments. When emitting calls to these, we must NOT wrap the
/// arguments in `(uint64_t)(uintptr_t)` casts, because the compiler will
/// reject the resulting integer-typed arguments under -Wint-conversion.
fn is_libc_memory_fn(name: &str) -> bool {
    matches!(
        name,
        "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "strlen"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strcmp"
            | "strncmp"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strdup"
            | "__memcpy_chk"
            | "__memmove_chk"
            | "__memset_chk"
            | "__strcpy_chk"
            | "__strncpy_chk"
    )
}

/// Return the C cast prefix for argument N of a libc memory function.
/// Pointer positions get `(void*)`; scalar/size positions get `(uintptr_t)`.
/// memset/memchr have an `int` second argument; the memcpy and str families
/// follow the (pointer, pointer, …) pattern.
fn libc_arg_cast(name: &str, position: usize) -> &'static str {
    match name {
        "memset" | "__memset_chk" | "memchr" => match position {
            0 => "(void*)",
            1 => "(int)",
            _ => "(uintptr_t)",
        },
        _ => match position {
            0 | 1 => "(void*)",
            _ => "(uintptr_t)",
        },
    }
}

/// If `r` is a sub-register of a wider parent register, return the parent name
/// and the C cast that narrows the parent to this sub-register's width.
///
/// AArch64: w0..w30 → x0..x30 truncated to uint32_t
/// x86_64:  eax/ebx/ecx/edx/esi/edi/ebp/esp → rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp
///          r8d..r15d → r8..r15 (all truncate to uint32_t)
///
/// Byte/word-level x86 partial updates (ax, al, ah, sil, dil, etc.) are NOT
/// tracked — those require bitfield-aware partial writes and are deferred to a
/// separate work order.
fn sub_register_info(r: &str) -> Option<(String, &'static str)> {
    let r_lower = r.to_lowercase();

    // AArch64 wN → xN
    if r_lower.starts_with('w') && r_lower.len() > 1 {
        let tail = &r_lower[1..];
        if tail.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = tail.parse::<usize>() {
                if n < 31 {
                    return Some((format!("x{}", n), "(uint32_t)"));
                }
            }
        }
    }

    // x86_64 32-bit → 64-bit
    let map: &[(&str, &str)] = &[
        ("eax", "rax"),
        ("ebx", "rbx"),
        ("ecx", "rcx"),
        ("edx", "rdx"),
        ("esi", "rsi"),
        ("edi", "rdi"),
        ("ebp", "rbp"),
        ("esp", "rsp"),
        ("r8d", "r8"),
        ("r9d", "r9"),
        ("r10d", "r10"),
        ("r11d", "r11"),
        ("r12d", "r12"),
        ("r13d", "r13"),
        ("r14d", "r14"),
        ("r15d", "r15"),
    ];
    for (sub, parent) in map {
        if r_lower == *sub {
            return Some((parent.to_string(), "(uint32_t)"));
        }
    }

    None
}
