//! Region and control-flow structuring (If-Then, If-Then-Else, While, Do-While, Break, Continue).

use super::cfgraph::CfGraph;
use super::dominators::ipost_dom;
use super::loops::LoopInfo;
use super::StructuredNode;
use crate::decompiler::ir::{BinaryOp, IrBlock, IrExpr, IrFunction, IrStmt, IrType, UnaryOp};
use std::collections::HashSet;

pub fn structure_function(
    ctx: &crate::elf_parser::ElfContext,
    func: &IrFunction,
    graph: &CfGraph,
    loop_info: &LoopInfo,
) -> Vec<StructuredNode> {
    // Attempt jump-table recovery for every indirect-branch block. If the
    // function has indirect branches but ALL of them resolve to real tables,
    // we can structure it like any other function (switches become `switch`
    // statements) instead of bailing to goto-soup for the whole body. If any
    // indirect branch is unresolved, keep the exact conservative fallback.
    let jump_tables = recover_jump_tables(ctx, func);
    let all_indirect_resolved =
        !graph.has_indirect_branch || indirect_all_resolved(func, &jump_tables);

    if !loop_info.is_reducible || !all_indirect_resolved {
        return fallback_to_gotos(func, graph);
    }

    let ipdom = ipost_dom(graph);
    let mut visited = vec![false; graph.blocks.len()];
    structure_sequence(
        func,
        graph,
        loop_info,
        &ipdom,
        0,
        graph.blocks.len(),
        None,
        &mut visited,
        &jump_tables,
    )
}

/// Recover jump tables for blocks whose last statement is an `IndirectBranch`.
fn recover_jump_tables(
    ctx: &crate::elf_parser::ElfContext,
    func: &IrFunction,
) -> std::collections::HashMap<u64, super::jumptable::JumpTable> {
    let mut out = std::collections::HashMap::new();
    for b in &func.blocks {
        if matches!(b.stmts.last(), Some(IrStmt::IndirectBranch { .. })) {
            if let Some(jt) = super::jumptable::recover(ctx, b.start_address, b.end_address) {
                out.insert(b.start_address, jt);
            }
        }
    }
    out
}

/// True when every block ending in an indirect branch is either
/// (a) a recovered jump table, or (b) a tail-call / return-like branch through
/// the ABI intra-procedure scratch registers (x16/x17 = ip0/ip1 on AArch64),
/// which are terminators, not switches. Treating (b) as "unresolved" would
/// force goto-soup onto every function that ends with a PLT/tail `br x16`.
fn indirect_all_resolved(
    func: &IrFunction,
    tables: &std::collections::HashMap<u64, super::jumptable::JumpTable>,
) -> bool {
    func.blocks.iter().all(|b| {
        if let Some(IrStmt::IndirectBranch { target }) = b.stmts.last() {
            if tables.contains_key(&b.start_address) {
                return true;
            }
            // Tail-call / PLT dispatch through ip0/ip1 -> terminator.
            if let IrExpr::Reg(r, _) = target {
                let rl = r.to_lowercase();
                if matches!(rl.as_str(), "x16" | "x17" | "ip0" | "ip1") {
                    return true;
                }
            }
            false
        } else {
            true
        }
    })
}

/// Maximum structuring recursion depth. Past this we stop recursing and emit
/// the remaining blocks linearly (valid, if less pretty, output). This prevents
/// a pathological / deeply-nested function from exhausting the native stack —
/// a stack overflow is NOT catchable by the JNI `catch_unwind` guard and would
/// abort the whole process.
const MAX_STRUCTURE_DEPTH: usize = 200;

#[allow(clippy::too_many_arguments, clippy::only_used_in_recursion)]
fn structure_sequence(
    func: &IrFunction,
    graph: &CfGraph,
    loop_info: &LoopInfo,
    ipdom: &[Option<usize>],
    start: usize,
    end: usize,
    stop_idx: Option<usize>,
    visited: &mut [bool],
    jump_tables: &std::collections::HashMap<u64, super::jumptable::JumpTable>,
) -> Vec<StructuredNode> {
    structure_sequence_d(
        func, graph, loop_info, ipdom, start, end, stop_idx, visited, jump_tables, 0,
    )
}

#[allow(clippy::too_many_arguments, clippy::only_used_in_recursion)]
fn structure_sequence_d(
    func: &IrFunction,
    graph: &CfGraph,
    loop_info: &LoopInfo,
    ipdom: &[Option<usize>],
    start: usize,
    end: usize,
    stop_idx: Option<usize>,
    visited: &mut [bool],
    jump_tables: &std::collections::HashMap<u64, super::jumptable::JumpTable>,
    depth: usize,
) -> Vec<StructuredNode> {
    // Depth guard: degrade to a flat linear listing instead of recursing further.
    if depth > MAX_STRUCTURE_DEPTH {
        let mut flat = Vec::new();
        let n_guard = graph.blocks.len();
        let mut j = start;
        while j < end && j < n_guard {
            if Some(j) == stop_idx {
                break;
            }
            if !visited[j] {
                visited[j] = true;
                flat.push(StructuredNode::Block(graph.blocks[j].clone()));
            }
            j += 1;
        }
        return flat;
    }
    let mut nodes = Vec::new();
    let mut i = start;
    let n = graph.blocks.len();

    while i < end && i < n {
        if Some(i) == stop_idx || visited[i] {
            break;
        }

        // 1. Check if block i is the header of a natural loop
        if let Some(lp) = loop_info.loops.iter().find(|l| l.header == i) {
            visited[i] = true;
            let header_block = &graph.blocks[i];

            // Determine if while or do-while
            let mut is_while = false;
            let mut while_cond = None;
            let mut loop_exit_tgt = None;
            let mut is_do_while = false;
            let mut do_while_cond = None;
            let mut do_while_exit = None;

            if let Some(IrStmt::Branch {
                cond: Some(c),
                target,
            }) = header_block.stmts.last()
            {
                if let Some(&tgt_idx) = graph.address_to_idx.get(target) {
                    if !lp.nodes.contains(&tgt_idx) {
                        // Branch target exits loop -> while (!c)
                        is_while = true;
                        while_cond = Some(negate_condition(c.clone()));
                        loop_exit_tgt = Some(tgt_idx);
                    } else if i + 1 < n && !lp.nodes.contains(&(i + 1)) {
                        // Fallthrough exits loop -> while (c)
                        is_while = true;
                        while_cond = Some(c.clone());
                        loop_exit_tgt = Some(i + 1);
                    }
                }
            }

            // Inverted loop with exit block inside loop (e.g. traverse_linked_list)
            if !is_while && lp.exit_blocks.len() == 1 {
                let eb_idx = lp.exit_blocks[0];
                let eb = &graph.blocks[eb_idx];
                if let Some(IrStmt::Branch {
                    cond: Some(c),
                    target,
                }) = eb.stmts.last()
                {
                    if let Some(&tgt_idx) = graph.address_to_idx.get(target) {
                        if !lp.nodes.contains(&tgt_idx) {
                            is_while = true;
                            while_cond = Some(negate_condition(c.clone()));
                            loop_exit_tgt = Some(tgt_idx);
                        } else if eb_idx + 1 < n && !lp.nodes.contains(&(eb_idx + 1)) {
                            is_while = true;
                            while_cond = Some(c.clone());
                            loop_exit_tgt = Some(eb_idx + 1);
                        }
                    }
                }
            }

            // Do-While detection (conservative): only when neither while heuristic
            // fired. A do-while's condition lives at the LATCH (bottom) block: its
            // last stmt is a conditional branch whose taken edge jumps back to the
            // header (loop again) and whose fallthrough exits the loop. Detecting
            // it here only *adds* structure where the current code would otherwise
            // emit nothing, so worst case is today's behavior (no regression).
            if !is_while {
                for &latch in &lp.nodes {
                    if latch == i {
                        continue;
                    }
                    let lb = &graph.blocks[latch];
                    if let Some(IrStmt::Branch {
                        cond: Some(c),
                        target,
                    }) = lb.stmts.last()
                    {
                        if let Some(&tgt_idx) = graph.address_to_idx.get(target) {
                            // Taken edge -> header (back-edge): classic do-while.
                            if tgt_idx == i {
                                let fall = latch + 1;
                                if fall < n && !lp.nodes.contains(&fall) {
                                    is_do_while = true;
                                    do_while_cond = Some(c.clone());
                                    do_while_exit = Some(fall);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if is_while {
                if let Some(cond) = while_cond {
                    let exit_idx = loop_exit_tgt.unwrap_or(end);

                    // Body statements of header (excluding trailing branch)
                    let mut header_stmts = header_block.stmts.clone();
                    header_stmts.pop();
                    let mut body_nodes = Vec::new();
                    if !header_stmts.is_empty() {
                        body_nodes.push(StructuredNode::Block(IrBlock {
                            id: header_block.id,
                            start_address: header_block.start_address,
                            end_address: header_block.end_address,
                            stmts: header_stmts,
                        }));
                    }

                    // Structure remaining loop body blocks
                    let mut body_seq = structure_sequence_d(
                        func,
                        graph,
                        loop_info,
                        ipdom,
                        i + 1,
                        end,
                        Some(exit_idx),
                        visited,
                        jump_tables,
                        depth + 1,
                    );
                    body_nodes.append(&mut body_seq);

                    // Transform loop back-edges and exits inside body
                    transform_loop_control(
                        &mut body_nodes,
                        header_block.start_address,
                        &lp.nodes,
                        graph,
                    );

                    nodes.push(StructuredNode::While {
                        cond,
                        body: body_nodes,
                    });

                    // Guard against non-termination: `exit_idx` is normally a
                    // forward block (outside the loop body we just consumed).
                    // In a malformed/irreducible edge case it can resolve to an
                    // index <= i (e.g. eb_idx + 1 where the exit block precedes
                    // the header), which would re-enter already-structured code.
                    // Force forward progress instead of looping forever.
                    if exit_idx <= i {
                        if i + 1 < n {
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i = exit_idx;
                    }
                    continue;
                }
            }

            // Do-While emission: body executes once, then `cond` decides whether to
            // repeat. The header block and the rest of the loop body up to the latch
            // are structured exactly like a while body; the latch's back-edge branch
            // is dropped by transform_loop_control (target == header -> no-op).
            if is_do_while {
                if let Some(cond) = do_while_cond {
                    let exit_idx = do_while_exit.unwrap_or(end);

                    let mut body_nodes = Vec::new();
                    // Header runs unconditionally first. Drop a trailing Branch only
                    // if present (a do-while header usually has no exiting branch;
                    // if it has an unconditional jump into the body, emit it via
                    // transform_loop_control rather than as a raw goto here).
                    let mut header_stmts = header_block.stmts.clone();
                    if matches!(header_stmts.last(), Some(IrStmt::Branch { .. })) {
                        header_stmts.pop();
                    }
                    if !header_stmts.is_empty() {
                        body_nodes.push(StructuredNode::Block(IrBlock {
                            id: header_block.id,
                            start_address: header_block.start_address,
                            end_address: header_block.end_address,
                            stmts: header_stmts,
                        }));
                    }

                    let mut body_seq = structure_sequence_d(
                        func,
                        graph,
                        loop_info,
                        ipdom,
                        i + 1,
                        end,
                        Some(exit_idx),
                        visited,
                        jump_tables,
                        depth + 1,
                    );
                    body_nodes.append(&mut body_seq);

                    transform_loop_control(
                        &mut body_nodes,
                        header_block.start_address,
                        &lp.nodes,
                        graph,
                    );

                    nodes.push(StructuredNode::DoWhile {
                        cond,
                        body: body_nodes,
                    });

                    if exit_idx <= i {
                        if i + 1 < n {
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i = exit_idx;
                    }
                    continue;
                }
            }
        }

        visited[i] = true;
        let curr_block = &graph.blocks[i];

        // 2. Check for Conditional Branch (If / If-Else)
        if let Some(IrStmt::Branch {
            cond: Some(c),
            target,
        }) = curr_block.stmts.last().cloned()
        {
            if let Some(&tgt_idx) = graph.address_to_idx.get(&target) {
                let fallthrough = i + 1;
                let join_idx = ipdom[i];

                let mut prefix_stmts = curr_block.stmts.clone();
                prefix_stmts.pop();
                if !prefix_stmts.is_empty() {
                    nodes.push(StructuredNode::Block(IrBlock {
                        id: curr_block.id,
                        start_address: curr_block.start_address,
                        end_address: curr_block.end_address,
                        stmts: prefix_stmts,
                    }));
                }

                // Case 1: Simple If-Then (fallthrough == join_idx)
                if Some(fallthrough) == join_idx && tgt_idx < n {
                    let then_nodes = structure_sequence_d(
                        func, graph, loop_info, ipdom, tgt_idx, end, join_idx, visited, jump_tables, depth + 1,
                    );
                    nodes.push(StructuredNode::If {
                        cond: c,
                        then: then_nodes,
                        otherwise: Vec::new(),
                    });
                    i = join_idx.unwrap_or(fallthrough);
                    continue;
                }

                // Case 2: Inverted If-Then (target == join_idx)
                if Some(tgt_idx) == join_idx && fallthrough < n {
                    let then_nodes = structure_sequence_d(
                        func,
                        graph,
                        loop_info,
                        ipdom,
                        fallthrough,
                        end,
                        join_idx,
                        visited,
                        jump_tables,
                        depth + 1,
                    );
                    nodes.push(StructuredNode::If {
                        cond: negate_condition(c),
                        then: then_nodes,
                        otherwise: Vec::new(),
                    });
                    i = join_idx.unwrap_or(tgt_idx);
                    continue;
                }

                // Case 3: If-Then-Else
                if let Some(j) = join_idx {
                    if tgt_idx < n && fallthrough < n && tgt_idx != j && fallthrough != j {
                        let then_nodes = structure_sequence_d(
                            func,
                            graph,
                            loop_info,
                            ipdom,
                            tgt_idx,
                            end,
                            Some(j),
                            visited,
                            jump_tables,
                            depth + 1,
                        );
                        let else_nodes = structure_sequence_d(
                            func,
                            graph,
                            loop_info,
                            ipdom,
                            fallthrough,
                            end,
                            Some(j),
                            visited,
                            jump_tables,
                            depth + 1,
                        );
                        nodes.push(StructuredNode::If {
                            cond: c,
                            then: then_nodes,
                            otherwise: else_nodes,
                        });
                        i = j;
                        continue;
                    }
                }
            }
        }

        // 2b. Recovered jump-table dispatch: emit the block's non-terminator
        // statements, then a real `switch`. The structurer cannot follow the
        // case edges as fall-through (they are labels reached via goto), so we
        // emit the switch and advance past this block; the case targets are
        // emitted later as labeled blocks by the normal sequential walk.
        if let Some(IrStmt::IndirectBranch { .. }) = curr_block.stmts.last() {
            if let Some(jt) = jump_tables.get(&curr_block.start_address) {
                let mut prefix = curr_block.stmts.clone();
                prefix.pop(); // drop the IndirectBranch terminator
                if !prefix.is_empty() {
                    nodes.push(StructuredNode::Block(IrBlock {
                        id: curr_block.id,
                        start_address: curr_block.start_address,
                        end_address: curr_block.end_address,
                        stmts: prefix,
                    }));
                }
                nodes.push(StructuredNode::Switch {
                    selector: IrExpr::reg(&jt.selector_reg, IrType::Int64),
                    cases: jt.cases.clone(),
                    default: jt.default_target,
                });
                visited[i] = true;
                i += 1;
                continue;
            }
        }

        // 3. Normal Sequential Block
        nodes.push(StructuredNode::Block(curr_block.clone()));
        i += 1;
    }

    nodes
}

fn transform_loop_control(
    nodes: &mut [StructuredNode],
    header_addr: u64,
    loop_nodes: &HashSet<usize>,
    graph: &CfGraph,
) {
    for node in nodes {
        match node {
            StructuredNode::Block(b) => {
                let mut new_stmts = Vec::new();
                for s in &b.stmts {
                    if let IrStmt::Branch { cond: None, target } = s {
                        if *target == header_addr {
                            // Loop back-edge -> no-op / continue
                        } else if let Some(&tgt_idx) = graph.address_to_idx.get(target) {
                            if !loop_nodes.contains(&tgt_idx) {
                                // Loop exit -> break
                            } else {
                                new_stmts.push(s.clone());
                            }
                        } else {
                            new_stmts.push(s.clone());
                        }
                    } else {
                        new_stmts.push(s.clone());
                    }
                }
                b.stmts = new_stmts;
            }
            StructuredNode::If {
                then, otherwise, ..
            } => {
                transform_loop_control(then, header_addr, loop_nodes, graph);
                transform_loop_control(otherwise, header_addr, loop_nodes, graph);
            }
            StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                transform_loop_control(body, header_addr, loop_nodes, graph);
            }
            _ => {}
        }
    }
}

pub fn negate_condition(expr: IrExpr) -> IrExpr {
    match expr {
        IrExpr::Binary(BinaryOp::Eq, l, r, ty) => IrExpr::Binary(BinaryOp::Ne, l, r, ty),
        IrExpr::Binary(BinaryOp::Ne, l, r, ty) => IrExpr::Binary(BinaryOp::Eq, l, r, ty),
        IrExpr::Binary(BinaryOp::LtS, l, r, ty) => IrExpr::Binary(BinaryOp::GeS, l, r, ty),
        IrExpr::Binary(BinaryOp::LeS, l, r, ty) => IrExpr::Binary(BinaryOp::GtS, l, r, ty),
        IrExpr::Binary(BinaryOp::GtS, l, r, ty) => IrExpr::Binary(BinaryOp::LeS, l, r, ty),
        IrExpr::Binary(BinaryOp::GeS, l, r, ty) => IrExpr::Binary(BinaryOp::LtS, l, r, ty),
        IrExpr::Binary(BinaryOp::LtU, l, r, ty) => IrExpr::Binary(BinaryOp::GeU, l, r, ty),
        IrExpr::Binary(BinaryOp::LeU, l, r, ty) => IrExpr::Binary(BinaryOp::GtU, l, r, ty),
        IrExpr::Binary(BinaryOp::GtU, l, r, ty) => IrExpr::Binary(BinaryOp::LeU, l, r, ty),
        IrExpr::Binary(BinaryOp::GeU, l, r, ty) => IrExpr::Binary(BinaryOp::LtU, l, r, ty),
        other => IrExpr::Unary(UnaryOp::Not, Box::new(other), IrType::Int8),
    }
}

fn fallback_to_gotos(func: &IrFunction, _graph: &CfGraph) -> Vec<StructuredNode> {
    let mut nodes = Vec::new();
    let mut jump_targets = HashSet::new();
    for b in &func.blocks {
        for s in &b.stmts {
            if let IrStmt::Branch { target, .. } = s {
                jump_targets.insert(*target);
            }
        }
    }

    for (idx, b) in func.blocks.iter().enumerate() {
        if idx > 0 && jump_targets.contains(&b.start_address) {
            nodes.push(StructuredNode::Label(b.start_address));
        }

        let mut stmts = Vec::new();
        for s in &b.stmts {
            match s {
                IrStmt::Branch {
                    cond: Some(c),
                    target,
                } => {
                    nodes.push(StructuredNode::Block(IrBlock {
                        id: b.id,
                        start_address: b.start_address,
                        end_address: b.end_address,
                        stmts: std::mem::take(&mut stmts),
                    }));
                    nodes.push(StructuredNode::If {
                        cond: c.clone(),
                        then: vec![StructuredNode::Goto(*target)],
                        otherwise: Vec::new(),
                    });
                }
                IrStmt::Branch { cond: None, target } => {
                    nodes.push(StructuredNode::Block(IrBlock {
                        id: b.id,
                        start_address: b.start_address,
                        end_address: b.end_address,
                        stmts: std::mem::take(&mut stmts),
                    }));
                    nodes.push(StructuredNode::Goto(*target));
                }
                other => stmts.push(other.clone()),
            }
        }

        if !stmts.is_empty() {
            nodes.push(StructuredNode::Block(IrBlock {
                id: b.id,
                start_address: b.start_address,
                end_address: b.end_address,
                stmts,
            }));
        }
    }

    // Inline shared tails to a (bounded) fixpoint: one expansion can itself
    // end in a goto to another inlinable shared tail (e.g. the canary-fail
    // block behind an error tail).
    let mut nodes = collapse_early_exit_ladder(inline_shared_joins_with_ret(nodes, &func.ret_reg));
    for _ in 0..2 {
        nodes = collapse_early_exit_ladder(inline_shared_joins_with_ret(nodes, &func.ret_reg));
    }
    nodes
}

/// Eliminate gotos to *shared join blocks* (the classic error-tail pattern:
/// `if (err) { args; goto loc_LOG; }` from many sites, where `loc_LOG:` is a
/// small log/assert/return chain) by duplicating the join region into each
/// goto site — "tail duplication". One original goto per join is kept so the
/// label and its body stay reachable exactly as before; we only ever add
/// copies and remove some gotos, never labels or bodies, so the rewrite is
/// semantics-preserving by construction.
///
/// A join region is inlinable when, from its label, a linear scan reaches an
/// explicit terminator (Return or unconditional Goto) through Blocks and
/// label-free Ifs only; falling into a further label splices that label's
/// region (recursively, depth/size capped). Labels inside the inlined copies
/// are dropped — the copies' gotos still target the *real* labels, which stay
/// in place at the original region.
const MAX_JOIN_DEPTH: usize = 6;
const MAX_JOIN_STMTS: usize = 64;
/// Cap on the size of a tail duplicated into each goto site: keeps the error-
/// tail expansions compact and refuses cascading ones (a shared tail that
/// splices a long chain of downstream regions) that would bloat the output.
const MAX_INLINE_STMTS: usize = 16;

/// Calls that never return: a Block ending in one terminates control flow, so
/// a shared tail can stop there instead of splicing the (often cyclic) code
/// that happens to follow the abort in the layout.
fn is_noreturn_call(stmt: &IrStmt) -> bool {
    const NORETURN: &[&str] = &[
        "__stack_chk_fail",
        "abort",
        "__assert_fail",
        "__android_log_assert",
        "__stack_chk_fail_rt",
    ];
    match stmt {
        IrStmt::Call { name: Some(n), .. } => {
            NORETURN.iter().any(|k| n.ends_with(k))
        }
        IrStmt::Trap => true,
        _ => false,
    }
}

fn block_terminates(b: &IrBlock) -> bool {
    b.stmts
        .last()
        .is_some_and(|s| matches!(s, IrStmt::Return(_)) || is_noreturn_call(s))
}

fn goto_refs(nodes: &[StructuredNode], refs: &mut std::collections::HashMap<u64, usize>) {
    for n in nodes {
        match n {
            StructuredNode::Goto(t) => *refs.entry(*t).or_insert(0) += 1,
            StructuredNode::If { then, otherwise, .. } => {
                goto_refs(then, refs);
                goto_refs(otherwise, refs);
            }
            StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                goto_refs(body, refs)
            }
            _ => {}
        }
    }
}

fn contains_label(nodes: &[StructuredNode]) -> bool {
    nodes.iter().any(|n| match n {
        StructuredNode::Label(_) => true,
        StructuredNode::If { then, otherwise, .. } => {
            contains_label(then) || contains_label(otherwise)
        }
        StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
            contains_label(body)
        }
        _ => false,
    })
}

/// Walk the region that starts at `label_idx` (a Label node in `top`) and clone
/// it up to an explicit terminator, splicing fall-through-into-next-label
/// chains. Returns None when the region is not safely inlinable.
fn try_region(
    top: &[StructuredNode],
    label_idx: usize,
    regions: &std::collections::HashMap<u64, usize>,
    depth: usize,
    budget: &mut usize,
) -> Option<Vec<StructuredNode>> {
    if depth > MAX_JOIN_DEPTH {
        return None;
    }
    let mut out = Vec::new();
    let mut i = label_idx + 1;
    while i < top.len() {
        match &top[i] {
            StructuredNode::Block(b) => {
                *budget = budget.checked_sub(b.stmts.len().max(1))?;
                out.push(top[i].clone());
                // A Block ending in `return` or a noreturn call is a
                // terminator: control never falls through to the next label.
                if block_terminates(b) {
                    return Some(out);
                }
            }
            StructuredNode::If { then, otherwise, .. } => {
                if contains_label(then) || contains_label(otherwise) {
                    return None;
                }
                *budget = budget.checked_sub(1)?;
                out.push(top[i].clone());
            }
            StructuredNode::Label(u) => {
                // Fall-through into the next join: splice its region (labels
                // dropped; the real label stays at its original position).
                let &ui = regions.get(u)?;
                let spliced = try_region(top, ui, regions, depth + 1, budget)?;
                out.extend(spliced);
            }
            StructuredNode::Return(_) | StructuredNode::Goto(_) => {
                out.push(top[i].clone());
                return Some(out);
            }
            // While/DoWhile/Switch/Break/Continue: not a linear tail.
            _ => return None,
        }
        i += 1;
    }
    // Ran off the end without a terminator: control would fall out of the
    // copy into unknown code. Refuse.
    None
}

fn has_plain_return(nodes: &[StructuredNode]) -> bool {
    nodes.iter().any(|n| match n {
        StructuredNode::Return(_) => true,
        StructuredNode::Block(b) => b.stmts.iter().any(|s| matches!(s, IrStmt::Return(_))),
        StructuredNode::If { then, otherwise, .. } => {
            has_plain_return(then) || has_plain_return(otherwise)
        }
        _ => false,
    })
}

/// Simulate the linear region that starts at `label_idx` and, if the function
/// provably returns a constant there, return the minimal statement sequence
/// that materializes that return. This is exit-block dataflow for the classic
/// error tail `log(); ret_reg = -1; <epilogue restores>; return ret_reg;`:
/// assignments are logged in order, and at the `return <reg>` the log is
/// walked backwards to collect only the assignments the returned register
/// depends on (e.g. `x19 = -1; a0 = x19;`). The walk stops at a Call, a
/// memory Load in the dependency chain or an unknown expression — those bails
/// keep the synthesis conservative. Label-free Ifs are transparent when their
/// arms end in a noreturn call (the canary check) so the fall-through path
/// continues; falling into a further label splices that region.
fn const_return_stmts(
    top: &[StructuredNode],
    label_idx: usize,
    regions: &std::collections::HashMap<u64, usize>,
    ret_reg: &str,
) -> Option<Vec<IrStmt>> {
    let mut log: Vec<IrStmt> = Vec::new();
    let mut i = label_idx + 1;
    while i < top.len() {
        match &top[i] {
            StructuredNode::Block(b) => {
                for s in &b.stmts {
                    match s {
                        // A bare return: the emitter prints `return a0;` for
                        // it, so the provable value is whatever the logged
                        // assigns most recently put into the return register
                        // (x0) or its sub-register (w0).
                        IrStmt::Return(None) => {
                            let mut candidates = [ret_reg.to_string(), String::new()];
                            candidates[1] = if let Some(stripped) = ret_reg.strip_prefix('x') {
                                format!("w{}", stripped)
                            } else {
                                String::new()
                            };
                            let start = log.iter().rev().find_map(|a| match a {
                                IrStmt::Assign {
                                    dst: IrExpr::Reg(r, _),
                                    ..
                                } if candidates.contains(r) => Some(r.clone()),
                                _ => None,
                            });
                            let chain = match start {
                                Some(r) => resolve_chain(&log, &r)?,
                                None => return None,
                            };
                            let mut picked = leading_calls(&log, &chain);
                            picked.extend(chain);
                            picked.push(IrStmt::Return(None));
                            return Some(picked);
                        }
                        IrStmt::Return(Some(v)) => {
                            // Backward chain walk over the logged assigns;
                            // the explicit return's own expression comes last.
                            let (chain, needs_ret) = match v {
                                IrExpr::Reg(r, _) => (resolve_chain(&log, r)?, true),
                                IrExpr::Const(_) => (Vec::new(), true),
                                _ => return None,
                            };
                            let mut picked = leading_calls(&log, &chain);
                            picked.extend(chain);
                            if needs_ret {
                                picked.push(IrStmt::Return(Some(v.clone())));
                            }
                            return Some(picked);
                        }
                        IrStmt::Assign {
                            dst: IrExpr::Reg(_, _),
                            ..
                        }
                        | IrStmt::Store { .. } => log.push(s.clone()),
                        // A call in the tail (the shared `__android_log_print`
                        // before the error return) is observable behavior: it is
                        // logged so it can be prepended to the synthesized
                        // per-site sequence. It is never resolved through —
                        // `resolve_chain` bails when it meets a Call while it
                        // still needs a register or memory slot.
                        IrStmt::Call { .. } => log.push(s.clone()),
                        _ => {}
                    }
                }
                if block_terminates(b) {
                    // Ends in a noreturn call: control never reaches a return
                    // through this path (a Return was already handled above).
                    return None;
                }
            }
            StructuredNode::If {
                then, otherwise, ..
            } => {
                // Label-free control flow is not required here: an arm that
                // contains no Return and ends in a noreturn call (the canary
                // check `if (flags_cond) loc_FAIL: __stack_chk_fail();`) is a
                // dead end, so the fall-through path continues after the If.
                if has_plain_return(then) || has_plain_return(otherwise) {
                    return None;
                }
            }
            StructuredNode::Label(u) => {
                // Fall-through into the next join: continue in its region.
                let &ui = regions.get(u)?;
                i = ui;
            }
            // A top-level Return of a register is not preceded by the label's
            // own assignments in this walk (they live in earlier regions);
            // without a chain the synthesis is not provable here.
            StructuredNode::Return(_) => return None,
            // Goto to unknown code / loops / switches: not a proven exit.
            _ => {
                return None;
            }
        }
        i += 1;
    }
    // The walk exhausted the region without an explicit Return: the emitter
    // appends an implicit `return <ret_reg>;` at function end, so the tail
    // still provably returns — resolve the chain for that register instead.
    if let Some(chain) = resolve_chain(&log, ret_reg) {
        let mut picked = leading_calls(&log, &chain);
        picked.extend(chain);
        picked.push(IrStmt::Return(Some(IrExpr::Reg(
            ret_reg.to_string(),
            IrType::Int64,
        ))));
        return Some(picked);
    }
    None
}

/// Calls the shared tail executes before the first statement of the resolved
/// return chain are part of the tail's observable behavior (an error log
/// printed before the return) and are prepended to the per-site synthesis.
/// Calls sitting between chain statements are left out — reordering them is
/// not provably safe.
fn leading_calls(log: &[IrStmt], chain: &[IrStmt]) -> Vec<IrStmt> {
    let cutoff = chain
        .first()
        .and_then(|first| log.iter().position(|l| l == first));
    match cutoff {
        Some(cut) => log[..cut]
            .iter()
            .filter(|l| matches!(l, IrStmt::Call { .. }))
            .cloned()
            .collect(),
        None => Vec::new(),
    }
}

/// Canonical key for a pointer expression (load/store slot identity).
fn ptr_key(e: &IrExpr) -> String {
    format!("{:?}", e)
}

/// What the backward chain walk is still looking for: a register copy or a
/// value that was stored to a stack slot (and must be found in a Store).
enum Need {
    Reg(String),
    Mem(String),
}

/// Walk the logged assignments backwards and return the minimal statement
/// sequence that materializes `ret_reg` as a constant. Follows register
/// copies and store→load forwarding through stack slots (the AArch64 epilogue
/// restores callee-saved regs via the stack: `x19 = -1; store; ...; a0 =
/// load;`). Any non-const/non-reg value, or a Call/DivRem sitting between the
/// copies, makes the result unprovable.
fn resolve_chain(log: &[IrStmt], ret_reg: &str) -> Option<Vec<IrStmt>> {
    let mut needed = Need::Reg(ret_reg.to_string());
    let mut picked: Vec<IrStmt> = Vec::new();
    for a in log.iter().rev() {
        match (&needed, a) {
            (
                Need::Reg(d),
                IrStmt::Assign {
                    dst: IrExpr::Reg(r, _),
                    src,
                },
            ) if r == d => match src {
                IrExpr::Const(_) | IrExpr::StringLit(_) => {
                    picked.push(a.clone());
                    needed = Need::Reg(String::new()); // satisfied sentinel
                }
                IrExpr::Reg(nr, _) => {
                    picked.push(a.clone());
                    needed = Need::Reg(nr.clone());
                }
                IrExpr::Load { ptr, .. } => {
                    picked.push(a.clone());
                    needed = Need::Mem(ptr_key(ptr));
                }
                _ => return None,
            },
            (Need::Mem(slot), IrStmt::Store { ptr, val, .. }) if ptr_key(ptr) == *slot => {
                match val {
                    IrExpr::Const(_) | IrExpr::StringLit(_) => {
                        picked.push(a.clone());
                        needed = Need::Reg(String::new());
                    }
                    IrExpr::Reg(nr, _) => {
                        picked.push(a.clone());
                        needed = Need::Reg(nr.clone());
                    }
                    _ => return None,
                }
            }
            (Need::Reg(d), IrStmt::Call { .. }) | (Need::Reg(d), IrStmt::DivRem { .. })
                if !d.is_empty() =>
            {
                // May clobber the chain: give up.
                return None;
            }
            (Need::Mem(_), IrStmt::Call { .. }) => {
                return None;
            }
            _ => {}
        }
        if let Need::Reg(d) = &needed {
            if d.is_empty() {
                break;
            }
        }
    }
    match needed {
        Need::Reg(ref d) if d.is_empty() => {}
        _ => return None,
    }
    picked.reverse();
    Some(picked)
}

pub fn inline_shared_joins(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    inline_shared_joins_with_ret(nodes, "x0")
}

/// Like [`inline_shared_joins`], with the function's return register so
/// tails ending in a bare `return` can be synthesized per site.
pub fn inline_shared_joins_with_ret(nodes: Vec<StructuredNode>, ret_reg: &str) -> Vec<StructuredNode> {
    // Top-level label -> index of its Label node (first occurrence wins).
    let mut regions: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, n) in nodes.iter().enumerate() {
        if let StructuredNode::Label(a) = n {
            regions.entry(*a).or_insert(i);
        }
    }
    if regions.is_empty() {
        return nodes;
    }
    let mut refs = std::collections::HashMap::new();
    goto_refs(&nodes, &mut refs);

    // Expand every shared join (refs >= 2) once; memoize.
    let mut memo: std::collections::HashMap<u64, Option<Vec<StructuredNode>>> =
        std::collections::HashMap::new();
    for (&addr, &n) in &refs {
        if n >= 2 {
            if let Some(&idx) = regions.get(&addr) {
                let mut budget = MAX_JOIN_STMTS;
                memo.insert(addr, try_region(&nodes, idx, &regions, 0, &mut budget).filter(|exp| {
                    let stmts: usize = exp
                        .iter()
                        .map(|n| match n {
                            StructuredNode::Block(b) => b.stmts.len().max(1),
                            StructuredNode::If { then, otherwise, .. } => {
                                then.len() + otherwise.len()
                            }
                            _ => 1,
                        })
                        .sum();
                    stmts <= MAX_INLINE_STMTS
                }));
            }
        }
    }
    // Join regions whose full expansion was refused (over the size cap) but
    // whose exit value is a proven constant: each goto site can simply become
    // a synthesized `return` (with its minimal assignment chain) instead of
    // duplicating the whole epilogue.
    let mut ret_syn: std::collections::HashMap<u64, Vec<IrStmt>> =
        std::collections::HashMap::new();
    for (&addr, &n) in &refs {
        if n >= 2 && !matches!(memo.get(&addr), Some(Some(_))) {
            if let Some(&idx) = regions.get(&addr) {
                if let Some(stmts) = const_return_stmts(&nodes, idx, &regions, &ret_reg) {
                    ret_syn.insert(addr, stmts);
                }
            }
        }
    }
    // Replace all refs to an inlinable join except the LAST one (in walk
    // order), so the label stays referenced and its body reachable as before.
    let mut remaining: std::collections::HashMap<u64, usize> = refs
        .into_iter()
        .filter(|(a, _)| matches!(memo.get(a), Some(Some(_))) || ret_syn.contains_key(a))
        .collect();

    fn subst(
        nodes: Vec<StructuredNode>,
        memo: &std::collections::HashMap<u64, Option<Vec<StructuredNode>>>,
        ret_syn: &std::collections::HashMap<u64, Vec<IrStmt>>,
        remaining: &mut std::collections::HashMap<u64, usize>,
    ) -> Vec<StructuredNode> {
        nodes
            .into_iter()
            .flat_map(|n| match n {
                StructuredNode::Goto(t) => {
                    if remaining.get_mut(&t).map(|r| {
                        let keep = *r <= 1;
                        if !keep {
                            *r -= 1;
                        }
                        keep
                    }) == Some(true)
                    {
                        vec![StructuredNode::Goto(t)]
                    } else if let Some(Some(exp)) = memo.get(&t) {
                        exp.clone()
                    } else if let Some(stmts) = ret_syn.get(&t) {
                        vec![StructuredNode::Block(IrBlock {
                            id: 0,
                            start_address: 0,
                            end_address: 0,
                            stmts: stmts.clone(),
                        })]
                    } else {
                        vec![StructuredNode::Goto(t)]
                    }
                }
                StructuredNode::If {
                    cond,
                    then,
                    otherwise,
                } => vec![StructuredNode::If {
                    cond,
                    then: subst(then, memo, ret_syn, remaining),
                    otherwise: subst(otherwise, memo, ret_syn, remaining),
                }],
                StructuredNode::While { cond, body } => {
                    vec![StructuredNode::While {
                        cond,
                        body: subst(body, memo, ret_syn, remaining),
                    }]
                }
                StructuredNode::DoWhile { cond, body } => {
                    vec![StructuredNode::DoWhile {
                        cond,
                        body: subst(body, memo, ret_syn, remaining),
                    }]
                }
                other => vec![other],
            })
            .collect()
    }

    subst(nodes, &memo, &ret_syn, &mut remaining)
}

/// Collapse the flat "early-exit ladder" pattern that `fallback_to_gotos`
/// produces for long validation chains, e.g.:
///
/// ```text
/// if (c) goto loc_NEXT;        // If{ cond:c, then:[Goto(NEXT)] }
/// <fail stmts>                 // Block(s)
/// goto loc_SHARED;             // still inside the fail region
/// loc_NEXT:                    // Label(NEXT)
/// if (c2) goto loc_NEXT2;
/// ...
/// ```
/// into nested conditionals:
///
/// ```text
/// if (!c) {
///     <fail stmts>
///     goto loc_SHARED;
/// }
/// if (c2) goto loc_NEXT2;
/// ...
/// ```
///
/// This is a *local, semantics-preserving* rewrite: `if (c) goto L; X; L:` is
/// exactly `if (!c) { X; }`. It only fires on an EXACT node shape (the If's then
/// arm is a single Goto, and a Label with that exact target follows the fail
/// region) and otherwise returns the input untouched. It never changes which
/// blocks execute, only how they nest — so it cannot break a function it
/// mis-matches; worst case it does nothing.
fn collapse_early_exit_ladder(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Count references to each label target so we never drop a Label that is
    // jumped to from more than the one If we are folding.
    let mut label_refs: std::collections::HashMap<u64, usize> =
        std::collections::HashMap::new();
    fn tally(nodes: &[StructuredNode], m: &mut std::collections::HashMap<u64, usize>) {
        for n in nodes {
            match n {
                StructuredNode::Goto(t) => *m.entry(*t).or_insert(0) += 1,
                StructuredNode::If { then, otherwise, .. } => {
                    tally(then, m);
                    tally(otherwise, m);
                }
                StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
                    tally(body, m)
                }
                _ => {}
            }
        }
    }
    tally(&nodes, &mut label_refs);

    let mut out: Vec<StructuredNode> = Vec::with_capacity(nodes.len());
    let mut i = 0usize;
    while i < nodes.len() {
        // Match: If { cond, then: [Goto(next)], otherwise: [] }
        let matched = match &nodes[i] {
            StructuredNode::If {
                cond,
                then,
                otherwise,
            } if otherwise.is_empty() && then.len() == 1 => {
                if let StructuredNode::Goto(next) = &then[0] {
                    Some((cond.clone(), *next))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some((cond, next)) = matched {
            // The fail region is everything after the If up to a Label(next).
            // It must be non-empty and reach a Label(next) before the next
            // unrelated If of the same shape; we conservatively require the
            // Label(next) to appear and no nested identical If in between.
            let mut j = i + 1;
            let mut fail_body: Vec<StructuredNode> = Vec::new();
            let mut found_label = false;
            // If we hit ANY label other than `next`, or any nested If, the fail
            // region is not a clean fall-through skip (it contains another join
            // point that other code may jump into). Folding would drag that
            // label — and its inbound gotos — inside the if-block, producing
            // mis-nested output. Abort the fold in that case (safe: no change).
            let mut aborted = false;
            while j < nodes.len() {
                match &nodes[j] {
                    StructuredNode::Label(a) if *a == next => {
                        found_label = true;
                        break;
                    }
                    StructuredNode::Label(_) | StructuredNode::If { .. } => {
                        aborted = true;
                        break;
                    }
                    other => fail_body.push(other.clone()),
                }
                j += 1;
            }
            if aborted {
                out.push(nodes[i].clone());
                i += 1;
                continue;
            }

            // Only fold when: a matching label closes the region, the fail
            // body is non-empty, and the label is referenced exactly once
            // (by this If) so dropping it is safe.
            if found_label
                && !fail_body.is_empty()
                && label_refs.get(&next).copied().unwrap_or(0) == 1
            {
                out.push(StructuredNode::If {
                    cond: negate_condition(cond),
                    // Recurse so nested rungs inside the fail region collapse too;
                    // otherwise rung 1 wraps a still-flat interior.
                    then: collapse_early_exit_ladder(fail_body),
                    otherwise: Vec::new(),
                });
                i = j + 1; // skip past the consumed Label(next)
                continue;
            }
        }

        out.push(nodes[i].clone());
        i += 1;
    }

    out
}

#[cfg(test)]
fn dbg_syn(so: &str, fa: u64) -> (usize, Vec<(u64, Option<usize>, Option<Vec<IrStmt>>)>) {
    let _ = (so, fa);
    (0, Vec::new())
}
