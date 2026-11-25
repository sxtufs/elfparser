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

/// True when every block ending in an indirect branch has a recovered table.
fn indirect_all_resolved(
    func: &IrFunction,
    tables: &std::collections::HashMap<u64, super::jumptable::JumpTable>,
) -> bool {
    func.blocks.iter().all(|b| {
        if matches!(b.stmts.last(), Some(IrStmt::IndirectBranch { .. })) {
            tables.contains_key(&b.start_address)
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

    nodes
}
