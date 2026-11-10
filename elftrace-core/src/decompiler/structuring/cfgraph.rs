//! Control Flow Graph construction from IR blocks.

use crate::decompiler::ir::{IrBlock, IrStmt};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CfGraph {
    pub blocks: Vec<IrBlock>,
    pub address_to_idx: HashMap<u64, usize>,
    pub succ: Vec<Vec<usize>>,
    pub pred: Vec<Vec<usize>>,
    pub entry: usize,
    pub has_indirect_branch: bool,
}

impl CfGraph {
    pub fn from_blocks(blocks: Vec<IrBlock>) -> Self {
        let n = blocks.len();
        let mut address_to_idx = HashMap::new();
        for (i, b) in blocks.iter().enumerate() {
            address_to_idx.insert(b.start_address, i);
        }

        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut has_indirect = false;

        for (i, b) in blocks.iter().enumerate() {
            let mut found_terminator = false;

            for stmt in &b.stmts {
                match stmt {
                    IrStmt::Branch { cond, target } => {
                        found_terminator = true;
                        if let Some(&tgt_idx) = address_to_idx.get(target) {
                            if cond.is_some() {
                                // Conditional: branch-taken first, fallthrough second
                                succ[i].push(tgt_idx);
                                if i + 1 < n {
                                    succ[i].push(i + 1);
                                }
                            } else {
                                // Unconditional
                                succ[i].push(tgt_idx);
                            }
                        } else if cond.is_some() && i + 1 < n {
                            // Target outside function, but has fallthrough
                            succ[i].push(i + 1);
                        }
                    }
                    IrStmt::Return(_) => {
                        found_terminator = true;
                        // No successors
                    }
                    IrStmt::IndirectBranch { .. } => {
                        found_terminator = true;
                        has_indirect = true;
                    }
                    _ => {}
                }
            }

            // Fallthrough to next block if no unconditional jump or return
            if !found_terminator && i + 1 < n {
                succ[i].push(i + 1);
            }

            // Deduplicate successors
            succ[i].dedup();
        }

        let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (u, successors) in succ.iter().enumerate() {
            for &v in successors {
                if v < n && !pred[v].contains(&u) {
                    pred[v].push(u);
                }
            }
        }

        Self {
            blocks,
            address_to_idx,
            succ,
            pred,
            entry: 0,
            has_indirect_branch: has_indirect,
        }
    }
}
