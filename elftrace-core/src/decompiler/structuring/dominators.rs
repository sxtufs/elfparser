//! Dominator and Post-Dominator tree computation.

use super::cfgraph::CfGraph;
use std::collections::HashSet;

pub fn dominators(g: &CfGraph) -> Vec<HashSet<usize>> {
    let n = g.blocks.len();
    if n == 0 {
        return Vec::new();
    }

    let all_nodes: HashSet<usize> = (0..n).collect();
    let mut dom: Vec<HashSet<usize>> = vec![all_nodes.clone(); n];

    // Entry node dominates only itself
    dom[g.entry].clear();
    dom[g.entry].insert(g.entry);

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if i == g.entry {
                continue;
            }

            let preds = &g.pred[i];
            let new_dom: HashSet<usize> = if preds.is_empty() {
                let mut s = HashSet::new();
                s.insert(i);
                s
            } else {
                let mut intersection = dom[preds[0]].clone();
                for &p in &preds[1..] {
                    intersection = intersection.intersection(&dom[p]).copied().collect();
                }
                intersection.insert(i);
                intersection
            };

            if new_dom != dom[i] {
                dom[i] = new_dom;
                changed = true;
            }
        }
    }

    dom
}

pub fn idom(g: &CfGraph) -> Vec<Option<usize>> {
    let n = g.blocks.len();
    if n == 0 {
        return Vec::new();
    }

    let dom = dominators(g);
    let mut idoms = vec![None; n];

    for i in 0..n {
        if i == g.entry {
            continue;
        }

        let strict_doms: Vec<usize> = dom[i].iter().copied().filter(|&d| d != i).collect();
        // Immediate dominator is the strictly closest dominator
        let mut best: Option<usize> = None;
        for &d in &strict_doms {
            // d is immediate if no other strict dominator is dominated by d
            let is_immediate = strict_doms
                .iter()
                .all(|&other| other == d || !dom[other].contains(&d));
            if is_immediate {
                best = Some(d);
                break;
            }
        }
        idoms[i] = best;
    }

    idoms
}

#[allow(clippy::needless_range_loop)]
pub fn post_dominators(g: &CfGraph) -> Vec<HashSet<usize>> {
    let n = g.blocks.len();
    if n == 0 {
        return Vec::new();
    }

    // Add synthetic exit node at index n
    let exit_node = n;
    let total_nodes = n + 1;

    let mut rev_succ: Vec<Vec<usize>> = vec![Vec::new(); total_nodes];
    let mut rev_pred: Vec<Vec<usize>> = vec![Vec::new(); total_nodes];

    for u in 0..n {
        if g.succ[u].is_empty() {
            // Node u reaches synthetic exit
            rev_succ[exit_node].push(u);
            rev_pred[u].push(exit_node);
        } else {
            for &v in &g.succ[u] {
                rev_succ[v].push(u);
                rev_pred[u].push(v);
            }
        }
    }

    let all_nodes: HashSet<usize> = (0..total_nodes).collect();
    let mut pdom: Vec<HashSet<usize>> = vec![all_nodes; total_nodes];

    pdom[exit_node].clear();
    pdom[exit_node].insert(exit_node);

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..total_nodes {
            if i == exit_node {
                continue;
            }

            let preds = &rev_pred[i];
            let new_pdom: HashSet<usize> = if preds.is_empty() {
                let mut s = HashSet::new();
                s.insert(i);
                s
            } else {
                let mut intersection = pdom[preds[0]].clone();
                for &p in &preds[1..] {
                    intersection = intersection.intersection(&pdom[p]).copied().collect();
                }
                intersection.insert(i);
                intersection
            };

            if new_pdom != pdom[i] {
                pdom[i] = new_pdom;
                changed = true;
            }
        }
    }

    // Project back to original nodes, removing synthetic exit
    pdom.truncate(n);
    for set in &mut pdom {
        set.remove(&exit_node);
    }
    pdom
}

pub fn ipost_dom(g: &CfGraph) -> Vec<Option<usize>> {
    let n = g.blocks.len();
    if n == 0 {
        return Vec::new();
    }

    let pdom = post_dominators(g);
    let mut ipdoms = vec![None; n];

    for i in 0..n {
        let strict_pdoms: Vec<usize> = pdom[i].iter().copied().filter(|&d| d != i).collect();
        let mut best: Option<usize> = None;
        for &d in &strict_pdoms {
            let is_immediate = strict_pdoms
                .iter()
                .all(|&other| other == d || !pdom[other].contains(&d));
            if is_immediate {
                best = Some(d);
                break;
            }
        }
        ipdoms[i] = best;
    }

    ipdoms
}
