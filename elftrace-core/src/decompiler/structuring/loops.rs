//! Natural loop detection and reducibility verification.

use super::cfgraph::CfGraph;
use super::dominators::dominators;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: usize,
    pub nodes: HashSet<usize>,
    pub back_edges: Vec<(usize, usize)>,
    pub exit_blocks: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub loops: Vec<NaturalLoop>,
    pub is_reducible: bool,
}

pub fn detect_loops(g: &CfGraph) -> LoopInfo {
    let n = g.blocks.len();
    if n == 0 {
        return LoopInfo {
            loops: Vec::new(),
            is_reducible: true,
        };
    }

    if g.has_indirect_branch {
        return LoopInfo {
            loops: Vec::new(),
            is_reducible: false,
        };
    }

    let dom = dominators(g);
    let mut back_edges = Vec::new();

    for (u, dom_set) in dom.iter().enumerate().take(n) {
        for &v in &g.succ[u] {
            if v < n && dom_set.contains(&v) {
                // v dominates u, so u -> v is a back edge and v is the header
                back_edges.push((u, v));
            }
        }
    }

    let all_back_edges = back_edges.clone();

    // Group back-edges by header
    let mut header_to_backedges: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for (from, to) in back_edges {
        header_to_backedges.entry(to).or_default().push(from);
    }

    let mut loops = Vec::new();
    let mut is_reducible = true;

    for (&header, from_nodes) in &header_to_backedges {
        let mut loop_nodes = HashSet::new();
        loop_nodes.insert(header);

        let mut worklist = Vec::new();
        for &from in from_nodes {
            if from != header {
                loop_nodes.insert(from);
                worklist.push(from);
            }
        }

        while let Some(curr) = worklist.pop() {
            for &p in &g.pred[curr] {
                if !loop_nodes.contains(&p) {
                    loop_nodes.insert(p);
                    worklist.push(p);
                }
            }
        }

        // Verify single entry: no edge from outside loop into a body node other than header
        for &node in &loop_nodes {
            if node != header {
                for &p in &g.pred[node] {
                    if !loop_nodes.contains(&p) {
                        // Edge enters loop at a node other than the header -> IRREDUCIBLE!
                        is_reducible = false;
                    }
                }
            }
        }

        // Collect exit blocks
        let mut exit_blocks = Vec::new();
        for &node in &loop_nodes {
            for &s in &g.succ[node] {
                if !loop_nodes.contains(&s) && !exit_blocks.contains(&node) {
                    exit_blocks.push(node);
                }
            }
        }

        let back_edge_pairs: Vec<(usize, usize)> =
            from_nodes.iter().map(|&from| (from, header)).collect();

        loops.push(NaturalLoop {
            header,
            nodes: loop_nodes,
            back_edges: back_edge_pairs,
            exit_blocks,
        });
    }

    // Check if forward graph (CFG with back-edges removed) contains any cycles.
    // If a cycle exists without a back-edge to a dominating header, the graph is IRREDUCIBLE!
    if is_reducible {
        let mut forward_succ = g.succ.clone();
        for (from, to) in all_back_edges {
            if from < forward_succ.len() {
                forward_succ[from].retain(|&v| v != to);
            }
        }
        if has_cycle(&forward_succ, n) {
            is_reducible = false;
        }
    }

    // Sort loops innermost first: smaller node count first
    loops.sort_by_key(|l| l.nodes.len());

    LoopInfo {
        loops,
        is_reducible,
    }
}

fn has_cycle(succ: &[Vec<usize>], n: usize) -> bool {
    let mut visited = vec![0u8; n];
    for i in 0..n {
        if visited[i] == 0 && dfs_cycle(i, succ, &mut visited) {
            return true;
        }
    }
    false
}

fn dfs_cycle(u: usize, succ: &[Vec<usize>], visited: &mut [u8]) -> bool {
    visited[u] = 1;
    for &v in &succ[u] {
        if v < visited.len() {
            if visited[v] == 1 {
                return true;
            }
            if visited[v] == 0 && dfs_cycle(v, succ, visited) {
                return true;
            }
        }
    }
    visited[u] = 2;
    false
}
