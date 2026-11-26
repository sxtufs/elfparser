//! Structured Control-Flow Recovery Engine.

pub mod cfgraph;
pub mod dominators;
pub mod emit;
pub mod jumptable;
pub mod loops;
pub mod regions;

use self::cfgraph::CfGraph;
use self::emit::emit_structured_c;
use self::loops::detect_loops;
use self::regions::structure_function;
use crate::decompiler::codegen::CodeGenerator;
use crate::decompiler::ir::{IrBlock, IrExpr, IrFunction};
use crate::elf_parser::ElfContext;

#[derive(Debug, Clone)]
pub enum StructuredNode {
    Block(IrBlock),
    If {
        cond: IrExpr,
        then: Vec<StructuredNode>,
        otherwise: Vec<StructuredNode>,
    },
    While {
        cond: IrExpr,
        body: Vec<StructuredNode>,
    },
    DoWhile {
        cond: IrExpr,
        body: Vec<StructuredNode>,
    },
    Break,
    Continue,
    Return(Option<IrExpr>),
    Goto(u64),
    Label(u64),
    /// Recovered jump-table dispatch. `cases` maps case value -> target block
    /// address; `default` is the out-of-range/fall-through target. Emitted as a
    /// real `switch` statement rather than a wall of gotos.
    Switch {
        selector: IrExpr,
        cases: Vec<(i64, u64)>,
        default: Option<u64>,
    },
}

pub fn structure(ctx: &ElfContext, func: &IrFunction, graph: &CfGraph) -> Vec<StructuredNode> {
    let loop_info = detect_loops(graph);
    structure_function(ctx, func, graph, &loop_info)
}

pub fn decompile_to_c_structured(ctx: &ElfContext, address: u64) -> String {
    use crate::decompiler::analysis::DecompilerPipeline;
    use crate::decompiler::find_function_range;

    let fn_range = find_function_range(ctx, address);
    let pipeline = DecompilerPipeline::new(crate::decompiler::arch::ArchKind::from_e_machine(
        ctx.get_info().map(|i| i.e_machine).unwrap_or(183),
    ));

    let ir_func = match pipeline.analyze_function(
        ctx,
        fn_range.name.clone(),
        fn_range.start,
        fn_range.size,
        fn_range.thumb,
    ) {
        Ok(f) => f,
        Err(e) => return format!("// [Decompilation Error] {}\n", e),
    };

    let graph = CfGraph::from_blocks(ir_func.blocks.clone());
    let nodes = structure(ctx, &ir_func, &graph);
    let codegen = CodeGenerator::new(ctx, pipeline.arch);
    // Last structuring pass: shared exit tails the inliner kept (cyclic
    // epilogue chains) become static helper functions; their goto sites
    // become `return tail_XXXXXXXX(...)`. Void functions call the helper
    // and return; value-returning functions tail-return it.
    let ret_void = matches!(
        ir_func.ret_type,
        crate::decompiler::ir::IrType::Void
    );
    let (nodes, helpers) = regions::extract_tail_helpers(nodes, ret_void);
    emit_structured_c(&ir_func, &nodes, &codegen, &helpers)
}
