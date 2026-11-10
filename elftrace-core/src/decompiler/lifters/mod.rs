pub mod arm32;
pub mod arm64;
pub mod x86_32;
pub mod x86_64;

use crate::decompiler::ir::IrStmt;
use crate::elf_parser::ElfContext;

pub trait InstructionLifter {
    fn lift(
        &mut self,
        ctx: &ElfContext,
        address: u64,
        mnemonic: &str,
        op_str: &str,
        insn_bytes: &[u8],
    ) -> Vec<IrStmt>;

    fn reset_state(&mut self) {}
}
