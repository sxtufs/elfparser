#![allow(clippy::missing_safety_doc)]
pub mod decompiler;
pub mod disasm;
pub mod elf_parser;
pub mod il2cpp;
pub mod jni_bridge;
pub mod jni_resolver;
pub mod model;
pub mod patcher;
pub mod scanner;
pub mod tracer;
pub mod xref;

pub use elf_parser::ElfContext;
pub use il2cpp::{load_global_metadata, load_script_json};
pub use jni_resolver::resolve_jni_offset;
pub use model::{CodeIns, ElfInfo, SData};
pub use patcher::{apply_quick_patch, assemble_and_patch, PatchResult, QuickPatchType};
pub use scanner::{
    calculate_entropy_report, scan_security, EntropyReport, ScanReport, SectionEntropy,
    SecurityFinding,
};
pub use tracer::{RegisterState, VirtualCpu};
pub use xref::{find_callers_to, get_hierarchy, CallHierarchy, CalleeItem, XRefItem, XRefResponse};
