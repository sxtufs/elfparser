//! Multi-Architecture Definitions, Register Modeling, and Calling Conventions.

use super::ir::IrType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchKind {
    AArch64,
    Arm32,
    X86_64,
    X86_32,
    RiscV64,
    Unknown,
}

impl ArchKind {
    pub fn from_e_machine(e_machine: u32) -> Self {
        match e_machine {
            183 => ArchKind::AArch64,
            40 => ArchKind::Arm32,
            62 => ArchKind::X86_64,
            3 => ArchKind::X86_32,
            243 => ArchKind::RiscV64,
            _ => ArchKind::Unknown,
        }
    }

    pub fn pointer_size(&self) -> usize {
        match self {
            ArchKind::AArch64 | ArchKind::X86_64 | ArchKind::RiscV64 => 8,
            ArchKind::Arm32 | ArchKind::X86_32 => 4,
            ArchKind::Unknown => 8,
        }
    }

    pub fn pointer_type(&self) -> IrType {
        if self.pointer_size() == 8 {
            IrType::Int64
        } else {
            IrType::Int32
        }
    }

    pub fn default_return_register(&self) -> &'static str {
        match self {
            ArchKind::AArch64 => "x0",
            ArchKind::Arm32 => "r0",
            ArchKind::X86_64 => "rax",
            ArchKind::X86_32 => "eax",
            ArchKind::RiscV64 => "a0",
            ArchKind::Unknown => "x0",
        }
    }

    pub fn argument_registers(&self) -> &'static [&'static str] {
        match self {
            ArchKind::AArch64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            ArchKind::Arm32 => &["r0", "r1", "r2", "r3"],
            ArchKind::X86_64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            ArchKind::X86_32 => &[], // x86_32 cdecl uses stack arguments
            ArchKind::RiscV64 => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
            ArchKind::Unknown => &["x0", "x1", "x2", "x3"],
        }
    }

    pub fn is_callee_saved(&self, reg: &str) -> bool {
        let r = reg.to_lowercase();
        match self {
            ArchKind::AArch64 => {
                matches!(
                    r.as_str(),
                    "x19"
                        | "x20"
                        | "x21"
                        | "x22"
                        | "x23"
                        | "x24"
                        | "x25"
                        | "x26"
                        | "x27"
                        | "x28"
                        | "x29"
                        | "x30"
                )
            }
            ArchKind::Arm32 => {
                matches!(
                    r.as_str(),
                    "r4" | "r5" | "r6" | "r7" | "r8" | "r9" | "r10" | "r11" | "lr"
                )
            }
            ArchKind::X86_64 => {
                matches!(r.as_str(), "rbx" | "rbp" | "r12" | "r13" | "r14" | "r15")
            }
            ArchKind::X86_32 => {
                matches!(r.as_str(), "ebx" | "esi" | "edi" | "ebp")
            }
            ArchKind::RiscV64 => {
                matches!(
                    r.as_str(),
                    "s0" | "s1"
                        | "s2"
                        | "s3"
                        | "s4"
                        | "s5"
                        | "s6"
                        | "s7"
                        | "s8"
                        | "s9"
                        | "s10"
                        | "s11"
                        | "ra"
                )
            }
            ArchKind::Unknown => false,
        }
    }

    pub fn normalize_sub_register(&self, reg: &str) -> String {
        let r = reg.to_lowercase();
        match self {
            ArchKind::AArch64 => {
                if let Some(stripped) = r.strip_prefix('w') {
                    format!("x{}", stripped)
                } else {
                    r
                }
            }
            ArchKind::X86_64 => match r.as_str() {
                "eax" | "ax" | "al" | "ah" => "rax".to_string(),
                "ebx" | "bx" | "bl" | "bh" => "rbx".to_string(),
                "ecx" | "cx" | "cl" | "ch" => "rcx".to_string(),
                "edx" | "dx" | "dl" | "dh" => "rdx".to_string(),
                "esi" | "si" | "sil" => "rsi".to_string(),
                "edi" | "di" | "dil" => "rdi".to_string(),
                "ebp" | "bp" | "bpl" => "rbp".to_string(),
                "esp" | "sp" | "spl" => "rsp".to_string(),
                "r8d" | "r8w" | "r8b" => "r8".to_string(),
                "r9d" | "r9w" | "r9b" => "r9".to_string(),
                "r10d" | "r10w" | "r10b" => "r10".to_string(),
                "r11d" | "r11w" | "r11b" => "r11".to_string(),
                "r12d" | "r12w" | "r12b" => "r12".to_string(),
                "r13d" | "r13w" | "r13b" => "r13".to_string(),
                "r14d" | "r14w" | "r14b" => "r14".to_string(),
                "r15d" | "r15w" | "r15b" => "r15".to_string(),
                _ => r,
            },
            ArchKind::X86_32 => match r.as_str() {
                "ax" | "al" | "ah" => "eax".to_string(),
                "bx" | "bl" | "bh" => "ebx".to_string(),
                "cx" | "cl" | "ch" => "ecx".to_string(),
                "dx" | "dl" | "dh" => "edx".to_string(),
                "si" => "esi".to_string(),
                "di" => "edi".to_string(),
                "bp" => "ebp".to_string(),
                "sp" => "esp".to_string(),
                _ => r,
            },
            _ => r,
        }
    }
}
