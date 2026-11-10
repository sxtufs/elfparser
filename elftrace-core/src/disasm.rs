use crate::model::{CodeIns, CodeInsItem};
use capstone::prelude::*;
use std::collections::HashMap;

pub fn resolve_aarch64_syscall(num: u64) -> Option<&'static str> {
    match num {
        56 => Some("openat"),
        63 => Some("read"),
        64 => Some("write"),
        65 => Some("close"),
        78 => Some("readlinkat"),
        79 => Some("newfstatat"),
        93 => Some("exit"),
        94 => Some("exit_group"),
        117 => Some("ptrace [Anti-Debug]"),
        129 => Some("kill"),
        134 => Some("rt_sigaction"),
        135 => Some("rt_sigprocmask"),
        172 => Some("getpid"),
        173 => Some("getppid"),
        215 => Some("munmap"),
        220 => Some("clone"),
        221 => Some("execve"),
        222 => Some("mmap"),
        226 => Some("mprotect [Memory Hook/Unpack]"),
        260 => Some("wait4"),
        29 => Some("ioctl"),
        _ => None,
    }
}

pub fn disassemble(
    code_bytes: &[u8],
    address: u64,
    size: u64,
    e_machine: u32,
    thumb: bool,
) -> Result<CodeIns, String> {
    disassemble_with_resolver(code_bytes, address, size, e_machine, thumb, None, false)
}

pub fn disassemble_with_resolver(
    code_bytes: &[u8],
    address: u64,
    size: u64,
    e_machine: u32,
    thumb: bool,
    resolver: Option<&dyn Fn(u64) -> Option<String>>,
    is_jni_function: bool,
) -> Result<CodeIns, String> {
    let cs = match e_machine {
        183 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map_err(|e| format!("Failed to create ARM64 Capstone: {}", e))?,
        40 => {
            if thumb {
                Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Thumb)
                    .extra_mode([arch::arm::ArchExtraMode::V8].iter().copied())
                    .build()
                    .map_err(|e| format!("Failed to create Thumb Capstone: {}", e))?
            } else {
                Capstone::new()
                    .arm()
                    .mode(arch::arm::ArchMode::Arm)
                    .extra_mode([arch::arm::ArchExtraMode::V8].iter().copied())
                    .build()
                    .map_err(|e| format!("Failed to create ARM Capstone: {}", e))?
            }
        }
        62 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .map_err(|e| format!("Failed to create X86_64 Capstone: {}", e))?,
        3 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .build()
            .map_err(|e| format!("Failed to create X86 Capstone: {}", e))?,
        _ => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map_err(|e| format!("Failed to create default Capstone: {}", e))?,
    };

    let max_len = if size > 0 && (size as usize) <= code_bytes.len() {
        size as usize
    } else {
        std::cmp::min(code_bytes.len(), 8192)
    };

    let slice = &code_bytes[..max_len];
    let insns = cs
        .disasm_all(slice, address)
        .map_err(|e| format!("Disassembly error: {}", e))?;

    let mut items = Vec::with_capacity(insns.len());

    // Tracking registers for in-line string annotations & syscall resolution
    let mut adrp_regs: HashMap<String, u64> = HashMap::new();
    let mut last_w8_val: Option<u64> = None;
    let mut jni_regs: HashMap<String, &'static str> = HashMap::new();
    let mut tls_regs: std::collections::HashSet<String> = std::collections::HashSet::new();

    for insn in insns.iter() {
        let mnem = insn.mnemonic().unwrap_or("").to_string();
        let ops = insn.op_str().unwrap_or("").to_string();
        let mut comment: Option<String> = None;

        // Thread Local Storage (Stack Canary tracking)
        if mnem == "mrs" && ops.contains("tpidr_el0") {
            let reg = ops.split(',').next().unwrap_or("").trim().to_lowercase();
            tls_regs.insert(reg);
        }

        // 1. Syscall Resolution (mov w8, #num followed by svc #0)
        if mnem == "mov" || mnem == "movz" {
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 && (parts[0] == "w8" || parts[0] == "x8") {
                let imm_str = parts[1].trim_start_matches('#');
                if imm_str.starts_with("0x") || imm_str.starts_with("0X") {
                    last_w8_val = u64::from_str_radix(&imm_str[2..], 16).ok();
                } else {
                    last_w8_val = imm_str.parse::<u64>().ok();
                }
            } else {
                last_w8_val = None;
            }
        } else if mnem == "svc" {
            if let Some(sys_num) = last_w8_val {
                if let Some(name) = resolve_aarch64_syscall(sys_num) {
                    comment = Some(format!("; syscall: {}", name));
                }
            }
            last_w8_val = None;
        } else {
            last_w8_val = None;
        }

        // 2. In-Line String Resolution (ADRP + ADD / LDR)
        if mnem == "adrp" {
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let reg = parts[0].to_string();
                let imm_str = parts[1].trim_start_matches('#');
                let target = if imm_str.starts_with("0x") || imm_str.starts_with("0X") {
                    u64::from_str_radix(&imm_str[2..], 16).ok()
                } else {
                    imm_str.parse::<u64>().ok()
                };
                if let Some(page) = target {
                    adrp_regs.insert(reg, page);
                }
            }
        } else if mnem == "add" {
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 3 {
                let src_reg = parts[1];
                if let Some(&page) = adrp_regs.get(src_reg) {
                    let imm_str = parts[2].trim_start_matches('#');
                    let off_opt = if imm_str.starts_with("0x") || imm_str.starts_with("0X") {
                        u64::from_str_radix(&imm_str[2..], 16).ok()
                    } else {
                        imm_str.parse::<u64>().ok()
                    };
                    if let Some(off) = off_opt {
                        let target_vaddr = page + off;
                        if let Some(res) = resolver {
                            if let Some(s) = res(target_vaddr) {
                                comment = Some(format!("; \"{}\"", s));
                            }
                        }
                    }
                }
            }
        } else if mnem.starts_with("ldr") {
            if let Some(start_bracket) = ops.find('[') {
                if let Some(end_bracket) = ops.find(']') {
                    let inside = &ops[start_bracket + 1..end_bracket];
                    let parts: Vec<&str> = inside.split(',').map(|s| s.trim()).collect();
                    if parts.len() == 2 {
                        let base_reg = parts[0];
                        let imm_str = parts[1].trim_start_matches('#');
                        if !imm_str.starts_with('-') {
                            let off_opt = if imm_str.starts_with("0x") || imm_str.starts_with("0X")
                            {
                                u64::from_str_radix(&imm_str[2..], 16).ok()
                            } else {
                                imm_str.parse::<u64>().ok()
                            };

                            if let Some(&page) = adrp_regs.get(base_reg) {
                                if let Some(off) = off_opt {
                                    let target_vaddr = page + off;
                                    if let Some(res) = resolver {
                                        if let Some(s) = res(target_vaddr) {
                                            comment = Some(format!("; \"{}\"", s));
                                        }
                                    }
                                }
                            } else if tls_regs.contains(&base_reg.to_lowercase()) {
                                if off_opt == Some(0x28) {
                                    comment =
                                        Some("; Stack Canary (__stack_chk_guard)".to_string());
                                }
                            } else if let Some(off) = off_opt {
                                let base_lower = base_reg.to_lowercase();
                                if mnem == "ldr"
                                    && base_lower != "sp"
                                    && base_lower != "x29"
                                    && is_jni_function
                                {
                                    let is_64 = e_machine == 183;
                                    if let Some(jni_fn) =
                                        crate::jni_resolver::resolve_jni_offset(off, is_64)
                                    {
                                        comment = Some(format!("; JNI: {}", jni_fn));
                                        let dst_reg = ops
                                            .split(',')
                                            .next()
                                            .unwrap_or("")
                                            .trim()
                                            .to_lowercase();
                                        jni_regs.insert(dst_reg, jni_fn);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (mnem == "blr" || mnem == "br") && comment.is_none() {
            let call_reg = ops.trim().to_lowercase();
            if let Some(&jni_fn) = jni_regs.get(&call_reg) {
                comment = Some(format!("; call JNI: {}", jni_fn));
            }
        }

        // 3. Function Call & Branch Symbol Annotation (bl, blx, call)
        if (mnem == "bl" || mnem == "blx" || mnem == "call") && comment.is_none() {
            if let Some(target) = parse_imm_target(&ops) {
                if let Some(res) = resolver {
                    if let Some(name) = res(target) {
                        comment = Some(format!("; {}", name));
                    }
                }
            }
        }

        items.push(CodeInsItem {
            address: insn.address(),
            bytes: insn.bytes().to_vec(),
            mnemonic: mnem,
            op_str: ops,
            comment,
            json: None,
        });
    }

    Ok(CodeIns { data: items })
}

fn parse_imm_target(ops: &str) -> Option<u64> {
    for part in ops.split(',') {
        let trimmed = part.trim().trim_start_matches('#');
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            if let Ok(addr) = u64::from_str_radix(&trimmed[2..], 16) {
                return Some(addr);
            }
        } else if let Ok(addr) = u64::from_str_radix(trimmed, 16) {
            if addr > 0x1000 {
                return Some(addr);
            }
        }
    }
    None
}
