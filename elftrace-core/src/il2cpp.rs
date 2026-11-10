use crate::elf_parser::ElfContext;
use crate::model::SymsDTO;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const IL2CPP_METADATA_MAGIC: u32 = 0xFAB11BAF;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Il2CppMethodScript {
    #[serde(alias = "Address", alias = "address")]
    pub address: u64,
    #[serde(alias = "Name", alias = "name")]
    pub name: String,
    #[serde(alias = "Signature", alias = "signature", default)]
    pub signature: String,
}

/// Parses Il2CppDumper's standard `script.json` and injects all C# methods directly into the ELF symbol table
pub fn load_script_json(ctx: &mut ElfContext, json_path: &str) -> Result<usize, String> {
    let content = fs::read_to_string(Path::new(json_path))
        .map_err(|e| format!("Failed to read script.json: {}", e))?;

    let methods: Vec<Il2CppMethodScript> = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse script.json: {}", e))?;

    let count = methods.len();
    for m in methods {
        if m.address != 0 && !m.name.is_empty() {
            let clean_addr = m.address & !1;
            let (cls, meth) = parse_cs_method(&m.name);
            ctx.syms_map.insert(
                clean_addr,
                SymsDTO {
                    sym: m.name.clone(),
                    value: clean_addr,
                    size: 0,
                    thumb: (m.address & 1) != 0,
                    demangled: Some(m.name.clone()),
                    jni_class: cls,
                    jni_method: meth,
                    json: if !m.signature.is_empty() {
                        Some(m.signature)
                    } else {
                        None
                    },
                },
            );
        }
    }

    Ok(count)
}

/// Validates a Unity `global-metadata.dat` file.
///
/// The full metadata format requires the paired `script.json` from Il2CppDumper to map
/// C# method names to ELF addresses. Without the script, this function can only confirm
/// the file is a well-formed metadata blob — it cannot inject symbols into the ELF.
///
/// Returns:
///   Ok(0)  — file is valid but no symbols were injected (expected)
///   Err(_) — file is malformed or has wrong magic
pub fn load_global_metadata(_ctx: &mut ElfContext, dat_path: &str) -> Result<usize, String> {
    let data = fs::read(Path::new(dat_path))
        .map_err(|e| format!("Failed to read global-metadata.dat: {}", e))?;

    if data.len() < 32 {
        return Err("global-metadata.dat is too small".to_string());
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != IL2CPP_METADATA_MAGIC {
        return Err(format!(
            "Invalid metadata magic: 0x{:08X} (expected 0xFAB11BAF)",
            magic
        ));
    }

    // File is a valid metadata blob, but we cannot recover C# method names from it alone.
    // The symbol injection path is load_script_json(). Return 0 to signal "validated, no
    // symbols added" so the UI does not show a misleading success count.
    Ok(0)
}

fn parse_cs_method(full_name: &str) -> (Option<String>, Option<String>) {
    if let Some((cls, meth)) = full_name.split_once("::") {
        (Some(cls.to_string()), Some(meth.to_string()))
    } else if let Some((cls, meth)) = full_name.split_once('.') {
        (Some(cls.to_string()), Some(meth.to_string()))
    } else {
        (None, Some(full_name.to_string()))
    }
}
