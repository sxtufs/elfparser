use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymsDTO {
    pub sym: String,
    pub value: u64,
    pub size: u64,
    pub thumb: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jni_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jni_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraDTO {
    pub name: String,
    pub info: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfInfo {
    pub e_machine: u32,
    pub entry: u64,
    pub is_64: bool,
    pub soname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    pub libraries: Vec<String>,
    pub syms: Vec<SymsDTO>,
    pub yara: Vec<YaraDTO>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeInsItem {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeIns {
    pub data: Vec<CodeInsItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SDataItem {
    pub paddr: u64,
    pub vaddr: u64,
    pub size: usize,
    pub string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SData {
    pub data: Vec<SDataItem>,
}
