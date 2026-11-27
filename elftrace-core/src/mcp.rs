//! MCP (Model Context Protocol) server for the elftrace analysis engine.
//!
//! Exposes the same analysis the Android app uses to an AI agent: ELF metadata,
//! symbols, disassembly, decompilation, xrefs, call hierarchy, the security
//! scanner, entropy, string extraction, function discovery and the JSON plugin
//! runtime. Transport is newline-delimited JSON-RPC 2.0 on stdio (what desktop
//! clients spawn) or Streamable HTTP (`elftrace-mcp --http`).
//!
//! Every tool here is read-only: it parses the target ELF and returns text.
//! Nothing in this module writes to the file, so a client that can only reach
//! this server cannot corrupt a binary. Patch tools, when they come, belong
//! behind separate names with an explicit approval step.

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::elf_parser::ElfContext;
use crate::model::{CodeIns, SymsDTO};

/// Newest protocol revision this server implements.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", PROTOCOL_VERSION];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// Tool output cap. A decompiled function or a string dump of a large library
/// can be megabytes; pasting that into a model's context is useless and
/// expensive, so results are cut at a character boundary with a note.
const MAX_RESULT_CHARS: usize = 400_000;

/// Parsed ELFs kept open per process. Analysis tools revisit the same file
/// constantly (decompile, xrefs, callers), and re-parsing a 100 MB `.so` for
/// every call would dominate the run time.
const MAX_CACHED_FILES: usize = 8;

const MAX_HTTP_BODY: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Request context
// ---------------------------------------------------------------------------

/// Holds the parsed ELFs for the lifetime of the server.
///
/// A small front-loaded `Vec` is used instead of a `HashMap` so the most
/// recently used file is always at index 0 and eviction is a `truncate`.
#[derive(Default)]
pub struct Host {
    files: Vec<(String, ElfContext)>,
}

impl Host {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse `path` once and return the cached context.
    pub fn context(&mut self, path: &str) -> Result<&ElfContext, String> {
        let canonical =
            std::fs::canonicalize(path).map_err(|e| format!("cannot open '{path}': {e}"))?;
        let key = canonical.to_string_lossy().into_owned();
        if let Some(pos) = self.files.iter().position(|(p, _)| *p == key) {
            let entry = self.files.remove(pos);
            self.files.insert(0, entry);
            return Ok(&self.files[0].1);
        }
        let ctx = ElfContext::open(&key)?;
        self.files.insert(0, (key, ctx));
        self.files.truncate(MAX_CACHED_FILES);
        Ok(&self.files[0].1)
    }

    /// Same cache, mutable: the patch/rename/save tools change the in-memory image.
    pub fn context_mut(&mut self, path: &str) -> Result<&mut ElfContext, String> {
        self.context(path)?;
        Ok(&mut self.files[0].1)
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 framing
// ---------------------------------------------------------------------------

struct RpcError {
    code: i64,
    message: String,
}

fn rpc_error(code: i64, message: impl Into<String>) -> RpcError {
    RpcError {
        code,
        message: message.into(),
    }
}

fn ok_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Handle one transport message (a single JSON value on one line, or an HTTP
/// body). Returns the response text, or `None` for notifications and blank
/// input.
pub fn handle_message(host: &mut Host, raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let value: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return Some(
                err_response(Value::Null, PARSE_ERROR, &format!("invalid JSON: {e}")).to_string(),
            )
        }
    };
    if let Value::Array(items) = value {
        // MCP dropped JSON-RPC batching in 2025-06-18, but an older client may
        // still send an array; answer each element instead of failing.
        let responses: Vec<Value> = items.iter().filter_map(|m| handle_one(host, m)).collect();
        return if responses.is_empty() {
            None
        } else {
            Some(Value::Array(responses).to_string())
        };
    }
    handle_one(host, &value).map(|v| v.to_string())
}

fn handle_one(host: &mut Host, msg: &Value) -> Option<Value> {
    // A message without an id is a notification (initialized, cancelled,
    // progress): JSON-RPC forbids replying to it. "id": null is still a request.
    let id = msg.get("id")?.clone();
    let method = match msg.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => {
            return Some(err_response(id, INVALID_REQUEST, "missing 'method'"));
        }
    };
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    Some(match dispatch(host, method, &params) {
        Ok(result) => ok_response(id, result),
        Err(e) => err_response(id, e.code, &e.message),
    })
}

fn dispatch(host: &mut Host, method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "initialize" => Ok(initialize_result(params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_definitions()})),
        "tools/call" => call_tool_message(host, params),
        other => Err(rpc_error(
            METHOD_NOT_FOUND,
            format!("unknown method: {other}"),
        )),
    }
}

fn initialize_result(params: &Value) -> Value {
    // Echo the client's revision when we speak it; otherwise advertise ours and
    // let the client decide whether it can downgrade.
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    let version = match requested {
        Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
        _ => PROTOCOL_VERSION,
    };
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "elftrace-mcp", "version": env!("CARGO_PKG_VERSION")},
        "instructions": "Static analysis for Android/iOS native binaries (.so, .dylib). \
    Call elf_info first to learn the architecture, then list_symbols, then decompile \
    or disassemble a specific address. All tools are read-only; nothing is patched.",
    })
}

fn call_tool_message(host: &mut Host, params: &Value) -> Result<Value, RpcError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_error(INVALID_PARAMS, "tools/call requires a tool 'name'"))?;
    if !is_known_tool(name) {
        return Err(rpc_error(INVALID_PARAMS, format!("unknown tool: {name}")));
    }
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // The parsers are hardened but operate on hostile input; a panic must not
    // take the server down (same reasoning as the JNI bridge's guard).
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| call_tool(host, name, &args)));
    Ok(match outcome {
        Ok(Ok(text)) => tool_result(&text, false),
        Ok(Err(message)) => tool_result(&message, true),
        Err(_) => tool_result(
            "internal error: the analysis panicked; the input is probably malformed",
            true,
        ),
    })
}

fn tool_result(text: &str, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": truncate_result(text)}],
        "isError": is_error,
    })
}

fn truncate_result(text: &str) -> String {
    if text.len() <= MAX_RESULT_CHARS {
        return text.to_string();
    }
    let mut cut = MAX_RESULT_CHARS;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}\n\n[truncated: {} of {} bytes shown]",
        &text[..cut],
        cut,
        text.len()
    )
}

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

fn is_known_tool(name: &str) -> bool {
    TOOL_NAMES.contains(&name)
}

const TOOL_NAMES: [&str; 22] = [
    "current_file",
    "list_imports",
    "elf_info",
    "list_symbols",
    "disassemble",
    "decompile",
    "xrefs",
    "call_hierarchy",
    "security_scan",
    "entropy",
    "strings",
    "discover_functions",
    "list_plugins",
    "run_plugin",
    "read_bytes",
    "binary_facts",
    "resolve_jni",
    "rename_function",
    "assemble",
    "patch",
    "undo",
    "save",
];

/// Tools that change the in-memory image or write files. Everything else is
/// read-only, and `tools/list` says so through `annotations`.
const WRITE_TOOLS: [&str; 3] = ["patch", "undo", "save"];

fn tool_definitions() -> Value {
    let defs = json!([
        {
            "name": "current_file",
            "description": "The binary ELFTrace currently has open, as a path every other tool accepts. Call this first when you do not know which file is on screen.",
            "inputSchema": object_schema(json!({}), &[])
        },
        {
            "name": "list_imports",
            "description": "Files the user imported into ELFTrace for agent analysis (MCP dialog > Import a file). Returns {name, path, size, modified_unix} per file; pass a returned path to any tool.",
            "inputSchema": object_schema(json!({}), &[])
        },
        {
            "name": "elf_info",
            "description": "ELF header, architecture, soname, DT_NEEDED libraries, program segments and sections. Symbol count only; use list_symbols for names.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file (.so, .dylib or executable) on this machine")
            }), &["path"])
        },
        {
            "name": "list_symbols",
            "description": "Symbol table as {name, demangled, address, size, thumb}. Filter is a case-insensitive substring match over the symbol and demangled names.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "filter": string_prop("Optional case-insensitive substring, e.g. 'JNI_OnLoad' or 'verify'"),
                "limit": int_prop("Maximum symbols to return (default 200, max 5000)"),
                "offset": int_prop("Skip this many matches, for paging through a long list")
            }), &["path"])
        },
        {
            "name": "disassemble",
            "description": "Disassemble machine code at a virtual address. The size is clamped to the enclosing function so output never runs into the next symbol.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address: 0x-prefixed hex or decimal (ARM Thumb low bit is accepted)"),
                "size": int_prop("Bytes to decode (default 128)"),
                "thumb": bool_prop("Force ARM Thumb decoding (auto-detected from the symbol otherwise)")
            }), &["path", "address"])
        },
        {
            "name": "decompile",
            "description": "Decompile the function containing an address to pseudo-C. style: structured (default, real if/while/switch), linear (per-block C), disassembly (annotated listing), flowchart (text graph).",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address inside the function"),
                "style": {
                    "type": "string",
                    "enum": ["structured", "linear", "disassembly", "flowchart"],
                    "description": "Output style (default structured)"
                }
            }), &["path", "address"])
        },
        {
            "name": "xrefs",
            "description": "Every instruction that references an address (calls, branches, literal loads), with the containing function name.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Target virtual address")
            }), &["path", "address"])
        },
        {
            "name": "call_hierarchy",
            "description": "Callers and callees of the function containing an address, with call counts.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address inside the function")
            }), &["path", "address"])
        },
        {
            "name": "security_scan",
            "description": "Protection and hardening scan: packers, root/emulator checks, anti-debug, integrity checks, exported JNI surface, dangerous permissions.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file")
            }), &["path"])
        },
        {
            "name": "entropy",
            "description": "Shannon entropy per section and the overall file, to spot packed or encrypted regions.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file")
            }), &["path"])
        },
        {
            "name": "strings",
            "description": "Extract printable strings with their virtual addresses. Filter is a case-insensitive substring match.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "filter": string_prop("Optional case-insensitive substring, e.g. 'http' or 'license'"),
                "min_length": int_prop("Minimum string length (default 4)"),
                "limit": int_prop("Maximum strings to return (default 200, max 5000)")
            }), &["path"])
        },
        {
            "name": "discover_functions",
            "description": "Recover functions the symbol table does not name (BL targets, .eh_frame FDEs, PLT imports, vtables, rodata string references). Read-only: nothing is added to the symbol table.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "max_scanned_bytes": int_prop("Cap on executable bytes decoded (default 32 MiB)"),
                "limit": int_prop("Maximum entries per list in the result (default 200)")
            }), &["path"])
        },
        {
            "name": "list_plugins",
            "description": "List the elftrace JSON plugins (rules-based detectors) available in a plugins directory, with id, name, severity coverage and whether each ships a Rhai script.",
            "inputSchema": object_schema(json!({
                "dir": string_prop("Plugins directory. Defaults to $ELFTRACE_PLUGINS_DIR, then app/src/main/assets/plugins")
            }), &[])
        },
        {
            "name": "run_plugin",
            "description": "Run one JSON plugin against an ELF and return its findings (rule name, address, severity, matched value). 'plugin' is a path to a .json manifest or the manifest JSON itself.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "plugin": string_prop("Plugin manifest: file path, or inline JSON starting with '{'")
            }), &["path", "plugin"])
        },
        {
            "name": "read_bytes",
            "description": "Hex dump of bytes at a virtual address (default 64, max 4096). Useful to inspect a patch site before writing an external patch.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address"),
                "length": int_prop("Bytes to read (default 64, max 4096)")
            }), &["path", "address"])
        },
        {
            "name": "binary_facts",
            "description": "Binary-level facts that the section tables do not show: DT_RUNPATH/DT_RPATH and the number of DT_INIT/INIT_ARRAY constructors.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file")
            }), &["path"])
        },
        {
            "name": "resolve_jni",
            "description": "Map a JNIEnv vtable byte offset (the displacement of an `ldr x9, [x9, #offset]` in a Java_* function) to the JNI method name, e.g. 0x2b8 -> FindClass.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "offset": address_prop("Byte offset into the JNIEnv vtable, as written in the load instruction")
            }), &["path", "offset"])
        },
        {
            "name": "rename_function",
            "description": "Give a function a readable name for the rest of this session. Changes names only in memory; no bytes are written. Later disassemble/decompile/xrefs calls use the new name.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address of the function"),
                "name": string_prop("New function name")
            }), &["path", "address", "name"])
        },
        {
            "name": "assemble",
            "description": "Assemble one AArch64/ARM instruction at an address and return its bytes without applying them. Use it to check syntax and encoding before calling patch.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address the instruction would be placed at"),
                "instruction": string_prop("Assembly text, e.g. 'mov w0, #0' or 'ret'")
            }), &["path", "address", "instruction"])
        },
        {
            "name": "patch",
            "description": "Write bytes into the loaded image and record an undo entry. Either 'kind' (nop, true, false, void) or 'bytes' (hex string). Nothing is written to disk until save. Rejects misaligned and non-executable targets.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "address": address_prop("Virtual address to patch"),
                "kind": string_prop("Quick patch: nop, true, false or void"),
                "bytes": string_prop("Raw replacement bytes as hex, e.g. '1f2003d5'")
            }), &["path", "address"])
        },
        {
            "name": "undo",
            "description": "Revert the most recent patches. Returns the addresses that were restored; use count to undo several at once.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "count": int_prop("How many patches to revert (default 1)")
            }), &["path"])
        },
        {
            "name": "save",
            "description": "Write the current, patched image to a new file. Never overwrites the input: the output path must differ from the source.",
            "inputSchema": object_schema(json!({
                "path": string_prop("Path to the ELF file"),
                "output": string_prop("Path to write the patched copy to")
            }), &["path", "output"])
        }
    ]);

    with_annotations(defs)
}

/// Attach MCP tool annotations so clients can label write tools before running
/// them instead of guessing from descriptions.
fn with_annotations(list: Value) -> Value {
    let Value::Array(tools) = list else {
        return list;
    };
    Value::Array(
        tools
            .into_iter()
            .map(|mut tool| {
                // `path` became optional once the app could report its open file.
                if let Some(required) = tool["inputSchema"]["required"].as_array_mut() {
                    required.retain(|name| name.as_str() != Some("path"));
                }
                let write = tool["name"]
                    .as_str()
                    .is_some_and(|name| WRITE_TOOLS.contains(&name));
                tool["annotations"] = if write {
                    json!({
                        "readOnlyHint": false,
                        "destructiveHint": true,
                        "idempotentHint": false,
                        "openWorldHint": false,
                    })
                } else {
                    json!({
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                    })
                };
                tool
            })
            .collect(),
    )
}

fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

fn string_prop(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn int_prop(description: &str) -> Value {
    json!({"type": "integer", "description": description})
}

/// Addresses arrive as either a JSON integer or a "0x..." string, and models do
/// both, so the schema allows the union and the parser accepts either.
fn address_prop(description: &str) -> Value {
    json!({"type": ["integer", "string"], "description": description})
}

fn bool_prop(description: &str) -> Value {
    json!({"type": "boolean", "description": description})
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

fn string_arg(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing required argument '{key}' (string)"))
}

fn optional_string(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

/// `path`, or the file the app has open when the call omits it. This is what
/// lets an agent work on "the binary on screen" without knowing where it lives.
fn file_arg(args: &Value) -> Result<String, String> {
    if let Some(path) = optional_string(args, "path").filter(|path| !path.trim().is_empty()) {
        if is_shared_storage_path(&path) {
            return Err(format!(
                "Android scoped storage denies this app every path under /storage ({}). \
                 Import the file instead: in ELFTrace open the MCP dialog and tap 'Import a file', \
                 then pass the path returned by list_imports.",
                path
            ));
        }
        return Ok(path);
    }
    current_file().ok_or_else(|| {
        "no 'path' given and ELFTrace has no file open; open a binary in the app or pass 'path'"
            .to_string()
    })
}

/// Shared-storage locations Android blocks from app-private code on API 33+;
/// a path here is always a permission error, so say so instead of letting the
/// OS return a bare EACCES.
fn is_shared_storage_path(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    lowered.starts_with("/storage/emulated")
        || lowered.starts_with("/sdcard")
        || lowered.starts_with("/mnt/media")
        || lowered.starts_with("/mnt/sdcard")
}

fn optional_bool(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// Accept 4096, "4096" or "0x1000".
fn optional_u64(args: &Value, key: &str, default: u64) -> Result<u64, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("'{key}' must be a non-negative integer")),
        Some(Value::String(s)) => parse_u64(s).map_err(|e| format!("'{key}': {e}")),
        Some(_) => Err(format!("'{key}' must be an integer")),
    }
}

fn optional_usize(args: &Value, key: &str, default: usize) -> Result<usize, String> {
    let value = optional_u64(args, key, default as u64)?;
    usize::try_from(value).map_err(|_| format!("'{key}' is too large"))
}

fn address_arg(args: &Value, key: &str) -> Result<u64, String> {
    match args.get(key) {
        None | Some(Value::Null) => Err(format!("missing required argument '{key}' (address)")),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("'{key}' must be a non-negative address")),
        Some(Value::String(s)) => parse_u64(s).map_err(|e| format!("'{key}': {e}")),
        Some(_) => Err(format!("'{key}' must be an address")),
    }
}

fn parse_u64(text: &str) -> Result<u64, String> {
    let trimmed = text.trim().replace('_', "");
    let result = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => trimmed.parse::<u64>(),
    };
    result.map_err(|_| format!("'{text}' is not a number (use 0x-prefixed hex or decimal)"))
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

fn call_tool(host: &mut Host, name: &str, args: &Value) -> Result<String, String> {
    match name {
        "current_file" => tool_current_file(host, args),
        "list_imports" => tool_list_imports(host, args),
        "elf_info" => tool_elf_info(host, args),
        "list_symbols" => tool_list_symbols(host, args),
        "disassemble" => tool_disassemble(host, args),
        "decompile" => tool_decompile(host, args),
        "xrefs" => tool_xrefs(host, args),
        "call_hierarchy" => tool_call_hierarchy(host, args),
        "security_scan" => tool_security_scan(host, args),
        "entropy" => tool_entropy(host, args),
        "strings" => tool_strings(host, args),
        "discover_functions" => tool_discover_functions(host, args),
        "list_plugins" => tool_list_plugins(args),
        "run_plugin" => tool_run_plugin(host, args),
        "read_bytes" => tool_read_bytes(host, args),
        "binary_facts" => tool_binary_facts(host, args),
        "resolve_jni" => tool_resolve_jni(host, args),
        "rename_function" => tool_rename_function(host, args),
        "assemble" => tool_assemble(host, args),
        "patch" => tool_patch(host, args),
        "undo" => tool_undo(host, args),
        "save" => tool_save(host, args),
        other => Err(format!("unknown tool: {other}")),
    }
}
fn tool_current_file(_host: &mut Host, _args: &Value) -> Result<String, String> {
    Ok(json!({
        "path": current_file(),
        "open": current_file().is_some(),
    })
    .to_string())
}

fn tool_list_imports(_host: &mut Host, _args: &Value) -> Result<String, String> {
    let Some(dir) = import_dir() else {
        return Ok(json!({ "files": [], "hint": IMPORT_HINT }).to_string());
    };
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|age| age.as_secs())
                .unwrap_or(0);
            files.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "path": entry.path().to_string_lossy(),
                "size": meta.len(),
                "modified_unix": modified,
            }));
        }
    }
    files.sort_by_key(|file| std::cmp::Reverse(file["modified_unix"].as_u64().unwrap_or(0)));
    let hint = if files.is_empty() {
        Some(IMPORT_HINT)
    } else {
        None
    };
    Ok(json!({ "dir": dir, "files": files, "hint": hint }).to_string())
}

const IMPORT_HINT: &str =
    "Nothing imported yet. In ELFTrace open the MCP dialog and tap 'Import a file', then call list_imports again.";

fn tool_binary_facts(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let ctx = host.context(&path)?;
    let facts = crate::scanner::build_binary_facts(ctx);
    serde_json::to_string(&facts).map_err(|e| e.to_string())
}

fn tool_resolve_jni(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let offset = address_arg(args, "offset")?;
    let ctx = host.context(&path)?;
    let is_64 = ctx.get_info().map(|info| info.is_64).unwrap_or(true);
    let width = if is_64 { 8 } else { 4 };
    Ok(json!({
        "offset": hex(offset),
        "index": offset / width,
        "method": crate::jni_resolver::resolve_jni_offset(offset, is_64),
    })
    .to_string())
}

fn tool_rename_function(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let name = string_arg(args, "name")?;
    let ctx = host.context_mut(&path)?;
    ctx.rename_function(address, &name);
    Ok(json!({"address": hex(address & !1), "name": name}).to_string())
}

fn tool_assemble(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let instruction = string_arg(args, "instruction")?;
    let ctx = host.context(&path)?;
    let bytes = crate::patcher::assemble_instruction(&instruction, address)?;
    let rendered: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(json!({
        "address": hex(address),
        "length": bytes.len(),
        "bytes": rendered.join(" "),
        "predictable": !ctx.raw.is_empty(),
    })
    .to_string())
}

fn tool_patch(host: &mut Host, args: &Value) -> Result<String, String> {
    use crate::patcher::QuickPatchType;

    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let kind = optional_string(args, "kind");
    let bytes = optional_string(args, "bytes");
    let ctx = host.context_mut(&path)?;

    let result = match (kind, bytes) {
        (Some(kind), None) => {
            let patch_type = match kind.to_ascii_lowercase().as_str() {
                "nop" => QuickPatchType::Nop,
                "true" => QuickPatchType::ReturnTrue,
                "false" => QuickPatchType::ReturnFalse,
                "void" => QuickPatchType::ReturnVoid,
                other => return Err(format!("unknown patch kind: {other}")),
            };
            let is_thumb = ctx
                .get_info()
                .map(|info| info.e_machine == 40)
                .unwrap_or(false);
            crate::patcher::apply_quick_patch(ctx, address, patch_type, is_thumb)
        }
        (None, Some(bytes)) => {
            let patch = crate::patcher::assemble_instruction(&bytes, address)?;
            let offset = ctx
                .vaddr_to_offset(address)
                .ok_or_else(|| format!("{} is not mapped in any program segment", hex(address)))?;
            let offset = usize::try_from(offset).map_err(|_| "file offset is too large")?;
            let end = (offset + patch.len()).min(ctx.raw.len());
            if end - offset != patch.len() {
                return Err("patch runs past the end of the file".to_string());
            }
            let original = ctx.raw[offset..end].to_vec();
            ctx.patch_bytes(address, &patch)?;
            ctx.push_undo(address, original.clone());
            crate::patcher::PatchResult {
                address,
                original_bytes: original,
                patched_bytes: patch,
                patch_type: "bytes".to_string(),
                success: true,
                error: None,
            }
        }
        _ => return Err("give exactly one of kind or bytes".to_string()),
    };

    if !result.success {
        return Err(result.error.unwrap_or_else(|| "patch failed".to_string()));
    }
    let original: Vec<String> = result
        .original_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let patched: Vec<String> = result
        .patched_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(json!({
        "address": hex(result.address),
        "kind": result.patch_type,
        "original": original.join(" "),
        "patched": patched.join(" "),
        "undo_entries": ctx.undo_len(),
    })
    .to_string())
}

fn tool_undo(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let count = optional_usize(args, "count", 1)?.clamp(1, 256);
    let ctx = host.context_mut(&path)?;
    let mut restored = Vec::new();
    for _ in 0..count {
        match ctx.undo_last() {
            Some(address) => restored.push(hex(address)),
            None => break,
        }
    }
    Ok(json!({
        "restored": restored,
        "remaining": ctx.undo_len(),
    })
    .to_string())
}

fn tool_save(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let output = string_arg(args, "output")?;
    let ctx = host.context(&path)?;
    let same = match (std::fs::canonicalize(&path), std::fs::canonicalize(&output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => path == output,
    };
    if same {
        return Err("refusing to overwrite the input file; choose another output path".to_string());
    }
    std::fs::write(&output, &ctx.raw[..]).map_err(|e| format!("cannot write {output}: {e}"))?;
    Ok(json!({"output": output, "bytes": ctx.raw.len()}).to_string())
}

fn tool_elf_info(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let ctx = host.context(&path)?;
    let info = ctx.get_info()?;
    let segments: Vec<Value> = info
        .segments
        .iter()
        .map(|s| {
            json!({
                "type": s.p_type,
                "flags": s.flags,
                "vaddr": hex(s.vaddr),
                "offset": hex(s.offset),
                "filesz": s.filesz,
                "memsz": s.memsz,
            })
        })
        .collect();
    let sections: Vec<Value> = info
        .sections
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "type": s.sh_type,
                "flags": s.flags,
                "vaddr": hex(s.vaddr),
                "offset": hex(s.offset),
                "size": s.size,
            })
        })
        .collect();
    Ok(json!({
        "path": ctx.path,
        "e_machine": info.e_machine,
        "arch": arch_name(info.e_machine),
        "is_64": info.is_64,
        "entry": hex(info.entry),
        "soname": info.soname,
        "interpreter": info.interpreter,
        "libraries": info.libraries,
        "symbol_count": info.syms.len(),
        "segment_count": segments.len(),
        "segments": segments,
        "sections": sections,
    })
    .to_string())
}

fn arch_name(e_machine: u32) -> &'static str {
    match e_machine {
        40 => "arm",
        183 => "aarch64",
        3 => "x86",
        62 => "x86_64",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        243 => "riscv",
        _ => "unknown",
    }
}

fn tool_list_symbols(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let filter = optional_string(args, "filter").map(|f| f.to_lowercase());
    let limit = optional_usize(args, "limit", 200)?.min(5000);
    let offset = optional_usize(args, "offset", 0)?;
    let ctx = host.context(&path)?;
    let info = ctx.get_info()?;

    let mut matched = 0usize;
    let mut symbols = Vec::new();
    for sym in &info.syms {
        if let Some(needle) = &filter {
            if !symbol_matches(sym, needle) {
                continue;
            }
        }
        matched += 1;
        if matched <= offset || symbols.len() >= limit {
            continue;
        }
        symbols.push(json!({
            "name": sym.sym,
            "demangled": sym.demangled,
            "address": hex(sym.value),
            "size": sym.size,
            "thumb": sym.thumb,
            "jni_class": sym.jni_class,
            "jni_method": sym.jni_method,
        }));
    }
    Ok(json!({
        "total_matched": matched,
        "offset": offset,
        "returned": symbols.len(),
        "symbols": symbols,
    })
    .to_string())
}

fn symbol_matches(sym: &SymsDTO, needle: &str) -> bool {
    sym.sym.to_lowercase().contains(needle)
        || sym
            .demangled
            .as_ref()
            .is_some_and(|d| d.to_lowercase().contains(needle))
}

/// Mirrors the JNI disassembly path (jni_bridge.rs `handle_disasm`): the same
/// address normalization, function clamping and symbol/string resolution, so an
/// agent sees byte-identical output to the app.
fn disassemble_at(
    ctx: &ElfContext,
    address: u64,
    size: u64,
    thumb: bool,
) -> Result<CodeIns, String> {
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    let vaddr = if e_machine == 40 {
        address & !1
    } else {
        address
    };
    let offset = ctx
        .vaddr_to_offset(vaddr)
        .ok_or_else(|| format!("{} is not mapped in any program segment", hex(vaddr)))?;
    let offset = usize::try_from(offset).map_err(|_| "file offset is too large")?;
    if offset >= ctx.raw.len() {
        return Err(format!("{} points past the end of the file", hex(vaddr)));
    }
    let code_slice = &ctx.raw[offset..];
    let fn_range = crate::decompiler::find_function_range(ctx, vaddr);
    let is_thumb = if e_machine == 40 {
        thumb || (address & 1) != 0 || fn_range.thumb
    } else {
        false
    };
    let max_available = (ctx.raw.len() - offset) as u64;
    let requested = if size > 0 { size } else { 256 };
    let fn_remaining = if fn_range.size > 0 {
        fn_range
            .start
            .saturating_add(fn_range.size)
            .saturating_sub(vaddr)
            .max(4)
    } else {
        requested
    };
    let clamped = requested.min(fn_remaining).min(max_available);
    let is_jni = ctx.syms_map.get(&vaddr).is_some_and(|s| {
        s.sym.starts_with("Java_") || s.sym == "JNI_OnLoad" || s.jni_method.is_some()
    });
    let resolver = |v: u64| {
        if let Some(sym) = ctx.syms_map.get(&v) {
            return Some(sym.demangled.clone().unwrap_or_else(|| sym.sym.clone()));
        }
        ctx.get_string_at_vaddr(v)
            .map(|s| crate::decompiler::c_string_literal(&s))
    };
    crate::disasm::disassemble_with_resolver(
        code_slice,
        vaddr,
        clamped,
        e_machine,
        is_thumb,
        Some(&resolver),
        is_jni,
    )
}

fn tool_disassemble(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let size = optional_u64(args, "size", 128)?;
    let thumb = optional_bool(args, "thumb", false);
    let ctx = host.context(&path)?;
    let code = disassemble_at(ctx, address, size, thumb)?;
    let instructions: Vec<Value> = code
        .data
        .iter()
        .map(|i| {
            json!({
                "address": hex(i.address),
                "bytes": i.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "comment": i.comment,
            })
        })
        .collect();
    Ok(json!({
        "address": hex(address),
        "count": instructions.len(),
        "instructions": instructions,
    })
    .to_string())
}

fn tool_decompile(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let style = optional_string(args, "style").unwrap_or_else(|| "structured".to_string());
    let ctx = host.context(&path)?;
    let text = match style.as_str() {
        "structured" | "c" => crate::decompiler::decompile_to_c_structured(ctx, address),
        "linear" => crate::decompiler::decompile_to_c(ctx, address),
        "disassembly" | "asm" => crate::decompiler::generate_disassembly_text(ctx, address),
        "flowchart" => crate::decompiler::generate_flowchart_text(ctx, address),
        other => {
            return Err(format!(
                "unknown style '{other}': use structured, linear, disassembly or flowchart"
            ))
        }
    };
    let range = crate::decompiler::find_function_range(ctx, address);
    Ok(format!(
        "// {} @ {} (size {})\n{}",
        range.name,
        hex(range.start),
        range.size,
        text
    ))
}

fn tool_xrefs(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let ctx = host.context(&path)?;
    let refs: Vec<Value> = crate::xref::find_callers_to(ctx, address)
        .iter()
        .map(xref_json)
        .collect();
    Ok(json!({
        "target_address": hex(address),
        "count": refs.len(),
        "refs": refs,
    })
    .to_string())
}

fn xref_json(item: &crate::xref::XRefItem) -> Value {
    json!({
        "from": hex(item.from_address),
        "to": hex(item.to_address),
        "kind": item.kind,
        "instruction": item.instruction,
        "caller_function": item.caller_func,
    })
}

fn tool_call_hierarchy(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let ctx = host.context(&path)?;
    let hierarchy = crate::xref::get_hierarchy(ctx, address);
    let callers: Vec<Value> = hierarchy.callers.iter().map(xref_json).collect();
    let callees: Vec<Value> = hierarchy
        .callees
        .iter()
        .map(|c| {
            json!({
                "name": c.target_name,
                "address": hex(c.target_address),
                "instruction": c.instruction,
                "call_count": c.call_count,
            })
        })
        .collect();
    Ok(json!({
        "function_name": hierarchy.function_name,
        "function_address": hex(hierarchy.function_address),
        "callers": callers,
        "callees": callees,
    })
    .to_string())
}

fn tool_security_scan(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let ctx = host.context(&path)?;
    serde_json::to_string(&crate::scanner::scan_security(ctx))
        .map_err(|e| format!("could not serialize the scan report: {e}"))
}

fn tool_entropy(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let ctx = host.context(&path)?;
    serde_json::to_string(&crate::scanner::calculate_entropy_report(ctx))
        .map_err(|e| format!("could not serialize the entropy report: {e}"))
}

fn tool_strings(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let filter = optional_string(args, "filter").map(|f| f.to_lowercase());
    let min_length = optional_usize(args, "min_length", 4)?;
    let limit = optional_usize(args, "limit", 200)?.min(5000);
    let ctx = host.context(&path)?;
    let data = ctx.extract_strings()?;

    let mut matched = 0usize;
    let mut strings = Vec::new();
    for item in &data.data {
        if item.string.chars().count() < min_length {
            continue;
        }
        if let Some(needle) = &filter {
            if !item.string.to_lowercase().contains(needle) {
                continue;
            }
        }
        matched += 1;
        if strings.len() >= limit {
            continue;
        }
        strings.push(json!({
            "address": hex(item.vaddr),
            "offset": hex(item.paddr),
            "size": item.size,
            "string": item.string,
        }));
    }
    Ok(json!({
        "total_matched": matched,
        "returned": strings.len(),
        "strings": strings,
    })
    .to_string())
}

fn tool_discover_functions(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let max_scanned = optional_u64(
        args,
        "max_scanned_bytes",
        crate::discovery::MAX_SCANNED_BYTES,
    )?;
    let limit = optional_usize(args, "limit", 200)?.min(5000);
    let ctx = host.context(&path)?;
    let report = crate::discovery::discover(ctx, max_scanned);
    let functions: Vec<Value> = report
        .functions
        .iter()
        .take(limit)
        .map(|f| {
            json!({
                "name": f.name,
                "address": hex(f.address),
                "size": f.size,
                "thumb": f.thumb,
            })
        })
        .collect();
    let imports: Vec<Value> = report
        .plt_imports
        .iter()
        .take(limit)
        .map(|(address, name)| json!({"stub": hex(*address), "name": name}))
        .collect();
    let vtables: Vec<Value> = report
        .vtables
        .iter()
        .take(limit)
        .map(|(address, name)| json!({"address": hex(*address), "class": name}))
        .collect();
    Ok(json!({
        "added": report.added,
        "known": report.known,
        "scanned_bytes": report.scanned_bytes,
        "truncated": report.truncated,
        "function_count": report.functions.len(),
        "fde_count": report.fde_sizes.len(),
        "string_ref_count": report.string_refs.len(),
        "functions": functions,
        "plt_imports": imports,
        "vtables": vtables,
    })
    .to_string())
}

fn tool_list_plugins(args: &Value) -> Result<String, String> {
    let dir = match optional_string(args, "dir") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => default_plugins_dir()?,
    };
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("cannot read plugins directory {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort();

    let mut plugins = Vec::new();
    for path in &entries {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<crate::plugins::PluginManifest>(&text) {
                Ok(manifest) => plugins.push(json!({
                    "id": manifest.id,
                    "name": manifest.name,
                    "version": manifest.version,
                    "description": manifest.description,
                    "rule_count": manifest.rules.len(),
                    "has_script": manifest.script.is_some(),
                    "file": path.display().to_string(),
                })),
                Err(e) => plugins.push(json!({
                    "file": path.display().to_string(),
                    "error": e.to_string(),
                })),
            },
            Err(e) => plugins.push(json!({
                "file": path.display().to_string(),
                "error": e.to_string(),
            })),
        }
    }
    Ok(json!({
        "dir": dir.display().to_string(),
        "count": entries.len(),
        "plugins": plugins,
    })
    .to_string())
}

/// The manifests ship as Android assets, so the server looks for the app tree
/// when no explicit directory is given.
fn default_plugins_dir() -> Result<std::path::PathBuf, String> {
    if let Ok(dir) = std::env::var("ELFTRACE_PLUGINS_DIR") {
        return Ok(std::path::PathBuf::from(dir));
    }
    const CANDIDATES: [&str; 4] = [
        "app/src/main/assets/plugins",
        "../app/src/main/assets/plugins",
        "assets/plugins",
        "plugins",
    ];
    CANDIDATES
        .iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_dir())
        .ok_or_else(|| {
            "no plugins directory found; pass 'dir' or set ELFTRACE_PLUGINS_DIR".to_string()
        })
}

fn tool_run_plugin(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let plugin = string_arg(args, "plugin")?;
    let manifest = if plugin.trim_start().starts_with('{') {
        plugin
    } else {
        std::fs::read_to_string(&plugin)
            .map_err(|e| format!("cannot read plugin '{plugin}': {e}"))?
    };
    let ctx = host.context(&path)?;
    Ok(crate::plugins::run_plugin_json(ctx, &manifest))
}

fn tool_read_bytes(host: &mut Host, args: &Value) -> Result<String, String> {
    let path = file_arg(args)?;
    let address = address_arg(args, "address")?;
    let length = optional_usize(args, "length", 64)?.min(4096);
    let ctx = host.context(&path)?;
    let mapped = ctx
        .vaddr_to_offset(address)
        .ok_or_else(|| format!("{} is not mapped in any program segment", hex(address)))?;
    let offset = usize::try_from(mapped).map_err(|_| "file offset is too large")?;
    let end = offset.saturating_add(length).min(ctx.raw.len());
    let bytes = &ctx.raw[offset..end];
    let hex_bytes: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let ascii: String = bytes
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    Ok(json!({
        "address": hex(address),
        "file_offset": hex(offset as u64),
        "length": bytes.len(),
        "hex": hex_bytes.join(" "),
        "ascii": ascii,
    })
    .to_string())
}

// ---------------------------------------------------------------------------
// stdio transport
// ---------------------------------------------------------------------------

/// Serve MCP on stdin/stdout: one JSON-RPC message per line, one response line
/// per request. This is the transport desktop clients launch the binary with.
pub fn serve_stdio() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    // One buffered reader for the whole session: a reader rebuilt per line would
    // read ahead and then discard the following requests that shared the read.
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut host = Host::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Ok(());
        }
        if let Some(response) = handle_message(&mut host, &line) {
            let mut out = stdout.lock();
            out.write_all(response.as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()?;
        }
    }
}

// ---------------------------------------------------------------------------
// Streamable HTTP transport
// ---------------------------------------------------------------------------

/// Port the in-app server listens on. Deliberately not 8989: that port is what
/// the desktop `--http` default used to be, and the phone should not collide
/// with a local dev server on the same network.
pub const DEFAULT_HTTP_PORT: u16 = 8765;

/// Serve MCP over Streamable HTTP at `http://<addr>/mcp`.
///
/// Stateless: no `Mcp-Session-Id` is issued or required, and each POST is
/// handled on its own. Without a token this must stay bound to loopback; the
/// in-app server always passes one and may listen on the LAN.
pub fn serve_http(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    eprintln!("elftrace-mcp: listening on http://{bound}/mcp");
    serve_http_listener(listener)
}

/// Accept loop split out from [`serve_http`] so tests can bind port 0 and keep
/// the listener that was actually bound.
pub fn serve_http_listener(listener: TcpListener) -> std::io::Result<()> {
    serve_listener(listener, None, None)
}

/// Shared accept loop. `token` turns on bearer auth; `stop` switches the
/// listener to non-blocking and makes the loop exit once the flag is set, which
/// is how the in-app toggle shuts the server down.
fn serve_listener(
    listener: TcpListener,
    token: Option<Arc<String>>,
    stop: Option<Arc<AtomicBool>>,
) -> std::io::Result<()> {
    if stop.is_some() {
        listener.set_nonblocking(true)?;
    }
    let host = Arc::new(Mutex::new(Host::new()));
    loop {
        if let Some(stop) = &stop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                stream
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(_) => continue,
        };
        let host = Arc::clone(&host);
        let token = token.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(
                stream,
                &host,
                token.as_ref().map(|t| t.as_str()),
                stop.as_deref(),
            ) {
                eprintln!("elftrace-mcp: connection error: {e}");
            }
        });
    }
}

struct RunningServer {
    url: String,
    stop: Arc<AtomicBool>,
}

static RUNNING: Mutex<Option<RunningServer>> = Mutex::new(None);

/// The file the app currently has open. Tools then work without a `path`, which
/// is how an agent asks about "the binary on screen" instead of guessing where
/// the app put it.
static CURRENT_FILE: Mutex<Option<String>> = Mutex::new(None);

/// Record (or clear, with `None`) the file the app has open.
pub fn set_current_file(path: Option<String>) {
    let mut current = match CURRENT_FILE.lock() {
        Ok(current) => current,
        Err(poisoned) => poisoned.into_inner(),
    };
    *current = path.filter(|path| !path.trim().is_empty());
}

/// Path of the file the app has open, if any.
pub fn current_file() -> Option<String> {
    match CURRENT_FILE.lock() {
        Ok(current) => current.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Directory inside app storage where the user's "Import a file" picks land.
/// Android scoped storage keeps the server out of `/storage/emulated/0`, so
/// this is how an agent reaches a file the app has not opened.
static IMPORT_DIR: Mutex<Option<String>> = Mutex::new(None);

/// Record (or clear, with `None`) the import directory.
pub fn set_import_dir(dir: Option<String>) {
    let mut current = match IMPORT_DIR.lock() {
        Ok(current) => current,
        Err(poisoned) => poisoned.into_inner(),
    };
    *current = dir.filter(|dir| !dir.trim().is_empty());
}

/// The import directory, if the app registered one.
pub fn import_dir() -> Option<String> {
    match IMPORT_DIR.lock() {
        Ok(current) => current.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Start the in-app HTTP server on `addr` and return the client URL
/// (`http://<bound>/mcp`).
///
/// `token` is required: once the server listens beyond loopback, every request
/// must present it as `Authorization: Bearer <token>`, as the bare token in
/// `Authorization`, or as `X-MCP-Token`.
/// Starting while already running stops the previous instance first.
pub fn start_server(addr: &str, token: &str) -> Result<String, String> {
    if token.is_empty() {
        return Err("an access token is required".to_string());
    }
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    let url = format!("http://{bound}/mcp");

    stop_server();

    let stop = Arc::new(AtomicBool::new(false));
    let token = Arc::new(token.to_string());
    let thread_token = Arc::clone(&token);
    let thread_stop = Arc::clone(&stop);
    std::thread::spawn(move || {
        if let Err(e) = serve_listener(listener, Some(thread_token), Some(thread_stop)) {
            eprintln!("elftrace-mcp: server stopped: {e}");
        }
    });

    let mut running = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
    *running = Some(RunningServer {
        url: url.clone(),
        stop,
    });
    Ok(url)
}

/// Stop the in-app server if it is running. Returns whether one was running.
pub fn stop_server() -> bool {
    let mut running = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
    match running.take() {
        Some(server) => {
            server.stop.store(true, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

/// URL of the running in-app server, or `None`.
pub fn running_url() -> Option<String> {
    RUNNING
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(|server| server.url.clone())
}

struct HttpRequest {
    method: String,
    path: String,
    /// Everything after `?` in the request target, without the `?`.
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// `?token=`/`?key=`/`?access_token=` in the URL. Some clients drop their
    /// configured headers on the first request, and a bare 401 sends them into
    /// an OAuth flow this server does not have.
    fn query_token(&self) -> Option<&str> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            match key {
                "token" | "key" | "access_token" if !value.is_empty() => Some(value),
                _ => None,
            }
        })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    host: &Arc<Mutex<Host>>,
    token: Option<&str>,
    stop: Option<&AtomicBool>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let request = match read_http_request(&mut stream)? {
        Some(request) => request,
        None => return Ok(()),
    };

    // Token auth before anything else: the in-app server may listen on Wi-Fi,
    // where every neighbour could otherwise read the user's binaries.
    if let Some(expected) = token {
        if !request_has_token(&request, expected) {
            return write_response(&mut stream, 401, "missing or invalid access token");
        }
    }

    // DNS-rebinding guard from the MCP spec: a browser-originated request from a
    // foreign origin must not reach this server. Loopback and private LAN
    // origins are allowed; the token is the actual gate.
    if let Some(origin) = request.header("origin") {
        if !origin_is_local(origin) {
            return write_response(&mut stream, 403, "origin not allowed");
        }
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/mcp") | ("POST", "/") => {
            let response = {
                let mut host = host.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                handle_message(&mut host, &request.body)
            };
            match response {
                Some(text) => write_response(&mut stream, 200, &text),
                None => write_response(&mut stream, 202, ""),
            }
        }
        // The spec's other GET branch: hold the connection open as a server-sent
        // event stream. Clients probe GET before POST and treat 405 as "no
        // connection", so an idle stream is what keeps them talking to us.
        ("GET", "/mcp") | ("GET", "/") => serve_sse_stream(&mut stream, stop),
        ("DELETE", "/mcp") => write_response(&mut stream, 204, ""),
        ("OPTIONS", _) => write_response(&mut stream, 204, ""),
        _ => write_response(&mut stream, 404, "not found"),
    }
}

/// Accepts `Authorization: Bearer <token>`, the bare token in `Authorization`
/// (clients whose header field is filled in by hand), and `X-MCP-Token`.
fn request_has_token(request: &HttpRequest, expected: &str) -> bool {
    let presented = request
        .header("authorization")
        .map(|value| {
            let value = value.trim();
            match value.len() >= 7 && value[..7].eq_ignore_ascii_case("bearer ") {
                true => value[7..].trim(),
                false => value,
            }
        })
        .or_else(|| request.header("x-mcp-token"))
        .or_else(|| request.query_token())
        .unwrap_or_default()
        .trim();
    // Length-independent comparison so a wrong token leaks no timing signal.
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn origin_is_local(origin: &str) -> bool {
    let host = origin
        .split("://")
        .nth(1)
        .unwrap_or(origin)
        .trim_end_matches('/');
    let host = match host.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.split(':').next().unwrap_or(host),
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") {
        return true;
    }
    // Private LAN ranges: the phone's own Wi-Fi clients (a browser on the same
    // network) send their address as the origin.
    let octets: Vec<u8> = host
        .split('.')
        .filter_map(|part| part.parse::<u8>().ok())
        .collect();
    matches!(
        octets.as_slice(),
        [10, ..] | [192, 168, ..] | [172, 16..=31, ..]
    )
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Option<HttpRequest>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buffer) {
            break pos;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HTTP_BODY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = path.to_string();
    let query = query.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    let content_length = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_HTTP_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(Some(HttpRequest {
        method,
        path,
        query,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Holds the connection open as a `text/event-stream`, which is what the MCP
/// spec expects for server-initiated messages. Nothing is queued on it yet, so
/// it carries keep-alive comments only; the point is that a client probing GET
/// sees a live stream instead of a 405.
fn serve_sse_stream(stream: &mut TcpStream, stop: Option<&AtomicBool>) -> std::io::Result<()> {
    let header = "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\r\n";
    stream.write_all(header.as_bytes())?;
    stream.write_all(b": stream open\n\n")?;
    stream.flush()?;
    loop {
        if let Some(stop) = stop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(2));
        if stream
            .write_all(b": keep-alive\n\n")
            .and_then(|_| stream.flush())
            .is_err()
        {
            return Ok(());
        }
    }
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: content-type, authorization, x-mcp-token, mcp-session-id, mcp-protocol-version\r\n\
         Access-Control-Expose-Headers: mcp-session-id\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses_in_every_shape_a_model_sends() {
        assert_eq!(parse_u64("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_u64("4096").unwrap(), 4096);
        assert_eq!(parse_u64("0x1_000").unwrap(), 0x1000);
        assert!(parse_u64("not-a-number").is_err());
    }

    #[test]
    fn address_argument_accepts_integer_and_string() {
        let args = json!({"address": 4096});
        assert_eq!(address_arg(&args, "address").unwrap(), 4096);
        let args = json!({"address": "0x1000"});
        assert_eq!(address_arg(&args, "address").unwrap(), 0x1000);
        assert!(address_arg(&json!({}), "address").is_err());
    }

    #[test]
    fn accepts_the_token_with_and_without_the_bearer_prefix() {
        let request = |authorization: &str| HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            query: String::new(),
            headers: vec![("Authorization".into(), authorization.into())],
            body: String::new(),
        };
        assert!(request_has_token(&request("Bearer s3cret"), "s3cret"));
        assert!(request_has_token(&request("bearer s3cret"), "s3cret"));
        // Clients with a hand-typed header field send the bare token.
        assert!(request_has_token(&request("s3cret"), "s3cret"));
        assert!(!request_has_token(&request("Bearer wrong"), "s3cret"));
        assert!(!request_has_token(&request(""), "s3cret"));
        // A token in the URL survives clients that drop their custom headers.
        let in_url = HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            query: "client=app&token=s3cret".into(),
            headers: Vec::new(),
            body: String::new(),
        };
        assert!(request_has_token(&in_url, "s3cret"));
        assert_eq!(
            HttpRequest {
                query: String::new(),
                ..in_url
            }
            .query_token(),
            None
        );
    }

    #[test]
    fn truncates_at_a_char_boundary() {
        let text = "a".repeat(MAX_RESULT_CHARS + 10);
        let cut = truncate_result(&text);
        assert!(cut.len() > MAX_RESULT_CHARS);
        assert!(cut.contains("[truncated:"));
    }

    #[test]
    fn local_and_lan_origins() {
        assert!(origin_is_local("http://localhost:3000"));
        assert!(origin_is_local("http://127.0.0.1"));
        assert!(origin_is_local("http://[::1]:8989"));
        assert!(origin_is_local("http://192.168.1.42:8765"));
        assert!(origin_is_local("http://10.0.0.7"));
        assert!(origin_is_local("http://172.16.5.4:3000"));
        assert!(!origin_is_local("http://172.32.5.4"));
        assert!(!origin_is_local("https://evil.example"));
    }
}
