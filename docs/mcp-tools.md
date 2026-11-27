# MCP tools

Served by the in-app server on `http://<ip>:8765/mcp` and by the standalone
`elftrace-mcp` binary (stdio, or `--http 127.0.0.1:<port>`). Every tool takes a
`path` argument: the ELF is parsed once per path and cached, so repeated calls
on the same file are cheap.

`tools/list` marks write tools with `"readOnlyHint": false`; everything else is
read-only. Nothing is written to disk unless you call `save`.

## Read-only

| Tool | Arguments | Returns |
| --- | --- | --- |
| `elf_info` | — | Header, machine, soname, `DT_NEEDED`, segments, sections, symbol count |
| `list_symbols` | `filter`, `limit` | Function symbols with addresses |
| `disassemble` | `address`, `count`, `symbol` | Instructions with symbol and string resolution |
| `decompile` | `address` or `symbol`, `format` | `c` (default), `structured`, `linear`, `flowchart`, `disassembly` |
| `xrefs` | `address` | Every instruction referencing the address |
| `call_hierarchy` | `address` / `symbol` | Callers and callees |
| `security_scan` | — | Protection and packer findings |
| `entropy` | — | Section entropy |
| `strings` | `limit`, `min_length` | Extracted strings |
| `discover_functions` | — | Functions recovered from code, not symbols |
| `list_plugins` | — | Shipped JSON plugin manifests |
| `run_plugin` | `plugin` | Findings from one plugin |
| `read_bytes` | `address`, `length` | Hex dump (default 64, max 4096) |
| `binary_facts` | — | `DT_RUNPATH`/`DT_RPATH`, constructor count |
| `resolve_jni` | `offset` | JNIEnv method name and vtable index for a load displacement |
| `rename_function` | `address`, `name` | Renames in the session only, no bytes written |
| `assemble` | `address`, `instruction` | Encoded bytes, nothing applied |

## Write

| Tool | Arguments | Effect |
| --- | --- | --- |
| `patch` | `address` + `kind` (`nop`, `true`, `false`, `void`) or `bytes` (hex) | Writes into the loaded image, records an undo entry |
| `undo` | `count` (default 1) | Restores the most recent patches, returns the addresses |
| `save` | `output` | Writes the patched copy; refuses to overwrite the input |

`patch` and `undo` change memory only. The client sees the result through later
`disassemble`/`read_bytes` calls; `save` is the only step that touches the disk.

## Deliberately absent

`assemble` never applies its bytes, and there is no tool that launches the
analysed binary. Anything that executes or publishes code stays out of the MCP
surface.
