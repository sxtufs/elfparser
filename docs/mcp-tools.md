# MCP tools

Served by the in-app server on `http://<ip>:8765/mcp` and by the standalone
`elftrace-mcp` binary (stdio, or `--http 127.0.0.1:<port>`). Every tool takes an
optional `path` argument: with no `path`, the tool works on the file the app has
open (reported by `current_file`). The ELF is parsed once per path and cached,
so repeated calls on the same file are cheap.

Android note: paths under `/storage/emulated/0` are refused with instructions —
scoped storage keeps app-private code out. Use the app's MCP dialog
"Import a file" pick (it copies into app storage and becomes the current file),
then `list_imports` to see what is available.

`tools/list` marks write tools with `"readOnlyHint": false`; everything else is
read-only. Nothing is written to disk unless you call `save`.

## Read-only

| Tool | Arguments | Returns |
| --- | --- | --- |
| `current_file` | — | Path of the file the app has open, if any |
| `list_imports` | — | Files imported through the app's MCP dialog, newest first |
| `elf_info` | `path`? | Header, machine, soname, `DT_NEEDED`, segments, sections, symbol count |
| `list_symbols` | `path`?, `filter`, `limit` | Function symbols with addresses |
| `disassemble` | `path`?, `address`, `count`, `symbol` | Instructions with symbol and string resolution |
| `decompile` | `path`?, `address` or `symbol`, `format` | `c` (default), `structured`, `linear`, `flowchart`, `disassembly` |
| `xrefs` | `path`?, `address` | Every instruction referencing the address |
| `call_hierarchy` | `path`?, `address` / `symbol` | Callers and callees |
| `security_scan` | `path`? | Protection and packer findings |
| `entropy` | `path`? | Section entropy |
| `strings` | `path`?, `limit`, `min_length` | Extracted strings |
| `discover_functions` | `path`? | Functions recovered from code, not symbols |
| `list_plugins` | — | Shipped JSON plugin manifests |
| `run_plugin` | `path`?, `plugin` | Findings from one plugin |
| `read_bytes` | `path`?, `address`, `length` | Hex dump (default 64, max 4096) |
| `binary_facts` | `path`? | `DT_RUNPATH`/`DT_RPATH`, constructor count |
| `resolve_jni` | `path`?, `offset` | JNIEnv method name and vtable index for a load displacement |
| `rename_function` | `path`?, `address`, `name` | Renames in the session only, no bytes written |
| `assemble` | `path`?, `address`, `instruction` | Encoded bytes, nothing applied |

## Write

| Tool | Arguments | Effect |
| --- | --- | --- |
| `patch` | `path`?, `address` + `kind` (`nop`, `true`, `false`, `void`) or `bytes` (hex) | Writes into the loaded image, records an undo entry |
| `undo` | `count` (default 1) | Restores the most recent patches, returns the addresses |
| `save` | `path`?, `output` | Writes the patched copy; refuses to overwrite the input |

`patch` and `undo` change memory only. The client sees the result through later
`disassemble`/`read_bytes` calls; `save` is the only step that touches the disk.

## Deliberately absent

`assemble` never applies its bytes, and there is no tool that launches the
analysed binary. Anything that executes or publishes code stays out of the MCP
surface.
