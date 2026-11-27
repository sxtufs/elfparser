# Decisions

## 2026-11-27 — MCP endpoint answers real clients: GET stream, bare token, Wi-Fi-only address
An Android MCP client on the same phone could not connect even on one device.
Three server-side causes, each fixed and pinned by a test:
- GET `/mcp` no longer returns 405. It holds the connection open as a
  `text/event-stream` (the spec's server-initiated branch) with 2 s keep-alive
  comments and closes when the stop flag flips. Clients probe GET before POST
  and read 405 as "unreachable"; the stream carries no messages yet.
- `request_has_token` accepts `Authorization: Bearer <t>`, the bare token in
  `Authorization:` (clients' header fields are typed by hand) and `X-MCP-Token`.
  CORS preflight now allows `authorization` and `x-mcp-token`.
- `McpServer.lanAddress()` ranks wlan/ap/eth/rndis first and skips cellular
  (`rmnet*`, `ccmni*`, `pdp*`, `clat*`): carrier-grade NAT hands out 10.x
  addresses that are site-local but unreachable from another device, and the old
  first-match code could hand the dialog the cellular one. The dialog now shows
  `127.0.0.1` for a client on this phone and the Wi-Fi URL for another device.
- CI: `setup-ndk` only exports `ndk-path`/PATH, so cargo-ndk used the runner's
  preinstalled r27. The build step now sets `ANDROID_NDK_HOME`/`ANDROID_NDK_ROOT`
  and the verify step fails unless `.note.android.ident` contains `72 33 30 00`
  ("r30" as hex — readelf prints that note in hex, not as a quoted string).
- Tests: `mcp_tests::get_on_mcp_opens_a_server_sent_event_stream`,
  `mcp::tests::accepts_the_token_with_and_without_the_bearer_prefix`,
  `McpServerAddressTest`.

## 2026-11-27 — In-app MCP toggle: token-gated HTTP on 8765, desktop CI job removed
The MCP engine is now switchable from the phone itself, MT-Manager style:
- `mcp::start_server(addr, token)` / `stop_server()` / `running_url()` in
  `elftrace-core/src/mcp.rs` run the accept loop on its own thread; the loop
  polls an `AtomicBool` (non-blocking listener, 50 ms) so Stop closes the socket.
- `serve_listener` takes `Option<token>`: every request must send
  `Authorization: Bearer <token>` or `X-MCP-Token`, compared length-independently.
  The origin guard also accepts RFC1918 LAN origins (10/8, 192.168/16,
  172.16/12) because the token, not the origin, is the gate once bound to Wi-Fi.
- JNI: `JNIBridge.startMcp0/stopMcp0/mcpStatus0`; Kotlin `McpServerService`
  (foreground, `dataSync`, Stop action) keeps it alive, `McpServer` object holds
  the persisted random token, port and LAN URL.
- Default port is **8765** (was 8989) for both the desktop `--http` default and
  the app, to avoid colliding with a local dev server on the same network.
- The GitHub Actions `mcp` job (ubuntu/macos/windows binary builds) was removed:
  the product shape is the phone toggle, not desktop side binaries.
- Tests: `mcp_tests::in_app_server_requires_the_token_and_stops_on_request`
  covers 401 without/with a wrong token, 200 with the token from a LAN origin,
  listener closure after stop, and refusal to start with an empty token.

## 2026-11-27 — MCP server: separate read-only binary, stdio first, HTTP opt-in
`elftrace-core/src/mcp.rs` + `src/bin/elftrace-mcp.rs` expose the analysis
engine to MCP clients (Claude Desktop, Cursor, Claude Code). It is a normal
binary built from the same crate as the `.so` (`crate-type = ["cdylib", "rlib"]`
already allowed this); the Android app is unchanged and dead-code-strips the
module.
- Default transport is stdio (client spawns the binary); `--http 127.0.0.1:8765`
  serves the same tools as stateless Streamable HTTP at `/mcp`. No session id,
  GET opens an idle `text/event-stream`, foreign `Origin` refused with 403
  (DNS-rebinding guard).
- 13 tools, all read-only: elf_info, list_symbols, disassemble, decompile,
  xrefs, call_hierarchy, security_scan, entropy, strings, discover_functions,
  list_plugins, run_plugin, read_bytes. Patch/write tools are deliberately
  absent: an MCP client can call anything exposed, so byte-writing must come
  later under separate, approval-gated names.
- `disassemble_at` in mcp.rs mirrors jni_bridge `handle_disasm` (same clamping,
  symbol/string resolution and JNI detection) rather than sharing code, so the
  shipped app path was not touched.
- Tool results are capped at 400k chars at a char boundary; parsed ELFs are
  cached (8 files, most-recent-first) because tools revisit one file constantly.
- Tests: `tests/mcp_tests.rs` runs the protocol, a real ELF (the test binary
  itself), the AArch64 fixture when built, the plugin catalog, a spawned binary
  stdio session and an HTTP round-trip. The stdio test caught a real deadlock:
  a `BufReader` rebuilt per line discarded requests that shared a read.

## 2026-11-26 — Shared-tail goto inlining: terminators generalized, expansion capped
The "46 gotos" in functions like Poweramp's JNI_OnLoad were shared error tails
whose terminator (IrStmt::Return or a noreturn call like __stack_chk_fail) sits
INSIDE a Block's statements — try_region only stopped at StructuredNode::Return,
so the splice entered the cyclic epilogue labels and refused; nothing inlined.
Fixed: `block_terminates()` treats Block-ending Return / noreturn call / Trap as
terminators, and fallback_to_gotos runs inline_shared_joins to a bounded
fixpoint (3 iterations) so nested inlinable tails expand too.
Poweramp JNI_OnLoad: goto loc_00209610 sites 4 → 1; total gotos 36 → 32.
Deliberately NOT zero: the error tails flow through the stack-canary epilogue,
whose full expansion is ~31 stmts per site; inlining it everywhere tripled the
output (398 → 1307 lines). MAX_INLINE_STMTS = 16 caps expansion size, so long
cascading tails stay as single gotos.

## 2026-11-26 — Return-value synthesis keeps the tail's leading calls; goto count counts gotos only
Two follow-ups from the Poweramp JNI_OnLoad output:
- `const_return_stmts` now logs `IrStmt::Call` while walking a shared tail, and
  `leading_calls()` prepends every call that the tail executes BEFORE the first
  statement of the resolved return chain (e.g. the shared `__android_log_print`
  before the error `return -1`). Per-site synthesis reads
  `x1..x4 = ...; __android_log_print(); x19 = -1; a0 = x19; return a0;` instead
  of silently dropping the log call. Calls between chain statements are still
  skipped (reordering is not provably safe); resolve_chain still bails on Call
  when it needs a register, so no value is resolved through a call.
- The header note counter (`count_gotos` in emit.rs) counted Label nodes too;
  it now counts Goto nodes only ("11 goto(s) kept" instead of "22").

## 2026-11-26 — Tail-helper extraction: gotos the inliner kept become static helpers
The last structuring pass (`extract_tail_helpers` in regions.rs, wired in
mod.rs before emit) takes every still-referenced shared exit tail, splices it
(including explicit-Goto chains into the cyclic canary epilogue, bounded by
MAX_JOIN_STMTS + a visited set) into a `static int64_t tail_XXXXXXXX(...)`
helper, and rewrites each goto site into `return tail_...(...)` (void function
