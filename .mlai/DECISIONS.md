# Decisions

## 2026-11-27 — MCP reaches files through the open binary, not a permission
Reading `/storage/emulated/0/*.so` from MCP tools is blocked by scoped storage
(`targetSdk 36`; `READ_EXTERNAL_STORAGE` capped at API 32), and Play policy
lists "file selection where the user manually selects individual files" as an
invalid use of `MANAGE_EXTERNAL_STORAGE`. So:
- Every tool's `path` is optional and falls back to the file the app has open
  (`current_file`, `CURRENT_FILE` static, set by `loadElf` via JNI
  `setCurrentFile0`).
- `list_imports` (tool #22) lists binaries in app storage — the open file plus
  cached copies — newest first; JNI `setMcpImportDir0` registers cacheDir at
  service start.
- `file_arg` refuses shared-storage paths (`/storage/emulated`, `/sdcard`,
  `/mnt/media`, `/mnt/sdcard`) telling the user to open the file in the app,
  instead of returning EACCES.
- The manual "Import a file" picker was built and then removed (commit
  `8bddba6`) at the user's request: the open file already reaches the agent,
  and the extra step only cluttered the MCP dialog. Do not reintroduce a second
  user step in that dialog without asking.

## 2026-11-27 — MCP write tools exposed at user request
The earlier "patch/write tools are deliberately absent" rule was reversed when
the user asked to expose patch/assemble/undo/save: `patch`, `undo`, `save`
(`readOnlyHint: false`) plus read-only `assemble`, `binary_facts`,
`resolve_jni`, `rename_function`. The two tests that asserted "no write tools
may exist" were rewritten for that purpose. `save` refuses to overwrite its
input. Total tools: 22.

## 2026-11-27 — In-app MCP toggle: token-gated HTTP on 8765, desktop CI job removed
The MCP engine is switchable from the phone itself, MT-Manager style:
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

## 2026-11-28 — MCP settings pane: port and optional token live there
The main MCP dialog shows only the switch and the two endpoint URLs. Port,
token and the "Require access token" switch are behind a `Settings` button left
of `Close`:
- Port is validated 1024–65535 (`McpServer.MIN_PORT`/`MAX_PORT`); saving while
  running restarts the server on the new port.
- The token switch can be turned off, which starts the listener with
  `token = [redacted] and lets `mcpserver.json` persist that choice; the LAN is then
  unauthenticated by design.
- `ThemedSwitch` paints the track with `colors.primary` so switches follow the
  app accent instead of Material's default purple.
- The token is always visible in the pane; the Show/Hide link was removed at the
  user's request, as was the amber "anyone on this Wi-Fi" paragraph.

## 2026-11-28 — Annotation colour is warm sand, not loud amber
Orange was the loudest thing on the disassembly screen and competed with the
instruction payload. `ELFTraceColors.annotation` is the single annotation
colour: `#D4A72C` (warm sand) in dark, `#92702A` (bronze) in light so it stays
readable on the light card. Rules:
- Annotation text (in-line comments, the sheet's comment, XREF kind labels, JNI
  callee names) uses `colors.annotation` at `FontWeight.Normal` — never bold,
  never the legacy `AmberAccent` (`#FFA000`), which now only survives on status
  badges (THUMB, exec segment, severity, security findings).
- `AmberAccent` is a status colour, not an annotation colour; do not reuse it
  for commentary.
- In the instruction sheet the warm sand is the accent of the annotation layer:
  `Patch All` (bulk patch of xrefs) and `Frida Hook` are the only warm actions.
  Everything else is `colors.primary`; `Undo` takes a red-tinted border
  (`colors.changedReg` at 50% alpha) and `Export .so` closes the sheet as the
  last action.
- Chip rows stay grouped by small grey `SectionLabel`s (PATCH, NAVIGATE, EDIT,
  GLOBAL) at 10sp, `textSecondary`, letterSpacing 1.2.
