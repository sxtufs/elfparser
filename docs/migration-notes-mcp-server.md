# Migration notes: MCP server from desktop binaries to the in-app toggle

## What moved

The MCP server started as a desktop-only feature: a `elftrace-mcp` binary
(stdio, or `--http 127.0.0.1:8989`) built by a three-OS CI matrix. The product
shape was wrong for this app: the user wants a switch inside ELFTrace, the way
MT Manager starts its own server, so an agent on the same Wi-Fi can point at the
phone.

## Phases (each leaves the app buildable and the desktop transport working)

1. **Transport made controllable.** `mcp::start_server(addr, token)` /
   `stop_server()` / `running_url()` in `elftrace-core/src/mcp.rs`. The accept
   loop moved into `serve_listener`, which takes an optional token and an
   optional stop flag; `serve_http_listener` (used by the binary and the tests)
   keeps its old blocking behaviour.
2. **Default port changed** from 8989 to **8765** for both the desktop default
   (`src/bin/elftrace-mcp.rs`) and the app. 8989 collides with local dev servers
   commonly used on the same network.
3. **Auth added before the app could listen on Wi-Fi.** Every request must send
   `Authorization: Bearer <token>` (or `X-MCP-Token`), compared
   length-independently. The DNS-rebinding origin guard now also accepts RFC1918
   origins (10/8, 192.168/16, 172.16/12) because the token is the gate.
4. **Android wiring.** JNI `startMcp0/stopMcp0/mcpStatus0`; `McpServerService`
   (foreground, `dataSync`, Stop action); `McpServer` object (persisted random
   token, port, LAN URL); a gear button in the Home header opening
   `McpServerDialog`; manifest permissions (INTERNET, ACCESS_NETWORK_STATE,
   FOREGROUND_SERVICE, FOREGROUND_SERVICE_DATA_SYNC, POST_NOTIFICATIONS).
5. **Desktop CI job removed** from `.github/workflows/build.yml`. The
   `elftrace-mcp` source stays for local desktop use; only the artifact matrix
   was dropped.

## Behaviour that must stay the same (and does)

- The 13 read-only tools, their JSON shapes, the 400k result cap, the 8-file ELF
  cache and the stdio transport are untouched.
- The Android analysis/decompile paths do not call into the new code; the JNI
  additions are new symbols only.
- GET on `/mcp` opens a `text/event-stream` (keep-alive comments only, no
  server-initiated messages yet) instead of returning 405: clients probe GET
  before POST and read 405 as "unreachable". POST is stateless as before.

## UI phase — dialog holds only what a client needs (2026-11-28)

The MCP dialog was split into two screens so the panel the user reads while
copying is short, and the knobs live behind Settings. All of it is UI only:
`McpServerDialog.kt` (`ServerBody` / `SettingsBody`), no Rust, no preference
keys, no protocol change.

- Main panel: the server switch and, while running, the two endpoint URLs
  (`127.0.0.1:<port>` and the LAN address) with COPY. The token block, its
  Show/Hide link, and the amber "anyone on this network…" paragraph are gone
  from it.
- Settings: port field (hint `Available range 1024–65535`, error text from
  `McpServer.MIN_PORT`/`MAX_PORT`), the "Enable token" switch (off by default),
  and — while the token is required — the full token with COPY under a "Token"
  label. The description under the switch names the `Token` field and the
  `Authorization: Bearer <token>` header. No amber warning text remains.
- Switches use `LocalELFTraceColors.primary` (`ThemedSwitch`) instead of the M3
  defaults, so the track matches the app accent in both themes.

Rollback: revert this commit; the previous dialog carried the token inline and
`Show`/`Hide`. Nothing persisted changes, so no data step is involved. Bumping
the port or turning the token off remains reversible from the same panel.

Verification: `./gradlew :app:assembleDebug :app:lintDebug
:app:testDebugUnitTest` → BUILD SUCCESSFUL, and `cd elftrace-core && cargo test
--all` → 146 passed, 0 failed. Not verified: rendering on a physical phone.

## Cutover and rollback

No data migration is involved; the token lives in SharedPreferences and the
server binds only while the switch is on.

- Stop: the notification's Stop action, or the switch → `stop_server()` flips
  the flag and the socket closes (the service's `onDestroy` also stops it).
- Roll back the whole change: revert the commit(s); the app then has no MCP
  entry point and the desktop binary again defaults to 8989 only if that line is
  reverted too.
- Port back-out: change `DEFAULT_HTTP_PORT` in `mcp.rs` and
  `DEFAULT_HTTP_ADDR` in `src/bin/elftrace-mcp.rs`; nothing else depends on it.

## Verification

- `cd elftrace-core && cargo test --all` → 140 passed, 0 failed (includes
  `mcp_tests::in_app_server_requires_the_token_and_stops_on_request`: 401
  without/with a wrong token, 200 with the token from a LAN origin, listener
  closed after stop). That test's last assertion changed later, when the dialog
  gained a token switch: an empty token now starts an unauthenticated server and
  the test asserts the 200 instead of a refusal.
- `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` clean.
- `./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug` and
  `:app:assembleRelease` → BUILD SUCCESSFUL.
- arm64 `libelftrace.so` rebuilt with NDK r30: 16 KB page alignment kept and the
  three new JNI symbols exported.

Not verified: runtime behaviour on a physical phone (no device here).
