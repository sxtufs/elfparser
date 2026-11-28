//! MCP server: protocol conformance, tool dispatch and both transports.
//!
//! The analysis assertions run against this test binary's own executable, which
//! is always a real ELF, so they hold on any Linux CI runner without fixtures.
//! Decompilation is ARM-specific, so that part uses the local AArch64 fixture
//! and skips when it has not been built (see CONVENTIONS.md).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};

use elftrace::mcp::{self, Host};
use serde_json::{json, Value};

/// What the host sink recorded: the file name it was handed and the bytes.
type SinkRecord = std::sync::Arc<std::sync::Mutex<Option<(String, Vec<u8>)>>>;

fn rpc(host: &mut Host, message: Value) -> Value {
    let text = mcp::handle_message(host, &message.to_string()).expect("expected a response");
    serde_json::from_str(&text).expect("response must be valid JSON")
}

fn call_tool(host: &mut Host, name: &str, arguments: Value) -> (String, bool) {
    let response = rpc(
        host,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }),
    );
    let result = &response["result"];
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (text, result["isError"].as_bool().unwrap_or(true))
}

fn self_exe() -> String {
    std::env::current_exe()
        .expect("test binary path")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn initialize_negotiates_a_supported_protocol_version() {
    let mut host = Host::new();
    let response = rpc(
        &mut host,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
        }),
    );
    let result = &response["result"];
    assert_eq!(result["protocolVersion"], "2025-06-18");
    assert_eq!(result["serverInfo"]["name"], "elftrace-mcp");
    assert!(result["capabilities"]["tools"].is_object());

    // An unknown revision falls back to the newest one we implement.
    let response = rpc(
        &mut host,
        json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}),
    );
    assert_eq!(response["result"]["protocolVersion"], mcp::PROTOCOL_VERSION);
}

#[test]
fn tools_list_is_well_formed_and_read_only() {
    let mut host = Host::new();
    let response = rpc(
        &mut host,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
    );
    let tools = response["result"]["tools"].as_array().expect("tools array");
    assert!(
        tools.len() >= 13,
        "expected the full tool set, got {}",
        tools.len()
    );

    for tool in tools {
        let name = tool["name"].as_str().expect("tool name");
        assert!(!name.is_empty());
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "{name} needs a description"
        );
        assert_eq!(tool["inputSchema"]["type"], "object", "{name} schema");
        assert!(
            tool["inputSchema"]["properties"].is_object(),
            "{name} properties"
        );
        // Write tools are exposed on purpose: patch, undo and save must say so
        // in their annotations instead of pretending to be read-only.
        if ["patch", "undo", "save"].contains(&name) {
            assert!(
                tool["annotations"]["readOnlyHint"].as_bool() == Some(false),
                "{name} writes, so readOnlyHint must be false"
            );
        }
    }

    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in ["elf_info", "decompile", "disassemble", "run_plugin"] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
}

#[test]
fn protocol_errors_are_reported_not_ignored() {
    let mut host = Host::new();

    let response = rpc(
        &mut host,
        json!({"jsonrpc": "2.0", "id": 1, "method": "nope"}),
    );
    assert_eq!(response["error"]["code"], -32601);

    let response = rpc(
        &mut host,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}),
    );
    assert_eq!(response["error"]["code"], -32602);

    let text = mcp::handle_message(&mut host, "{not json").expect("parse error response");
    let response: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(response["error"]["code"], -32700);

    // Notifications get no reply at all.
    assert!(mcp::handle_message(
        &mut host,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )
    .is_none());
    assert!(mcp::handle_message(&mut host, "   ").is_none());

    let text = mcp::handle_message(
        &mut host,
        &json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}).to_string(),
    )
    .expect("ping reply");
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["result"],
        json!({})
    );
}

#[test]
fn analyses_a_real_elf_end_to_end() {
    let path = self_exe();
    let mut host = Host::new();

    let (info_text, is_error) = call_tool(&mut host, "elf_info", json!({"path": path}));
    assert!(!is_error, "elf_info failed: {info_text}");
    let info: Value = serde_json::from_str(&info_text).expect("elf_info JSON");
    assert!(info["e_machine"].as_u64().is_some(), "e_machine missing");
    assert!(info["sections"].as_array().is_some_and(|s| !s.is_empty()));
    let text_section = info["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == ".text")
        .expect(".text section in a test binary");
    let text_address = text_section["vaddr"].as_str().expect("vaddr string");

    let (symbols_text, is_error) = call_tool(
        &mut host,
        "list_symbols",
        json!({"path": path, "filter": "main", "limit": 5}),
    );
    assert!(!is_error, "list_symbols failed: {symbols_text}");
    let symbols: Value = serde_json::from_str(&symbols_text).unwrap();
    assert!(symbols["total_matched"].as_u64().is_some());

    let (disasm_text, is_error) = call_tool(
        &mut host,
        "disassemble",
        json!({"path": path, "address": text_address, "size": 64}),
    );
    assert!(!is_error, "disassemble failed: {disasm_text}");
    let disasm: Value = serde_json::from_str(&disasm_text).unwrap();
    assert!(
        disasm["count"].as_u64().unwrap_or(0) > 0,
        "no instructions decoded: {disasm_text}"
    );

    let (bytes_text, is_error) = call_tool(
        &mut host,
        "read_bytes",
        json!({"path": path, "address": text_address, "length": 16}),
    );
    assert!(!is_error, "read_bytes failed: {bytes_text}");
    let bytes: Value = serde_json::from_str(&bytes_text).unwrap();
    assert_eq!(bytes["length"], 16);

    let (scan_text, is_error) = call_tool(&mut host, "security_scan", json!({"path": path}));
    assert!(!is_error, "security_scan failed: {scan_text}");
    assert!(serde_json::from_str::<Value>(&scan_text)
        .unwrap()
        .is_object());

    let (entropy_text, is_error) = call_tool(&mut host, "entropy", json!({"path": path}));
    assert!(!is_error, "entropy failed: {entropy_text}");
    assert!(serde_json::from_str::<Value>(&entropy_text)
        .unwrap()
        .is_object());

    let (strings_text, is_error) =
        call_tool(&mut host, "strings", json!({"path": path, "limit": 5}));
    assert!(!is_error, "strings failed: {strings_text}");
    assert!(serde_json::from_str::<Value>(&strings_text).unwrap()["strings"].is_array());
}

#[test]
fn aarch64_fixture_decompiles() {
    let fixture = std::path::Path::new("test_fixtures/accuracy/libpowerampcore.so");
    if !fixture.is_file() {
        eprintln!("skipping: {} is not built", fixture.display());
        return;
    }
    let mut host = Host::new();
    let path = fixture.to_string_lossy().into_owned();
    let (symbols_text, _) = call_tool(
        &mut host,
        "list_symbols",
        json!({"path": path, "filter": "JNI_OnLoad", "limit": 1}),
    );
    let symbols: Value = serde_json::from_str(&symbols_text).unwrap();
    let address = symbols["symbols"][0]["address"]
        .as_str()
        .expect("JNI_OnLoad symbol");

    let (text, is_error) = call_tool(
        &mut host,
        "decompile",
        json!({"path": path, "address": address, "style": "structured"}),
    );
    assert!(!is_error, "decompile failed: {text}");
    assert!(text.contains("JNI_OnLoad"), "header missing: {text}");
    assert!(text.len() > 100, "decompiled output looks empty");
}

#[test]
fn missing_file_and_bad_arguments_become_tool_errors() {
    let mut host = Host::new();
    let (text, is_error) = call_tool(
        &mut host,
        "elf_info",
        json!({"path": "/nonexistent/file.so"}),
    );
    assert!(is_error, "a missing file must be an error, got: {text}");
    assert!(text.contains("cannot open"), "unhelpful message: {text}");

    let (text, is_error) = call_tool(&mut host, "disassemble", json!({"path": self_exe()}));
    assert!(is_error, "missing address must be an error, got: {text}");

    let (text, is_error) = call_tool(
        &mut host,
        "disassemble",
        json!({"path": self_exe(), "address": 0xdead_beefu64}),
    );
    assert!(is_error, "unmapped address must be an error, got: {text}");
}

#[test]
fn plugin_tools_read_the_shipped_manifests() {
    let dir = std::path::Path::new("../app/src/main/assets/plugins");
    if !dir.is_dir() {
        eprintln!("skipping: {} not present", dir.display());
        return;
    }
    let mut host = Host::new();
    let (text, is_error) = call_tool(
        &mut host,
        "list_plugins",
        json!({"dir": dir.to_string_lossy()}),
    );
    assert!(!is_error, "list_plugins failed: {text}");
    let listing: Value = serde_json::from_str(&text).unwrap();
    let plugins = listing["plugins"].as_array().expect("plugins array");
    assert!(
        plugins.len() >= 20,
        "expected the full catalog, got {}",
        plugins.len()
    );
    assert!(plugins
        .iter()
        .all(|p| p["error"].is_null() || p.get("error").is_none()));
    let first_file = plugins[0]["file"].as_str().unwrap().to_string();

    let (text, is_error) = call_tool(
        &mut host,
        "run_plugin",
        json!({"path": self_exe(), "plugin": first_file}),
    );
    assert!(!is_error, "run_plugin failed: {text}");
    let report: Value = serde_json::from_str(&text).unwrap();
    assert!(report["total_findings"].as_u64().is_some());
}

#[test]
fn binary_serves_a_stdio_session() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_elftrace-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn elftrace-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    let requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "elf_info", "arguments": {"path": self_exe()}}}),
    ];
    for request in &requests {
        writeln!(stdin, "{request}").expect("write request");
    }
    stdin.flush().unwrap();

    let mut responses = Vec::new();
    for _ in 0..requests.len() {
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("read response");
        assert!(read > 0, "server closed stdout early");
        responses.push(serde_json::from_str::<Value>(line.trim()).expect("JSON line"));
    }

    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "elftrace-mcp");
    assert_eq!(
        responses[1]["result"]["tools"].as_array().unwrap().len(),
        26
    );
    let info_text = responses[2]["result"]["content"][0]["text"]
        .as_str()
        .expect("elf_info text");
    let info: Value = serde_json::from_str(info_text).expect("elf_info JSON");
    assert!(info["e_machine"].as_u64().is_some());

    drop(stdin);
    let status = child.wait().expect("server exit");
    assert!(status.success(), "server exited with {status}");
}

#[test]
fn http_mode_answers_json_rpc_on_mcp_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = mcp::serve_http_listener(listener);
    });

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "elf_info", "arguments": {"path": self_exe()}},
    })
    .to_string();
    let response = post(address, "/mcp", &body);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected status: {response}"
    );
    let payload = response.split("\r\n\r\n").nth(1).expect("body");
    let value: Value = serde_json::from_str(payload.trim()).expect("JSON body");
    let info_text = value["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    assert!(serde_json::from_str::<Value>(info_text).is_ok());

    // A foreign Origin is refused (DNS-rebinding guard), and unknown paths 404.
    let response = post_with_origin(address, "/mcp", &body, "https://evil.example");
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    let response = post(address, "/nope", &body);
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");

    // A query string is part of the target, not the path: clients append
    // `?token=` or their own parameters and must still reach the endpoint.
    let response = post(address, "/mcp?client=test", &body);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "query target: {response}"
    );
}

fn post(address: std::net::SocketAddr, path: &str, body: &str) -> String {
    post_with_origin(address, path, body, "http://127.0.0.1")
}

fn post_with_origin(address: std::net::SocketAddr, path: &str, body: &str, origin: &str) -> String {
    post_with_auth(address, path, body, origin, None)
}

fn post_with_auth(
    address: std::net::SocketAddr,
    path: &str,
    body: &str,
    origin: &str,
    token: Option<&str>,
) -> String {
    let mut stream = TcpStream::connect(address).expect("connect");
    let auth = match token {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

#[test]
fn in_app_server_requires_the_token_and_stops_on_request() {
    let url = mcp::start_server("127.0.0.1:0", "s3cret-token").expect("server should start");
    assert!(url.ends_with("/mcp"), "{url}");
    let address: std::net::SocketAddr = url
        .trim_start_matches("http://")
        .trim_end_matches("/mcp")
        .parse()
        .expect("url carries the bound address");
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
    })
    .to_string();

    let response = post(address, "/mcp", &body);
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    let response = post_with_auth(address, "/mcp", &body, "http://127.0.0.1", Some("wrong"));
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");

    // A LAN browser origin is accepted once the token is right.
    let response = post_with_auth(
        address,
        "/mcp",
        &body,
        "http://192.168.1.42:3000",
        Some("s3cret-token"),
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("protocolVersion"), "{response}");

    assert!(mcp::stop_server());
    assert!(mcp::running_url().is_none());
    let mut refused = false;
    for _ in 0..100 {
        if TcpStream::connect(address).is_err() {
            refused = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(refused, "listener should be closed after stop_server");

    // An empty token serves without auth: the app's switch for clients that
    // cannot send headers.
    let url = mcp::start_server("127.0.0.1:0", "").expect("tokenless server should start");
    let address: std::net::SocketAddr = url
        .trim_start_matches("http://")
        .trim_end_matches("/mcp")
        .parse()
        .expect("url carries the bound address");
    assert_eq!(mcp::running_auth(), Some(false));
    let response = post(address, "/mcp", &body);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("protocolVersion"), "{response}");
    assert!(mcp::stop_server());
}

#[test]
fn get_on_mcp_opens_a_server_sent_event_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = mcp::serve_http_listener(listener);
    });

    // Clients open GET before their first POST and read 405 as "unreachable",
    // so the endpoint must answer with a live text/event-stream.
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let request =
        format!("GET /mcp HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().unwrap();
    let mut head = [0u8; 512];
    let read = stream.read(&mut head).expect("read stream head");
    let head = String::from_utf8_lossy(&head[..read]).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "status: {head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/event-stream"),
        "content type: {head}"
    );
}

#[test]
fn every_advertised_tool_dispatches_and_declares_annotations() {
    let mut host = Host::new();
    let response = rpc(
        &mut host,
        json!({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}),
    );
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let write_tools = ["patch", "undo", "save"];

    for tool in tools {
        let name = tool["name"].as_str().expect("tool name");
        let read_only = tool["annotations"]["readOnlyHint"]
            .as_bool()
            .unwrap_or_else(|| panic!("{name} needs a readOnlyHint annotation"));
        assert_eq!(
            read_only,
            !write_tools.contains(&name),
            "{name} has the wrong readOnlyHint"
        );

        // A tool with no dispatch arm answers "unknown tool" whatever its
        // arguments are, so a bogus path is enough to tell the two apart.
        let call = rpc(
            &mut host,
            json!({
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": {"name": name, "arguments": {"path": "/nonexistent.so"}}
            }),
        );
        let text = call["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(
            !text.contains("unknown tool"),
            "{name} is advertised but has no dispatch arm"
        );
    }
}

#[test]
fn patch_undo_and_save_round_trip_on_a_real_elf() {
    let elf = std::env::current_exe().expect("test binary path");
    let path = elf.to_string_lossy().into_owned();
    let mut host = Host::new();

    let (info, is_error) = call_tool(&mut host, "elf_info", json!({"path": path}));
    assert!(!is_error, "elf_info failed: {info}");
    let info: Value = serde_json::from_str(&info).expect("elf_info JSON");
    let entry = info["entry"].as_str().expect("entry point");
    let entry = u64::from_str_radix(entry.trim_start_matches("0x"), 16).expect("entry hex");

    let (patched, is_error) = call_tool(
        &mut host,
        "patch",
        json!({"path": path, "address": entry, "bytes": "9090"}),
    );
    assert!(!is_error, "patch refused: {patched}");

    let (after, is_error) = call_tool(
        &mut host,
        "read_bytes",
        json!({"path": path, "address": entry, "length": 2}),
    );
    assert!(!is_error, "read_bytes failed: {after}");
    assert!(
        after.contains("90 90"),
        "patched bytes not visible: {after}"
    );

    let (undo, is_error) = call_tool(&mut host, "undo", json!({"path": path}));
    assert!(!is_error, "undo failed: {undo}");
    assert!(undo.contains("restored"), "undo result: {undo}");

    let output = std::env::temp_dir().join("elftrace-mcp-save-test.so");
    let (saved, is_error) = call_tool(
        &mut host,
        "save",
        json!({"path": path, "output": output.to_string_lossy()}),
    );
    assert!(!is_error, "save refused: {saved}");
    let wrote = std::fs::read(&output).expect("saved file");
    assert_eq!(
        wrote,
        std::fs::read(&elf).expect("source"),
        "saved copy differs"
    );
    let _ = std::fs::remove_file(&output);
}

#[test]
fn save_with_a_bare_name_goes_through_the_host_sink() {
    let elf = std::env::current_exe().expect("test binary path");
    let path = elf.to_string_lossy().into_owned();
    let mut host = Host::new();

    // On Android the app registers a sink that writes to public Download/;
    // this stands in for it and records what `save` asked for.
    let seen: SinkRecord = std::sync::Arc::new(std::sync::Mutex::new(None));
    let recorder = seen.clone();
    mcp::set_publisher(Some(Box::new(move |name: &str, bytes: &[u8]| {
        *recorder.lock().unwrap() = Some((name.to_string(), bytes.to_vec()));
        Ok(format!("Download/{name}"))
    })));

    let (saved, is_error) = call_tool(
        &mut host,
        "save",
        json!({"path": path, "output": "Download/libx_patched.so"}),
    );
    assert!(!is_error, "save refused: {saved}");
    assert!(saved.contains("Download/libx_patched.so"), "{saved}");
    let (name, bytes) = seen.lock().unwrap().take().expect("sink must be called");
    assert_eq!(
        name, "libx_patched.so",
        "only the file name reaches the sink"
    );
    assert_eq!(
        bytes,
        std::fs::read(&elf).expect("source"),
        "saved copy differs"
    );

    // Without an output name the file is `<stem>_patched.<ext>`.
    let (saved, is_error) = call_tool(&mut host, "save", json!({"path": path}));
    assert!(!is_error, "save without output refused: {saved}");
    let (name, _) = seen.lock().unwrap().take().expect("sink must be called");
    assert!(name.ends_with("_patched"), "default name: {name}");
    assert!(
        name.starts_with("mcp_tests"),
        "derived from the input: {name}"
    );

    // The input name and escapes are refused before anything is written.
    let input_name = std::path::Path::new(&path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let (_, is_error) = call_tool(
        &mut host,
        "save",
        json!({"path": path, "output": input_name}),
    );
    assert!(is_error, "saving over the input must be refused");
    let (_, is_error) = call_tool(
        &mut host,
        "save",
        json!({"path": path, "output": "../x.so"}),
    );
    assert!(is_error, "a path escape must be refused");
    assert!(
        seen.lock().unwrap().is_none(),
        "nothing may be written on refusal"
    );

    mcp::set_publisher(None);

    // Without a sink the bytes land in the import directory (the desktop and
    // stdio path). Both halves stay in one test because the sink is global.
    let dir = std::env::temp_dir().join(format!("elftrace-mcp-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create export dir");
    mcp::set_import_dir(Some(dir.to_string_lossy().into_owned()));

    let (saved, is_error) = call_tool(
        &mut host,
        "save",
        json!({"path": path, "output": "desktop_patched.so"}),
    );
    assert!(!is_error, "save refused: {saved}");
    let saved: Value = serde_json::from_str(&saved).expect("save JSON");
    let written = saved["output"].as_str().expect("reported path").to_string();
    assert!(written.ends_with("desktop_patched.so"), "{written}");
    assert_eq!(
        std::fs::read(&written).expect("written file"),
        std::fs::read(&elf).expect("source"),
        "fallback copy differs"
    );
    let _ = std::fs::remove_file(&written);

    mcp::set_import_dir(None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tools_work_without_a_path_when_a_file_is_open() {
    let elf = std::env::current_exe().expect("test binary path");
    let path = elf.to_string_lossy().into_owned();
    let mut host = Host::new();

    mcp::set_current_file(Some(path.clone()));

    let (open, is_error) = call_tool(&mut host, "current_file", json!({}));
    assert!(!is_error, "current_file failed: {open}");
    assert!(
        open.contains(&path),
        "current_file did not report the path: {open}"
    );

    // No "path" argument: the server falls back to the open file.
    let (info, is_error) = call_tool(&mut host, "elf_info", json!({}));
    assert!(!is_error, "elf_info without a path failed: {info}");
    assert!(info.contains("e_machine"), "elf_info output: {info}");

    mcp::set_current_file(Some(String::new()));
    let (_, is_error) = call_tool(&mut host, "elf_info", json!({}));
    assert!(is_error, "an empty current file must not be used");
}

#[test]
fn list_imports_reports_the_import_dir_and_shared_storage_paths_are_refused() {
    let dir = std::env::temp_dir().join(format!("elftrace-mcp-imports-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create import dir");
    let old = std::fs::File::create(dir.join("mcp_import_old.so")).expect("old import");
    old.set_times(
        std::fs::FileTimes::new().set_modified(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000),
        ),
    )
    .ok();
    drop(old);
    std::fs::write(dir.join("mcp_import_new.so"), b"new").expect("new import");
    let sub = dir.join("subdir.so");
    std::fs::create_dir_all(&sub).expect("subdir");
    mcp::set_import_dir(Some(dir.to_string_lossy().into_owned()));
    let mut host = Host::new();

    let (listing, is_error) = call_tool(&mut host, "list_imports", json!({}));
    assert!(!is_error, "list_imports failed: {listing}");
    assert!(listing.contains("mcp_import_new.so"), "{listing}");
    assert!(
        listing.contains("mcp_import_old.so"),
        "files must be listed: {listing}"
    );
    assert!(
        listing.find("mcp_import_new.so").unwrap() < listing.find("mcp_import_old.so").unwrap(),
        "newest import must sort first: {listing}"
    );
    assert!(
        !listing.contains("subdir.so"),
        "directories must not be listed: {listing}"
    );

    mcp::set_import_dir(None);
    let (empty, is_error) = call_tool(&mut host, "list_imports", json!({}));
    assert!(
        !is_error,
        "list_imports without a dir must be empty, not an error: {empty}"
    );
    assert!(
        empty.contains("Open a binary"),
        "expected the open-file hint: {empty}"
    );

    // A shared-storage path is always a permission error on Android 13+;
    // refuse it with instructions instead of letting the OS say EACCES.
    let (_, is_error) = call_tool(
        &mut host,
        "elf_info",
        json!({"path": "/storage/emulated/0/lib.so"}),
    );
    assert!(
        is_error,
        "shared-storage paths must be refused with a message"
    );
    let (_, is_error) = call_tool(&mut host, "elf_info", json!({"path": "/sdcard/lib.so"}));
    assert!(is_error, "/sdcard paths must be refused too");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_patches_reports_the_session_and_empties_after_undo() {
    let elf = std::env::current_exe().expect("test binary path");
    let path = elf.to_string_lossy().into_owned();
    let mut host = Host::new();

    let (before, is_error) = call_tool(&mut host, "list_patches", json!({"path": path}));
    assert!(!is_error, "list_patches failed: {before}");
    let before: Value = serde_json::from_str(&before).expect("list_patches JSON");
    assert_eq!(before["count"], 0, "a fresh session has no patches");
    assert!(
        before["hint"].as_str().unwrap_or_default().contains("unchanged"),
        "empty listing should say save writes nothing: {before}"
    );

    let (info, _) = call_tool(&mut host, "elf_info", json!({"path": path}));
    let info: Value = serde_json::from_str(&info).expect("elf_info JSON");
    let entry = info["entry"].as_str().expect("entry point");
    let entry = u64::from_str_radix(entry.trim_start_matches("0x"), 16).expect("entry hex");

    let (patched, is_error) = call_tool(
        &mut host,
        "patch",
        json!({"path": path, "address": entry, "bytes": "9090"}),
    );
    assert!(!is_error, "patch refused: {patched}");

    let (listing, is_error) = call_tool(&mut host, "list_patches", json!({"path": path}));
    assert!(!is_error, "list_patches failed: {listing}");
    let listing: Value = serde_json::from_str(&listing).expect("list_patches JSON");
    assert_eq!(listing["count"], 1, "one patch expected: {listing}");
    let only = &listing["patches"][0];
    assert_eq!(only["patch"], 1, "the top of the undo stack is patch 1");
    assert_eq!(
        only["address"].as_str().unwrap_or_default(),
        format!("0x{entry:x}")
    );
    assert_eq!(only["patched"].as_str().unwrap_or_default(), "90 90");
    assert_ne!(
        only["original"].as_str().unwrap_or_default(),
        "90 90",
        "original bytes must be the pre-patch ones"
    );

    let (undo, is_error) = call_tool(&mut host, "undo", json!({"path": path}));
    assert!(!is_error, "undo failed: {undo}");

    let (after, _) = call_tool(&mut host, "list_patches", json!({"path": path}));
    let after: Value = serde_json::from_str(&after).expect("list_patches JSON");
    assert_eq!(after["count"], 0, "undo must empty the listing: {after}");
}

#[test]
fn find_pattern_locates_bytes_we_wrote_and_honours_wildcards() {
    let elf = std::env::current_exe().expect("test binary path");
    let path = elf.to_string_lossy().into_owned();
    let mut host = Host::new();

    let (info, _) = call_tool(&mut host, "elf_info", json!({"path": path}));
    let info: Value = serde_json::from_str(&info).expect("elf_info JSON");
    let entry = info["entry"].as_str().expect("entry point");
    let entry = u64::from_str_radix(entry.trim_start_matches("0x"), 16).expect("entry hex");

    // Scan the section that actually holds the entry point: on a PIE the entry
    // is .text, but do not assume the name, and do not assume .text is first.
    let sections = info["sections"].as_array().expect("sections array");
    let entry_section = sections
        .iter()
        .find(|sec| {
            let start = sec["vaddr"].as_u64().unwrap_or(0);
            let size = sec["size"].as_u64().unwrap_or(0);
            entry >= start && entry < start.saturating_add(size)
        })
        .and_then(|sec| sec["name"].as_str().map(str::to_string))
        .expect("a section covering the entry point");

    // Two distinct byte runs so the wildcard match cannot be the literal one.
    let (patched, is_error) = call_tool(
        &mut host,
        "patch",
        json!({"path": path, "address": entry, "bytes": "deadbeef0a0b0c0d"}),
    );
    assert!(!is_error, "patch refused: {patched}");

    let (found, is_error) = call_tool(
        &mut host,
        "find_pattern",
        json!({"path": path, "pattern": "de ad be ef 0a 0b 0c 0d", "section": entry_section}),
    );
    assert!(!is_error, "find_pattern failed: {found}");
    let found: Value = serde_json::from_str(&found).expect("find_pattern JSON");
    let addresses: Vec<&str> = found["matches"]
        .as_array()
        .expect("matches array")
        .iter()
        .filter_map(|m| m["address"].as_str())
        .collect();
    let wanted = format!("0x{entry:x}");
    assert!(
        addresses.contains(&wanted.as_str()),
        "patched bytes not found at {wanted}: {found}"
    );

    let (wild, is_error) = call_tool(
        &mut host,
        "find_pattern",
        json!({"path": path, "pattern": "de ad be ef ?? ?? ?? ??", "section": entry_section, "max": 128}),
    );
    assert!(!is_error, "wildcard search failed: {wild}");
    let wild: Value = serde_json::from_str(&wild).expect("find_pattern JSON");
    let wild_addresses: Vec<&str> = wild["matches"]
        .as_array()
        .expect("matches array")
        .iter()
        .filter_map(|m| m["address"].as_str())
        .collect();
    assert!(
        wild_addresses.contains(&wanted.as_str()),
        "wildcards must still match the patched bytes: {wild}"
    );

    let (compact, is_error) = call_tool(
        &mut host,
        "find_pattern",
        json!({"path": path, "pattern": "deadbeef0a0b0c0d", "section": entry_section, "max": 128}),
    );
    assert!(!is_error, "compact pattern failed: {compact}");
    let compact: Value = serde_json::from_str(&compact).expect("find_pattern JSON");
    let compact_addresses: Vec<&str> = compact["matches"]
        .as_array()
        .expect("matches array")
        .iter()
        .filter_map(|m| m["address"].as_str())
        .collect();
    assert!(
        compact_addresses.contains(&wanted.as_str()),
        "compact hex must parse like spaced hex: {compact}"
    );

    let (_, is_error) = call_tool(
        &mut host,
        "find_pattern",
        json!({"path": path, "pattern": "de adx be ef"}),
    );
    assert!(is_error, "a non-hex token must be refused");

    let (undo, is_error) = call_tool(&mut host, "undo", json!({"path": path}));
    assert!(!is_error, "undo failed: {undo}");
}

#[test]
fn function_info_and_resolve_import_answer_questions_about_a_real_elf() {
    let elf = std::env::current_exe().expect("test binary path");
    let path = elf.to_string_lossy().into_owned();
    let mut host = Host::new();

    let (info, _) = call_tool(&mut host, "elf_info", json!({"path": path}));
    let info: Value = serde_json::from_str(&info).expect("elf_info JSON");
    let entry = info["entry"].as_str().expect("entry point");
    let entry = u64::from_str_radix(entry.trim_start_matches("0x"), 16).expect("entry hex");

    let (func, is_error) = call_tool(
        &mut host,
        "function_info",
        json!({"path": path, "address": entry}),
    );
    assert!(!is_error, "function_info failed: {func}");
    let func: Value = serde_json::from_str(&func).expect("function_info JSON");
    let start = u64::from_str_radix(
        func["start"].as_str().expect("start").trim_start_matches("0x"),
        16,
    )
    .expect("start hex");
    let end = u64::from_str_radix(
        func["end"].as_str().expect("end").trim_start_matches("0x"),
        16,
    )
    .expect("end hex");
    assert!(start <= entry, "the function must start at or before the entry");
    assert!(entry < end, "the entry must fall inside the function");
    assert_eq!(func["size"].as_u64(), Some(end - start));
    assert!(
        !func["name"].as_str().unwrap_or_default().is_empty(),
        "a function needs a name: {func}"
    );
    assert!(
        ["symbol", "eh_frame", "scan"].contains(&func["source"].as_str().unwrap_or("")),
        "unknown size source: {func}"
    );

    // A symbol address is not an import, and the tool should say so rather
    // than pretend the name came from a relocation.
    let (symbols, _) = call_tool(
        &mut host,
        "list_symbols",
        json!({"path": path, "limit": 500, "filter": ""}),
    );
    let symbols: Value = serde_json::from_str(&symbols).expect("list_symbols JSON");
    let named = symbols["symbols"]
        .as_array()
        .expect("symbols array")
        .iter()
        .find(|sym| {
            sym["size"].as_u64().unwrap_or(0) > 0
                && sym["address"].as_str().unwrap_or("0x0") != "0x0"
        })
        .expect("at least one sized symbol in the test binary");
    let named_address = u64::from_str_radix(
        named["address"]
            .as_str()
            .expect("symbol address")
            .trim_start_matches("0x"),
        16,
    )
    .expect("symbol hex");

    let (resolved, is_error) = call_tool(
        &mut host,
        "resolve_import",
        json!({"path": path, "address": named_address}),
    );
    assert!(!is_error, "resolve_import failed: {resolved}");
    let resolved: Value = serde_json::from_str(&resolved).expect("resolve_import JSON");
    assert_ne!(
        resolved["kind"].as_str().unwrap_or_default(),
        "unknown",
        "a real symbol address must resolve: {resolved}"
    );

    // u64::MAX - 0xf is outside every segment of any real file, so this must
    // come back as a non-answer rather than a fabricated symbol.
    let (nothing, is_error) = call_tool(
        &mut host,
        "resolve_import",
        json!({"path": path, "address": 0xffff_ffff_ffff_fff0u64}),
    );
    assert!(!is_error, "an unmapped address is an answer, not an error: {nothing}");
    let nothing: Value = serde_json::from_str(&nothing).expect("resolve_import JSON");
    assert_eq!(nothing["kind"], "unknown");
    assert!(nothing["hint"].as_str().unwrap_or_default().contains("relocation"));
}
