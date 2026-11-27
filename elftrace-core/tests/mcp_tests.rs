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
        // Nothing in this server may write to the analysed file.
        for prefix in ["apply_", "patch", "write_", "assemble_"] {
            assert!(
                !name.starts_with(prefix),
                "{name} looks like a write tool; those must not be exposed here"
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
        13
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
    // Starting without a token is refused.
    assert!(mcp::start_server("127.0.0.1:0", "").is_err());
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
