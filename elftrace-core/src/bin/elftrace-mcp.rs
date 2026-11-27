//! Standalone MCP server for the elftrace analysis engine.
//!
//! Desktop clients launch this on stdio; `--http` serves the same tools over
//! Streamable HTTP at `http://<addr>/mcp`.

use elftrace::mcp;

const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:8989";

fn main() {
    let mut http: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            print_help();
            return;
        }
        if arg == "--version" || arg == "-V" {
            println!("elftrace-mcp {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        if let Some(addr) = arg.strip_prefix("--http=") {
            http = Some(addr.to_string());
            continue;
        }
        if arg == "--http" {
            http = Some(args.next().unwrap_or_else(|| DEFAULT_HTTP_ADDR.to_string()));
            continue;
        }
        eprintln!("elftrace-mcp: unknown argument '{arg}'");
        print_help();
        std::process::exit(2);
    }

    let result = match http {
        Some(addr) => mcp::serve_http(&addr),
        None => mcp::serve_stdio(),
    };
    if let Err(e) = result {
        eprintln!("elftrace-mcp: {e}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "elftrace-mcp {} - read-only static analysis for native binaries over MCP

USAGE:
    elftrace-mcp                 serve MCP on stdin/stdout (what desktop clients spawn)
    elftrace-mcp --http [ADDR]   serve Streamable HTTP at http://ADDR/mcp
                                 (ADDR defaults to {DEFAULT_HTTP_ADDR})

Tools: elf_info, list_symbols, disassemble, decompile, xrefs, call_hierarchy,
       security_scan, entropy, strings, discover_functions, list_plugins,
       run_plugin, read_bytes.
Nothing is written to the analysed file.",
        env!("CARGO_PKG_VERSION")
    );
}
