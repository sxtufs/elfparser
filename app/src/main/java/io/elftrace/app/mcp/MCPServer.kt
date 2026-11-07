package io.elftrace.app.mcp

import android.content.Context
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import io.elftrace.app.viewmodel.ELFTraceViewModel
import java.io.*
import java.net.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * Built-in Model Context Protocol (MCP) Server for ELFTrace.
 * Enables external AI agents (Claude Desktop, Cursor, local LLMs) to connect
 * via Server-Sent Events (SSE) or direct JSON-RPC HTTP over Wi-Fi/LAN.
 */
class MCPServer(
    private val viewModel: ELFTraceViewModel,
    private val context: Context,
    val port: Int = 8080
) {
    private val gson = Gson()
    private var serverSocket: ServerSocket? = null
    private var isRunning = false
    private val executor = Executors.newCachedThreadPool()

    // Active SSE sessions: sessionId -> PrintWriter
    private val sseSessions = ConcurrentHashMap<String, PrintWriter>()

    fun start(): Boolean {
        if (isRunning) return true
        return try {
            serverSocket = ServerSocket(port)
            isRunning = true
            thread(name = "ELFTrace-MCP-Server", isDaemon = true) {
                while (isRunning && !serverSocket!!.isClosed) {
                    try {
                        val client = serverSocket!!.accept()
                        executor.submit { handleClient(client) }
                    } catch (_: Exception) {
                        break
                    }
                }
            }
            true
        } catch (e: Exception) {
            isRunning = false
            false
        }
    }

    fun stop() {
        isRunning = false
        try {
            serverSocket?.close()
        } catch (_: Exception) {}
        sseSessions.values.forEach {
            try { it.close() } catch (_: Exception) {}
        }
        sseSessions.clear()
    }

    fun isRunning(): Boolean = isRunning

    fun getSseUrl(): String {
        val ip = getLocalIpAddress(context)
        return "http://$ip:$port/sse"
    }

    fun getClaudeConfigJson(): String {
        val url = getSseUrl()
        return """
        {
          "mcpServers": {
            "elftrace": {
              "url": "$url"
            }
          }
        }
        """.trimIndent()
    }

    private fun handleClient(socket: Socket) {
        try {
            socket.soTimeout = 0 // Keep alive for SSE
            val input = BufferedReader(InputStreamReader(socket.getInputStream()))
            val output = socket.getOutputStream()
            val writer = PrintWriter(output, true)

            val requestLine = input.readLine() ?: return
            val parts = requestLine.split(" ")
            if (parts.size < 2) return

            val method = parts[0].uppercase()
            val uri = parts[1]

            // Parse headers
            val headers = mutableMapOf<String, String>()
            var line: String? = input.readLine()
            var contentLength = 0
            while (!line.isNullOrEmpty()) {
                val colon = line.indexOf(':')
                if (colon != -1) {
                    val key = line.substring(0, colon).trim().lowercase()
                    val value = line.substring(colon + 1).trim()
                    headers[key] = value
                    if (key == "content-length") {
                        contentLength = value.toIntOrNull() ?: 0
                    }
                }
                line = input.readLine()
            }

            // Handle CORS preflight
            if (method == "OPTIONS") {
                writer.print("HTTP/1.1 200 OK\r\n")
                writer.print("Access-Control-Allow-Origin: *\r\n")
                writer.print("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n")
                writer.print("Access-Control-Allow-Headers: *\r\n")
                writer.print("Content-Length: 0\r\n\r\n")
                writer.flush()
                socket.close()
                return
            }

            when {
                // 1. GET /sse - Establish Server-Sent Events stream
                method == "GET" && uri.startsWith("/sse") -> {
                    val sessionId = UUID.randomUUID().toString()
                    writer.print("HTTP/1.1 200 OK\r\n")
                    writer.print("Content-Type: text/event-stream\r\n")
                    writer.print("Cache-Control: no-cache\r\n")
                    writer.print("Connection: keep-alive\r\n")
                    writer.print("Access-Control-Allow-Origin: *\r\n\r\n")
                    writer.flush()

                    // Send endpoint event with session ID
                    writer.print("event: endpoint\r\n")
                    writer.print("data: /message?sessionId=$sessionId\r\n\r\n")
                    writer.flush()

                    sseSessions[sessionId] = writer

                    // Keep-alive loop
                    try {
                        while (isRunning && !socket.isClosed) {
                            Thread.sleep(15000)
                            writer.print(": ping\r\n\r\n")
                            writer.flush()
                        }
                    } catch (_: Exception) {
                    } finally {
                        sseSessions.remove(sessionId)
                    }
                }

                // 2. POST /message?sessionId=... - MCP JSON-RPC over SSE
                method == "POST" && uri.startsWith("/message") -> {
                    val body = readBody(input, contentLength)
                    val sessionId = uri.substringAfter("sessionId=", "")

                    // Respond 202 Accepted immediately
                    writer.print("HTTP/1.1 202 Accepted\r\n")
                    writer.print("Access-Control-Allow-Origin: *\r\n")
                    writer.print("Content-Length: 0\r\n\r\n")
                    writer.flush()
                    socket.close()

                    // Process JSON-RPC and send response via active SSE session
                    val sseWriter = sseSessions[sessionId]
                    if (sseWriter != null && body.isNotEmpty()) {
                        val responseJson = handleJsonRpc(body)
                        if (responseJson.isNotEmpty()) {
                            synchronized(sseWriter) {
                                sseWriter.print("event: message\r\n")
                                sseWriter.print("data: $responseJson\r\n\r\n")
                                sseWriter.flush()
                            }
                        }
                    }
                }

                // 3. POST /mcp - Direct Stateless JSON-RPC (curl / HTTP clients)
                method == "POST" && uri.startsWith("/mcp") -> {
                    val body = readBody(input, contentLength)
                    val responseJson = handleJsonRpc(body)
                    val responseBytes = responseJson.toByteArray(Charsets.UTF_8)

                    writer.print("HTTP/1.1 200 OK\r\n")
                    writer.print("Content-Type: application/json; charset=utf-8\r\n")
                    writer.print("Access-Control-Allow-Origin: *\r\n")
                    writer.print("Content-Length: ${responseBytes.size}\r\n\r\n")
                    writer.flush()
                    output.write(responseBytes)
                    output.flush()
                    socket.close()
                }

                // 4. GET / - Clean Web Status Dashboard
                else -> {
                    val ip = getLocalIpAddress(context)
                    val fileName = viewModel.currentFileName.value.ifEmpty { "None (Open a .so first)" }
                    val html = """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>ELFTrace MCP Server</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <style>
                            body { font-family: monospace; background: #16181D; color: #E0E0E0; padding: 24px; }
                            .card { background: #1E222B; border: 1px solid #334155; border-radius: 12px; padding: 18px; max-width: 600px; margin: 0 auto; }
                            h2 { color: #00E5FF; margin-top: 0; }
                            pre { background: #0F1115; padding: 12px; border-radius: 8px; color: #38BDF8; overflow-x: auto; }
                            .badge { color: #4CAF50; font-weight: bold; }
                        </style>
                    </head>
                    <body>
                        <div class="card">
                            <h2>ELFTrace MCP Server</h2>
                            <p>Status: <span class="badge">● Online (Port $port)</span></p>
                            <p>Active Binary: <b>$fileName</b></p>
                            <p>SSE Endpoint: <code>http://$ip:$port/sse</code></p>
                            <h3>Claude Desktop Configuration:</h3>
                            <pre>${getClaudeConfigJson()}</pre>
                        </div>
                    </body>
                    </html>
                    """.trimIndent()
                    val htmlBytes = html.toByteArray(Charsets.UTF_8)

                    writer.print("HTTP/1.1 200 OK\r\n")
                    writer.print("Content-Type: text/html; charset=utf-8\r\n")
                    writer.print("Access-Control-Allow-Origin: *\r\n")
                    writer.print("Content-Length: ${htmlBytes.size}\r\n\r\n")
                    writer.flush()
                    output.write(htmlBytes)
                    output.flush()
                    socket.close()
                }
            }
        } catch (_: Exception) {}
    }

    private fun readBody(reader: BufferedReader, length: Int): String {
        if (length <= 0) return ""
        val chars = CharArray(length)
        var totalRead = 0
        while (totalRead < length) {
            val read = reader.read(chars, totalRead, length - totalRead)
            if (read == -1) break
            totalRead += read
        }
        return String(chars, 0, totalRead)
    }

    private fun handleJsonRpc(jsonStr: String): String {
        return try {
            val req = JsonParser.parseString(jsonStr).asJsonObject
            val id = if (req.has("id")) req.get("id") else null
            val method = if (req.has("method")) req.get("method").asString else ""

            when (method) {
                "initialize" -> {
                    val resp = JsonObject().apply {
                        addProperty("jsonrpc", "2.0")
                        id?.let { add("id", it) }
                        val result = JsonObject().apply {
                            addProperty("protocolVersion", "2024-11-05")
                            val caps = JsonObject().apply {
                                add("tools", JsonObject())
                            }
                            add("capabilities", caps)
                            val serverInfo = JsonObject().apply {
                                addProperty("name", "elftrace-mcp-server")
                                addProperty("version", "1.0.0")
                            }
                            add("serverInfo", serverInfo)
                        }
                        add("result", result)
                    }
                    gson.toJson(resp)
                }

                "notifications/initialized" -> ""

                "tools/list" -> {
                    val resp = JsonObject().apply {
                        addProperty("jsonrpc", "2.0")
                        id?.let { add("id", it) }
                        val result = JsonObject().apply {
                            add("tools", MCPTools.getToolsList())
                        }
                        add("result", result)
                    }
                    gson.toJson(resp)
                }

                "tools/call" -> {
                    val params = if (req.has("params")) req.getAsJsonObject("params") else JsonObject()
                    val toolName = if (params.has("name")) params.get("name").asString else ""
                    val args = if (params.has("arguments")) params.getAsJsonObject("arguments") else JsonObject()

                    val toolResultText = MCPTools.executeTool(toolName, args, viewModel, context)

                    val resp = JsonObject().apply {
                        addProperty("jsonrpc", "2.0")
                        id?.let { add("id", it) }
                        val result = JsonObject().apply {
                            val content = com.google.gson.JsonArray().apply {
                                add(JsonObject().apply {
                                    addProperty("type", "text")
                                    addProperty("text", toolResultText)
                                })
                            }
                            add("content", content)
                            addProperty("isError", false)
                        }
                        add("result", result)
                    }
                    gson.toJson(resp)
                }

                else -> {
                    val resp = JsonObject().apply {
                        addProperty("jsonrpc", "2.0")
                        id?.let { add("id", it) }
                        val error = JsonObject().apply {
                            addProperty("code", -32601)
                            addProperty("message", "Method not found: $method")
                        }
                        add("error", error)
                    }
                    gson.toJson(resp)
                }
            }
        } catch (e: Exception) {
            val resp = JsonObject().apply {
                addProperty("jsonrpc", "2.0")
                val error = JsonObject().apply {
                    addProperty("code", -32700)
                    addProperty("message", "Parse error: ${e.message}")
                }
                add("error", error)
            }
            gson.toJson(resp)
        }
    }

    companion object {
        fun getLocalIpAddress(context: Context): String {
            try {
                val interfaces = NetworkInterface.getNetworkInterfaces()
                while (interfaces.hasMoreElements()) {
                    val iface = interfaces.nextElement()
                    if (iface.isLoopback || !iface.isUp) continue
                    val addrs = iface.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        if (!addr.isLoopbackAddress && addr is Inet4Address) {
                            return addr.hostAddress ?: "127.0.0.1"
                        }
                    }
                }
            } catch (_: Exception) {}
            return "127.0.0.1"
        }
    }
}
