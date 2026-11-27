package io.elftrace.app.core

import android.content.Context
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.SecureRandom

/**
 * Settings and helpers for the in-app MCP server.
 *
 * The token is generated once and kept in SharedPreferences: it is the only
 * thing standing between the user's Wi-Fi and their binaries, so it must be
 * long, random and stable across app restarts.
 */
object McpServer {
    const val DEFAULT_PORT = 8765

    private const val PREFS = "mcp_server"
    private const val KEY_TOKEN = "token"
    private const val KEY_PORT = "port"

    fun token(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.getString(KEY_TOKEN, null)?.let { if (it.isNotEmpty()) return it }
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        prefs.edit().putString(KEY_TOKEN, token).apply()
        return token
    }

    fun regenerateToken(context: Context): String {
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_TOKEN, token).apply()
        return token
    }

    fun port(context: Context): Int =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt(KEY_PORT, DEFAULT_PORT)

    fun lanAddress(): String? = try {
        NetworkInterface.getNetworkInterfaces()
            .asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.asSequence() }
            .filterIsInstance<Inet4Address>()
            .firstOrNull { it.isSiteLocalAddress }
            ?.hostAddress
    } catch (_: Exception) {
        null
    }

    fun clientUrl(context: Context): String {
        val host = lanAddress() ?: "127.0.0.1"
        return "http://$host:${port(context)}/mcp"
    }

    /** Whether the native server is running in this process. */
    fun isRunning(): Boolean = try {
        JNIBridge.mcpStatus().contains("\"running\":true")
    } catch (_: Throwable) {
        false
    }
}
