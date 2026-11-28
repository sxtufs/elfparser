package io.elftrace.app.core

import android.content.Context
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.SecureRandom

/**
 * Settings and helpers for the in-app MCP server.
 *
 * The token is generated once and kept in SharedPreferences: while it is on it
 * is the only thing standing between the user's Wi-Fi and their binaries, so it
 * must be long, random and stable across app restarts. The user may turn it off
 * in the dialog's settings, which makes every device on the network trusted.
 */
object McpServer {
    const val DEFAULT_PORT = 8765

    /** Lowest port the user may pick: privileged ports need root. */
    const val MIN_PORT = 1024
    const val MAX_PORT = 65535

    private const val PREFS = "mcp_server"
    private const val KEY_TOKEN = "token"
    private const val KEY_PORT = "port"
    private const val KEY_TOKEN_REQUIRED = "token_required"

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

    /** False when the user turned the barrier off in the dialog's settings. */
    fun tokenRequired(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_TOKEN_REQUIRED, true)

    fun setTokenRequired(context: Context, required: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_TOKEN_REQUIRED, required).apply()
    }

    fun setPort(context: Context, port: Int) {
        require(isValidPort(port)) { "port must be $MIN_PORT..$MAX_PORT" }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putInt(KEY_PORT, port).apply()
    }

    fun isValidPort(port: Int): Boolean = port in MIN_PORT..MAX_PORT

    /** The token to hand the native server: empty means "no auth". */
    fun activeToken(context: Context): String =
        if (tokenRequired(context)) token(context) else ""

    /**
     * Wi-Fi and USB tethering first: those are the interfaces another device can
     * actually reach. Mobile data is skipped outright, because carrier-grade NAT
     * hands out 10.x addresses that look site-local but route nowhere else.
     */
    fun lanAddress(): String? = try {
        NetworkInterface.getNetworkInterfaces()
            .asSequence()
            .filter { it.isUp && !it.isLoopback }
            .filterNot { isCellularInterface(it.name) }
            .sortedBy { interfaceRank(it.name) }
            .flatMap { it.inetAddresses.asSequence() }
            .filterIsInstance<Inet4Address>()
            .firstOrNull { it.isSiteLocalAddress }
            ?.hostAddress
    } catch (_: Exception) {
        null
    }

    /** URL for an MCP client running on this same phone. */
    fun localUrl(context: Context): String = "http://127.0.0.1:${port(context)}/mcp"

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

/** Lower is better: a Wi-Fi or tethering address is one another device can reach. */
internal fun interfaceRank(name: String): Int = when {
    name.startsWith("wlan") || name.startsWith("swlan") || name.startsWith("ap") -> 0
    name.startsWith("eth") || name.startsWith("rndis") || name.startsWith("usb") -> 1
    else -> 2
}

/**
 * Mobile-data interfaces are excluded rather than ranked: their carrier-grade
 * NAT addresses are site-local but only exist inside the carrier's network.
 */
internal fun isCellularInterface(name: String): Boolean =
    listOf("rmnet", "rev_rmnet", "ccmni", "pdp", "clat", "dummy", "v4-rmnet")
        .any { name.startsWith(it) }
