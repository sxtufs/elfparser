package io.elftrace.app.core

import android.content.Context

/**
 * Export sink for the native MCP server. `save` runs inside `libelftrace.so`,
 * which cannot write to shared storage, so it calls back here (JNI static
 * `publish`) and the bytes go to public Download/ through [BinaryExport].
 */
object McpExport {
    @Volatile
    private var appContext: Context? = null

    /** Called once from the MCP foreground service before the server starts. */
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** JNI entry point. Returns the path shown to the client, or throws. */
    @JvmStatic
    fun publish(name: String, bytes: ByteArray): String {
        val context = appContext ?: throw IllegalStateException("MCP export is not initialized")
        return BinaryExport.toDownloads(context, name, bytes)
    }
}
