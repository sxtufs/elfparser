package io.elftrace.app.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.elftrace.app.MainActivity
import io.elftrace.app.R
import org.json.JSONObject

/**
 * Keeps the MCP HTTP listener alive while the screen is off, and shows the
 * address and token state in its notification. The native listener lives in
 * this process, so the service is also what makes it survive backgrounding.
 */
class McpServerService : Service() {

    companion object {
        const val ACTION_START = "io.elftrace.app.mcp.START"
        const val ACTION_STOP = "io.elftrace.app.mcp.STOP"
        const val EXTRA_PORT = "port"
        private const val CHANNEL_ID = "mcp_server"
        private const val NOTIFICATION_ID = 4211

        fun start(context: Context, port: Int) {
            val intent = Intent(context, McpServerService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PORT, port)
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, McpServerService::class.java).apply { action = ACTION_STOP }
            )
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            JNIBridge.stopMcp()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val port = intent?.getIntExtra(EXTRA_PORT, McpServer.DEFAULT_PORT) ?: McpServer.DEFAULT_PORT
        // startForeground must come quickly on Android 8+; post a placeholder
        // first, then update it with the real result.
        startForegroundCompat(buildNotification("Starting MCP server…", null))
        val token = McpServer.activeToken(this)
        JNIBridge.setMcpImportDir(cacheDir.absolutePath)
        McpExport.init(this)
        val result = JNIBridge.startMcp("0.0.0.0:$port", token)
        val url = try {
            JSONObject(result).optString("url", "")
        } catch (_: Exception) {
            ""
        }
        val text = if (url.isNotEmpty()) {
            // The bind address is 0.0.0.0, which no client can use: show the
            // address another device on the same network actually reaches.
            McpServer.clientUrl(this).removeSuffix("/mcp")
        } else {
            val error = try {
                JSONObject(result).optString("error", "unknown error")
            } catch (_: Exception) {
                "unknown error"
            }
            "Failed to start: $error"
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(text, url.ifEmpty { null }))
        return START_STICKY
    }

    override fun onDestroy() {
        JNIBridge.stopMcp()
        super.onDestroy()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(text: String, url: String?): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "MCP server", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, McpServerService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("MCP Server")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setShowWhen(false)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
        return builder.build()
    }
}
