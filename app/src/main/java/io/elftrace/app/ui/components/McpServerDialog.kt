package io.elftrace.app.ui.components

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import io.elftrace.app.core.JNIBridge
import io.elftrace.app.core.McpServer
import io.elftrace.app.core.McpServerService
import io.elftrace.app.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File

/**
 * MCP server toggle: switch, client URL and access token.
 *
 * Copied from MT Manager's shape — a switch you flip in the app, an address to
 * paste into the client, and a secret the client must send. The server binds
 * `0.0.0.0`, so the token is not optional.
 */
@Composable
fun McpServerDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val scope = rememberCoroutineScope()

    var running by remember { mutableStateOf(McpServer.isRunning()) }
    var url by remember { mutableStateOf(McpServer.clientUrl(context)) }
    var token by remember { mutableStateOf(McpServer.token(context)) }
    var showToken by remember { mutableStateOf(false) }
    var lastImport by remember { mutableStateOf<String?>(null) }

    fun refresh() {
        url = McpServer.clientUrl(context)
        token = McpServer.token(context)
    }

    fun enableServer() {
        McpServerService.start(context, McpServer.port(context))
        scope.launch {
            delay(300)
            running = McpServer.isRunning()
            refresh()
            if (!running) Toast.makeText(context, "MCP server failed to start", Toast.LENGTH_SHORT).show()
        }
    }

    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { enableServer() }

    // Scoped storage keeps the agent out of /storage/emulated/0, so a file the
    // user wants analysed goes through the picker into app storage, and becomes
    // the MCP "current file" straight away.
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val copied = runCatching {
                val name = pickedDisplayName(context, uri) ?: "import.so"
                val safe = name.replace(Regex("[^A-Za-z0-9._-]"), "_")
                val dest = File(context.cacheDir, "mcp_import_$safe")
                context.contentResolver.openInputStream(uri)?.use { input ->
                    dest.outputStream().use { output -> input.copyTo(output) }
                } ?: error("cannot open the picked file")
                dest.absolutePath
            }.getOrNull()
            if (copied == null) {
                Toast.makeText(context, "Import failed", Toast.LENGTH_SHORT).show()
            } else {
                JNIBridge.setCurrentFile(copied)
                lastImport = copied
                Toast.makeText(context, "Imported — the agent can analyse it now", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun toggle(on: Boolean) {
        if (!on) {
            McpServerService.stop(context)
            scope.launch {
                delay(150)
                running = McpServer.isRunning()
            }
            return
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            enableServer()
        }
    }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.card),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(18.dp)) {
                Text("MCP Server", color = colors.textPrimary, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Let an AI agent on this Wi-Fi call ELFTrace tools through the Model Context Protocol.",
                    color = colors.textSecondary, fontSize = 12.sp, lineHeight = 16.sp
                )
                Spacer(Modifier.height(14.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            if (running) "Server running" else "Server off",
                            color = if (running) GreenAccent else colors.textSecondary,
                            fontSize = 13.sp, fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            if (running) "Listening on all interfaces" else "Turn on to accept connections",
                            color = colors.textSecondary, fontSize = 11.sp
                        )
                    }
                    Switch(
                        checked = running,
                        onCheckedChange = { toggle(it) },
                        colors = SwitchDefaults.colors(checkedTrackColor = GreenAccent)
                    )
                }

                if (running) {
                    Spacer(Modifier.height(14.dp))
                    FieldLabel("Endpoint")
                    EndpointRow(
                        label = "This phone",
                        value = McpServer.localUrl(context),
                        onCopied = {
                            copyToClipboard(context, McpServer.localUrl(context))
                            Toast.makeText(context, "URL copied", Toast.LENGTH_SHORT).show()
                        }
                    )
                    EndpointRow(
                        label = "Same Wi-Fi network",
                        value = url,
                        onCopied = {
                            copyToClipboard(context, url)
                            Toast.makeText(context, "URL copied", Toast.LENGTH_SHORT).show()
                        }
                    )
                    Spacer(Modifier.height(12.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "TOKEN", color = colors.textSecondary, fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold, letterSpacing = 0.8.sp,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            if (showToken) "Hide" else "Show",
                            color = CyanAccent, fontSize = 11.sp,
                            modifier = Modifier.clickable { showToken = !showToken }
                        )
                    }
                    CopyRow(
                        value = if (showToken) token else "•".repeat(24),
                        monospace = true,
                        maxLines = 2,
                        onCopied = {
                            copyToClipboard(context, token)
                            Toast.makeText(context, "Token copied", Toast.LENGTH_SHORT).show()
                        }
                    )
                    Text(
                        "Header: Authorization: Bearer <token>, or the token alone",
                        color = colors.textSecondary, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp)
                    )
                }

                Spacer(Modifier.height(14.dp))
                FieldLabel("Import for agent analysis")
                Text(
                    "Android hides /storage from tools. Pick a file here and the agent reaches it in app storage.",
                    color = colors.textSecondary, fontSize = 10.5.sp, lineHeight = 14.sp,
                    modifier = Modifier.padding(top = 4.dp)
                )
                TextButton(onClick = { importLauncher.launch(arrayOf("*/*")) }) {
                    Text("Import a file…", color = CyanAccent)
                }
                lastImport?.let { path ->
                    CopyRow(
                        value = path,
                        monospace = true,
                        maxLines = 2,
                        onCopied = {
                            copyToClipboard(context, path)
                            Toast.makeText(context, "Path copied", Toast.LENGTH_SHORT).show()
                        }
                    )
                }

                Spacer(Modifier.height(14.dp))
                Text(
                    "Anyone on this network with the token can read the binaries you open. " +
                        "Turn the server off when you are done.",
                    color = AmberAccent, fontSize = 10.5.sp, lineHeight = 14.sp
                )

                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                    TextButton(onClick = onDismiss) { Text("Close", color = colors.textSecondary) }
                }
            }
        }
    }
}

@Composable
private fun CopyRow(value: String, monospace: Boolean, maxLines: Int = 1, onCopied: () -> Unit) {
    val colors = LocalELFTraceColors.current
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp)
            .background(colors.surface, RoundedCornerShape(8.dp))
            .padding(start = 10.dp, end = 2.dp, top = 6.dp, bottom = 6.dp)
    ) {
        Text(
            value,
            color = colors.textPrimary,
            fontSize = 11.sp,
            lineHeight = 15.sp,
            fontFamily = if (monospace) FontFamily.Monospace else null,
            maxLines = maxLines,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        Text(
            "COPY", color = CyanAccent, fontSize = 10.sp, fontWeight = FontWeight.Bold,
            letterSpacing = 0.5.sp,
            modifier = Modifier
                .clickable(onClick = onCopied)
                .padding(horizontal = 8.dp, vertical = 6.dp)
        )
    }
}

@Composable
private fun FieldLabel(text: String) {
    val colors = LocalELFTraceColors.current
    Text(
        text.uppercase(),
        color = colors.textSecondary,
        fontSize = 10.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.8.sp
    )
}

@Composable
private fun EndpointRow(label: String, value: String, onCopied: () -> Unit) {
    val colors = LocalELFTraceColors.current
    Text(
        label, color = colors.textSecondary, fontSize = 10.sp,
        modifier = Modifier.padding(top = 8.dp)
    )
    CopyRow(value = value, monospace = true, onCopied = onCopied)
}

private fun copyToClipboard(context: Context, text: String) {
    val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    manager.setPrimaryClip(ClipData.newPlainText("ELFTrace MCP", text))
}

private fun pickedDisplayName(context: Context, uri: android.net.Uri): String? =
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
