package io.elftrace.app.ui.components

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import io.elftrace.app.core.McpServer
import io.elftrace.app.core.McpServerService
import io.elftrace.app.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * MCP server toggle: switch and client URLs, plus a settings panel that holds
 * the port, the access token and the token switch.
 *
 * Copied from MT Manager's shape — a switch you flip in the app, an address to
 * paste into the client, and a secret the client may be required to send. The
 * server binds `0.0.0.0`; the token switch is off by default and the Settings
 * panel turns it on for clients that can send headers, and changes the port.
 */
@Composable
fun McpServerDialog(
    onDismiss: () -> Unit,
    isDark: Boolean,
    onToggleTheme: () -> Unit,
) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val scope = rememberCoroutineScope()

    var running by remember { mutableStateOf(McpServer.isRunning()) }
    var url by remember { mutableStateOf(McpServer.clientUrl(context)) }
    var token by remember { mutableStateOf(McpServer.token(context)) }

    var showSettings by remember { mutableStateOf(false) }
    var portText by remember { mutableStateOf(McpServer.port(context).toString()) }
    var tokenRequired by remember { mutableStateOf(McpServer.tokenRequired(context)) }
    var portError by remember { mutableStateOf(false) }

    fun refresh() {
        url = McpServer.clientUrl(context)
        token = McpServer.token(context)
        portText = McpServer.port(context).toString()
        tokenRequired = McpServer.tokenRequired(context)
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

    fun applySettings() {
        val port = portText.trim().toIntOrNull()
        if (port == null || !McpServer.isValidPort(port)) {
            portError = true
            return
        }
        val restart = running &&
            (port != McpServer.port(context) || tokenRequired != McpServer.tokenRequired(context))
        McpServer.setPort(context, port)
        McpServer.setTokenRequired(context, tokenRequired)
        refresh()
        if (restart) {
            // The listener closes on its own thread, so give it time before the
            // new instance tries the same port.
            McpServerService.stop(context)
            scope.launch {
                delay(400)
                McpServerService.start(context, McpServer.port(context))
                delay(400)
                running = McpServer.isRunning()
                refresh()
            }
        }
        showSettings = false
        Toast.makeText(
            context,
            if (restart) "Saved — server restarted" else "Settings saved",
            Toast.LENGTH_SHORT
        ).show()
    }

    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { enableServer() }

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
                Row(verticalAlignment = Alignment.Top) {
                    Column(Modifier.weight(1f).padding(end = 8.dp)) {
                        Text(
                            if (showSettings) "MCP Settings" else "MCP Server",
                            color = colors.textPrimary, fontSize = 17.sp, fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            if (showSettings) "Port and access control for the MCP server."
                            else "Let an AI agent call ELFTrace tools through the Model Context Protocol.",
                            color = colors.textSecondary, fontSize = 12.sp, lineHeight = 16.sp
                        )
                    }
                    IconButton(
                        onClick = onToggleTheme,
                        modifier = Modifier.size(36.dp)
                    ) {
                        ThemeToggleIcon(
                            isDark = isDark,
                            tint = if (isDark) Color(0xFFFFD54F) else colors.textSecondary
                        )
                    }
                }
                Spacer(Modifier.height(14.dp))

                if (showSettings) {
                    SettingsBody(
                        portText = portText,
                        portError = portError,
                        token = token,
                        tokenRequired = tokenRequired,
                        onPortChange = { input ->
                            portText = input.filter(Char::isDigit).take(5)
                            portError = false
                        },
                        onTokenRequiredChange = { tokenRequired = it }
                    )
                } else {
                    ServerBody(
                        running = running,
                        url = url,
                        onToggle = { toggle(it) }
                    )
                }

                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                    if (showSettings) {
                        TextButton(onClick = { showSettings = false }) {
                            Text("Cancel", color = colors.textSecondary)
                        }
                        TextButton(onClick = { applySettings() }) { Text("Save", color = CyanAccent) }
                    } else {
                        TextButton(onClick = { showSettings = true }) {
                            Text("Settings", color = CyanAccent)
                        }
                        TextButton(onClick = onDismiss) { Text("Close", color = colors.textSecondary) }
                    }
                }
            }
        }
    }
}

@Composable
private fun ServerBody(
    running: Boolean,
    url: String,
    onToggle: (Boolean) -> Unit
) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current

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
        ThemedSwitch(checked = running, onCheckedChange = onToggle)
    }

    if (running) {
        Spacer(Modifier.height(14.dp))
        EndpointRow(
            label = "Local address",
            value = McpServer.localUrl(context),
            onCopied = {
                copyToClipboard(context, McpServer.localUrl(context))
                Toast.makeText(context, "URL copied", Toast.LENGTH_SHORT).show()
            }
        )
        EndpointRow(
            label = "LAN address",
            value = url,
            onCopied = {
                copyToClipboard(context, url)
                Toast.makeText(context, "URL copied", Toast.LENGTH_SHORT).show()
            }
        )
    }
}

@Composable
private fun SettingsBody(
    portText: String,
    portError: Boolean,
    token: String,
    tokenRequired: Boolean,
    onPortChange: (String) -> Unit,
    onTokenRequiredChange: (Boolean) -> Unit
) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current

    FieldLabel("Port")
    Spacer(Modifier.height(4.dp))
    OutlinedTextField(
        value = portText,
        onValueChange = onPortChange,
        singleLine = true,
        isError = portError,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        textStyle = LocalTextStyle.current.copy(
            fontFamily = FontFamily.Monospace, fontSize = 13.sp
        ),
        modifier = Modifier
            .fillMaxWidth()
            .height(46.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = colors.primary,
            unfocusedBorderColor = colors.border,
            focusedTextColor = colors.textPrimary,
            unfocusedTextColor = colors.textPrimary,
            cursorColor = colors.primary
        )
    )
    Text(
        if (portError) "Enter a port from ${McpServer.MIN_PORT} to ${McpServer.MAX_PORT}"
        else "Available range ${McpServer.MIN_PORT}–${McpServer.MAX_PORT}",
        color = if (portError) RedAccent else colors.textSecondary,
        fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp)
    )
    Spacer(Modifier.height(12.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            "Enable token",
            color = colors.textPrimary, fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(1f)
        )
        ThemedSwitch(checked = tokenRequired, onCheckedChange = onTokenRequiredChange)
    }
    Spacer(Modifier.height(4.dp))
    Text(
        "When enabled, MCP clients need an access token to connect. " +
            "Paste the token directly into the Token field. " +
            "For an Authorization request header, use Bearer <token>.",
        color = colors.textSecondary, fontSize = 11.sp, lineHeight = 15.sp
    )
    if (tokenRequired) {
        Spacer(Modifier.height(12.dp))
        FieldLabel("Token")
        CopyRow(
            value = token,
            monospace = true,
            maxLines = 3,
            onCopied = {
                copyToClipboard(context, token)
                Toast.makeText(context, "Token copied", Toast.LENGTH_SHORT).show()
            }
        )
    }
}

/**
 * A quieter switch than the Material default: an outlined pill with no filled
 * track, one theme-coloured thumb, and 36×20dp instead of 52×32dp so it sits
 * level with the label text instead of shouting.
 */
@Composable
private fun ThemedSwitch(checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    val colors = LocalELFTraceColors.current
    val progress by animateFloatAsState(if (checked) 1f else 0f, label = "switch")
    val thumbColor by animateColorAsState(
        if (checked) colors.primary else colors.textSecondary.copy(alpha = 0.55f),
        label = "switchThumb"
    )
    val trackWidth = 36.dp
    val trackHeight = 20.dp
    val inset = 3.dp
    val thumbSize = 12.dp
    val interactionSource = remember { MutableInteractionSource() }
    Box(
        // 44×32dp tap target around the 36×20dp pill, flush with the row's
        // right edge like the M3 switch it replaces. No indication: the
        // ripple/state layer was the grey block the pill sat inside on tap.
        modifier = Modifier
            .size(width = 44.dp, height = 32.dp)
            .toggleable(
                value = checked,
                interactionSource = interactionSource,
                indication = null,
                role = Role.Switch,
                onValueChange = onCheckedChange
            ),
        contentAlignment = Alignment.CenterEnd
    ) {
        Box(
            modifier = Modifier
                .size(trackWidth, trackHeight)
                .clip(CircleShape)
                .border(
                    1.dp,
                    if (checked) colors.primary.copy(alpha = 0.75f) else colors.border,
                    CircleShape
                )
        ) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .offset(x = inset + (trackWidth - inset * 2 - thumbSize) * progress)
                    .size(thumbSize)
                    .background(thumbColor, CircleShape)
            )
        }
    }
}

@Composable
private fun CopyRow(value: String, monospace: Boolean, maxLines: Int = 1, onCopied: () -> Unit) {
    val colors = LocalELFTraceColors.current
    val shape = RoundedCornerShape(8.dp)
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp)
            // `surface` is white in light mode, the same colour as the dialog
            // card, so the chip vanished there; `bg` plus a hairline reads as
            // a field in both themes.
            .background(if (colors.isDark) colors.surface else colors.bg, shape)
            .border(1.dp, colors.border.copy(alpha = if (colors.isDark) 0f else 1f), shape)
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
