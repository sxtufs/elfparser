package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.LoadedPlugin
import io.elftrace.app.core.models.PluginFinding
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen

@Composable
fun PluginsScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val plugins by viewModel.plugins.collectAsState()
    val isRunning by viewModel.isRunningPlugins.collectAsState()
    val bridge by viewModel.bridge.collectAsState()

    var showPasteDialog by remember { mutableStateOf(false) }
    var pasteJsonText by remember { mutableStateOf("") }
    var expandedPluginId by remember { mutableStateOf<String?>(null) }

    val jsonPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            try {
                val text = context.contentResolver.openInputStream(it)?.bufferedReader()?.use { r -> r.readText() }
                if (text != null) {
                    viewModel.importPluginJson(text).onSuccess { manifest ->
                        Toast.makeText(context, "Imported plugin: ${manifest.name}", Toast.LENGTH_SHORT).show()
                        expandedPluginId = manifest.id
                    }.onFailure { err ->
                        Toast.makeText(context, "Invalid plugin: ${err.message}", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Failed to read file: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        // Toolbar
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, colors.border),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Default.Extension, contentDescription = null, tint = colors.primary)
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text("Plugins & Recipes", style = MaterialTheme.typography.titleMedium, color = colors.textPrimary)
                        val totalFindings = plugins.sumOf { it.lastReport?.total_findings ?: 0 }
                        Text(
                            text = "${plugins.size} plugins • $totalFindings findings",
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { showPasteDialog = true }) {
                        Icon(Icons.Default.Add, contentDescription = "Paste JSON Plugin", tint = colors.primary)
                    }
                    IconButton(onClick = { jsonPicker.launch(arrayOf("application/json", "*/*")) }) {
                        Icon(Icons.Default.FileOpen, contentDescription = "Import JSON", tint = colors.primary)
                    }
                    IconButton(
                        enabled = bridge != null && !isRunning,
                        onClick = { viewModel.runAllEnabledPlugins() }
                    ) {
                        if (isRunning) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = colors.primary)
                        } else {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Run All", tint = GreenAccent)
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (bridge == null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.card),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Load an ELF (.so) or APK in the Files tab to run plugins.",
                    color = colors.textSecondary,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(14.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            flingBehavior = rememberMomentumFlingBehavior(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(
                items = plugins,
                key = { it.manifest.id }
            ) { plugin ->
                PluginCard(
                    plugin = plugin,
                    hasBinary = bridge != null,
                    isExpanded = expandedPluginId == plugin.manifest.id,
                    onToggleExpand = {
                        expandedPluginId = if (expandedPluginId == plugin.manifest.id) null else plugin.manifest.id
                    },
                    onToggleEnabled = { viewModel.togglePlugin(plugin.manifest.id) },
                    onRun = {
                        viewModel.runPlugin(plugin.manifest.id)
                        expandedPluginId = plugin.manifest.id
                    },
                    onRemove = { viewModel.removePlugin(plugin.manifest.id) },
                    onJumpToAddress = { addr, sym ->
                        viewModel.selectFunction(addr, sym ?: "0x${addr.toString(16)}")
                        viewModel.codeSubTab.value = 0
                        viewModel.navigateTo(Screen.Code)
                    },
                    onApplyPatch = { finding ->
                        val patch = finding.patch ?: return@PluginCard
                        viewModel.applyPluginPatch(finding.address, patch) { res ->
                            val msg = if (res.success) {
                                "Patched 0x${res.address.toString(16)} (${res.patch_type})"
                            } else {
                                "Patch failed: ${res.error}"
                            }
                            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                        }
                    }
                )
            }
        }
    }

    if (showPasteDialog) {
        AlertDialog(
            onDismissRequest = { showPasteDialog = false },
            containerColor = colors.surface,
            title = { Text("Import Plugin JSON", color = colors.textPrimary) },
            text = {
                Column {
                    Text(
                        "Paste a JSON plugin manifest with byte_pattern, symbol, or string rules.",
                        color = colors.textSecondary,
                        fontSize = 12.sp
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = pasteJsonText,
                        onValueChange = { pasteJsonText = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(200.dp),
                        placeholder = { Text("{\"id\":\"my-plugin\",\"name\":\"...\",\"rules\":[...]}", fontSize = 11.sp) },
                        textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.importPluginJson(pasteJsonText).onSuccess { manifest ->
                        Toast.makeText(context, "Imported: ${manifest.name}", Toast.LENGTH_SHORT).show()
                        expandedPluginId = manifest.id
                        pasteJsonText = ""
                        showPasteDialog = false
                    }.onFailure { err ->
                        Toast.makeText(context, "Error: ${err.message}", Toast.LENGTH_LONG).show()
                    }
                }) {
                    Text("Import", color = colors.primary)
                }
            },
            dismissButton = {
                TextButton(onClick = { showPasteDialog = false }) {
                    Text("Cancel", color = colors.textSecondary)
                }
            }
        )
    }
}

@Composable
private fun PluginCard(
    plugin: LoadedPlugin,
    hasBinary: Boolean,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onToggleEnabled: () -> Unit,
    onRun: () -> Unit,
    onRemove: () -> Unit,
    onJumpToAddress: (Long, String?) -> Unit,
    onApplyPatch: (PluginFinding) -> Unit
) {
    val colors = LocalELFTraceColors.current
    val report = plugin.lastReport

    Card(
        colors = CardDefaults.cardColors(containerColor = colors.card),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, colors.border),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onToggleExpand() },
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = plugin.manifest.name,
                            color = colors.textPrimary,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 14.sp
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = "v${plugin.manifest.version}",
                            color = colors.textSecondary,
                            fontSize = 11.sp
                        )
                    }
                    if (plugin.manifest.description.isNotEmpty()) {
                        Text(
                            text = plugin.manifest.description,
                            color = colors.textSecondary,
                            fontSize = 11.5.sp,
                            maxLines = 2
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "${plugin.manifest.rules.size} rules",
                            color = colors.primary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium
                        )
                        if (report != null) {
                            val countColor = if (report.total_findings > 0) AmberAccent else GreenAccent
                            Text(
                                text = if (report.error != null) "Error" else "${report.total_findings} matches",
                                color = if (report.error != null) RedAccent else countColor,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(
                        checked = plugin.enabled,
                        onCheckedChange = { onToggleEnabled() }
                    )
                    IconButton(enabled = hasBinary, onClick = onRun) {
                        Icon(Icons.Default.PlayArrow, contentDescription = "Run Plugin", tint = if (hasBinary) GreenAccent else colors.textSecondary)
                    }
                    if (!plugin.isBuiltIn) {
                        IconButton(onClick = onRemove) {
                            Icon(Icons.Default.Delete, contentDescription = "Remove", tint = RedAccent)
                        }
                    }
                }
            }

            if (isExpanded && report != null) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = colors.border)
                Spacer(Modifier.height(8.dp))

                if (report.error != null) {
                    Text(
                        text = report.error,
                        color = RedAccent,
                        fontSize = 12.sp
                    )
                } else if (report.findings.isEmpty()) {
                    Text(
                        text = "No matches found for this plugin.",
                        color = colors.textSecondary,
                        fontSize = 12.sp
                    )
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        report.findings.forEach { finding ->
                            PluginFindingRow(
                                finding = finding,
                                onJump = { onJumpToAddress(finding.address, finding.symbol_name) },
                                onPatch = { onApplyPatch(finding) }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PluginFindingRow(
    finding: PluginFinding,
    onJump: () -> Unit,
    onPatch: () -> Unit
) {
    val colors = LocalELFTraceColors.current
    val sevColor = when (finding.severity.lowercase()) {
        "high" -> RedAccent
        "medium" -> AmberAccent
        else -> GreenAccent
    }

    Surface(
        color = colors.surface,
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, colors.border),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onJump() }
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = finding.rule_name,
                    color = colors.textPrimary,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 12.5.sp,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = finding.severity.uppercase(),
                    color = sevColor,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(Modifier.height(2.dp))
            Text(
                text = "0x${finding.address.toString(16)} • ${finding.matched_value}",
                color = colors.primary,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                maxLines = 2
            )
            if (!finding.symbol_name.isNullOrEmpty()) {
                Text(
                    text = "Symbol: ${finding.symbol_name}",
                    color = colors.textSecondary,
                    fontSize = 11.sp,
                    maxLines = 1
                )
            }
            if (finding.description.isNotEmpty()) {
                Text(
                    text = finding.description,
                    color = colors.textSecondary,
                    fontSize = 11.sp
                )
            }
            if (finding.patch != null) {
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onJump,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.height(30.dp)
                    ) {
                        Text("Inspect", fontSize = 11.sp)
                    }
                    Button(
                        onClick = onPatch,
                        colors = ButtonDefaults.buttonColors(containerColor = AmberAccent),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.height(30.dp)
                    ) {
                        Text("Patch (${finding.patch.mode}: ${finding.patch.value})", fontSize = 11.sp)
                    }
                }
            }
        }
    }
}
