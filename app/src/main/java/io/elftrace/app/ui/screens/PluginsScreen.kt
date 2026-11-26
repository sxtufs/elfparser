package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.gson.Gson
import io.elftrace.app.core.models.LoadedPlugin
import io.elftrace.app.core.models.PluginFinding
import io.elftrace.app.core.models.PluginManifest
import io.elftrace.app.core.models.PluginPatch
import io.elftrace.app.core.models.PluginRule
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
    val loadErrors by viewModel.builtInLoadErrors.collectAsState()

    val expandedPluginId by viewModel.expandedPluginId.collectAsState()
    var showAddDialog by remember { mutableStateOf(false) }
    var ruleType by remember { mutableStateOf("symbol") }
    var rulePattern by remember { mutableStateOf("") }
    var rulePatch by remember { mutableStateOf("none") }
    // Set when Patch All is pressed on a plugin whose patches deserve a
    // confirmation (generic symbol names could match benign functions).
    var confirmPatchAllFor by remember { mutableStateOf<LoadedPlugin?>(null) }
    var showEditor by remember { mutableStateOf(false) }

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
                Column(modifier = Modifier.weight(1f)) {
                    Text("Plugins & Recipes", style = MaterialTheme.typography.titleMedium, color = colors.textPrimary)
                    val totalFindings = plugins.sumOf { it.lastReport?.total_findings ?: 0 }
                    Text(
                        text = "${plugins.size} plugins • $totalFindings findings",
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.textSecondary
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { showEditor = true }) {
                        Icon(Icons.Default.Code, contentDescription = "Rhai Editor", tint = AmberAccent)
                    }
                    IconButton(onClick = { showAddDialog = true }) {
                        Icon(Icons.Default.Add, contentDescription = "Add Quick Rule", tint = colors.primary)
                    }
                    IconButton(
                        enabled = bridge != null && !isRunning,
                        onClick = { viewModel.runAllEnabledPlugins() }
                    ) {
                        if (isRunning) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = colors.primary)
                        } else {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Run All", tint = colors.primary)
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (loadErrors.isNotEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.card),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, RedAccent),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "${loadErrors.size} built-in plugin(s) failed to load",
                        color = RedAccent,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    loadErrors.forEach { err ->
                        Text(
                            text = "• $err",
                            color = colors.textSecondary,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
        }

        if (bridge == null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.card),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Load a .so or APK in the Files tab to run plugins.",
                    color = colors.textSecondary,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(14.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            state = viewModel.pluginsListState,
            flingBehavior = rememberMomentumFlingBehavior(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(
                items = plugins,
                key = { it.manifest.id }
            ) { plugin ->
                PluginCard(
                    plugin = plugin,
                    isExpanded = expandedPluginId == plugin.manifest.id,
                    onToggleExpand = {
                        val willExpand = expandedPluginId != plugin.manifest.id
                        viewModel.expandedPluginId.value = if (willExpand) plugin.manifest.id else null
                        if (willExpand && bridge != null && plugin.lastReport == null) {
                            viewModel.runPlugin(plugin.manifest.id)
                        }
                    },
                    onRemove = { viewModel.removePlugin(plugin.manifest.id) },
                    onJumpToAddress = { addr, sym, ruleType ->
                        val isData = ruleType == "string" || ruleType == "str" ||
                            ruleType == "byte_pattern" || ruleType == "bytes"
                        viewModel.selectFunction(addr, sym ?: "0x${addr.toString(16)}")
                        if (isData) {
                            // String/byte findings are data in .rodata; disassembling
                            // them yields garbage, so position the Hex view at the hit.
                            viewModel.loadHexDump(addr)
                            viewModel.codeSubTab.value = 3
                        } else {
                            viewModel.codeSubTab.value = 0
                        }
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
                    },
                    onPatchAll = {
                        if (plugin.manifest.id == "builtin-iap-license") {
                            // Its rules match generic names (isPremium, etc.),
                            // so batch-patching deserves one confirmation.
                            confirmPatchAllFor = plugin
                        } else {
                            val patchable = plugin.lastReport?.findings?.filter { it.patch != null } ?: emptyList()
                            if (patchable.isEmpty()) {
                                Toast.makeText(context, "No patchable findings", Toast.LENGTH_SHORT).show()
                            } else {
                                viewModel.applyAllPluginPatches(patchable) { applied, skipped ->
                                    Toast.makeText(
                                        context,
                                        "Patched " + applied + (if (skipped > 0) ", skipped " + skipped else ""),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            }
                        }
                    }
                )
            }
        }
    }

    if (confirmPatchAllFor != null) {
        val target = confirmPatchAllFor!!
        Dialog(onDismissRequest = { confirmPatchAllFor = null }) {
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = colors.surface,
                border = BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Patch all in ${target.manifest.name}?",
                        style = MaterialTheme.typography.titleMedium,
                        color = colors.textPrimary
                    )
                    Text(
                        text = "These rules match generic symbol names that benign functions can also define. Review each finding, or apply all patches now?",
                        color = colors.textSecondary,
                        fontSize = 12.sp
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        TextButton(onClick = { confirmPatchAllFor = null }) {
                            Text("Cancel", color = colors.textSecondary)
                        }
                        TextButton(onClick = {
                            confirmPatchAllFor = null
                            val patchable = target.lastReport?.findings?.filter { it.patch != null } ?: emptyList()
                            if (patchable.isEmpty()) {
                                Toast.makeText(context, "No patchable findings", Toast.LENGTH_SHORT).show()
                            } else {
                                viewModel.applyAllPluginPatches(patchable) { applied, skipped ->
                                    Toast.makeText(
                                        context,
                                        "Patched " + applied + (if (skipped > 0) ", skipped " + skipped else ""),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            }
                        }) {
                            Text("Patch all", color = AmberAccent, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }
    }

    if (showEditor) {
        RhaiEditorDialog(
            viewModel = viewModel,
            onClose = { showEditor = false }
        )
    }

    if (showAddDialog) {
        Dialog(onDismissRequest = { showAddDialog = false }) {
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = colors.surface,
                border = BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Quick Custom Rule",
                        style = MaterialTheme.typography.titleMedium,
                        color = colors.textPrimary
                    )

                    Text("Type", color = colors.textSecondary, fontSize = 11.5.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf("symbol" to "Symbol", "string" to "String", "byte_pattern" to "Bytes").forEach { (key, label) ->
                            FilterChip(
                                selected = ruleType == key,
                                onClick = { ruleType = key },
                                label = { Text(label, fontSize = 11.sp) }
                            )
                        }
                    }

                    OutlinedTextField(
                        value = rulePattern,
                        onValueChange = { rulePattern = it },
                        label = { Text("Pattern", fontSize = 12.sp) },
                        placeholder = {
                            val hint = when (ruleType) {
                                "byte_pattern" -> "FD 7B BF A9 ?? ?? ?? 94"
                                "string" -> "https://api."
                                else -> "isVip"
                            }
                            Text(hint, fontSize = 12.sp)
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Text("Optional Patch", color = colors.textSecondary, fontSize = 11.5.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf("none" to "None", "ret_true" to "True", "ret_false" to "False", "nop" to "NOP").forEach { (key, label) ->
                            FilterChip(
                                selected = rulePatch == key,
                                onClick = { rulePatch = key },
                                label = { Text(label, fontSize = 11.sp) }
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        TextButton(onClick = { showAddDialog = false }) {
                            Text("Cancel", color = colors.textSecondary)
                        }
                        TextButton(
                            enabled = rulePattern.isNotBlank(),
                            onClick = {
                                val pat = rulePattern.trim()
                                val patchObj = if (rulePatch == "none") null else PluginPatch(mode = "quick", value = rulePatch, offset = 0)
                                val manifest = PluginManifest(
                                    id = "custom-${System.currentTimeMillis()}",
                                    name = "Custom: $pat",
                                    version = "1.0",
                                    author = "User",
                                    description = "Custom $ruleType search",
                                    rules = listOf(
                                        PluginRule(
                                            name = pat,
                                            type = ruleType,
                                            pattern = pat,
                                            severity = "HIGH",
                                            description = "Custom $ruleType match",
                                            patch = patchObj
                                        )
                                    )
                                )
                                val json = Gson().toJson(manifest)
                                viewModel.importPluginJson(json).onSuccess {
                                    if (bridge != null) {
                                        viewModel.runPlugin(manifest.id)
                                    }
                                    viewModel.expandedPluginId.value = manifest.id
                                    rulePattern = ""
                                    rulePatch = "none"
                                    showAddDialog = false
                                }
                            }
                        ) {
                            Text("Add", color = colors.primary)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PluginCard(
    plugin: LoadedPlugin,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onRemove: () -> Unit,
    onJumpToAddress: (Long, String?, String) -> Unit,
    onApplyPatch: (PluginFinding) -> Unit,
    onPatchAll: () -> Unit
) {
    val colors = LocalELFTraceColors.current
    val report = plugin.lastReport
    val patchable = report?.findings?.count { it.patch != null } ?: 0

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
                    Text(
                        text = plugin.manifest.name,
                        color = colors.textPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp
                    )
                    if (plugin.manifest.description.isNotEmpty()) {
                        Text(
                            text = plugin.manifest.description,
                            color = colors.textSecondary,
                            fontSize = 11.sp,
                            lineHeight = 14.sp,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                            letterSpacing = 0.1.sp
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (!plugin.manifest.script.isNullOrBlank()) {
                            Text(
                                text = "RHAI",
                                color = AmberAccent,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        if (plugin.manifest.rules.isNotEmpty()) {
                            Text(
                                text = "${plugin.manifest.rules.size} rules",
                                color = colors.primary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }
                        if (report != null) {
                            val countColor = if (report.total_findings > 0) AmberAccent else GreenAccent
                            Text(
                                text = if (report.error != null) "Error" else "${report.total_findings} matches",
                                color = if (report.error != null) RedAccent else countColor,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                            if (report.truncated) {
                                Text(
                                    text = "capped",
                                    color = AmberAccent,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                }

                if (patchable > 0) {
                    Button(
                        onClick = onPatchAll,
                        colors = ButtonDefaults.buttonColors(containerColor = colors.card, contentColor = colors.annotation),
                        border = BorderStroke(1.dp, colors.border),
                        shape = RoundedCornerShape(50),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text("Patch All", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    }
                }

                if (!plugin.isBuiltIn) {
                    IconButton(onClick = onRemove) {
                        Icon(Icons.Default.Delete, contentDescription = "Remove", tint = RedAccent)
                    }
                }
            }

            if (isExpanded && report != null) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = colors.border)
                Spacer(Modifier.height(8.dp))

                // Batch-apply action lives as a small chip in the card header;
                // nothing shown here when no finding carries a patch.

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
                    if (report.truncated) {
                        Surface(
                            color = colors.surface,
                            shape = RoundedCornerShape(6.dp),
                            border = BorderStroke(1.dp, AmberAccent.copy(alpha = 0.5f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = "Results capped at ${report.total_findings} — more matches exist and were not shown.",
                                color = AmberAccent,
                                fontSize = 11.sp,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)
                            )
                        }
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        report.findings.forEach { finding ->
                            PluginFindingRow(
                                finding = finding,
                                onJump = { onJumpToAddress(finding.address, finding.symbol_name, finding.rule_type) },
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
            val addrHex = "0x${finding.address.toString(16)}"
            val addrLine = if (finding.matched_value.equals(addrHex, ignoreCase = true) || finding.matched_value.isBlank()) {
                addrHex
            } else {
                "$addrHex • ${finding.matched_value}"
            }
            Text(
                text = addrLine,
                color = colors.primary,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                maxLines = 2
            )
            if (!finding.symbol_name.isNullOrEmpty() && finding.symbol_name != finding.matched_value) {
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
            if (finding.patch != null && finding.address != 0L) {
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onJump,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.height(30.dp)
                    ) {
                        Text("Inspect", fontSize = 11.sp)
                    }
                    val patchLabel = when (finding.patch.value.lowercase()) {
                        "ret_true", "return_true", "true" -> "Patch: True"
                        "ret_false", "return_false", "false" -> "Patch: False"
                        "ret_void", "return_void", "void" -> "Patch: Void"
                        "nop" -> "Patch: NOP"
                        else -> "Patch (${finding.patch.value})"
                    }
                    Button(
                        onClick = onPatch,
                        colors = ButtonDefaults.buttonColors(containerColor = AmberAccent),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                        modifier = Modifier.height(30.dp)
                    ) {
                        Text(patchLabel, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}

private data class RhaiTemplate(val title: String, val description: String, val script: String)

private val RHAI_TEMPLATES = listOf(
    RhaiTemplate(
        "Starter",
        "Report each symbol matching a name you type",
        """let syms = find_symbols("your_symbol");
for s in syms {
  report("My Finding", s.address, "MEDIUM", "Matched " + s.name);
}"""
    ),
    RhaiTemplate(
        "String hunt",
        "Report every string containing a keyword",
        """let hits = find_strings("keyword");
for h in hits {
  report("String Hit", h.address, "INFO", h.value);
}"""
    ),
    RhaiTemplate(
        "Callers of a function",
        "Trace who calls an import, optionally patch",
        """let syms = find_symbols("target_function");
for s in syms {
  let xrefs = get_xrefs(s.address);
  for x in xrefs {
    report_patch("Caller of " + s.name, x.from, "HIGH", x.instruction, "quick", "nop");
  }
}"""
    ),
    RhaiTemplate(
        "Instruction pattern",
        "Disassemble a function and match a mnemonic",
        """let syms = find_symbols("JNI_OnLoad");
for s in syms {
  let insns = disasm(s.address, 128);
  for ins in insns {
    if ins.mnemonic == "svc" || ins.mnemonic == "syscall" {
      report("Direct Syscall", ins.address, "HIGH", ins.mnemonic + " " + ins.op_str);
    }
  }
}"""
    )
)

@Composable
private fun RhaiEditorDialog(
    viewModel: ELFTraceViewModel,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    var script by rememberSaveable { mutableStateOf(RHAI_TEMPLATES[0].script) }
    var template by rememberSaveable { mutableStateOf(RHAI_TEMPLATES[0].title) }
    var autoRun by rememberSaveable { mutableStateOf(true) }

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)
    ) {
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = colors.surface,
            border = BorderStroke(1.dp, colors.border),
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.78f)
                .padding(start = 16.dp, end = 16.dp, top = 16.dp)
                .navigationBarsPadding()
                .imePadding()
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Text(
                    text = "Rhai Editor",
                    style = MaterialTheme.typography.titleMedium,
                    color = colors.textPrimary,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "Write a script, save it as a plugin, run it against the loaded binary.",
                    color = colors.textSecondary,
                    fontSize = 11.sp,
                    lineHeight = 14.sp,
                    modifier = Modifier.padding(top = 2.dp, bottom = 8.dp)
                )

                // Template picker
                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(RHAI_TEMPLATES.size) { idx ->
                        val t = RHAI_TEMPLATES[idx]
                        FilterChip(
                            selected = template == t.title,
                            onClick = {
                                template = t.title
                                script = t.script
                            },
                            label = { Text(t.title, fontSize = 11.sp) }
                        )
                    }
                }
                Text(
                    text = RHAI_TEMPLATES.first { it.title == template }.description,
                    color = colors.textSecondary,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(top = 4.dp, bottom = 6.dp)
                )

                // Script editor — a plain scrollable text field, mono font.
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = colors.bg,
                    border = BorderStroke(1.dp, colors.border),
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                ) {
                    BasicTextField(
                        value = script,
                        onValueChange = { script = it },
                        textStyle = androidx.compose.material3.LocalTextStyle.current.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            lineHeight = 17.sp,
                            color = colors.textPrimary
                        ),
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(10.dp)
                    )
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${script.length} chars",
                        color = colors.textSecondary,
                        fontSize = 11.sp,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = onClose) {
                        Text("Close", color = colors.textSecondary)
                    }
                    Button(
                        onClick = {
                            val manifest = viewModel.importPluginJson(script.trim()).getOrNull()
                            if (manifest == null) {
                                Toast.makeText(context, "Empty script — nothing to save", Toast.LENGTH_SHORT).show()
                            } else {
                                Toast.makeText(context, "Saved as \"${manifest.name}\"", Toast.LENGTH_SHORT).show()
                                if (autoRun) viewModel.runPlugin(manifest.id)
                                onClose()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color.Transparent,
                            contentColor = AmberAccent
                        ),
                        border = BorderStroke(1.dp, AmberAccent),
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                    ) {
                        Text("Save & Run", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}
