package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.SymsDTO
import io.elftrace.app.ui.theme.LocalELFTraceColors
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen

/**
 * Symbol / JNI browser — the replacement for the old execution tracer.
 *
 * This is intentionally pure data: it reads the already-parsed symbol table from
 * the ViewModel. It performs no emulation, so it cannot crash or hang, and it is
 * genuinely useful for Android reversing — you can search every JNI export,
 * inspect a symbol's address/size, and jump straight into its disassembly.
 */
@Composable
fun TraceScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val elfInfo by viewModel.elfInfo.collectAsState()
    val fileName by viewModel.currentFileName.collectAsState()

    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(SymbolFilter.All) }

    val allSyms = elfInfo?.syms ?: emptyList()

    val filtered = remember(allSyms, query, filter) {
        val q = query.trim().lowercase()
        allSyms.asSequence()
            .filter { sym ->
                when (filter) {
                    SymbolFilter.All -> true
                    SymbolFilter.Jni -> sym.isJni
                    SymbolFilter.Exports -> sym.value != 0L
                }
            }
            .filter { sym ->
                q.isEmpty() ||
                    sym.displayName.lowercase().contains(q) ||
                    "0x%08X".format(sym.value).lowercase().contains(q)
            }
            .sortedBy { it.value }
            .toList()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        // Header
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    text = "SYMBOL / JNI BROWSER",
                    color = colors.primary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = fileName.ifEmpty { "No file loaded" },
                    color = colors.textSecondary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    maxLines = 1
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "${filtered.size} of ${allSyms.size} symbols",
                    color = colors.textSecondary,
                    fontSize = 11.sp
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        // Search box
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            singleLine = true,
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = colors.textSecondary) },
            placeholder = { Text("Search symbol or address", fontSize = 12.sp, color = colors.textSecondary) },
            textStyle = androidx.compose.ui.text.TextStyle(
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                color = colors.textPrimary
            ),
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = colors.primary,
                unfocusedBorderColor = colors.border,
                cursorColor = colors.primary,
                focusedContainerColor = colors.surface,
                unfocusedContainerColor = colors.surface
            )
        )

        Spacer(Modifier.height(8.dp))

        // Filter chips
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            SymbolFilter.values().forEach { f ->
                val selected = filter == f
                Box(
                    modifier = Modifier
                        .background(
                            if (selected) colors.primary.copy(alpha = 0.18f) else colors.card,
                            RoundedCornerShape(50)
                        )
                        .border(
                            1.dp,
                            if (selected) colors.primary else colors.border,
                            RoundedCornerShape(50)
                        )
                        .clickable { filter = f }
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = f.label,
                        color = if (selected) colors.primary else colors.textSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (allSyms.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "Open a .so / .apk to browse its symbols",
                    color = colors.textSecondary,
                    fontSize = 12.sp
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(filtered, key = { it.value.toString() + it.displayName }) { sym ->
                    SymbolRow(
                        sym = sym,
                        onClick = {
                            if (sym.value != 0L) {
                                viewModel.selectFunction(sym.value, sym.displayName)
                                viewModel.navigateTo(Screen.Code)
                            }
                        }
                    )
                }
            }
        }
    }
}

private enum class SymbolFilter(val label: String) {
    All("All"),
    Jni("JNI"),
    Exports("Exports")
}

@Composable
private fun SymbolRow(sym: SymsDTO, onClick: () -> Unit) {
    val colors = LocalELFTraceColors.current
    val isImport = sym.value == 0L
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.card),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = !isImport, onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = sym.displayName,
                    color = if (sym.isJni) colors.mnemonic else colors.textPrimary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    fontWeight = if (sym.isJni) FontWeight.Bold else FontWeight.Normal,
                    maxLines = 1
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = if (isImport) "import" else "0x%08X".format(sym.value),
                        color = if (isImport) colors.textSecondary else colors.address,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp
                    )
                    if (sym.size > 0) {
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "${sym.size} B",
                            color = colors.textSecondary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp
                        )
                    }
                }
            }
            if (sym.isJni) {
                Text(
                    text = "JNI",
                    color = colors.primary,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
