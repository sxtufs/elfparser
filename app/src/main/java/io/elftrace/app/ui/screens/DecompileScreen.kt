package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

private fun cleanPseudoC(raw: String): String {
    if (raw.isBlank()) return raw
    val voidLineRegex = Regex("""^\s*\(void\)\w+;\s*$""")
    return raw.lines()
        .filterNot { voidLineRegex.matches(it) }
        .joinToString("\n")
        .replace("(uint64_t)(uint32_t)", "(uint32_t)")
        .replace("(int64_t)(uintptr_t)", "")
        .replace("(uint64_t)(uintptr_t)", "")
        .replace(Regex("""\n{3,}"""), "\n\n")
}

private fun highlightPseudoC(
    code: String,
    searchQuery: String,
    colors: ELFTraceColors
): AnnotatedString {
    val commentColor = colors.textSecondary
    val stringColor = GreenAccent.copy(alpha = 0.85f)
    val keywordColor = colors.mnemonic
    val typeColor = colors.primary.copy(alpha = 0.85f)
    val numberColor = colors.operands
    val labelColor = colors.primary

    val tokenRegex = Regex(
        """(//[^\n]*)|("(?:\\.|[^"\\])*")|\b(if|else|goto|return|while|for|do|switch|case|break|continue|__asm__)\b|\b(int64_t|uint64_t|int32_t|uint32_t|int16_t|uint16_t|int8_t|uint8_t|uintptr_t|void|char|bool)\b|\b(loc_[0-9a-fA-F]+)\b|\b(0x[0-9a-fA-F]+|\d+)\b"""
    )

    return buildAnnotatedString {
        append(code)
        for (m in tokenRegex.findAll(code)) {
            val style = when {
                m.groups[1] != null -> SpanStyle(color = commentColor)
                m.groups[2] != null -> SpanStyle(color = stringColor)
                m.groups[3] != null -> SpanStyle(color = keywordColor, fontWeight = FontWeight.SemiBold)
                m.groups[4] != null -> SpanStyle(color = typeColor)
                m.groups[5] != null -> SpanStyle(color = labelColor, fontWeight = FontWeight.Bold)
                m.groups[6] != null -> SpanStyle(color = numberColor)
                else -> null
            }
            if (style != null) {
                addStyle(style, m.range.first, m.range.last + 1)
            }
        }

        if (searchQuery.isNotBlank()) {
            val q = searchQuery.trim()
            var idx = code.indexOf(q, ignoreCase = true)
            while (idx >= 0) {
                addStyle(
                    SpanStyle(
                        background = AmberAccent.copy(alpha = 0.35f),
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    ),
                    idx,
                    idx + q.length
                )
                idx = code.indexOf(q, idx + q.length, ignoreCase = true)
            }
        }
    }
}

@Composable
fun DecompileScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val clipboardManager = LocalClipboardManager.current
    val decompileCode by viewModel.decompileText.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    var cleanMode by remember { mutableStateOf(true) }
    var showSearch by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    val displayTitle = remember(symbolName, currentAddr) {
        symbolName.ifEmpty { "sub_%08X".format(currentAddr) }
    }

    val displayedText = remember(decompileCode, cleanMode) {
        val base = decompileCode.ifEmpty { "// Select a function to decompile" }
        if (cleanMode && decompileCode.isNotEmpty()) cleanPseudoC(base) else base
    }

    val highlightedCode = remember(displayedText, searchQuery, colors) {
        highlightPseudoC(displayedText, searchQuery, colors)
    }

    val matchCount = remember(displayedText, searchQuery) {
        if (searchQuery.isBlank()) 0
        else {
            val q = searchQuery.trim()
            var count = 0
            var idx = displayedText.indexOf(q, ignoreCase = true)
            while (idx >= 0) {
                count++
                idx = displayedText.indexOf(q, idx + q.length, ignoreCase = true)
            }
            count
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        // Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = displayTitle,
                color = colors.primary,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                lineHeight = 17.sp,
                maxLines = 2,
                softWrap = true,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp)
            )

            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = if (cleanMode) colors.primary.copy(alpha = 0.18f) else colors.card,
                    border = BorderStroke(1.dp, if (cleanMode) colors.primary else colors.border),
                    modifier = Modifier.clickable { cleanMode = !cleanMode }
                ) {
                    Text(
                        text = if (cleanMode) "Clean" else "Raw",
                        color = if (cleanMode) colors.primary else colors.textSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }

                IconButton(
                    onClick = {
                        showSearch = !showSearch
                        if (!showSearch) searchQuery = ""
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = "Search",
                        tint = if (showSearch) colors.primary else colors.textPrimary,
                        modifier = Modifier.size(18.dp)
                    )
                }

                IconButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(displayedText))
                        Toast.makeText(context, "Copied C code to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Copy",
                        tint = colors.textPrimary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        if (showSearch) {
            Spacer(Modifier.height(4.dp))
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Find in C code...", fontSize = 12.sp) },
                singleLine = true,
                trailingIcon = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (searchQuery.isNotBlank()) {
                            Text(
                                text = "$matchCount",
                                color = colors.primary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(end = 4.dp)
                            )
                        }
                        IconButton(onClick = {
                            searchQuery = ""
                            showSearch = false
                        }) {
                            Icon(Icons.Default.Close, contentDescription = "Close", modifier = Modifier.size(16.dp))
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Spacer(Modifier.height(4.dp))

        val momentumFling = rememberMomentumFlingBehavior()

        // Selectable Monospaced Code View with Syntax Highlighting
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.card, RoundedCornerShape(8.dp))
                .padding(8.dp)
                .verticalScroll(rememberScrollState(), flingBehavior = momentumFling)
        ) {
            SelectionContainer {
                Text(
                    text = highlightedCode,
                    color = colors.operands,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 18.sp,
                    modifier = Modifier.fillMaxWidth(),
                    softWrap = true
                )
            }
        }
    }
}
