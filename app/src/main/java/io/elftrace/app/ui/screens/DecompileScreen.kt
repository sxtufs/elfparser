package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Search
import androidx.compose.ui.text.TextLayoutResult
import kotlinx.coroutines.launch
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
    val labelColor = colors.primary

    val tokenRegex = Regex(
        """(//[^\n]*)|("(?:\\.|[^"\\])*")|\b(if|else|goto|return|while|for|do|switch|case|break|continue|__asm__)\b|\b(loc_[0-9a-fA-F]+)\b"""
    )

    return buildAnnotatedString {
        append(code)
        for (m in tokenRegex.findAll(code)) {
            val style = when {
                m.groups[1] != null -> SpanStyle(color = commentColor)
                m.groups[2] != null -> SpanStyle(color = stringColor)
                m.groups[3] != null -> SpanStyle(color = keywordColor, fontWeight = FontWeight.SemiBold)
                m.groups[4] != null -> SpanStyle(color = labelColor, fontWeight = FontWeight.Bold)
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
    val decompileStructured by viewModel.decompileStructured.collectAsState()
    val decompileMode by viewModel.decompileMode.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()
    var showSearch by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var currentMatchIdx by remember { mutableStateOf(0) }
    var textLayoutResult by remember { mutableStateOf<TextLayoutResult?>(null) }
    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()

    val displayTitle = remember(symbolName, currentAddr) {
        symbolName.ifEmpty { "sub_%08X".format(currentAddr) }
    }

    val displayedText = remember(decompileCode, decompileStructured, decompileMode) {
        val base = when (decompileMode) {
            2 -> decompileStructured.ifEmpty { "// Structuring… (or no structured output for this function)" }
            0 -> decompileCode.ifEmpty { "// Select a function to decompile" }
            else -> decompileCode.ifEmpty { "// Select a function to decompile" }
        }
        // Strip (void)param; noise for both Clean (1) and Struct (2): the
        // structured emitter also emits those lines and they only add clutter.
        if (decompileMode != 0 && base.isNotEmpty()) cleanPseudoC(base) else base
    }

    val highlightedCode = remember(displayedText, searchQuery, colors) {
        highlightPseudoC(displayedText, searchQuery, colors)
    }

    val matchOffsets = remember(displayedText, searchQuery) {
        if (searchQuery.isBlank()) emptyList()
        else {
            val q = searchQuery.trim()
            val list = mutableListOf<Int>()
            var idx = displayedText.indexOf(q, ignoreCase = true)
            while (idx >= 0) {
                list.add(idx)
                idx = displayedText.indexOf(q, idx + q.length, ignoreCase = true)
            }
            list
        }
    }
    val matchCount = matchOffsets.size

    fun scrollToMatch(index: Int) {
        val layout = textLayoutResult ?: return
        if (matchOffsets.isEmpty()) return
        val safeIdx = index.coerceIn(0, matchOffsets.lastIndex)
        currentMatchIdx = safeIdx
        val charOffset = matchOffsets[safeIdx].coerceIn(0, displayedText.length)
        val line = layout.getLineForOffset(charOffset)
        val y = layout.getLineTop(line).toInt()
        coroutineScope.launch {
            scrollState.animateScrollTo((y - 80).coerceAtLeast(0))
        }
    }

    LaunchedEffect(searchQuery, matchOffsets) {
        if (matchOffsets.isNotEmpty()) {
            scrollToMatch(0)
        } else {
            currentMatchIdx = 0
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
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
                // Two-way engine/filter switch:
                //   Clean (1) = linear, minus (void)param; noise
                //   Struct(2) = structured emitter (if/while/switch)
                listOf(1 to "Clean", 2 to "Struct").forEach { (mode, label) ->
                    val active = decompileMode == mode
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = if (active) colors.primary.copy(alpha = 0.18f) else colors.card,
                        border = BorderStroke(1.dp, if (active) colors.primary else colors.border),
                        modifier = Modifier.clickable { viewModel.setDecompileMode(mode) }
                    ) {
                        Text(
                            text = label,
                            color = if (active) colors.primary else colors.textSecondary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
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
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = colors.surface,
                border = BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(38.dp)
                        .padding(horizontal = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Search,
                        contentDescription = null,
                        tint = colors.textSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier.weight(1f),
                        contentAlignment = Alignment.CenterStart
                    ) {
                        if (searchQuery.isEmpty()) {
                            Text(
                                text = "Find in C code...",
                                color = colors.textSecondary,
                                fontSize = 12.sp
                            )
                        }
                        BasicTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(
                                color = colors.textPrimary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp
                            ),
                            cursorBrush = SolidColor(colors.primary),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    if (searchQuery.isNotBlank()) {
                        Text(
                            text = if (matchCount > 0) "${currentMatchIdx + 1}/$matchCount" else "0",
                            color = colors.primary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 4.dp)
                        )
                        if (matchCount > 1) {
                            IconButton(
                                onClick = {
                                    val prev = if (currentMatchIdx > 0) currentMatchIdx - 1 else matchCount - 1
                                    scrollToMatch(prev)
                                },
                                modifier = Modifier.size(26.dp)
                            ) {
                                Icon(Icons.Default.ChevronLeft, contentDescription = "Prev Match", tint = colors.textPrimary, modifier = Modifier.size(16.dp))
                            }
                            IconButton(
                                onClick = {
                                    val next = (currentMatchIdx + 1) % matchCount
                                    scrollToMatch(next)
                                },
                                modifier = Modifier.size(26.dp)
                            ) {
                                Icon(Icons.Default.ChevronRight, contentDescription = "Next Match", tint = colors.textPrimary, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                    IconButton(
                        onClick = {
                            searchQuery = ""
                            showSearch = false
                        },
                        modifier = Modifier.size(26.dp)
                    ) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = colors.textSecondary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }

        Spacer(Modifier.height(4.dp))

        val momentumFling = rememberMomentumFlingBehavior()

        // Selectable Monospaced Code View with Syntax Highlighting
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.card, RoundedCornerShape(8.dp))
                .padding(8.dp)
                .verticalScroll(scrollState, flingBehavior = momentumFling)
        ) {
            SelectionContainer {
                Text(
                    text = highlightedCode,
                    color = colors.operands,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 18.sp,
                    onTextLayout = { textLayoutResult = it },
                    modifier = Modifier.fillMaxWidth(),
                    softWrap = true
                )
            }
        }
    }
}
