package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import kotlinx.coroutines.launch
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.NearMe
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HexScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val clipboardManager = LocalClipboardManager.current

    val hexBytes by viewModel.hexBytes.collectAsState()
    val startAddress by viewModel.hexStartAddress.collectAsState()
    val elfInfo by viewModel.elfInfo.collectAsState()

    var showGotoDialog by remember { mutableStateOf(false) }
    var gotoAddressInput by remember { mutableStateOf("") }
    var selectedRow by remember(hexBytes, startAddress) { mutableStateOf<HexRow?>(null) }
    var editingRow by remember { mutableStateOf<HexRow?>(null) }
    var editHexInput by remember { mutableStateOf("") }

    val momentumFling = rememberMomentumFlingBehavior()
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()
    var dialogMode by remember { mutableStateOf("goto") } // "goto" or "search"

    // Break raw bytes into 8-byte rows (perfect fit for mobile screens & ARM64 4-byte alignment)
    val rows = remember(hexBytes, startAddress) {
        val list = mutableListOf<HexRow>()
        for (i in hexBytes.indices step 8) {
            val chunkLen = minOf(8, hexBytes.size - i)
            val chunk = hexBytes.sliceArray(i until i + chunkLen)
            val rowAddr = startAddress + i
            list.add(HexRow(address = rowAddr, bytes = chunk))
        }
        list
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        // Toolbar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "0x${"%08X".format(startAddress)}",
                    color = colors.primary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(
                    enabled = startAddress >= 2048L,
                    onClick = { viewModel.loadHexDump((startAddress - 2048L).coerceAtLeast(0L), 2048) },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(Icons.Default.ChevronLeft, contentDescription = "Prev 2KB", tint = if (startAddress >= 2048L) colors.textPrimary else colors.textSecondary.copy(alpha = 0.4f), modifier = Modifier.size(20.dp))
                }

                IconButton(
                    onClick = { viewModel.loadHexDump(startAddress + 2048L, 2048) },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(Icons.Default.ChevronRight, contentDescription = "Next 2KB", tint = colors.textPrimary, modifier = Modifier.size(20.dp))
                }

                IconButton(
                    onClick = {
                        gotoAddressInput = if (dialogMode == "goto") "0x${"%08X".format(startAddress)}" else ""
                        showGotoDialog = true
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(Icons.Default.NearMe, contentDescription = "Go to Address", tint = colors.primary, modifier = Modifier.size(18.dp))
                }

                IconButton(
                    onClick = {
                        val fullDump = rows.joinToString("\n") { row ->
                            val hexStr = row.bytes.joinToString(" ") { "%02X".format(it) }
                            val asciiStr = row.bytes.map { b ->
                                val c = (b.toInt() and 0xFF).toChar()
                                if (c in ' '..'~') c else '.'
                            }.joinToString("")
                            "%08X  %-24s  |%s|".format(row.address, hexStr, asciiStr)
                        }
                        clipboardManager.setText(AnnotatedString(fullDump))
                        Toast.makeText(context, "Copied Hex Dump to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy Hex", tint = colors.textPrimary, modifier = Modifier.size(18.dp))
                }

            }
        }

        Spacer(Modifier.height(4.dp))

        // Mobile-Optimized 8-Byte Hex View Card (Full horizontal width distribution)
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(colors.card, RoundedCornerShape(8.dp))
                .padding(horizontal = 10.dp, vertical = 8.dp)
        ) {
            SelectionContainer {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    flingBehavior = momentumFling,
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    // Header Row (Shared Column Alignment)
                    item(key = "hex_header") {
                        HexRowLayout(
                            modifier = Modifier.padding(bottom = 4.dp),
                            addressContent = {
                                Text(
                                    text = "OFFSET",
                                    color = colors.textSecondary,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            },
                            hexContent = {
                                Text(
                                    text = "00 01 02 03  04 05 06 07",
                                    color = colors.textSecondary,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            },
                            asciiContent = {
                                Text(
                                    text = "ASCII",
                                    color = colors.textSecondary,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        )
                    }

                    itemsIndexed(
                        items = rows,
                        key = { _, row -> row.address },
                        contentType = { _, _ -> "hex_row" }
                    ) { _, row ->
                        val part1 = row.bytes.take(4).joinToString(" ") { "%02X".format(it) }
                        val part2 = if (row.bytes.size > 4) {
                            row.bytes.drop(4).joinToString(" ") { "%02X".format(it) }
                        } else ""
                        val hexFormatted = "$part1  $part2"

                        val ascii = row.bytes.map { b ->
                            val c = (b.toInt() and 0xFF).toChar()
                            if (c in ' '..'~') c else '.'
                        }.joinToString("")

                        val isSelected = selectedRow?.address == row.address
                        HexRowLayout(
                            modifier = Modifier
                                .background(
                                    if (isSelected) colors.primary.copy(alpha = 0.14f) else Color.Transparent,
                                    RoundedCornerShape(4.dp)
                                )
                                .clickable {
                                    selectedRow = if (isSelected) null else row
                                }
                                .padding(vertical = 2.dp, horizontal = 2.dp),
                            addressContent = {
                                Text(
                                    text = "%08X".format(row.address),
                                    color = colors.address,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            },
                            hexContent = {
                                Text(
                                    text = hexFormatted,
                                    color = colors.hexBytes,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            },
                            asciiContent = {
                                Text(
                                    text = "|$ascii|",
                                    color = colors.operands,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    maxLines = 1,
                                    softWrap = false
                                )
                            }
                        )
                    }
                }
            }
        }

        // Byte Inspector & Quick Actions Bar (when a row is tapped)
        selectedRow?.let { sel ->
            Spacer(Modifier.height(4.dp))
            val u32 = if (sel.bytes.size >= 4) {
                ((sel.bytes[0].toLong() and 0xFF)) or
                    ((sel.bytes[1].toLong() and 0xFF) shl 8) or
                    ((sel.bytes[2].toLong() and 0xFF) shl 16) or
                    ((sel.bytes[3].toLong() and 0xFF) shl 24)
            } else null
            val u64 = if (sel.bytes.size >= 8) {
                (0 until 8).fold(0L) { acc, idx ->
                    acc or ((sel.bytes[idx].toLong() and 0xFF) shl (idx * 8))
                }
            } else null

            Surface(
                shape = RoundedCornerShape(8.dp),
                color = colors.surface,
                border = BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "0x${"%08X".format(sel.address)}",
                            color = colors.primary,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.5.sp
                        )
                        val infoText = buildString {
                            if (u32 != null) append("u32: 0x${"%08X".format(u32)}")
                            if (u64 != null) append("  u64: 0x${"%016X".format(u64)}")
                        }
                        if (infoText.isNotEmpty()) {
                            Text(
                                text = infoText,
                                color = colors.textSecondary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                maxLines = 1
                            )
                        }
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(
                            onClick = {
                                editHexInput = sel.bytes.joinToString(" ") { "%02X".format(it) }
                                editingRow = sel
                            },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                            modifier = Modifier.height(30.dp)
                        ) {
                            Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(13.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Edit", fontSize = 11.sp)
                        }
                        Button(
                            onClick = {
                                viewModel.selectFunction(sel.address, "0x${"%08X".format(sel.address)}")
                                viewModel.codeSubTab.value = 0
                            },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                            modifier = Modifier.height(30.dp)
                        ) {
                            Text("Disasm", fontSize = 11.sp)
                        }
                    }
                }
            }
        }

        // Edit Hex Bytes Dialog
        editingRow?.let { row ->
            Dialog(onDismissRequest = { editingRow = null }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "Edit Bytes @ 0x${"%08X".format(row.address)}",
                            color = colors.primary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold
                        )
                        OutlinedTextField(
                            value = editHexInput,
                            onValueChange = { editHexInput = it },
                            label = { Text("Hex (${row.bytes.size} ${if (row.bytes.size == 1) "byte" else "bytes"})", fontSize = 12.sp) },
                            singleLine = true,
                            textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End
                        ) {
                            TextButton(onClick = { editingRow = null }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                            TextButton(onClick = {
                                val clean = editHexInput.replace(" ", "").replace(",", "").trim()
                                if (clean.isEmpty() || clean.length % 2 != 0 || !clean.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
                                    Toast.makeText(context, "Invalid hex bytes", Toast.LENGTH_SHORT).show()
                                } else {
                                    val newBytes = ByteArray(clean.length / 2) { idx ->
                                        clean.substring(idx * 2, idx * 2 + 2).toInt(16).toByte()
                                    }
                                    viewModel.patchHexBytes(row.address, newBytes) { ok ->
                                        if (ok) {
                                            Toast.makeText(context, "Patched ${newBytes.size} bytes", Toast.LENGTH_SHORT).show()
                                            editingRow = null
                                        } else {
                                            Toast.makeText(context, "Patch failed", Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                }
                            }) {
                                Text("Apply", color = colors.primary, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // Go to Address / Search Dialog
        if (showGotoDialog) {
            Dialog(onDismissRequest = { showGotoDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            FilterChip(
                                selected = dialogMode == "goto",
                                onClick = {
                                    dialogMode = "goto"
                                    if (gotoAddressInput.isBlank()) {
                                        gotoAddressInput = "0x${"%08X".format(startAddress)}"
                                    }
                                },
                                label = { Text("Go to", fontSize = 11.sp) }
                            )
                            FilterChip(
                                selected = dialogMode == "search",
                                onClick = {
                                    dialogMode = "search"
                                    if (gotoAddressInput.startsWith("0x", ignoreCase = true)) {
                                        gotoAddressInput = ""
                                    }
                                },
                                label = { Text("Find", fontSize = 11.sp) }
                            )
                            FilterChip(
                                selected = dialogMode == "calc",
                                onClick = {
                                    dialogMode = "calc"
                                    if (gotoAddressInput.isBlank()) {
                                        gotoAddressInput = "0x${"%08X".format(startAddress)}"
                                    }
                                },
                                label = { Text("Calc", fontSize = 11.sp) }
                            )
                        }

                        OutlinedTextField(
                            value = gotoAddressInput,
                            onValueChange = { gotoAddressInput = it },
                            label = {
                                Text(
                                    when (dialogMode) {
                                        "goto" -> "Address / Offset"
                                        "calc" -> "Hex / Dec / Expr (+ -)"
                                        else -> "Hex or ASCII"
                                    },
                                    fontSize = 12.sp
                                )
                            },
                            placeholder = {
                                Text(
                                    when (dialogMode) {
                                        "goto" -> "e.g. 0x2A35C"
                                        "calc" -> "e.g. 0xaa8e8 - 0x10000 or 12345"
                                        else -> "e.g. 7F 45 4C 46 or JNI_OnLoad"
                                    },
                                    fontSize = 12.sp
                                )
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = colors.primary,
                                unfocusedBorderColor = colors.border,
                                focusedTextColor = colors.textPrimary,
                                unfocusedTextColor = colors.textPrimary,
                                focusedLabelColor = colors.primary,
                                unfocusedLabelColor = colors.textSecondary,
                                cursorColor = colors.primary
                            )
                        )

                        val calcValue = remember(gotoAddressInput, dialogMode) {
                            if (dialogMode == "calc") evalHexExpr(gotoAddressInput) else null
                        }
                        if (dialogMode == "calc" && calcValue != null) {
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = colors.card,
                                border = BorderStroke(1.dp, colors.border),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    val loads = elfInfo?.segments?.filter { it.p_type == "PT_LOAD" }.orEmpty()
                                    val fileOff = loads.firstOrNull {
                                        calcValue >= it.vaddr && calcValue < it.vaddr + it.filesz
                                    }?.let { it.offset + (calcValue - it.vaddr) }
                                    val vmaFromOff = loads.firstOrNull {
                                        calcValue >= it.offset && calcValue < it.offset + it.filesz
                                    }?.let { it.vaddr + (calcValue - it.offset) }

                                    Text(
                                        "Hex:  0x${calcValue.toString(16).uppercase()}",
                                        color = colors.primary,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.5.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        "Dec:  $calcValue",
                                        color = colors.textPrimary,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.5.sp
                                    )
                                    Text(
                                        "VMA -> File Off:  ${fileOff?.let { "0x${it.toString(16).uppercase()}" } ?: "N/A"}",
                                        color = colors.address,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp
                                    )
                                    Text(
                                        "File Off -> VMA:  ${vmaFromOff?.let { "0x${it.toString(16).uppercase()}" } ?: "N/A"}",
                                        color = colors.hexBytes,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(onClick = { showGotoDialog = false }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                            Spacer(Modifier.width(8.dp))
                            Button(
                                onClick = {
                                    if (dialogMode == "goto") {
                                        val clean = gotoAddressInput.trim().removePrefix("0x").removePrefix("0X")
                                        val addr = clean.toLongOrNull(16)
                                        if (addr != null) {
                                            viewModel.loadHexDump(addr, 2048)
                                            showGotoDialog = false
                                        } else {
                                            Toast.makeText(context, "Invalid hex address", Toast.LENGTH_SHORT).show()
                                        }
                                    } else if (dialogMode == "calc") {
                                        if (calcValue != null && calcValue >= 0L) {
                                            viewModel.loadHexDump(calcValue, 2048)
                                            showGotoDialog = false
                                        } else {
                                            Toast.makeText(context, "Invalid expression", Toast.LENGTH_SHORT).show()
                                        }
                                    } else {
                                        val query = gotoAddressInput.trim()
                                        if (query.isEmpty()) {
                                            Toast.makeText(context, "Enter hex bytes or text", Toast.LENGTH_SHORT).show()
                                            return@Button
                                        }
                                        val hexClean = query.replace(" ", "")
                                        val isHex = hexClean.length >= 2 && hexClean.length % 2 == 0 &&
                                            hexClean.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
                                        val needle = if (isHex) {
                                            ByteArray(hexClean.length / 2) { idx ->
                                                hexClean.substring(idx * 2, idx * 2 + 2).toInt(16).toByte()
                                            }
                                        } else {
                                            query.toByteArray(Charsets.UTF_8)
                                        }
                                        var matchIdx = -1
                                        for (i in 0..(hexBytes.size - needle.size)) {
                                            var ok = true
                                            for (j in needle.indices) {
                                                if (hexBytes[i + j] != needle[j]) {
                                                    ok = false
                                                    break
                                                }
                                            }
                                            if (ok) {
                                                matchIdx = i
                                                break
                                            }
                                        }
                                        if (matchIdx >= 0) {
                                            val rowIdx = matchIdx / 8
                                            if (rowIdx in rows.indices) {
                                                selectedRow = rows[rowIdx]
                                                coroutineScope.launch {
                                                    listState.animateScrollToItem(rowIdx + 1)
                                                }
                                            }
                                            showGotoDialog = false
                                        } else {
                                            Toast.makeText(context, "Not found in current 2 KB window", Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White),
                                shape = RoundedCornerShape(50)
                            ) {
                                Text(if (dialogMode == "search") "Find" else "Jump", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun evalHexExpr(input: String): Long? {
    val s = input.replace(" ", "")
    if (s.isEmpty() || s.endsWith("+") || s.endsWith("-")) return null
    var total = 0L
    var sign = 1L
    var i = 0
    while (i < s.length) {
        if (s[i] == '+') {
            sign = 1L
            i++
            continue
        } else if (s[i] == '-') {
            sign = -1L
            i++
            continue
        }
        val start = i
        while (i < s.length && s[i] != '+' && s[i] != '-') {
            i++
        }
        val tok = s.substring(start, i)
        if (tok.isEmpty()) return null
        val num = when {
            tok.startsWith("0x", ignoreCase = true) -> tok.substring(2).toLongOrNull(16)
            tok.any { it.lowercaseChar() in 'a'..'f' } -> tok.toLongOrNull(16)
            else -> tok.toLongOrNull(10)
        } ?: return null
        total += sign * num
    }
    return total
}

@Composable
private fun HexRowLayout(
    modifier: Modifier = Modifier,
    addressContent: @Composable () -> Unit,
    hexContent: @Composable () -> Unit,
    asciiContent: @Composable () -> Unit
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        // Address / offset column.
        Box(
            modifier = Modifier.weight(0.24f),
            contentAlignment = Alignment.CenterStart
        ) {
            addressContent()
        }

        // Hex column.
        Box(
            modifier = Modifier.weight(0.52f),
            contentAlignment = Alignment.Center
        ) {
            hexContent()
        }

        // ASCII column.
        Box(
            modifier = Modifier.weight(0.24f),
            contentAlignment = Alignment.CenterEnd
        ) {
            asciiContent()
        }
    }
}

private data class HexRow(
    val address: Long,
    val bytes: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HexRow) return false
        return address == other.address && bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int {
        var result = address.hashCode()
        result = 31 * result + bytes.contentHashCode()
        return result
    }
}
