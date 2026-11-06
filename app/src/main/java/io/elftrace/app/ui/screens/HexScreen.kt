package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.NearMe
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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

    var showGotoDialog by remember { mutableStateOf(false) }
    var gotoAddressInput by remember { mutableStateOf("") }
    var bytesPerRow by remember { mutableStateOf(16) }

    val momentumFling = rememberMomentumFlingBehavior()

    // Break raw bytes into rows (8 or 16 bytes per row)
    val rows = remember(hexBytes, startAddress, bytesPerRow) {
        val list = mutableListOf<HexRow>()
        for (i in hexBytes.indices step bytesPerRow) {
            val chunkLen = minOf(bytesPerRow, hexBytes.size - i)
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
                    text = "VMA: 0x${"%08X".format(startAddress)}",
                    color = colors.primary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "${hexBytes.size} B",
                    color = colors.textSecondary,
                    fontSize = 11.sp
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                // 8-Byte / 16-Byte Layout Toggle
                OutlinedButton(
                    onClick = { bytesPerRow = if (bytesPerRow == 16) 8 else 16 },
                    shape = RoundedCornerShape(50),
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    modifier = Modifier.height(28.dp)
                ) {
                    Text(
                        text = if (bytesPerRow == 16) "16-Byte" else "8-Byte",
                        color = colors.primary,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                IconButton(onClick = {
                    gotoAddressInput = "0x${"%08X".format(startAddress)}"
                    showGotoDialog = true
                }) {
                    Icon(Icons.Default.NearMe, contentDescription = "Go to Address", tint = colors.primary, modifier = Modifier.size(18.dp))
                }

                IconButton(onClick = {
                    val fullDump = rows.joinToString("\n") { row ->
                        val hexStr = row.bytes.joinToString(" ") { "%02X".format(it) }
                        val asciiStr = row.bytes.map { b ->
                            val c = (b.toInt() and 0xFF).toChar()
                            if (c in ' '..'~') c else '.'
                        }.joinToString("")
                        val hexCols = if (bytesPerRow == 16) "%-48s".format(hexStr) else "%-24s".format(hexStr)
                        "%08X  %s  |%s|".format(row.address, hexCols, asciiStr)
                    }
                    clipboardManager.setText(AnnotatedString(fullDump))
                    Toast.makeText(context, "Copied Hex Dump to clipboard", Toast.LENGTH_SHORT).show()
                }) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy Hex", tint = colors.textPrimary, modifier = Modifier.size(18.dp))
                }

                IconButton(onClick = { viewModel.loadHexDump(startAddress, 2048) }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Reload", tint = colors.textSecondary, modifier = Modifier.size(18.dp))
                }
            }
        }

        Spacer(Modifier.height(4.dp))

        // Virtualized Hex View with Horizontal & Vertical Scrolling
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.card, RoundedCornerShape(8.dp))
                .padding(8.dp)
                .horizontalScroll(rememberScrollState(), flingBehavior = momentumFling)
        ) {
            SelectionContainer {
                LazyColumn(
                    modifier = Modifier.fillMaxHeight(),
                    flingBehavior = momentumFling,
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    // Header Row
                    item(key = "hex_header") {
                        val headerCols = if (bytesPerRow == 16) {
                            "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F"
                        } else {
                            "00 01 02 03 04 05 06 07"
                        }

                        Row(modifier = Modifier.padding(bottom = 4.dp)) {
                            Text(
                                text = "OFFSET   ",
                                color = colors.textSecondary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = headerCols,
                                color = colors.textSecondary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(Modifier.width(16.dp))
                            Text(
                                text = "ASCII",
                                color = colors.textSecondary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    itemsIndexed(
                        items = rows,
                        key = { _, row -> "${bytesPerRow}_${row.address}" },
                        contentType = { _, _ -> "hex_row" }
                    ) { _, row ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            // Address column
                            Text(
                                text = "%08X ".format(row.address),
                                color = colors.address,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold
                            )

                            // Hex bytes column
                            val hexFormatted = if (bytesPerRow == 16) {
                                val part1 = row.bytes.take(8).joinToString(" ") { "%02X".format(it) }
                                val part2 = if (row.bytes.size > 8) {
                                    row.bytes.drop(8).joinToString(" ") { "%02X".format(it) }
                                } else ""
                                "%-23s  %-23s".format(part1, part2)
                            } else {
                                "%-23s".format(row.bytes.joinToString(" ") { "%02X".format(it) })
                            }

                            Text(
                                text = hexFormatted,
                                color = colors.hexBytes,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp
                            )

                            Spacer(Modifier.width(16.dp))

                            // ASCII representation
                            val ascii = row.bytes.map { b ->
                                val c = (b.toInt() and 0xFF).toChar()
                                if (c in ' '..'~') c else '.'
                            }.joinToString("")

                            Text(
                                text = "|$ascii|",
                                color = colors.operands,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp
                            )
                        }
                    }
                }
            }
        }

        // Jump to Address Dialog
        if (showGotoDialog) {
            AlertDialog(onDismissRequest = { showGotoDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Go to Hex Address", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(4.dp))
                        Text("Enter virtual address or file offset:", color = colors.textSecondary, fontSize = 11.sp)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = gotoAddressInput,
                            onValueChange = { gotoAddressInput = it },
                            label = { Text("Address / Offset (e.g. 0x2A35C)") },
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
                        Spacer(Modifier.height(12.dp))
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
                                    val clean = gotoAddressInput.trim().removePrefix("0x").removePrefix("0X")
                                    val addr = clean.toLongOrNull(16)
                                    if (addr != null) {
                                        viewModel.loadHexDump(addr, 2048)
                                        showGotoDialog = false
                                    } else {
                                        Toast.makeText(context, "Invalid hex address", Toast.LENGTH_SHORT).show()
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White),
                                shape = RoundedCornerShape(50)
                            ) {
                                Text("Jump", color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
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
