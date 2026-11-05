package com.diself.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.CallMade
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diself.app.R
import com.diself.app.core.models.Instruction
import com.diself.app.core.models.XRefItem
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DisasmScreen(viewModel: DisElfViewModel) {
    val context = LocalContext.current
    val colors = LocalDisElfColors.current
    val instructions by viewModel.instructions.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    var selectedInsn by remember { mutableStateOf<Instruction?>(null) }
    var xrefsList by remember { mutableStateOf<List<XRefItem>>(emptyList()) }
    var showXrefDialog by remember { mutableStateOf(false) }
    var xrefDialogTitle by remember { mutableStateOf("Cross-References") }

    var showGotoDialog by remember { mutableStateOf(false) }
    var gotoAddressInput by remember { mutableStateOf("") }

    // Clean function title (e.g. JNIBridge -> info0 instead of full package that wraps mid-word)
    val shortTitle = remember(symbolName, currentAddr) {
        if (symbolName.contains(" -> ")) {
            val parts = symbolName.split(" -> ")
            val shortClass = parts[0].substringAfterLast('.')
            "$shortClass -> ${parts[1]}"
        } else if (symbolName.contains("::")) {
            symbolName.substringAfterLast("::")
        } else if (symbolName.isNotEmpty()) {
            symbolName
        } else {
            "0x${"%08X".format(currentAddr)}"
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(8.dp)
    ) {
        // Function Bar Header with Quick Theme Toggle, Go to & Callers
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    text = shortTitle,
                    color = colors.primary,
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "VMA: 0x${"%08X".format(currentAddr)}",
                    color = colors.textSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            // Action Buttons: Theme Switcher, Go to, Callers
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                IconButton(
                    onClick = { viewModel.toggleTheme() },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        painter = painterResource(
                            if (colors.isDark) R.drawable.ic_light_mode
                            else R.drawable.ic_dark_mode
                        ),
                        contentDescription = "Toggle Theme",
                        tint = if (colors.isDark) Color(0xFFFFD54F) else Color(0xFF0969DA),
                        modifier = Modifier.size(18.dp)
                    )
                }

                OutlinedButton(
                    onClick = {
                        gotoAddressInput = ""
                        showGotoDialog = true
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = colors.primary),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.ArrowForward, contentDescription = null, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(3.dp))
                    Text("Go to", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }

                OutlinedButton(
                    onClick = {
                        xrefsList = viewModel.getXrefsFor(currentAddr)
                        xrefDialogTitle = "Callers of $symbolName"
                        showXrefDialog = true
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = AmberAccent),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.CallMade, contentDescription = null, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(3.dp))
                    Text("Callers", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        // Virtualized Disassembly LazyColumn
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            items(instructions) { ins ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selectedInsn = ins }
                        .padding(horizontal = 4.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "0x${"%08X".format(ins.address)}",
                        color = colors.address,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        modifier = Modifier.width(90.dp)
                    )

                    Text(
                        text = ins.bytesHex,
                        color = colors.hexBytes,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        modifier = Modifier.width(100.dp)
                    )

                    Text(
                        text = ins.mnemonic,
                        color = colors.mnemonic,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.width(60.dp)
                    )

                    Text(
                        text = ins.op_str,
                        color = colors.operands,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }
        }

        // Quick Patch / Jump / XREF Bottom Sheet
        if (selectedInsn != null) {
            val ins = selectedInsn!!
            val branchTarget = parseBranchTarget(ins.mnemonic, ins.op_str)

            ModalBottomSheet(
                onDismissRequest = { selectedInsn = null },
                containerColor = colors.surface,
                tonalElevation = 0.dp,
                dragHandle = { BottomSheetDefaults.DragHandle(color = colors.border) }
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = "Instruction Analysis",
                        style = MaterialTheme.typography.titleMedium,
                        color = colors.textPrimary,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "0x${"%08X".format(ins.address)}: ${ins.mnemonic} ${ins.op_str}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = colors.primary,
                        fontWeight = FontWeight.SemiBold
                    )

                    // 1. Jump to Target Card
                    if (branchTarget != null) {
                        Spacer(Modifier.height(14.dp))
                        Card(
                            colors = CardDefaults.cardColors(containerColor = colors.card),
                            shape = RoundedCornerShape(10.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.primary.copy(alpha = 0.4f)),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    viewModel.selectFunction(branchTarget, "sub_${"%08X".format(branchTarget)}")
                                    selectedInsn = null
                                }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.OpenInNew, contentDescription = null, tint = colors.primary, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(10.dp))
                                    Text("Jump to Target", color = colors.primary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                }
                                Text("›", color = colors.primary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                    Text("QUICK PATCH", color = colors.textSecondary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))

                    // 2. Tactile Quick Patch Action Tiles (2x2 Grid)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        QuickPatchTile(
                            title = "⊘  NOP",
                            subLabel = "Skip instruction",
                            accentColor = colors.textPrimary,
                            bgColor = if (colors.isDark) Color(0xFF282C34) else Color(0xFFF1F5F9),
                            borderColor = colors.border,
                            modifier = Modifier.weight(1f),
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 1) { res ->
                                    Toast.makeText(context, "Patched NOP: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            }
                        )

                        QuickPatchTile(
                            title = "✓  Ret True",
                            subLabel = "Force return 1",
                            accentColor = Color(0xFF2E7D32),
                            bgColor = if (colors.isDark) Color(0x224CAF50) else Color(0xFFF0FDF4),
                            borderColor = Color(0xFF4CAF50).copy(alpha = 0.4f),
                            modifier = Modifier.weight(1f),
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 2) { res ->
                                    Toast.makeText(context, "Patched Return True: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            }
                        )
                    }

                    Spacer(Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        QuickPatchTile(
                            title = "✕  Ret False",
                            subLabel = "Force return 0",
                            accentColor = Color(0xFFC62828),
                            bgColor = if (colors.isDark) Color(0x22E53935) else Color(0xFFFEF2F2),
                            borderColor = Color(0xFFE53935).copy(alpha = 0.4f),
                            modifier = Modifier.weight(1f),
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 3) { res ->
                                    Toast.makeText(context, "Patched Return False: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            }
                        )

                        QuickPatchTile(
                            title = "↩  Ret Void",
                            subLabel = "Early return",
                            accentColor = Color(0xFFE65100),
                            bgColor = if (colors.isDark) Color(0x22FFA000) else Color(0xFFFFFBEB),
                            borderColor = Color(0xFFFFA000).copy(alpha = 0.4f),
                            modifier = Modifier.weight(1f),
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 4) { res ->
                                    Toast.makeText(context, "Patched Return Void: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            }
                        )
                    }

                    Spacer(Modifier.height(14.dp))

                    // 3. Find Cross-References Card
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.card),
                        shape = RoundedCornerShape(10.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val target = branchTarget ?: ins.address
                                xrefsList = viewModel.getXrefsFor(target)
                                xrefDialogTitle = "XREFs to 0x${"%08X".format(target)}"
                                showXrefDialog = true
                                selectedInsn = null
                            }
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.CallMade, contentDescription = null, tint = colors.textPrimary, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(10.dp))
                                Text("Find Cross-References", color = colors.textPrimary, fontWeight = FontWeight.Medium, fontSize = 13.sp)
                            }
                            Text("›", color = colors.textSecondary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                }
            }
        }

        // Go to Address Dialog
        if (showGotoDialog) {
            AlertDialog(
                onDismissRequest = { showGotoDialog = false },
                containerColor = colors.surface,
                title = { Text("Go to Address (VMA)", color = colors.primary, fontSize = 16.sp) },
                text = {
                    Column {
                        Text("Enter virtual address to disassemble:", color = colors.textSecondary, fontSize = 12.sp)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = gotoAddressInput,
                            onValueChange = { gotoAddressInput = it },
                            label = { Text("Enter Hex Address") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = colors.primary,
                                unfocusedBorderColor = colors.border,
                                focusedTextColor = colors.textPrimary,
                                unfocusedTextColor = colors.textPrimary
                            )
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val clean = gotoAddressInput.trim().removePrefix("0x").removePrefix("0X")
                            val addr = clean.toLongOrNull(16)
                            if (addr != null) {
                                viewModel.selectFunction(addr, "sub_${"%08X".format(addr)}")
                                showGotoDialog = false
                            } else {
                                Toast.makeText(context, "Invalid hex address", Toast.LENGTH_SHORT).show()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary)
                    ) {
                        Text("Jump", color = Color.Black, fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showGotoDialog = false }) {
                        Text("Cancel", color = colors.textSecondary)
                    }
                }
            )
        }

        // XREFs Dialog
        if (showXrefDialog) {
            val count = xrefsList.size
            val countText = when (count) {
                0 -> "No callers found"
                1 -> "1 caller found"
                else -> "$count callers found"
            }
            AlertDialog(
                onDismissRequest = { showXrefDialog = false },
                containerColor = colors.surface,
                title = { Text("$countText: $xrefDialogTitle", color = colors.primary, fontSize = 15.sp) },
                text = {
                    if (xrefsList.isEmpty()) {
                        Text("No callers or references found for this address in the binary.", color = colors.textSecondary, fontSize = 13.sp)
                    } else {
                        LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 300.dp)) {
                            items(xrefsList) { ref ->
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = colors.card),
                                    shape = RoundedCornerShape(6.dp),
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable {
                                        viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                        showXrefDialog = false
                                    }
                                ) {
                                    Column(modifier = Modifier.padding(10.dp)) {
                                        Text("[${ref.kind}] in ${ref.caller_func ?: "unknown"}", color = AmberAccent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                        Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = colors.textPrimary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                    }
                                }
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showXrefDialog = false }) {
                        Text("Close", color = colors.primary)
                    }
                }
            )
        }
    }
}

@Composable
fun QuickPatchTile(
    title: String,
    subLabel: String,
    accentColor: Color,
    bgColor: Color,
    borderColor: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = bgColor),
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, borderColor),
        modifier = modifier.clickable(onClick = onClick)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = title,
                color = accentColor,
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subLabel,
                color = accentColor.copy(alpha = 0.8f),
                fontSize = 10.sp,
                fontFamily = FontFamily.Default
            )
        }
    }
}

private fun parseBranchTarget(mnemonic: String, opStr: String): Long? {
    if (mnemonic.startsWith('b') || mnemonic.startsWith("cb") || mnemonic.startsWith("tb")) {
        for (part in opStr.split(',')) {
            val trimmed = part.trim().trimStart('#')
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                try {
                    return trimmed.substring(2).toLong(16)
                } catch (_: Exception) {}
            } else {
                try {
                    val addr = trimmed.toLong(16)
                    if (addr > 0x1000) return addr
                } catch (_: Exception) {}
            }
        }
    }
    return null
}
