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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(8.dp)
    ) {
        // Function Bar Header with Go to & Caller XREF Buttons
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(8.dp))
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = symbolName.ifEmpty { "0x${"%08X".format(currentAddr)}" },
                    color = colors.primary,
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "VMA: 0x${"%08X".format(currentAddr)} (tap any line to patch/jump)",
                    color = colors.textSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            // Header Action Buttons: Go to & Callers
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedButton(
                    onClick = {
                        gotoAddressInput = ""
                        showGotoDialog = true
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = colors.primary),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.ArrowForward, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
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
                    Icon(Icons.Default.CallMade, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
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
                containerColor = colors.surface
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp)
                ) {
                    Text("Modify & Analyze Instruction", style = MaterialTheme.typography.titleMedium, color = colors.primary)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "0x${"%08X".format(ins.address)}: ${ins.mnemonic} ${ins.op_str}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = colors.textPrimary
                    )

                    if (branchTarget != null) {
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = {
                                viewModel.selectFunction(branchTarget, "sub_${"%08X".format(branchTarget)}")
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = colors.primary),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.OpenInNew, contentDescription = null, tint = Color.Black, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Jump to Target (0x${"%08X".format(branchTarget)})", color = Color.Black, fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                    Text("ONE-TAP QUICK PATCH", color = AmberAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 1) { res ->
                                    Toast.makeText(context, "Patched NOP: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF37474F)),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("NOP", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }

                        Button(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 2) { res ->
                                    Toast.makeText(context, "Patched Return True: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = GreenAccent),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Ret True", color = Color.Black, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    Spacer(Modifier.height(8.dp))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 3) { res ->
                                    Toast.makeText(context, "Patched Return False: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC62828)),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Ret False", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }

                        Button(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 4) { res ->
                                    Toast.makeText(context, "Patched Return Void: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = AmberAccent),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Ret Void", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    Button(
                        onClick = {
                            val target = branchTarget ?: ins.address
                            xrefsList = viewModel.getXrefsFor(target)
                            xrefDialogTitle = "XREFs to 0x${"%08X".format(target)}"
                            showXrefDialog = true
                            selectedInsn = null
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.card),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Find Cross-References (XREFs)", color = colors.primary, fontWeight = FontWeight.Bold)
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
                            label = { Text("e.g. 0x2EB38 or 2EB38") },
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
