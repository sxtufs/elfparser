package com.diself.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
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
    val instructions by viewModel.instructions.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    var selectedInsn by remember { mutableStateOf<Instruction?>(null) }
    var xrefsList by remember { mutableStateOf<List<XRefItem>>(emptyList()) }
    var showXrefDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .padding(8.dp)
    ) {
        // Function Bar Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(SurfaceDark)
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text = symbolName.ifEmpty { "0x${"%08X".format(currentAddr)}" },
                    color = CyanAccent,
                    fontSize = 14.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "VMA: 0x${"%08X".format(currentAddr)} (tap any instruction to patch/xref)",
                    color = ColorHexBytes,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
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
                        color = ColorAddress,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        modifier = Modifier.width(90.dp)
                    )

                    Text(
                        text = ins.bytesHex,
                        color = ColorHexBytes,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        modifier = Modifier.width(100.dp)
                    )

                    Text(
                        text = ins.mnemonic,
                        color = ColorMnemonic,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.width(60.dp)
                    )

                    Text(
                        text = ins.op_str,
                        color = ColorOperands,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }
        }

        // Quick Patch / XREF Bottom Sheet
        if (selectedInsn != null) {
            val ins = selectedInsn!!
            ModalBottomSheet(
                onDismissRequest = { selectedInsn = null },
                containerColor = SurfaceDark
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp)
                ) {
                    Text("Modify & Analyze Instruction", style = MaterialTheme.typography.titleMedium, color = CyanAccent)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "0x${"%08X".format(ins.address)}: ${ins.mnemonic} ${ins.op_str}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = Color.White
                    )

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
                            colors = ButtonDefaults.buttonColors(containerColor = CardDark),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("NOP", fontSize = 11.sp)
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
                            Text("Ret True", color = Color.Black, fontSize = 11.sp, fontWeight = FontWeight.Bold)
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
                            colors = ButtonDefaults.buttonColors(containerColor = CardDark),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Ret False", fontSize = 11.sp)
                        }

                        Button(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 4) { res ->
                                    Toast.makeText(context, "Patched Return Void: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = CardDark),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Ret Void", fontSize = 11.sp)
                        }
                    }

                    Spacer(Modifier.height(16.dp))

                    // Check XREFs Button
                    Button(
                        onClick = {
                            xrefsList = viewModel.getXrefsFor(ins.address)
                            showXrefDialog = true
                            selectedInsn = null
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = CyanAccent),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Find Cross-References (XREFs)", color = Color.Black, fontWeight = FontWeight.Bold)
                    }

                    Spacer(Modifier.height(16.dp))
                }
            }
        }

        // XREFs Dialog
        if (showXrefDialog) {
            AlertDialog(
                onDismissRequest = { showXrefDialog = false },
                containerColor = SurfaceDark,
                title = { Text("Cross-References (${xrefsList.size})", color = CyanAccent) },
                text = {
                    if (xrefsList.isEmpty()) {
                        Text("No incoming calls or references found for this address.", color = ColorHexBytes)
                    } else {
                        LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 300.dp)) {
                            items(xrefsList) { ref ->
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = CardDark),
                                    shape = RoundedCornerShape(6.dp),
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable {
                                        viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                        showXrefDialog = false
                                    }
                                ) {
                                    Column(modifier = Modifier.padding(8.dp)) {
                                        Text("[${ref.kind}] in ${ref.caller_func ?: "unknown"}", color = AmberAccent, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                        Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                    }
                                }
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showXrefDialog = false }) {
                        Text("Close", color = CyanAccent)
                    }
                }
            )
        }
    }
}
