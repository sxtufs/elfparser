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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
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

    val clipboardManager = LocalClipboardManager.current
    var showFridaDialog by remember { mutableStateOf(false) }
    var fridaCode by remember { mutableStateOf("") }

    var showRenameDialog by remember { mutableStateOf(false) }
    var renameInput by remember { mutableStateOf("") }

    var showAssembleDialog by remember { mutableStateOf(false) }
    var assembleInput by remember { mutableStateOf("") }
    var currentEditInsnAddr by remember { mutableStateOf(0L) }

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

            // Action Buttons: Go to & Callers
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
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
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = colors.primary),
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

                    if (!ins.comment.isNullOrEmpty()) {
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = ins.comment,
                            color = Color(0xFFD97706),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            maxLines = 1
                        )
                    }
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

                    // 1. Jump to Target (Pill Button with comfortable, toned-down cyan)
                    if (branchTarget != null) {
                        Spacer(Modifier.height(14.dp))
                        Button(
                            onClick = {
                                viewModel.selectFunction(branchTarget, "sub_${"%08X".format(branchTarget)}")
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (colors.isDark) Color(0xFF00ACC1) else Color(0xFF0284C7),
                                contentColor = Color.White
                            ),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(48.dp)
                        ) {
                            Icon(
                                Icons.Default.OpenInNew,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Jump to Target",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }
                    }

                    Spacer(Modifier.height(18.dp))
                    Text(
                        "ONE-TAP QUICK PATCH",
                        color = colors.textSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(10.dp))

                    // 2. Quick Patch Buttons (Pill shape, same unified text color across all 4)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 1) { res ->
                                    Toast.makeText(context, "Patched NOP: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp)
                        ) {
                            Text("NOP", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }

                        OutlinedButton(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 2) { res ->
                                    Toast.makeText(context, "Patched Return True: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp)
                        ) {
                            Text("Ret True", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                    }

                    Spacer(Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 3) { res ->
                                    Toast.makeText(context, "Patched Return False: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp)
                        ) {
                            Text("Ret False", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }

                        OutlinedButton(
                            onClick = {
                                viewModel.applyQuickPatch(ins.address, 4) { res ->
                                    Toast.makeText(context, "Patched Return Void: ${res.success}", Toast.LENGTH_SHORT).show()
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp)
                        ) {
                            Text("Ret Void", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                    }

                    Spacer(Modifier.height(18.dp))

                    // 3. Find Cross-References Pill Button
                    OutlinedButton(
                        onClick = {
                            val target = branchTarget ?: ins.address
                            xrefsList = viewModel.getXrefsFor(target)
                            xrefDialogTitle = "XREFs to 0x${"%08X".format(target)}"
                            showXrefDialog = true
                            selectedInsn = null
                        },
                        colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                        shape = RoundedCornerShape(50),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp)
                    ) {
                        Text(
                            "Find Cross-References",
                            color = colors.primary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                    }

                    Spacer(Modifier.height(10.dp))

                    // 4. Action Row: Assemble, Rename, Frida Hook, Export .so
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                assembleInput = "${ins.mnemonic} ${ins.op_str}".trim()
                                currentEditInsnAddr = ins.address
                                showAssembleDialog = true
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.primary),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(44.dp)
                        ) {
                            Text("Assemble", color = colors.primary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1)
                        }

                        OutlinedButton(
                            onClick = {
                                renameInput = symbolName
                                showRenameDialog = true
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(44.dp)
                        ) {
                            Text("Rename", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1)
                        }

                        OutlinedButton(
                            onClick = {
                                fridaCode = generateFridaHook(
                                    moduleName = viewModel.currentFileName.value.ifEmpty { "libtarget.so" },
                                    funcName = symbolName,
                                    address = ins.address
                                )
                                showFridaDialog = true
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(44.dp)
                        ) {
                            Text("Frida", color = colors.primary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1)
                        }

                        OutlinedButton(
                            onClick = {
                                viewModel.savePatchedBinary(context) { savedPath ->
                                    if (savedPath != null) {
                                        Toast.makeText(context, "Saved to $savedPath", Toast.LENGTH_LONG).show()
                                    } else {
                                        Toast.makeText(context, "Failed to export binary", Toast.LENGTH_SHORT).show()
                                    }
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF4CAF50).copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(44.dp)
                        ) {
                            Text("Export", color = Color(0xFF4CAF50), fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1)
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
                shape = RoundedCornerShape(16.dp),
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
                                unfocusedTextColor = colors.textPrimary,
                                focusedLabelColor = colors.primary,
                                unfocusedLabelColor = colors.textSecondary,
                                cursorColor = colors.primary
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
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.primary,
                            contentColor = Color.White
                        )
                    ) {
                        Text("Jump", color = Color.White, fontWeight = FontWeight.Bold)
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
                shape = RoundedCornerShape(16.dp),
                title = { Text("$countText: $xrefDialogTitle", color = colors.primary, fontSize = 15.sp) },
                text = {
                    if (xrefsList.isEmpty()) {
                        Text("No callers or references found for this address in the binary.", color = colors.textSecondary, fontSize = 13.sp)
                    } else {
                        LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 300.dp)) {
                            items(xrefsList) { ref ->
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = colors.card),
                                    shape = RoundedCornerShape(8.dp),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
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

        // Frida Hook Script Dialog
        if (showFridaDialog) {
            AlertDialog(
                onDismissRequest = { showFridaDialog = false },
                containerColor = colors.surface,
                shape = RoundedCornerShape(16.dp),
                title = { Text("Frida Hook Script", color = colors.primary, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
                text = {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(colors.card, RoundedCornerShape(8.dp))
                            .padding(10.dp)
                    ) {
                        SelectionContainer {
                            Text(
                                text = fridaCode,
                                color = colors.operands,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            )
                        }
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(fridaCode))
                            Toast.makeText(context, "Copied Frida script to clipboard", Toast.LENGTH_SHORT).show()
                            showFridaDialog = false
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White)
                    ) {
                        Text("Copy Script", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showFridaDialog = false }) {
                        Text("Close", color = colors.textSecondary)
                    }
                }
            )
        }

        // Rename Function Dialog
        if (showRenameDialog) {
            AlertDialog(
                onDismissRequest = { showRenameDialog = false },
                containerColor = colors.surface,
                shape = RoundedCornerShape(16.dp),
                title = { Text("Rename Function", color = colors.primary, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
                text = {
                    Column {
                        Text("Enter new name for 0x${"%08X".format(currentAddr)}:", color = colors.textSecondary, fontSize = 12.sp)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = renameInput,
                            onValueChange = { renameInput = it },
                            label = { Text("Function Name") },
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
                            val newName = renameInput.trim()
                            if (newName.isNotEmpty()) {
                                viewModel.renameFunction(currentAddr, newName) { ok ->
                                    Toast.makeText(context, if (ok) "Function renamed" else "Rename failed", Toast.LENGTH_SHORT).show()
                                }
                                showRenameDialog = false
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White)
                    ) {
                        Text("Save", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showRenameDialog = false }) {
                        Text("Cancel", color = colors.textSecondary)
                    }
                }
            )
        }

        // Assemble / Edit Instruction Dialog
        if (showAssembleDialog) {
            AlertDialog(
                onDismissRequest = { showAssembleDialog = false },
                containerColor = colors.surface,
                shape = RoundedCornerShape(16.dp),
                title = { Text("Assemble / Edit Instruction", color = colors.primary, fontSize = 16.sp, fontWeight = FontWeight.Bold) },
                text = {
                    Column {
                        Text(
                            text = "Address: 0x${"%08X".format(currentEditInsnAddr)}",
                            color = colors.address,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = assembleInput,
                            onValueChange = { assembleInput = it },
                            label = { Text("Assembly or 4-byte Hex") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = colors.primary,
                                unfocusedBorderColor = colors.border,
                                focusedTextColor = colors.textPrimary,
                                unfocusedTextColor = colors.textPrimary
                            )
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Examples: b #0x37d58, bl #0x1234, nop, ret, or hex C4 26 00 14",
                            color = colors.textSecondary,
                            fontSize = 11.sp
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            viewModel.assemblePatch(currentEditInsnAddr, assembleInput) { res ->
                                if (res.success) {
                                    Toast.makeText(context, "Patched: ${res.patch_type}", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(context, "Error: ${res.error}", Toast.LENGTH_LONG).show()
                                }
                            }
                            showAssembleDialog = false
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White)
                    ) {
                        Text("Patch", color = Color.White, fontWeight = FontWeight.Bold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showAssembleDialog = false }) {
                        Text("Cancel", color = colors.textSecondary)
                    }
                }
            )
        }
    }
}

private fun generateFridaHook(moduleName: String, funcName: String, address: Long): String {
    val cleanMod = if (moduleName.endsWith(".so")) moduleName else "$moduleName.so"
    val cleanName = funcName.ifEmpty { "sub_${"%08X".format(address)}" }
    return """
// DisElf Frida Hook: $cleanName
var module = "$cleanMod";
var base = Module.findBaseAddress(module);

if (base) {
    var target = base.add(0x${"%X".format(address)});
    Interceptor.attach(target, {
        onEnter: function(args) {
            console.log("\n[+] Called $cleanName at " + target);
            console.log("    Caller: " + this.returnAddress);
            console.log("    Arg 0:  " + args[0]);
            console.log("    Arg 1:  " + args[1]);
        },
        onLeave: function(retval) {
            console.log("    Return: " + retval);
            // retval.replace(1);
        }
    });
    console.log("[*] Attached hook to $cleanName at " + target);
} else {
    console.log("[-] Module " + module + " is not loaded yet.");
}
""".trimIndent()
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
