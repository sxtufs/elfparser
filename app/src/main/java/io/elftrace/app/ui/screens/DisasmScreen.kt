package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.CallMade
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
import io.elftrace.app.core.models.CallHierarchy
import io.elftrace.app.core.models.Instruction
import io.elftrace.app.core.models.PatchPropagationReport
import io.elftrace.app.core.models.PropagatedPatch
import io.elftrace.app.core.models.XRefItem
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DisasmScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val instructions by viewModel.instructions.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()
    val undoDepth by viewModel.undoDepth.collectAsState()

    var selectedInsn by remember { mutableStateOf<Instruction?>(null) }
    var xrefsList by remember { mutableStateOf<List<XRefItem>>(emptyList()) }
    var showXrefDialog by remember { mutableStateOf(false) }
    var xrefDialogTitle by remember { mutableStateOf("Cross-References") }

    var showHierarchyDialog by remember { mutableStateOf(false) }
    var callHierarchy by remember { mutableStateOf(CallHierarchy()) }

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

    // Patch propagation review state (ExactClone = 1, Callers = 2).
    var showPropagateDialog by remember { mutableStateOf(false) }
    var propagateInsnAddr by remember { mutableStateOf(0L) }
    var propagateSeedLabel by remember { mutableStateOf("") }

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
                        viewModel.loadHierarchy(currentAddr) { hierarchy ->
                            callHierarchy = hierarchy
                            showHierarchyDialog = true
                        }
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = colors.primary),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.AccountTree, contentDescription = null, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(3.dp))
                    Text("Hierarchy", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        // Virtualized Disassembly LazyColumn with Momentum Fling & Native Text Selection
        SelectionContainer(modifier = Modifier.fillMaxSize()) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                flingBehavior = rememberMomentumFlingBehavior(),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                items(
                    items = instructions,
                    key = { it.address },
                    contentType = { "instruction" }
                ) { ins ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { selectedInsn = ins }
                            .padding(horizontal = 4.dp, vertical = 3.dp)
                    ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "0x${"%08X".format(ins.address)}",
                            color = colors.address,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            modifier = Modifier.width(86.dp)
                        )

                        Text(
                            text = ins.bytesHex,
                            color = colors.hexBytes,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            modifier = Modifier.width(92.dp)
                        )

                        Text(
                            text = ins.mnemonic,
                            color = colors.mnemonic,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.width(52.dp)
                        )

                        Text(
                            text = ins.op_str,
                            color = colors.operands,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp
                        )
                    }

                        // In-Line Annotation (Strings, JNI API calls, Syscalls) - cleanly visible on mobile screens!
                        if (!ins.comment.isNullOrEmpty()) {
                            Row(modifier = Modifier.padding(start = 86.dp, top = 1.dp)) {
                                Text(
                                    text = ins.comment,
                                    color = Color(0xFFF59E0B), // Vibrant Amber Glow
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
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
                shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
                dragHandle = null
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 18.dp, end = 18.dp, top = 16.dp, bottom = 12.dp)
                ) {
                    Text(
                        text = "Instruction Analysis",
                        style = MaterialTheme.typography.titleMedium,
                        color = colors.textPrimary,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = "0x${"%08X".format(ins.address)}: ${ins.mnemonic} ${ins.op_str}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = colors.primary,
                        fontWeight = FontWeight.SemiBold
                    )
                    if (!ins.comment.isNullOrEmpty()) {
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = ins.comment,
                            color = Color(0xFFF59E0B),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    // Jump to branch target
                    if (branchTarget != null) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                viewModel.selectFunction(branchTarget, "sub_${"%08X".format(branchTarget)}")
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(44.dp)
                        ) {
                            Text(
                                "Jump to Target",
                                color = colors.primary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                        }
                    }

                    Spacer(Modifier.height(10.dp))
                    Text(
                        "ONE-TAP QUICK PATCH",
                        color = colors.textSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(6.dp))

                    // Quick patch buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
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
                                .height(42.dp)
                        ) {
                            Text("NOP", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
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
                                .height(42.dp)
                        ) {
                            Text("Ret True", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }

                    Spacer(Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
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
                                .height(42.dp)
                        ) {
                            Text("Ret False", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
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
                                .height(42.dp)
                        ) {
                            Text("Ret Void", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }

                    Spacer(Modifier.height(10.dp))

                    // Find cross-references
                    OutlinedButton(
                        onClick = {
                            val target = branchTarget ?: ins.address
                            viewModel.loadXrefsFor(target) { list ->
                                xrefsList = list
                                xrefDialogTitle = "XREFs to 0x${"%08X".format(target)}"
                                showXrefDialog = true
                            }
                            selectedInsn = null
                        },
                        colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                        shape = RoundedCornerShape(50),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp)
                    ) {
                        Text(
                            "Find Cross-References",
                            color = colors.primary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }

                    Spacer(Modifier.height(8.dp))

                    // Utility actions (2x2 grid avoids label truncation)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
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
                            modifier = Modifier.weight(1f).height(42.dp)
                        ) {
                            Text("Assemble", color = colors.primary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1, softWrap = false)
                        }
                        OutlinedButton(
                            onClick = {
                                propagateInsnAddr = ins.address
                                propagateSeedLabel = "${ins.mnemonic} ${ins.op_str}".trim()
                                showPropagateDialog = true
                                selectedInsn = null
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.primary),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(42.dp)
                        ) {
                            Text("Propagate", color = colors.primary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1, softWrap = false)
                        }
                    }

                    Spacer(Modifier.height(6.dp))

                    // Undo + Rename on their own row so labels never truncate.
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                viewModel.undoLastPatch { addr ->
                                    Toast.makeText(
                                        context,
                                        if (addr >= 0) "Undid patch at 0x${addr.toString(16)}" else "Nothing to undo",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            },
                            enabled = undoDepth > 0,
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (undoDepth > 0) colors.primary else colors.border),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(42.dp)
                        ) {
                            Text("Undo" + if (undoDepth > 0) " ($undoDepth)" else "", color = if (undoDepth > 0) colors.primary else colors.textSecondary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1, softWrap = false)
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
                            modifier = Modifier.weight(1f).height(42.dp)
                        ) {
                            Text("Rename", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1, softWrap = false)
                        }
                    }

                    Spacer(Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
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
                            modifier = Modifier.weight(1f).height(42.dp)
                        ) {
                            Text("Frida Hook", color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1, softWrap = false)
                        }

                        OutlinedButton(
                            onClick = {
                                viewModel.savePatchedBinary(context) { outcome ->
                                    when (outcome) {
                                        is io.elftrace.app.viewmodel.ELFTraceViewModel.SaveOutcome.Public ->
                                            Toast.makeText(context, "Saved to ${outcome.path}", Toast.LENGTH_LONG).show()
                                        io.elftrace.app.viewmodel.ELFTraceViewModel.SaveOutcome.Failed ->
                                            Toast.makeText(context, "Failed to export binary", Toast.LENGTH_SHORT).show()
                                    }
                                    selectedInsn = null
                                }
                            },
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                            border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF4CAF50).copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.weight(1f).height(42.dp)
                        ) {
                            Text("Export .so", color = Color(0xFF4CAF50), fontWeight = FontWeight.Bold, fontSize = 11.sp, maxLines = 1, softWrap = false)
                        }
                    }

                    Spacer(Modifier.height(8.dp))
                }
            }
        }

        // Go-to-address dialog
        if (showGotoDialog) {
            AlertDialog(onDismissRequest = { showGotoDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Go to Address (VMA)", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(4.dp))
                        Text("Enter virtual address to disassemble:", color = colors.textSecondary, fontSize = 11.sp)
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
                        Spacer(Modifier.height(12.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
                            TextButton(onClick = { showGotoDialog = false }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                            Spacer(Modifier.width(8.dp))
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

        // Cross-reference dialog
        if (showXrefDialog) {
            val count = xrefsList.size
            val countText = when (count) {
                0 -> "No callers found"
                1 -> "1 caller found"
                else -> "$count callers found"
            }
            AlertDialog(onDismissRequest = { showXrefDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("$countText: $xrefDialogTitle", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        // Only true call sites (bl/blx) are safe to NOP in bulk.
                        // Branch refs (b, b.cond, cbz, tbz) are excluded because
                        // neutralising them can change control flow.
                        val callers = xrefsList.filter { it.kind == "Call" }
                        if (callers.isNotEmpty()) {
                            var confirmPatchAll by remember { mutableStateOf(false) }
                            Button(
                                onClick = { confirmPatchAll = true },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Patch all ${callers.size} callers (NOP)", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }
                            Spacer(Modifier.height(8.dp))
                            if (confirmPatchAll) {
                                Text(
                                    "This NOPs the call at each caller site (undoable). Continue?",
                                    color = colors.textSecondary, fontSize = 11.sp
                                )
                                Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                                    TextButton(onClick = { confirmPatchAll = false }) {
                                        Text("No", color = colors.textSecondary)
                                    }
                                    TextButton(onClick = {
                                        confirmPatchAll = false
                                        viewModel.patchCallers(callers.map { it.from_address }) { applied, skipped ->
                                            Toast.makeText(
                                                context,
                                                "Patched " + applied + (if (skipped > 0) ", skipped " + skipped else ""),
                                                Toast.LENGTH_SHORT
                                            ).show()
                                        }
                                    }) {
                                        Text("Patch all", color = colors.primary, fontWeight = FontWeight.Bold)
                                    }
                                }
                                Spacer(Modifier.height(8.dp))
                            }
                        }
                        if (xrefsList.isEmpty()) {
                            Text("No callers or references found for this address in the binary.", color = colors.textSecondary, fontSize = 12.sp)
                        } else {
                            LazyColumn(
                                modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp),
                                flingBehavior = rememberMomentumFlingBehavior(),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                items(xrefsList) { ref ->
                                    Card(
                                        colors = CardDefaults.cardColors(containerColor = colors.card),
                                        shape = RoundedCornerShape(8.dp),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                        modifier = Modifier.fillMaxWidth().clickable {
                                            viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                            showXrefDialog = false
                                        }
                                    ) {
                                        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
                                            Text("[${ref.kind}] in ${ref.caller_func ?: "unknown"}", color = AmberAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                            Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = colors.textPrimary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                        }
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { showXrefDialog = false }) {
                                Text("Close", color = colors.primary)
                            }
                        }
                    }
                }
            }
        }

        // Call Hierarchy Dialog (Callers & Callees Tree)
        if (showHierarchyDialog) {
            var selectedTab by remember { mutableStateOf(if (callHierarchy.callers.isNotEmpty()) 0 else 1) }

            AlertDialog(onDismissRequest = { showHierarchyDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 6.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text(
                            text = shortTitle,
                            color = colors.primary,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            lineHeight = 20.sp
                        )
                        Spacer(Modifier.height(8.dp))

                        // Sub-tabs: Callers vs Callees
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(colors.card, RoundedCornerShape(50))
                                .padding(2.dp)
                        ) {
                            val callersCount = callHierarchy.callers.size
                            val calleesCount = callHierarchy.callees.size

                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(
                                        if (selectedTab == 0) colors.primary else Color.Transparent,
                                        RoundedCornerShape(50)
                                    )
                                    .clickable { selectedTab = 0 }
                                    .padding(vertical = 6.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "Callers ($callersCount)",
                                    color = if (selectedTab == 0) Color.White else colors.textSecondary,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }

                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(
                                        if (selectedTab == 1) colors.primary else Color.Transparent,
                                        RoundedCornerShape(50)
                                    )
                                    .clickable { selectedTab = 1 }
                                    .padding(vertical = 6.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = "Callees ($calleesCount)",
                                    color = if (selectedTab == 1) Color.White else colors.textSecondary,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }

                        Spacer(Modifier.height(10.dp))

                        val momentumFling = rememberMomentumFlingBehavior()

                        if (selectedTab == 0) {
                            // Callers List
                            if (callHierarchy.callers.isEmpty()) {
                                Box(modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp), contentAlignment = Alignment.Center) {
                                    Text("No incoming callers found in binary.", color = colors.textSecondary, fontSize = 12.sp)
                                }
                            } else {
                                LazyColumn(
                                    modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp),
                                    flingBehavior = momentumFling,
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    items(callHierarchy.callers) { ref ->
                                        Card(
                                            colors = CardDefaults.cardColors(containerColor = colors.card),
                                            shape = RoundedCornerShape(8.dp),
                                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                            modifier = Modifier.fillMaxWidth().clickable {
                                                viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                                showHierarchyDialog = false
                                            }
                                        ) {
                                            Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
                                                Text(ref.caller_func ?: "unknown", color = colors.primary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                                Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = colors.textPrimary, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // Callees List
                            if (callHierarchy.callees.isEmpty()) {
                                Box(modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp), contentAlignment = Alignment.Center) {
                                    Text("No outgoing function calls from this routine.", color = colors.textSecondary, fontSize = 12.sp)
                                }
                            } else {
                                LazyColumn(
                                    modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp),
                                    flingBehavior = momentumFling,
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    items(callHierarchy.callees) { callee ->
                                        Card(
                                            colors = CardDefaults.cardColors(containerColor = colors.card),
                                            shape = RoundedCornerShape(8.dp),
                                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                            modifier = Modifier.fillMaxWidth().clickable {
                                                if (callee.target_address != 0L) {
                                                    viewModel.selectFunction(callee.target_address, callee.target_name)
                                                    showHierarchyDialog = false
                                                }
                                            }
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Column(modifier = Modifier.weight(1f)) {
                                                    Text(callee.target_name, color = if (callee.target_name.startsWith("JNI:")) AmberAccent else colors.primary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                                    if (callee.target_address != 0L) {
                                                        Text("0x${"%08X".format(callee.target_address)}  (${callee.instruction})", color = colors.textSecondary, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                                                    } else {
                                                        Text(callee.instruction, color = colors.textSecondary, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                                                    }
                                                }
                                                if (callee.call_count > 1) {
                                                    Text("${callee.call_count}x", color = colors.address, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { showHierarchyDialog = false }) {
                                Text("Close", color = colors.primary)
                            }
                        }
                    }
                }
            }
        }

        // Frida hook script dialog
        if (showFridaDialog) {
            AlertDialog(onDismissRequest = { showFridaDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Frida Hook Script", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 280.dp)
                                .background(colors.card, RoundedCornerShape(8.dp))
                                .padding(10.dp)
                                .verticalScroll(rememberScrollState(), flingBehavior = rememberMomentumFlingBehavior())
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
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(onClick = { showFridaDialog = false }) {
                                Text("Close", color = colors.textSecondary)
                            }
                            Spacer(Modifier.width(8.dp))
                            Button(
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(fridaCode))
                                    Toast.makeText(context, "Copied Frida script to clipboard", Toast.LENGTH_SHORT).show()
                                    showFridaDialog = false
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White),
                                shape = RoundedCornerShape(50)
                            ) {
                                Text("Copy Script", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }
                        }
                    }
                }
            }
        }

        // Rename function dialog
        if (showRenameDialog) {
            AlertDialog(onDismissRequest = { showRenameDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Rename Function", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(4.dp))
                        Text("Enter new name for 0x${"%08X".format(currentAddr)}:", color = colors.textSecondary, fontSize = 11.sp)
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
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(onClick = { showRenameDialog = false }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                            Spacer(Modifier.width(8.dp))
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
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White),
                                shape = RoundedCornerShape(50)
                            ) {
                                Text("Save", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }
                        }
                    }
                }
            }
        }

        // Assemble / edit instruction dialog
        if (showPropagateDialog) {
            PropagationReviewDialog(
                viewModel = viewModel,
                seedAddr = propagateInsnAddr,
                seedLabel = propagateSeedLabel,
                onDismiss = { showPropagateDialog = false }
            )
        }

        if (showAssembleDialog) {
            AlertDialog(onDismissRequest = { showAssembleDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Assemble / Edit Instruction", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Address: 0x${"%08X".format(currentEditInsnAddr)}",
                            color = colors.address,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp
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
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Examples: b #0x37d58, bl #0x1234, nop, ret, or hex C4 26 00 14",
                            color = colors.textSecondary,
                            fontSize = 10.sp
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(onClick = { showAssembleDialog = false }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                            Spacer(Modifier.width(8.dp))
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
                                colors = ButtonDefaults.buttonColors(containerColor = colors.primary, contentColor = Color.White),
                                shape = RoundedCornerShape(50)
                            ) {
                                Text("Patch", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}
private fun generateFridaHook(moduleName: String, funcName: String, address: Long): String {
    val cleanMod = if (moduleName.endsWith(".so")) moduleName else "$moduleName.so"
    val cleanName = funcName.ifEmpty { "sub_${"%08X".format(address)}" }
    return """
// ELFTrace Frida Hook: $cleanName
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

/**
 * Patch Propagation review dialog.
 *
 * Dry-run on open (nothing written) -> list every candidate / skip with a
 * checkbox -> "Apply N" re-runs propagation for the confirmed subset.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PropagationReviewDialog(
    viewModel: ELFTraceViewModel,
    seedAddr: Long,
    seedLabel: String,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    var report by remember { mutableStateOf<PatchPropagationReport?>(null) }
    var loading by remember { mutableStateOf(true) }
    var selected by remember { mutableStateOf<Set<Long>>(emptySet()) }

    // Exact Clone propagation only. Caller discovery is already covered by
    // the Hierarchy/XREF view, so a separate "Callers" mode here would be
    // redundant; Exact Clones is the unique capability (finding inline-
    // duplicated bodies that XREF cannot see).
    val mode = 1
    var patchValue by remember { mutableStateOf("nop") }

    LaunchedEffect(seedAddr, patchValue) {
        loading = true
        viewModel.propagatePatch(seedAddr, mode, "quick", patchValue, dryRun = true) { r ->
            report = r
            selected = r.entries.filter { it.status == "candidate" }.map { it.address }.toSet()
            loading = false
        }
    }

    AlertDialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = colors.card,
            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                Text(
                    "Propagate Patch",
                    color = colors.primary, fontWeight = FontWeight.Bold, fontSize = 15.sp
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Seed 0x" + "%08X".format(seedAddr) + "  (" + seedLabel + ")",
                    color = colors.address, fontFamily = FontFamily.Monospace, fontSize = 11.sp
                )
                Spacer(Modifier.height(6.dp))

                // Scope is fixed to Exact Clones (see rationale above).
                Text(
                    "Scope: Exact Clones (inline duplicates)",
                    color = colors.textSecondary, fontSize = 10.sp
                )
                Spacer(Modifier.height(6.dp))

                // Patch selector.
                Text("Patch", color = colors.textSecondary, fontSize = 10.sp)
                Row {
                    listOf("nop" to "NOP", "ret_true" to "True", "ret_false" to "False", "ret_void" to "Void").forEach { (v, label) ->
                        FilterChip(selected = patchValue == v, onClick = { patchValue = v },
                            label = { Text(label, fontSize = 10.sp) })
                        Spacer(Modifier.width(4.dp))
                    }
                }
                Spacer(Modifier.height(8.dp))
                val r = report
                when {
                    loading -> Text("Scanning for matches\u2026", color = colors.textSecondary, fontSize = 12.sp)
                    r == null -> Text("No report", color = colors.textSecondary, fontSize = 12.sp)
                    r.error != null -> Text("Error: " + r.error, color = Color(0xFFFF6B6B), fontSize = 12.sp)
                    r.total_candidates == 0 -> Text("No other matches found.", color = colors.textSecondary, fontSize = 12.sp)
                    else -> {
                        Text(
                            "" + r.total_candidates + " found, " + r.skipped + " skipped" + (if (r.truncated) " (capped)" else ""),
                            color = colors.textSecondary, fontSize = 12.sp
                        )
                        Spacer(Modifier.height(6.dp))
                        LazyColumn(modifier = Modifier.heightIn(max = 260.dp)) {
                            items(r.entries) { e ->
                                val isCandidate = e.status == "candidate"
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(
                                        checked = selected.contains(e.address),
                                        enabled = isCandidate,
                                        onCheckedChange = { on ->
                                            selected = if (on) selected + e.address else selected - e.address
                                        }
                                    )
                                    Column {
                                        Text(
                                            "0x" + "%08X".format(e.address),
                                            color = if (isCandidate) colors.primary else colors.textSecondary,
                                            fontFamily = FontFamily.Monospace, fontSize = 11.sp
                                        )
                                        if (!isCandidate && e.reason != null) {
                                            Text(e.reason, color = colors.textSecondary, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Buttons live INSIDE the content column so the M3 AlertDialog
                // does not reserve a separate bottom area (which produced large
                // empty gaps when the result was a single short line).
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Cancel", color = colors.textSecondary)
                    }
                    Spacer(Modifier.width(8.dp))
                    TextButton(
                        enabled = !loading && selected.isNotEmpty(),
                        onClick = {
                            viewModel.propagatePatch(seedAddr, mode, "quick", patchValue, dryRun = false) { applied ->
                                if (applied.error != null) {
                                    Toast.makeText(context, "Error: " + applied.error, Toast.LENGTH_LONG).show()
                                } else {
                                    Toast.makeText(
                                        context,
                                        "Applied " + applied.applied + ", skipped " + applied.skipped,
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                                onDismiss()
                            }
                        }
                    ) {
                        Text("Apply " + selected.size, color = colors.primary, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
