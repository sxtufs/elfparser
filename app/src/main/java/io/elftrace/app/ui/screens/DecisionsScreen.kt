
package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.Instruction
import io.elftrace.app.ui.theme.LocalELFTraceColors
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen

/**
 * Control-flow Decision Locator.
 *
 * Scans the current function's disassembly and surfaces every *decision point*:
 * conditional branches (`b.cond`, `cbz/cbnz`, `tbz/tbnz`), the comparison that
 * guards them, and conditional selects (`csel`, `cset`, `cinc`, `ccmp`, ...).
 *
 * This is the fastest way to find the `if`s that matter when reversing — license
 * checks, validation gates, feature flags, switch dispatch — and jump straight
 * to the instruction. Pure data over the already-loaded instruction list; it
 * performs no native calls and cannot crash.
 */
@Composable
fun DecisionsScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val instructions by viewModel.instructions.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    val decisions = remember(instructions) { findDecisions(instructions) }
    val guard = remember(instructions) { lastCompare(instructions) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    "DECISION LOCATOR",
                    color = colors.primary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = (symbolName.ifEmpty { "sub_%08X".format(currentAddr) }),
                    color = colors.textPrimary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    maxLines = 1
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "${decisions.size} branch decision(s) in ${instructions.size} instructions",
                    color = colors.textSecondary,
                    fontSize = 11.sp
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        if (instructions.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "Select a function in Files to analyze its decisions",
                    color = colors.textSecondary,
                    fontSize = 12.sp
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(decisions) { d ->
                    val isGuard = guard != null && guard.address == d.guardAddress
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.card),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                viewModel.selectFunction(d.address, "sub_%08X".format(d.address))
                                viewModel.navigateTo(Screen.Code)
                            }
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = d.kind,
                                    color = kindColor(d.kind, colors.mnemonic, colors.register, colors.primary),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    text = "0x%08X".format(d.address),
                                    color = colors.address,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp
                                )
                                Spacer(Modifier.weight(1f))
                                if (d.target != null) {
                                    Text(
                                        text = "→ 0x%08X".format(d.target),
                                        color = colors.textSecondary,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                            Spacer(Modifier.height(3.dp))
                            Text(
                                text = d.text,
                                color = colors.textPrimary,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp
                            )
                            if (d.guardText != null) {
                                Spacer(Modifier.height(3.dp))
                                Text(
                                    text = "guard: ${d.guardText}",
                                    color = colors.textSecondary,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 10.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private data class Decision(
    val address: Long,
    val kind: String,
    val text: String,
    val target: Long?,
    val guardAddress: Long?,
    val guardText: String?
)

private fun kindColor(kind: String, mnemonic: androidx.compose.ui.graphics.Color, register: androidx.compose.ui.graphics.Color, primary: androidx.compose.ui.graphics.Color) = when (kind) {
    "COND" -> mnemonic
    "SELECT" -> register
    "CMP" -> primary
    else -> mnemonic
}

/// True for a conditional (not unconditional) branch mnemonic.
private fun isCondBranch(m: String): Boolean = when {
    m.startsWith("b.") -> true
    m.startsWith("cb") -> true   // cbz / cbnz
    m.startsWith("tb") -> true   // tbz / tbnz
    else -> false
}

private fun isCompare(m: String): Boolean =
    m in setOf("cmp", "cmn", "tst", "subs", "adds", "ands", "ccmp", "ccmn", "fcmpe", "fcmp")

private fun isSelect(m: String): Boolean =
    m.startsWith("csel") || m.startsWith("cset") || m.startsWith("cinc") ||
        m.startsWith("cinv") || m.startsWith("cneg") || m == "csinc" || m == "csinv" || m == "csneg"

/// Extract the branch target from an op string like `w0, #0x2000` or `0x2000`.
private fun branchTarget(opStr: String): Long? {
    val idx = opStr.lastIndexOf("0x")
    if (idx < 0) return null
    val hex = opStr.substring(idx + 2).takeWhile { it.isLetterOrDigit() }
    return hex.toLongOrNull(16)
}

private fun findDecisions(instructions: List<Instruction>): List<Decision> {
    val out = ArrayList<Decision>()
    var pendingCompare: Instruction? = null
    for (ins in instructions) {
        val m = ins.mnemonic.lowercase()
        if (isCompare(m)) {
            pendingCompare = ins
            // A compare that immediately precedes a conditional branch is the guard.
        } else if (isCondBranch(m)) {
            out.add(
                Decision(
                    address = ins.address,
                    kind = "COND",
                    text = "${ins.mnemonic} ${ins.op_str}",
                    target = branchTarget(ins.op_str),
                    guardAddress = pendingCompare?.address,
                    guardText = pendingCompare?.let { "${it.mnemonic} ${it.op_str} @ 0x%08X".format(it.address) }
                )
            )
            pendingCompare = null
        } else if (isSelect(m)) {
            out.add(
                Decision(
                    address = ins.address,
                    kind = "SELECT",
                    text = "${ins.mnemonic} ${ins.op_str}",
                    target = null,
                    guardAddress = pendingCompare?.address,
                    guardText = pendingCompare?.let { "${it.mnemonic} ${it.op_str} @ 0x%08X".format(it.address) }
                )
            )
            pendingCompare = null
        } else {
            // Any other real instruction breaks the compare→branch adjacency.
            pendingCompare = null
        }
    }
    return out
}

private fun lastCompare(instructions: List<Instruction>): Instruction? =
    instructions.lastOrNull { isCompare(it.mnemonic.lowercase()) }
