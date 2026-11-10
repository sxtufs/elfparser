
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.Instruction
import io.elftrace.app.ui.theme.LocalELFTraceColors
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen

/**
 * Branch / control-flow analyzer for the selected function.
 *
 * Turns a flat disassembly into higher-level structure that a linear listing
 * hides:
 *   * COND    — conditional branches (`b.cond`, `cbz/cbnz`, `tbz/tbnz`) with
 *               their guard (the `cmp/tst` that set the flags, when applicable).
 *   * SELECT  — conditional selects (`csel`, `cset`, `cinc`, ...).
 *   * SWITCH  — jump-table / computed-dispatch patterns
 *               (`adrp+add+ldrsw+br`, `tbh/tbn`, pc-relative tables).
 *   * LOOP    — a branch whose target is *below* it (a back-edge), i.e. a loop.
 *
 * It analyzes the full-function disassembly window (`analysisInstructions`),
 * not just the 256-byte slice the Code tab shows, so it sees every branch. It
 * performs no native calls — pure data — so it cannot crash.
 */
@Composable
fun BranchesScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val instructions by viewModel.analysisInstructions.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    var filter by remember { mutableStateOf(BranchFilter.All) }

    val all = remember(instructions, currentAddr) { analyze(instructions, currentAddr) }
    val shown = remember(all, filter) {
        when (filter) {
            BranchFilter.All -> all
            BranchFilter.Cond -> all.filter { it.kind == "COND" }
            BranchFilter.Loops -> all.filter { it.isLoop }
            BranchFilter.Switch -> all.filter { it.kind == "SWITCH" }
        }
    }

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
                    "BRANCHES",
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
                    text = "${all.size} branch(es), ${all.count { it.isLoop }} loop(s), " +
                        "${all.count { it.kind == "SWITCH" }} switch(es) in ${instructions.size} insns",
                    color = colors.textSecondary,
                    fontSize = 11.sp
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            BranchFilter.values().forEach { f ->
                val selected = filter == f
                Box(
                    modifier = Modifier
                        .background(
                            if (selected) colors.primary.copy(alpha = 0.18f) else colors.card,
                            RoundedCornerShape(50)
                        )
                        .clickable { filter = f }
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = f.label,
                        color = if (selected) colors.primary else colors.textSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (instructions.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "Select a function in Files to analyze its branches",
                    color = colors.textSecondary,
                    fontSize = 12.sp
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(shown) { b ->
                    BranchCard(b, colors) {
                        viewModel.selectFunction(b.address, "sub_%08X".format(b.address))
                        viewModel.navigateTo(Screen.Code)
                    }
                }
            }
        }
    }
}

@Composable
private fun BranchCard(b: Branch, colors: io.elftrace.app.ui.theme.ELFTraceColors, onClick: () -> Unit) {
    val accent = when (b.kind) {
        "SWITCH" -> colors.register
        "SELECT" -> colors.primary
        else -> colors.mnemonic
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.card),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = b.kind,
                    color = accent,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "0x%08X".format(b.address),
                    color = colors.address,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp
                )
                Spacer(Modifier.width(6.dp))
                if (b.isLoop) {
                    Badge("LOOP ↵", colors.changedReg)
                }
                Spacer(Modifier.weight(1f))
                if (b.target != null) {
                    Text(
                        text = "→ 0x%08X".format(b.target),
                        color = colors.textSecondary,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp
                    )
                }
            }
            Spacer(Modifier.height(3.dp))
            Text(
                text = b.text,
                color = colors.textPrimary,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp
            )
            if (b.detail != null) {
                Spacer(Modifier.height(3.dp))
                Text(
                    text = b.detail,
                    color = colors.textSecondary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp
                )
            }
        }
    }
}

@Composable
private fun Badge(text: String, color: Color) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.18f), RoundedCornerShape(50))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            color = color,
            fontFamily = FontFamily.Monospace,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

private enum class BranchFilter(val label: String) {
    All("All"),
    Cond("Branches"),
    Loops("Loops"),
    Switch("Switches")
}

private data class Branch(
    val address: Long,
    val kind: String,
    val text: String,
    val target: Long?,
    val isLoop: Boolean,
    val detail: String?
)

// ---- analysis ----------------------------------------------------------

private val COMPARE_MNEMONICS = setOf(
    "cmp", "cmn", "tst", "subs", "adds", "ands", "ccmp", "ccmn", "fcmp", "fcmpe"
)

private fun isFlagBranch(m: String) = m.startsWith("b.")
private fun isRegTestBranch(m: String) = m.startsWith("cb") || m.startsWith("tb")
private fun isSelect(m: String) =
    m.startsWith("csel") || m.startsWith("cset") || m.startsWith("cinc") ||
        m.startsWith("cinv") || m.startsWith("cneg") ||
        m == "csinc" || m == "csinv" || m == "csneg"

/// Extract the last `0x...` operand as a branch target.
private fun lastHex(opStr: String): Long? {
    val idx = opStr.lastIndexOf("0x")
    if (idx < 0) return null
    val hex = opStr.substring(idx + 2).takeWhile { it.isLetterOrDigit() }
    return hex.toLongOrNull(16)
}

/// Analyze a full-function instruction list into a flat list of branches.
private fun analyze(instructions: List<Instruction>, funcStart: Long): List<Branch> {
    val out = ArrayList<Branch>()
    var guard: Instruction? = null
    var i = 0
    while (i < instructions.size) {
        val ins = instructions[i]
        val m = ins.mnemonic.lowercase()

        // --- Switch / computed dispatch heuristics ---
        // Pattern A: `br <reg>` shortly after an `ldrsw`/`ldr` from a table.
        // Pattern B: `tbh` / `tbn` (table branch).
        if (m == "tbh" || m == "tbn") {
            out.add(Branch(ins.address, "SWITCH", "${ins.mnemonic} ${ins.op_str}", null, false,
                "table branch (switch dispatch)"))
            guard = null; i++; continue
        }
        if (m == "br") {
            // Look back up to 4 instructions for the table load that fed this br.
            val tableLoad = (i - 1 downTo maxOf(0, i - 4)).map { instructions[it] }.firstOrNull {
                val mm = it.mnemonic.lowercase()
                mm == "ldrsw" || mm == "ldr" || mm == "ldrb" || mm == "ldrh"
            }
            if (tableLoad != null) {
                out.add(Branch(ins.address, "SWITCH", "${ins.mnemonic} ${ins.op_str}", null, false,
                    "computed jump via ${tableLoad.mnemonic} ${tableLoad.op_str}"))
            }
            guard = null; i++; continue
        }

        // --- Conditional branches ---
        if (isFlagBranch(m) || isRegTestBranch(m)) {
            val target = lastHex(ins.op_str)
            // Back-edge = target strictly before this branch BUT still inside
            // this function. Targets before funcStart are mis-attributed.
            val isLoop = target != null && target >= funcStart && target < ins.address
            val guardText = if (isFlagBranch(m)) {
                guard?.let { "guard: ${it.mnemonic} ${it.op_str} @ 0x%08X".format(it.address) }
            } else null
            out.add(Branch(ins.address, "COND", "${ins.mnemonic} ${ins.op_str}", target, isLoop, guardText))
            guard = null; i++; continue
        }

        // --- Conditional selects ---
        if (isSelect(m)) {
            val guardText = guard?.let { "guard: ${it.mnemonic} ${it.op_str} @ 0x%08X".format(it.address) }
            out.add(Branch(ins.address, "SELECT", "${ins.mnemonic} ${ins.op_str}", null, false, guardText))
            guard = null; i++; continue
        }

        // --- Track the flag-setting guard, else invalidate it ---
        if (m in COMPARE_MNEMONICS) {
            guard = ins
        } else {
            guard = null
        }
        i++
    }
    return out
}
