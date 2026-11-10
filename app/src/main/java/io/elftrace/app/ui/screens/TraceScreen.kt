package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

@Composable
fun TraceScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val traceState by viewModel.traceState.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        // Control Toolbar
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(
                    onClick = { viewModel.stepBackTrace() },
                    colors = ButtonDefaults.outlinedButtonColors(containerColor = colors.card),
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    shape = RoundedCornerShape(50)
                ) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Step Back", tint = colors.textPrimary, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Back", color = colors.textPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }

                Button(
                    onClick = { viewModel.stepTrace() },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = colors.primary,
                        contentColor = Color.White
                    ),
                    shape = RoundedCornerShape(50)
                ) {
                    Icon(Icons.Default.ArrowForward, contentDescription = "Step Next", tint = Color.White, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Step Next", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }

                IconButton(onClick = { viewModel.resetTrace() }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Reset Trace", tint = colors.textSecondary)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (traceState != null) {
            val state = traceState!!

            // Error banner (shown when the tracer halts on an unhandled instruction)
            if (state.error != null) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = Color(0x33FF5252)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                        Text(
                            "TRACE HALTED",
                            color = Color(0xFFFF5252),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = state.error!!,
                            color = colors.textPrimary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp
                        )
                    }
                }
                Spacer(Modifier.height(6.dp))
            } else {
                // Current Instruction Banner
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.card),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "PC: 0x${"%08X".format(state.pc)}",
                            color = colors.address,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.width(12.dp))
                        Text(
                            text = state.current_insn.ifEmpty { "Ready" },
                            color = colors.textPrimary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp
                        )
                    }
                }

                Spacer(Modifier.height(6.dp))

                // Flags Bar
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(colors.surface, RoundedCornerShape(8.dp))
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    // Prefer the architecture-native flag view when the engine
                    // provides one (x86 -> CF/ZF/SF/OF); otherwise show ARM's N/Z/C/V.
                    if (state.flags.isNotEmpty()) {
                        state.flags.forEach { f ->
                            FlagBadge(
                                f.name,
                                f.value,
                                isChanged = state.changed_flags.contains(f.name.lowercase()),
                                colors
                            )
                        }
                    } else {
                        FlagBadge("Z", state.z, isChanged = state.changed_flags.contains("z"), colors)
                        FlagBadge("N", state.n, isChanged = state.changed_flags.contains("n"), colors)
                        FlagBadge("C", state.c, isChanged = state.changed_flags.contains("c"), colors)
                        FlagBadge("V", state.v, isChanged = state.changed_flags.contains("v"), colors)
                    }
                }

                Spacer(Modifier.height(6.dp))

                // Registers Grid
                Text("REGISTER STATE", color = colors.textSecondary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))

                val regList = remember(state) {
                    // Prefer the architecture-neutral register view when the engine
                    // provides one (R0..R15, RAX..RIP, ...). Fall back to the
                    // legacy ARM64 layout (X0..X30 + SP) for the hand-written CPU.
                    if (state.regs.isNotEmpty()) {
                        state.regs.map { it.name to it.value }
                    } else {
                        val list = mutableListOf<Pair<String, Long>>()
                        list.add("SP" to state.sp)
                        state.x.forEachIndexed { i, val64 ->
                            list.add("X$i" to val64)
                        }
                        list
                    }
                }

                LazyVerticalGrid(
                    columns = GridCells.Fixed(3),
                    modifier = Modifier.fillMaxSize(),
                    flingBehavior = rememberMomentumFlingBehavior(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(
                        items = regList,
                        key = { it.first }
                    ) { (regName, regVal) ->
                        val isChanged = state.changed_regs.contains(regName.lowercase())
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = if (isChanged) colors.changedRegBg else colors.card
                            ),
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(8.dp)) {
                                Text(
                                    text = regName,
                                    color = if (isChanged) colors.changedReg else colors.register,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "0x${"%08X".format(regVal)}",
                                    color = colors.textPrimary,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun FlagBadge(name: String, active: Boolean, isChanged: Boolean, colors: ELFTraceColors) {
    Surface(
        shape = RoundedCornerShape(6.dp),
        color = when {
            isChanged -> Color(0x444CAF50)
            active -> Color(0x224CAF50)
            else -> colors.card
        },
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            when {
                isChanged -> Color(0xFF4CAF50)
                active -> Color(0xFF4CAF50).copy(alpha = 0.5f)
                else -> colors.border
            }
        )
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "${if (isChanged) "● " else ""}$name: ${if (active) "1" else "0"}",
                color = when {
                    active -> Color(0xFF4CAF50)
                    else -> colors.textSecondary
                },
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                fontWeight = if (active) FontWeight.Bold else FontWeight.Medium,
                maxLines = 1,
                softWrap = false
            )
        }
    }
}
