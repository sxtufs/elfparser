package com.diself.app.ui.screens

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
import com.diself.app.R
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel

@Composable
fun TraceScreen(viewModel: DisElfViewModel) {
    val colors = LocalDisElfColors.current
    val traceState by viewModel.traceState.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(12.dp)
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
                    .padding(8.dp),
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

        Spacer(Modifier.height(12.dp))

        if (traceState != null) {
            val state = traceState!!

            // Current Instruction Banner
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.card),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("EXECUTING INSTRUCTION", color = AmberAccent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
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
            }

            Spacer(Modifier.height(12.dp))

            // Flags Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(colors.surface, RoundedCornerShape(8.dp))
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceAround
            ) {
                FlagBadge("Z (Zero)", state.z, colors)
                FlagBadge("N (Neg)", state.n, colors)
                FlagBadge("C (Carry)", state.c, colors)
                FlagBadge("V (Ovf)", state.v, colors)
            }

            Spacer(Modifier.height(12.dp))

            // Registers Grid
            Text("REGISTER STATE", color = colors.textSecondary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))

            val regList = remember(state) {
                val list = mutableListOf<Pair<String, Long>>()
                list.add("SP" to state.sp)
                state.x.forEachIndexed { i, val64 ->
                    list.add("X$i" to val64)
                }
                list
            }

            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                modifier = Modifier.fillMaxSize(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(regList) { (regName, regVal) ->
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

@Composable
fun FlagBadge(name: String, active: Boolean, colors: DisElfColors) {
    Text(
        text = "$name: ${if (active) "1" else "0"}",
        color = if (active) colors.address else colors.textSecondary,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        fontWeight = if (active) FontWeight.Bold else FontWeight.Normal
    )
}
