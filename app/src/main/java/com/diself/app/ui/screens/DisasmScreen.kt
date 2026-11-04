package com.diself.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel

@Composable
fun DisasmScreen(viewModel: DisElfViewModel) {
    val instructions by viewModel.instructions.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

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
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "VMA: 0x${"%08X".format(currentAddr)}",
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
                        .padding(horizontal = 4.dp, vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Address
                    Text(
                        text = "0x${"%08X".format(ins.address)}",
                        color = ColorAddress,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        modifier = Modifier.width(90.dp)
                    )

                    // Hex Bytes
                    Text(
                        text = ins.bytesHex,
                        color = ColorHexBytes,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        modifier = Modifier.width(100.dp)
                    )

                    // Mnemonic
                    Text(
                        text = ins.mnemonic,
                        color = ColorMnemonic,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        modifier = Modifier.width(60.dp)
                    )

                    // Operands
                    Text(
                        text = ins.op_str,
                        color = ColorOperands,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }
        }
    }
}
