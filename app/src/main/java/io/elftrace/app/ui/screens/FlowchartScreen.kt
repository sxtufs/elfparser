package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

@Composable
fun FlowchartScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val flowchartText by viewModel.flowchartText.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        val momentumFling = rememberMomentumFlingBehavior()

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.card, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(8.dp)
                .verticalScroll(rememberScrollState(), flingBehavior = momentumFling)
                .horizontalScroll(rememberScrollState(), flingBehavior = momentumFling)
        ) {
            SelectionContainer {
                Text(
                    text = flowchartText.ifEmpty { "// Select a function to view its control flow graph" },
                    color = colors.operands,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                )
            }
        }
    }
}
