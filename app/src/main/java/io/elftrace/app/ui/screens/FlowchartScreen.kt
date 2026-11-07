package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

@Composable
fun FlowchartScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val clipboardManager = LocalClipboardManager.current
    val flowchartText by viewModel.flowchartText.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    val displayTitle = remember(symbolName, currentAddr) {
        symbolName.ifEmpty { "sub_%08X".format(currentAddr) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        // Adaptive Header: max 2 lines, subtitle removed, Copy button vertically centered
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = displayTitle,
                color = colors.primary,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                lineHeight = 17.sp,
                maxLines = 2,
                softWrap = true,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp)
            )

            IconButton(
                onClick = {
                    clipboardManager.setText(AnnotatedString(flowchartText))
                    Toast.makeText(context, "Copied Flowchart to clipboard", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy",
                    tint = colors.textPrimary,
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        Spacer(Modifier.height(4.dp))

        val momentumFling = rememberMomentumFlingBehavior()

        // Flowchart View with Pure Vertical Scrolling & Auto-Fit
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.card, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(8.dp)
                .verticalScroll(rememberScrollState(), flingBehavior = momentumFling)
        ) {
            SelectionContainer {
                Text(
                    text = flowchartText.ifEmpty { "// Select a function to view its control flow graph" },
                    color = colors.operands,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 18.sp,
                    modifier = Modifier.fillMaxWidth(),
                    softWrap = true
                )
            }
        }
    }
}
