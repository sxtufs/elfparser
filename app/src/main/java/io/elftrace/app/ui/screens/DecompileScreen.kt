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
fun DecompileScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val clipboardManager = LocalClipboardManager.current
    val decompileCode by viewModel.decompileText.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    val shortTitle = remember(symbolName, currentAddr) {
        if (symbolName.contains(" -> ")) {
            symbolName
        } else if (symbolName.contains("::")) {
            symbolName.substringAfterLast("::")
        } else if (symbolName.contains(".")) {
            val pkg = symbolName.substringBeforeLast(".")
            val meth = symbolName.substringAfterLast(".")
            val shortPkg = if (pkg.length > 20) pkg.take(18) + "…" else pkg
            "$shortPkg -> $meth"
        } else {
            symbolName
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        // Toolbar (Fixed weight ensures copy button is NEVER pushed off-screen)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    text = shortTitle,
                    color = colors.primary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.5.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "Decompiled C (0x${"%08X".format(currentAddr)})",
                    color = colors.textSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            IconButton(
                onClick = {
                    clipboardManager.setText(AnnotatedString(decompileCode))
                    Toast.makeText(context, "Copied C code to clipboard", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.size(32.dp)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = colors.textPrimary, modifier = Modifier.size(18.dp))
            }
        }

        Spacer(Modifier.height(4.dp))

        val momentumFling = rememberMomentumFlingBehavior()

        // Selectable Monospaced Code View with Pure Vertical Scrolling & Word-Wrap (Fits to screen width)
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(colors.card, androidx.compose.foundation.shape.RoundedCornerShape(8.dp))
                .padding(8.dp)
                .verticalScroll(rememberScrollState(), flingBehavior = momentumFling)
        ) {
            SelectionContainer {
                Text(
                    text = decompileCode.ifEmpty { "// Select a function to decompile" },
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
