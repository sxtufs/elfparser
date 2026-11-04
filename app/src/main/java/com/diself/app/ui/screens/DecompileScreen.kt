package com.diself.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel

@Composable
fun DecompileScreen(viewModel: DisElfViewModel) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val decompileCode by viewModel.decompileText.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .padding(12.dp)
    ) {
        // Toolbar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(SurfaceDark)
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Decompiled: $symbolName",
                color = CyanAccent,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp
            )
            IconButton(onClick = {
                clipboardManager.setText(AnnotatedString(decompileCode))
                Toast.makeText(context, "Copied C code to clipboard", Toast.LENGTH_SHORT).show()
            }) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = Color.White)
            }
        }

        Spacer(Modifier.height(8.dp))

        // Monospaced Code View with Horizontal & Vertical Scrolling
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(CardDark)
                .padding(12.dp)
                .verticalScroll(rememberScrollState())
                .horizontalScroll(rememberScrollState())
        ) {
            Text(
                text = decompileCode.ifEmpty { "// Select a function to decompile" },
                color = ColorOperands,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                lineHeight = 18.sp
            )
        }
    }
}
