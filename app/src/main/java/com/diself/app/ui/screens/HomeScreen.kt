package com.diself.app.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel
import com.diself.app.viewmodel.Screen
import java.io.File
import java.io.FileOutputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: DisElfViewModel) {
    val context = LocalContext.current
    val elfInfo by viewModel.elfInfo.collectAsState()
    var searchQuery by remember { mutableStateOf("") }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            // Copy file from SAF to app cache directory
            val tempFile = File(context.cacheDir, "target.so")
            context.contentResolver.openInputStream(it)?.use { input ->
                FileOutputStream(tempFile).use { output ->
                    input.copyTo(output)
                }
            }
            viewModel.loadElf(tempFile.absolutePath)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .padding(16.dp)
    ) {
        // Open File Card
        Card(
            colors = CardDefaults.cardColors(containerColor = CardDark),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = "Binary Inspector",
                        style = MaterialTheme.typography.titleMedium,
                        color = Color.White
                    )
                    Text(
                        text = "Open any ELF .so file to inspect and trace",
                        style = MaterialTheme.typography.bodySmall,
                        color = ColorHexBytes
                    )
                }
                Button(
                    onClick = { filePicker.launch(arrayOf("*/*")) },
                    colors = ButtonDefaults.buttonColors(containerColor = CyanAccent)
                ) {
                    Icon(Icons.Default.FileOpen, contentDescription = null, tint = Color.Black)
                    Spacer(Modifier.width(8.dp))
                    Text("Open", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        if (elfInfo != null) {
            val info = elfInfo!!

            // Metadata summary card
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceDark),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("ELF Header Metadata", style = MaterialTheme.typography.titleSmall, color = CyanAccent)
                    Spacer(Modifier.height(8.dp))

                    val archName = when (info.e_machine) {
                        183 -> "AArch64 (ARM64)"
                        40 -> "ARM32"
                        62 -> "x86_64"
                        3 -> "x86"
                        243 -> "RISC-V 64"
                        else -> "Machine ${info.e_machine}"
                    }

                    Text("Architecture:  $archName (64-bit: ${info.is_64})", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Color.White)
                    Text("Entrypoint:    0x${"%08X".format(info.entry)}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = ColorAddress)
                    if (info.libraries.isNotEmpty()) {
                        Text("Dependencies:  ${info.libraries.joinToString(", ")}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = ColorHexBytes)
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            // Search Symbols Bar
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                label = { Text("Search Symbols (${info.syms.size})") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyanAccent) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = CyanAccent,
                    unfocusedBorderColor = ColorHexBytes,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                )
            )

            Spacer(Modifier.height(8.dp))

            // Symbols List
            val filteredSyms = remember(searchQuery, info.syms) {
                if (searchQuery.isBlank()) info.syms
                else info.syms.filter { it.sym.contains(searchQuery, ignoreCase = true) }
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(filteredSyms) { sym ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = CardDark),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                viewModel.selectFunction(sym.value, sym.sym)
                                viewModel.navigateTo(Screen.Disassembly)
                            }
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = sym.sym,
                                    color = Color.White,
                                    fontWeight = FontWeight.Medium,
                                    fontSize = 14.sp
                                )
                                Text(
                                    text = "0x${"%08X".format(sym.value)}  |  size: ${sym.size} bytes",
                                    color = ColorAddress,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp
                                )
                            }
                            if (sym.thumb) {
                                Text("THUMB", color = AmberAccent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}
