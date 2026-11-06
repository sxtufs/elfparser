package io.elftrace.app.ui.screens

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
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
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipFile

data class ApkSoEntry(val entryName: String, val size: Long)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val elfInfo by viewModel.elfInfo.collectAsState()
    val currentFileName by viewModel.currentFileName.collectAsState()
    var searchQuery by remember { mutableStateOf("") }

    var apkSoList by remember { mutableStateOf<List<ApkSoEntry>>(emptyList()) }
    var showApkPicker by remember { mutableStateOf(false) }
    var apkCachedFile by remember { mutableStateOf<File?>(null) }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            val fileName = queryFileName(context, it)
            val tempFile = File(context.cacheDir, "input_target")
            context.contentResolver.openInputStream(it)?.use { input ->
                FileOutputStream(tempFile).use { output ->
                    input.copyTo(output)
                }
            }

            // Check if it's an APK or ZIP archive containing .so files
            val isZip = try {
                ZipFile(tempFile).use { zip ->
                    val soList = mutableListOf<ApkSoEntry>()
                    val entries = zip.entries()
                    while (entries.hasMoreElements()) {
                        val e = entries.nextElement()
                        if (!e.isDirectory && e.name.endsWith(".so", ignoreCase = true)) {
                            soList.add(ApkSoEntry(e.name, e.size))
                        }
                    }
                    if (soList.isNotEmpty()) {
                        apkSoList = soList.sortedByDescending { it.size }
                        apkCachedFile = tempFile
                        showApkPicker = true
                        true
                    } else {
                        false
                    }
                }
            } catch (_: Exception) {
                false
            }

            if (!isZip) {
                viewModel.loadElf(tempFile.absolutePath, fileName)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        // Open File Card
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.card),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                    Text(
                        text = "Binary & APK Inspector",
                        style = MaterialTheme.typography.titleMedium,
                        color = colors.textPrimary,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Open any .so, .apk, or split package directly",
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.textSecondary
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { viewModel.toggleTheme() }) {
                        ThemeToggleIcon(isDark = colors.isDark, tint = if (colors.isDark) Color(0xFFFFD54F) else colors.textSecondary)
                    }
                    Spacer(Modifier.width(4.dp))
                    Button(
                        onClick = { filePicker.launch(arrayOf("*/*")) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.primary,
                            contentColor = Color.White
                        ),
                        shape = RoundedCornerShape(50),
                        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        Icon(Icons.Default.FileOpen, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = "Open",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (elfInfo != null) {
            val info = elfInfo!!

            // Metadata summary card
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                    Text("ELF Header Metadata", style = MaterialTheme.typography.titleSmall, color = colors.primary, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))

                    val archName = when (info.e_machine) {
                        183 -> "AArch64 (ARM64)"
                        40 -> "ARM32"
                        62 -> "x86_64"
                        3 -> "x86"
                        243 -> "RISC-V 64"
                        else -> "Machine ${info.e_machine}"
                    }

                    Text("Architecture:  $archName (64-bit: ${info.is_64})", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = colors.textPrimary)
                    Text("Entrypoint:    0x${"%08X".format(info.entry)}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = colors.address)
                    if (info.libraries.isNotEmpty()) {
                        Text("Dependencies:  ${info.libraries.joinToString(", ")}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = colors.hexBytes)
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            // Search Symbols or Address Bar
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                label = { Text("Search Symbol or Address") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = colors.primary) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = colors.primary,
                    unfocusedBorderColor = colors.border,
                    focusedTextColor = colors.textPrimary,
                    unfocusedTextColor = colors.textPrimary,
                    focusedLabelColor = colors.primary,
                    unfocusedLabelColor = colors.textSecondary,
                    cursorColor = colors.primary
                )
            )

            Spacer(Modifier.height(8.dp))

            val cleanHex = searchQuery.trim().removePrefix("0x").removePrefix("0X")
            val parsedAddr = cleanHex.toLongOrNull(16)

            val filteredSyms = remember(searchQuery, info.syms) {
                if (searchQuery.isBlank()) info.syms
                else {
                    info.syms.filter { sym ->
                        sym.displayName.contains(searchQuery, ignoreCase = true) ||
                        (cleanHex.isNotEmpty() && "%08X".format(sym.value).contains(cleanHex, ignoreCase = true))
                    }
                }
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                flingBehavior = rememberMomentumFlingBehavior(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (parsedAddr != null && cleanHex.length >= 2) {
                    item(key = "jump_vma_direct") {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = colors.primary.copy(alpha = 0.15f)),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    viewModel.selectFunction(parsedAddr, "sub_${"%08X".format(parsedAddr)}")
                                    viewModel.codeSubTab.value = 0
                                    viewModel.navigateTo(Screen.Code)
                                }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Default.ArrowForward, contentDescription = null, tint = colors.primary)
                                Spacer(Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = "Jump directly to VMA 0x${"%08X".format(parsedAddr)}",
                                        color = colors.primary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp
                                    )
                                    Text(
                                        text = "Disassemble arbitrary address (unexported / stripped code)",
                                        color = colors.textSecondary,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                    }
                }

                items(
                    items = filteredSyms,
                    key = { "${it.value}_${it.sym}" },
                    contentType = { "symbol" }
                ) { sym ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.card),
                        shape = RoundedCornerShape(8.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                viewModel.selectFunction(sym.value, sym.displayName)
                                viewModel.codeSubTab.value = 0
                                viewModel.navigateTo(Screen.Code)
                            }
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = sym.displayName,
                                    color = colors.textPrimary,
                                    fontWeight = FontWeight.Medium,
                                    fontSize = 13.sp
                                )
                                Text(
                                    text = "0x${"%08X".format(sym.value)}  |  size: ${sym.size} B",
                                    color = colors.address,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp
                                )
                            }
                            if (info.e_machine == 40 && sym.thumb) {
                                Text("THUMB", color = AmberAccent, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // APK Native Library Selection Dialog
        if (showApkPicker && apkCachedFile != null) {
            AlertDialog(onDismissRequest = { showApkPicker = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("Select Native Library from APK", color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        LazyColumn(
                            modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp),
                            flingBehavior = rememberMomentumFlingBehavior(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            items(apkSoList) { entry ->
                                val simpleName = entry.entryName.substringAfterLast('/')
                                val sizeMb = "%.1f MB".format(entry.size / (1024.0 * 1024.0))
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = colors.card),
                                    shape = RoundedCornerShape(8.dp),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            val extracted = File(context.cacheDir, "extracted_$simpleName")
                                            if (extractSoFromApk(apkCachedFile!!, entry.entryName, extracted)) {
                                                viewModel.loadElf(extracted.absolutePath, simpleName)
                                                showApkPicker = false
                                            }
                                        }
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(simpleName, color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                            Text(entry.entryName, color = colors.textSecondary, fontSize = 10.sp, maxLines = 1)
                                        }
                                        Text(sizeMb, color = colors.address, fontFamily = FontFamily.Monospace, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { showApkPicker = false }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun extractSoFromApk(apkFile: File, entryName: String, outFile: File): Boolean {
    return try {
        ZipFile(apkFile).use { zip ->
            val entry = zip.getEntry(entryName) ?: return false
            zip.getInputStream(entry).use { input ->
                FileOutputStream(outFile).use { output ->
                    input.copyTo(output)
                }
            }
        }
        true
    } catch (_: Exception) {
        false
    }
}

private fun queryFileName(context: Context, uri: Uri): String {
    var name = "libtarget.so"
    try {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex != -1 && cursor.moveToFirst()) {
                name = cursor.getString(nameIndex)
            }
        }
    } catch (_: Exception) {}
    return name
}

@Composable
fun ThemeToggleIcon(isDark: Boolean, tint: Color) {
    if (isDark) {
        androidx.compose.foundation.Canvas(modifier = Modifier.size(20.dp)) {
            val r = size.minDimension / 2f
            val center = androidx.compose.ui.geometry.Offset(r, r)
            drawCircle(color = tint, radius = r * 0.42f, center = center)
            for (i in 0 until 8) {
                val angle = i * Math.PI / 4.0
                val start = androidx.compose.ui.geometry.Offset(
                    (center.x + Math.cos(angle) * r * 0.62).toFloat(),
                    (center.y + Math.sin(angle) * r * 0.62).toFloat()
                )
                val end = androidx.compose.ui.geometry.Offset(
                    (center.x + Math.cos(angle) * r * 0.95).toFloat(),
                    (center.y + Math.sin(angle) * r * 0.95).toFloat()
                )
                drawLine(color = tint, start = start, end = end, strokeWidth = 2.2f)
            }
        }
    } else {
        androidx.compose.foundation.Canvas(modifier = Modifier.size(20.dp)) {
            val r = size.minDimension / 2f
            drawCircle(color = tint, radius = r * 0.75f, center = androidx.compose.ui.geometry.Offset(r * 0.9f, r * 1.1f))
            drawCircle(color = Color.White, radius = r * 0.62f, center = androidx.compose.ui.geometry.Offset(r * 0.65f, r * 0.85f))
        }
    }
}
