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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

data class ApkSoEntry(val entryName: String, val size: Long)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val coroutineScope = rememberCoroutineScope()

    val elfInfo by viewModel.elfInfo.collectAsState()
    val currentFileName by viewModel.currentFileName.collectAsState()
    var searchQuery by remember { mutableStateOf("") }

    var apkSoList by remember { mutableStateOf<List<ApkSoEntry>>(emptyList()) }
    var showApkPicker by remember { mutableStateOf(false) }
    var selectedApkUri by remember { mutableStateOf<Uri?>(null) }
    var isScanningApk by remember { mutableStateOf(false) }
    var isExtractingSo by remember { mutableStateOf(false) }

    // Stream-based, zero-copy file picker:
    // Safely handles 1GB+ APKs by streaming ZIP headers without copying the giant archive to disk.
    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { selectedUri ->
            coroutineScope.launch(Dispatchers.IO) {
                withContext(Dispatchers.Main) { isScanningApk = true }

                val fileName = queryFileName(context, selectedUri)

                // Read first 4 magic bytes to determine file type in 1 millisecond
                val header = ByteArray(4)
                var bytesRead = 0
                try {
                    context.contentResolver.openInputStream(selectedUri)?.use { input ->
                        bytesRead = input.read(header, 0, 4)
                    }
                } catch (_: Exception) {}

                val isElf = bytesRead == 4 && header[0] == 0x7F.toByte() && header[1] == 'E'.code.toByte() && header[2] == 'L'.code.toByte() && header[3] == 'F'.code.toByte()
                val isZip = bytesRead == 4 && header[0] == 0x50.toByte() && header[1] == 0x4B.toByte()

                if (isElf) {
                    // Direct ELF shared library (.so) - small file, copy directly to cache
                    val tempFile = File(context.cacheDir, "input_target.so")
                    try {
                        context.contentResolver.openInputStream(selectedUri)?.use { input ->
                            FileOutputStream(tempFile).use { output -> input.copyTo(output) }
                        }
                        withContext(Dispatchers.Main) {
                            isScanningApk = false
                            viewModel.loadElf(tempFile.absolutePath, fileName)
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            isScanningApk = false
                            Toast.makeText(context, "Failed to load ELF: ${e.message}", Toast.LENGTH_SHORT).show()
                        }
                    }
                } else if (isZip) {
                    // APK / XAPK / ZIP bundle - stream-scan .so libraries WITHOUT copying 1GB+ archive to storage!
                    val soList = mutableListOf<ApkSoEntry>()
                    try {
                        context.contentResolver.openInputStream(selectedUri)?.use { stream ->
                            val zip = ZipInputStream(stream)
                            var entry = zip.nextEntry
                            while (entry != null) {
                                if (!entry.isDirectory) {
                                    val name = entry.name
                                    if (name.endsWith(".so", ignoreCase = true)) {
                                        soList.add(ApkSoEntry(name, entry.size.coerceAtLeast(0)))
                                    } else if (name.endsWith(".apk", ignoreCase = true)) {
                                        // Scan nested split APK inside .xapk bundle
                                        try {
                                            val nestedZip = ZipInputStream(zip)
                                            var nestedEntry = nestedZip.nextEntry
                                            while (nestedEntry != null) {
                                                if (!nestedEntry.isDirectory && nestedEntry.name.endsWith(".so", ignoreCase = true)) {
                                                    val compositeName = "$name!/${nestedEntry.name}"
                                                    soList.add(ApkSoEntry(compositeName, nestedEntry.size.coerceAtLeast(0)))
                                                }
                                                nestedEntry = nestedZip.nextEntry
                                            }
                                        } catch (_: Exception) {}
                                    }
                                }
                                entry = zip.nextEntry
                            }
                        }
                    } catch (_: Exception) {}

                    withContext(Dispatchers.Main) {
                        isScanningApk = false
                        if (soList.isNotEmpty()) {
                            apkSoList = soList.sortedByDescending { it.size }
                            selectedApkUri = selectedUri
                            showApkPicker = true
                        } else {
                            Toast.makeText(context, "No native .so libraries found in this package", Toast.LENGTH_SHORT).show()
                        }
                    }
                } else {
                    // Generic binary - try loading directly
                    val tempFile = File(context.cacheDir, "input_target")
                    try {
                        context.contentResolver.openInputStream(selectedUri)?.use { input ->
                            FileOutputStream(tempFile).use { output -> input.copyTo(output) }
                        }
                        withContext(Dispatchers.Main) {
                            isScanningApk = false
                            viewModel.loadElf(tempFile.absolutePath, fileName)
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            isScanningApk = false
                            Toast.makeText(context, "Failed to read file: ${e.message}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
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

            // Virtualized Symbol List with Momentum Fling
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                flingBehavior = rememberMomentumFlingBehavior(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                items(
                    items = filteredSyms,
                    key = { "${it.value}_${it.sym}" },
                    contentType = { "symbol_item" }
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
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = sym.displayName,
                                    color = if (sym.isJni) colors.primary else colors.textPrimary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "0x${"%08X".format(sym.value)} (${sym.size} B)",
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

        // Loading Dialog during background APK stream scan / SO extraction
        if (isScanningApk || isExtractingSo) {
            AlertDialog(onDismissRequest = {}) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.padding(16.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            color = colors.primary,
                            strokeWidth = 2.5.dp
                        )
                        Spacer(Modifier.width(16.dp))
                        Text(
                            text = if (isScanningApk) "Inspecting APK libraries..." else "Extracting native library...",
                            color = colors.textPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }

        // APK Native Library Selection Dialog (Zero-Copy Stream Extraction)
        if (showApkPicker && selectedApkUri != null) {
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
                                            coroutineScope.launch(Dispatchers.IO) {
                                                withContext(Dispatchers.Main) { isExtractingSo = true }
                                                val extracted = File(context.cacheDir, "extracted_$simpleName")
                                                val ok = extractSoFromUri(context, selectedApkUri!!, entry.entryName, extracted)
                                                withContext(Dispatchers.Main) {
                                                    isExtractingSo = false
                                                    if (ok) {
                                                        showApkPicker = false
                                                        viewModel.loadElf(extracted.absolutePath, simpleName)
                                                    } else {
                                                        Toast.makeText(context, "Failed to extract $simpleName", Toast.LENGTH_SHORT).show()
                                                    }
                                                }
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

/**
 * Stream-extracts ONLY the requested .so file from the APK/ZIP Uri directly.
 * Never writes or copies the giant 1GB+ APK archive to storage!
 */
private fun extractSoFromUri(context: Context, uri: Uri, entryName: String, outFile: File): Boolean {
    return try {
        context.contentResolver.openInputStream(uri)?.use { stream ->
            val zip = ZipInputStream(stream)
            var entry = zip.nextEntry
            while (entry != null) {
                if (entryName.contains("!/")) {
                    val parts = entryName.split("!/", limit = 2)
                    if (entry.name == parts[0]) {
                        val nestedZip = ZipInputStream(zip)
                        var nestedEntry = nestedZip.nextEntry
                        while (nestedEntry != null) {
                            if (nestedEntry.name == parts[1]) {
                                FileOutputStream(outFile).use { output ->
                                    nestedZip.copyTo(output)
                                }
                                return true
                            }
                            nestedEntry = nestedZip.nextEntry
                        }
                    }
                } else {
                    if (entry.name == entryName) {
                        FileOutputStream(outFile).use { output ->
                            zip.copyTo(output)
                        }
                        return true
                    }
                }
                entry = zip.nextEntry
            }
        }
        false
    } catch (_: Exception) {
        false
    }
}

private fun queryFileName(context: Context, uri: Uri): String {
    var name = "target.so"
    context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (nameIndex != -1 && cursor.moveToFirst()) {
            name = cursor.getString(nameIndex) ?: name
        }
    }
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
