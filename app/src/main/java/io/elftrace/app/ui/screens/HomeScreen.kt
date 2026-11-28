package io.elftrace.app.ui.screens

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.ui.window.Dialog
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.McpServer
import io.elftrace.app.ui.components.ThemeToggleIcon
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

data class ApkSoEntry(val entryName: String, val size: Long, val apkPath: String? = null)

data class InstalledApp(val label: String, val pkg: String, val apkPaths: List<String>)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val isDark by viewModel.isDarkMode.collectAsState()
    val coroutineScope = rememberCoroutineScope()

    val elfInfo by viewModel.elfInfo.collectAsState()
    val currentFileName by viewModel.currentFileName.collectAsState()
    val recentSessions by viewModel.recentSessions.collectAsState()
    val bookmarks by viewModel.bookmarks.collectAsState()
    val openError by viewModel.openError.collectAsState()

    LaunchedEffect(openError) {
        openError?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            viewModel.openError.value = null
        }
    }
    var searchQuery by remember { mutableStateOf("") }
    var showBookmarksDialog by remember { mutableStateOf(false) }

    var apkSoList by remember { mutableStateOf<List<ApkSoEntry>>(emptyList()) }
    var showApkPicker by remember { mutableStateOf(false) }
    var selectedApkUri by remember { mutableStateOf<Uri?>(null) }
    var isScanningApk by remember { mutableStateOf(false) }
    var isExtractingSo by remember { mutableStateOf(false) }
    var showInstalledPicker by remember { mutableStateOf(false) }
    var installedApps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var isLoadingApps by remember { mutableStateOf(false) }
    var symFilter by remember { mutableStateOf("all") } // "all", "funcs", "jni"
    var showHeadersDialog by remember { mutableStateOf(false) }
    var headersTab by remember { mutableStateOf(0) } // 0 = Segments, 1 = Sections
    var showMcpDialog by remember { mutableStateOf(false) }
    var showSettingsMenu by remember { mutableStateOf(false) }
    var mcpRunning by remember { mutableStateOf(false) }

    val il2cppPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { selectedUri ->
            coroutineScope.launch(Dispatchers.IO) {
                val fileName = queryFileName(context, selectedUri)
                val tempFile = File(context.cacheDir, fileName)
                try {
                    context.contentResolver.openInputStream(selectedUri)?.use { input ->
                        FileOutputStream(tempFile).use { output -> input.copyTo(output) }
                    }
                    withContext(Dispatchers.Main) {
                        viewModel.resolveIl2CppMetadata(tempFile.absolutePath) { count ->
                            val msg = when {
                                count > 0 -> "Resolved $count Il2Cpp methods"
                                count == 0 -> "Metadata validated (use script.json for symbols)"
                                else -> "Failed to load Il2Cpp metadata"
                            }
                            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "Failed to read file: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

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
                Column(Modifier.weight(1f).padding(end = 8.dp)) {
                    Text(
                        text = "ELFTrace",
                        fontSize = 16.sp,
                        color = colors.textPrimary,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "Binary & APK analysis",
                        fontSize = 10.5.sp,
                        color = colors.textSecondary,
                        lineHeight = 12.sp
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box {
                        IconButton(onClick = {
                            mcpRunning = McpServer.isRunning()
                            showSettingsMenu = true
                        }) {
                            Icon(
                                Icons.Default.Settings,
                                contentDescription = "Settings",
                                tint = colors.textSecondary
                            )
                        }
                        DropdownMenu(
                            expanded = showSettingsMenu,
                            onDismissRequest = { showSettingsMenu = false },
                            containerColor = colors.card,
                            shape = RoundedCornerShape(12.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border)
                        ) {
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = if (isDark) "Theme \u00b7 Dark" else "Theme \u00b7 Light",
                                        color = colors.textPrimary,
                                        fontSize = 14.sp
                                    )
                                },
                                leadingIcon = {
                                    ThemeToggleIcon(
                                        isDark = isDark,
                                        tint = if (isDark) Color(0xFFFFD54F) else colors.textSecondary
                                    )
                                },
                                onClick = {
                                    showSettingsMenu = false
                                    viewModel.toggleTheme()
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Text("MCP Server", color = colors.textPrimary, fontSize = 14.sp)
                                },
                                trailingIcon = {
                                    val chipColor = if (mcpRunning) colors.address else colors.textSecondary
                                    Text(
                                        text = if (mcpRunning) "Running" else "Off",
                                        color = chipColor,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        modifier = Modifier
                                            .background(chipColor.copy(alpha = 0.14f), RoundedCornerShape(50))
                                            .padding(horizontal = 8.dp, vertical = 3.dp)
                                    )
                                },
                                onClick = {
                                    showSettingsMenu = false
                                    showMcpDialog = true
                                }
                            )
                        }
                    }
                    Spacer(Modifier.width(4.dp))
                    OutlinedButton(
                        onClick = {
                            isLoadingApps = true
                            coroutineScope.launch(Dispatchers.IO) {
                                val apps = loadInstalledApps(context.packageManager)
                                withContext(Dispatchers.Main) {
                                    isLoadingApps = false
                                    if (apps.isEmpty()) {
                                        Toast.makeText(context, "No installed apps found", Toast.LENGTH_SHORT).show()
                                    } else {
                                        installedApps = apps
                                        showInstalledPicker = true
                                    }
                                }
                            }
                        },
                        shape = RoundedCornerShape(50),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
                    ) {
                        Text(
                            text = "Apps",
                            color = colors.textPrimary,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                    Spacer(Modifier.width(6.dp))
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

        if (recentSessions.isNotEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                    Text(
                        text = "Recent",
                        style = MaterialTheme.typography.labelMedium,
                        color = colors.textSecondary,
                        fontWeight = FontWeight.SemiBold
                    )
                    // One scrollable line of chips instead of a full row per
                    // session: the card keeps a fixed height no matter how
                    // many recents are stored (capped at 10 in WorkspaceStore).
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        items(recentSessions, key = { it.fileKey }) { session ->
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = colors.card,
                                border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                modifier = Modifier.clickable {
                                    viewModel.openRecent(session) { ok ->
                                        if (!ok) {
                                            Toast.makeText(
                                                context,
                                                "That file is no longer cached — open it again",
                                                Toast.LENGTH_SHORT
                                            ).show()
                                        }
                                    }
                                }
                            ) {
                                Text(
                                    text = session.displayName,
                                    fontSize = 11.sp,
                                    color = colors.textPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                )
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
        }

        if (showBookmarksDialog) {
            AlertDialog(
                onDismissRequest = { showBookmarksDialog = false },
                text = {
                    Column {
                        Text("Bookmarks", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(6.dp))
                        if (bookmarks.isEmpty()) {
                            Text(
                                "No bookmarks yet. Open a function and tap the star in the Code header.",
                                fontSize = 12.sp
                            )
                        } else {
                            Column(
                                modifier = Modifier
                                    .heightIn(max = 300.dp)
                                    .verticalScroll(rememberScrollState())
                            ) {
                                bookmarks.forEach { bookmark ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                showBookmarksDialog = false
                                                viewModel.navigateTo(Screen.Code)
                                                viewModel.selectFunction(bookmark.address, bookmark.name)
                                            }
                                            .padding(vertical = 7.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = bookmark.name,
                                                fontSize = 12.sp,
                                                color = colors.primary,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                            Text(
                                                text = "0x%08X".format(bookmark.address),
                                                fontSize = 10.sp,
                                                fontFamily = FontFamily.Monospace,
                                                color = colors.textSecondary
                                            )
                                        }
                                        IconButton(
                                            onClick = { viewModel.removeBookmark(bookmark.id) },
                                            modifier = Modifier.size(26.dp)
                                        ) {
                                            Icon(
                                                Icons.Default.Close,
                                                contentDescription = "Remove bookmark",
                                                tint = colors.textSecondary,
                                                modifier = Modifier.size(13.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(4.dp))
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showBookmarksDialog = false }) { Text("Close") }
                }
            )
        }

        if (elfInfo != null) {
            val info = elfInfo!!

            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surface),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = currentFileName.ifEmpty { "ELF Header Metadata" },
                            style = MaterialTheme.typography.titleSmall,
                            color = colors.primary,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f).padding(end = 8.dp)
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedButton(
                                onClick = { showHeadersDialog = true },
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                                modifier = Modifier.height(28.dp)
                            ) {
                                Text("Headers", fontSize = 10.5.sp, fontWeight = FontWeight.SemiBold)
                            }
                            OutlinedButton(
                                onClick = { il2cppPicker.launch(arrayOf("application/json", "*/*")) },
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                                modifier = Modifier.height(28.dp)
                            ) {
                                Text("Il2Cpp JSON", fontSize = 10.5.sp, fontWeight = FontWeight.SemiBold)
                            }
                            OutlinedButton(
                                onClick = { showBookmarksDialog = true },
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                                modifier = Modifier.height(28.dp)
                            ) {
                                Text("Bookmarks", fontSize = 10.5.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }
                    Spacer(Modifier.height(6.dp))

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

                    Spacer(Modifier.height(6.dp))
                    OutlinedButton(
                        onClick = {
                            viewModel.recoverFunctions { res ->
                                val msg = when {
                                    res.error != null -> res.error
                                    res.added == 0 -> "No new functions" +
                                        (if (res.truncated) " — partial scan" else "")
                                    else -> "Recovered ${res.added} new " +
                                        (if (res.added == 1) "function" else "functions") +
                                        (if (res.truncated) " — partial scan" else "")
                                }
                                Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                            }
                        },
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                        modifier = Modifier.fillMaxWidth().height(30.dp)
                    ) {
                        Text(
                            "Recover Functions",
                            fontSize = 10.5.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            var showSearch by remember { mutableStateOf(false) }

            // Filter chips row with collapsible search trigger at the right end
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                listOf("all" to "All", "funcs" to "Functions", "jni" to "JNI").forEach { (key, label) ->
                    FilterChip(
                        selected = symFilter == key,
                        onClick = { symFilter = key },
                        label = { Text(label, fontSize = 11.sp) }
                    )
                }
                Spacer(Modifier.weight(1f))
                IconButton(onClick = {
                    showSearch = !showSearch
                    if (!showSearch) searchQuery = ""
                }, modifier = Modifier.size(36.dp)) {
                    Icon(
                        if (showSearch) Icons.Default.Close else Icons.Default.Search,
                        contentDescription = if (showSearch) "Close Search" else "Search",
                        tint = colors.primary,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }

            Spacer(Modifier.height(4.dp))

            AnimatedVisibility(visible = showSearch) {
                var searchFocused by remember { mutableStateOf(false) }
                BasicTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    singleLine = true,
                    textStyle = androidx.compose.ui.text.TextStyle(fontSize = 14.sp, color = colors.textPrimary),
                    cursorBrush = SolidColor(colors.primary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .onFocusChanged { searchFocused = it.isFocused },
                    decorationBox = { inner ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(44.dp)
                                .border(
                                    1.dp,
                                    if (searchFocused) colors.primary else colors.border,
                                    RoundedCornerShape(10.dp)
                                )
                                .padding(horizontal = 12.dp)
                        ) {
                            Icon(
                                Icons.Default.Search,
                                contentDescription = null,
                                tint = colors.primary,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Box(Modifier.weight(1f)) {
                                if (searchQuery.isEmpty()) {
                                    Text("Search Symbol or Address", fontSize = 13.sp, color = colors.textSecondary)
                                }
                                inner()
                            }
                        }
                    }
                )
            }

            Spacer(Modifier.height(4.dp))

            val filteredSyms = remember(searchQuery, symFilter, info.syms) {
                val cleanHex = searchQuery.trim().removePrefix("0x").removePrefix("0X")
                info.syms.filter { sym ->
                    val matchesTab = when (symFilter) {
                        "funcs" -> sym.value != 0L
                        "jni" -> sym.isJni
                        else -> true
                    }
                    val matchesQuery = searchQuery.isBlank() ||
                        sym.displayName.contains(searchQuery, ignoreCase = true) ||
                        (cleanHex.isNotEmpty() && "%08X".format(sym.value).contains(cleanHex, ignoreCase = true))
                    matchesTab && matchesQuery
                }
            }

            // Virtualized Symbol List with Momentum Fling
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                flingBehavior = rememberMomentumFlingBehavior(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                itemsIndexed(
                    items = filteredSyms,
                    key = { idx, sym -> "${idx}_${sym.value}_${sym.sym}" },
                    contentType = { _, _ -> "symbol_item" }
                ) { _, sym ->
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
            Dialog(onDismissRequest = {}) {
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
                            text = if (isScanningApk) "Inspecting APK libraries" else "Extracting native library",
                            color = colors.textPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }

        // APK Native Library Selection Dialog (Zero-Copy Stream Extraction).
        // Entries from an installed app carry an apkPath and selectedApkUri is
        // null, so the guard accepts either source.
        if (showApkPicker && (selectedApkUri != null || apkSoList.any { it.apkPath != null })) {
            Dialog(onDismissRequest = { showApkPicker = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth()
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
                                                val ok = if (entry.apkPath != null) {
                                                    extractSoFromFile(entry.apkPath, entry.entryName, extracted)
                                                } else {
                                                    extractSoFromUri(context, selectedApkUri!!, entry.entryName, extracted)
                                                }
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

        // Installed Apps Picker: choose an app, stream-scan its APK(s) for native .so
        if (showInstalledPicker) {
            Dialog(onDismissRequest = { showInstalledPicker = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text(
                            text = "Installed Apps",
                            color = colors.primary,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Tap an app to list its native libraries",
                            color = colors.textSecondary,
                            fontSize = 11.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        if (isLoadingApps) {
                            Text("Loading…", color = colors.textSecondary, fontSize = 12.sp, modifier = Modifier.padding(vertical = 16.dp))
                        }
                        LazyColumn(
                            modifier = Modifier.fillMaxWidth().heightIn(max = 380.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            items(installedApps, key = { it.pkg }) { app ->
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = colors.card),
                                    shape = RoundedCornerShape(8.dp),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            coroutineScope.launch(Dispatchers.IO) {
                                                withContext(Dispatchers.Main) { isScanningApk = true }
                                                val soList = mutableListOf<ApkSoEntry>()
                                                try {
                                                    for (apkPath in app.apkPaths) {
                                                        java.util.zip.ZipFile(apkPath).use { zip ->
                                                            val entries = zip.entries()
                                                            while (entries.hasMoreElements()) {
                                                                val entry = entries.nextElement()
                                                                if (!entry.isDirectory && entry.name.endsWith(".so", ignoreCase = true)) {
                                                                    soList.add(ApkSoEntry(entry.name, entry.size.coerceAtLeast(0), apkPath))
                                                                }
                                                            }
                                                        }
                                                    }
                                                } catch (_: Exception) {}
                                                withContext(Dispatchers.Main) {
                                                    isScanningApk = false
                                                    if (soList.isNotEmpty()) {
                                                        apkSoList = soList.sortedByDescending { it.size }
                                                        selectedApkUri = null
                                                        showInstalledPicker = false
                                                        showApkPicker = true
                                                    } else {
                                                        Toast.makeText(context, "No native .so libraries in ${app.label}", Toast.LENGTH_SHORT).show()
                                                    }
                                                }
                                            }
                                        }
                                ) {
                                    Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                                        Text(app.label, color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        Text(app.pkg, color = colors.textSecondary, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { showInstalledPicker = false }) {
                                Text("Cancel", color = colors.textSecondary)
                            }
                        }
                    }
                }
            }
        }

        // ELF Headers & Segments Inspector Dialog
        if (showHeadersDialog && elfInfo != null) {
            val info = elfInfo!!
            Dialog(onDismissRequest = { showHeadersDialog = false }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text(
                            text = "ELF Headers & Segments",
                            color = colors.primary,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(
                                selected = headersTab == 0,
                                onClick = { headersTab = 0 },
                                label = { Text("Segments (${info.segments.size})", fontSize = 11.sp) }
                            )
                            FilterChip(
                                selected = headersTab == 1,
                                onClick = { headersTab = 1 },
                                label = { Text("Sections (${info.sections.size})", fontSize = 11.sp) }
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        LazyColumn(
                            modifier = Modifier.fillMaxWidth().heightIn(max = 320.dp),
                            flingBehavior = rememberMomentumFlingBehavior(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            if (headersTab == 0) {
                                itemsIndexed(info.segments) { _, seg ->
                                    val isExec = seg.flags.contains("X")
                                    Card(
                                        colors = CardDefaults.cardColors(containerColor = colors.card),
                                        shape = RoundedCornerShape(8.dp),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable(enabled = seg.vaddr > 0L || seg.offset > 0L || (isExec && info.entry > 0L)) {
                                                val target = when {
                                                    seg.vaddr > 0L -> seg.vaddr
                                                    isExec && info.entry > 0L -> info.entry
                                                    else -> seg.offset
                                                }
                                                showHeadersDialog = false
                                                if (target > 0L) {
                                                    viewModel.selectFunction(target, seg.p_type)
                                                    viewModel.codeSubTab.value = if (isExec) 0 else 3
                                                } else {
                                                    viewModel.loadHexDump(0L, 2048)
                                                    viewModel.codeSubTab.value = 3
                                                }
                                                viewModel.navigateTo(Screen.Code)
                                            }
                                    ) {
                                        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp)) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween
                                            ) {
                                                Text(seg.p_type, color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                                Text(
                                                    seg.flags,
                                                    color = if (isExec) AmberAccent else colors.address,
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 11.sp,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                            Text(
                                                "VA: 0x${seg.vaddr.toString(16)}  Off: 0x${seg.offset.toString(16)}  Sz: 0x${seg.filesz.toString(16)}",
                                                color = colors.textSecondary,
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 10.5.sp
                                            )
                                        }
                                    }
                                }
                            } else {
                                itemsIndexed(info.sections) { _, sec ->
                                    val isExec = sec.flags.contains("X")
                                    Card(
                                        colors = CardDefaults.cardColors(containerColor = colors.card),
                                        shape = RoundedCornerShape(8.dp),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable(enabled = sec.vaddr > 0L) {
                                                showHeadersDialog = false
                                                viewModel.selectFunction(sec.vaddr, sec.name.ifEmpty { "section" })
                                                viewModel.codeSubTab.value = if (isExec) 0 else 3
                                                viewModel.navigateTo(Screen.Code)
                                            }
                                    ) {
                                        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp)) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween
                                            ) {
                                                Text(
                                                    sec.name.ifEmpty { "<unnamed>" },
                                                    color = colors.textPrimary,
                                                    fontWeight = FontWeight.Bold,
                                                    fontSize = 12.sp,
                                                    maxLines = 1,
                                                    modifier = Modifier.weight(1f)
                                                )
                                                Text(
                                                    sec.flags,
                                                    color = if (isExec) AmberAccent else colors.address,
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 11.sp,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                            Text(
                                                "VA: 0x${sec.vaddr.toString(16)}  Off: 0x${sec.offset.toString(16)}  Sz: 0x${sec.size.toString(16)}",
                                                color = colors.textSecondary,
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 10.5.sp
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { showHeadersDialog = false }) {
                                Text("Close", color = colors.textSecondary)
                            }
                        }
                    }
                }
            }
        }

        if (showMcpDialog) {
            io.elftrace.app.ui.components.McpServerDialog(
                onDismiss = { showMcpDialog = false }
            )
        }
    }
}

/**
 * Stream-extracts ONLY the requested .so file from the APK/ZIP Uri directly.
 * Never writes or copies the giant 1GB+ APK archive to storage!
 */
private fun extractSoFromUri(context: Context, uri: Uri, entryName: String, outFile: File): Boolean {
    return try {
        if (entryName.contains("!/")) {
            // Composite entry ("base.apk!/lib/arm64-v8a/libx.so") inside an .xapk/zip.
            // A ZipInputStream cannot be wrapped around another ZipInputStream (the
            // outer stream has already consumed the nested entry's local header), so
            // first buffer ONLY the nested .apk entry to a temp file, then scan that
            // fresh, seekable-from-zero zip for the requested .so.
            val parts = entryName.split("!/", limit = 2)
            val outerName = parts[0]
            val innerName = parts[1]
            val nestedTmp = File(context.cacheDir, "nested_${System.nanoTime()}.apk")
            try {
                var foundNested = false
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    val zip = ZipInputStream(stream)
                    var entry = zip.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory && entry.name == outerName) {
                            FileOutputStream(nestedTmp).use { out -> zip.copyTo(out) }
                            foundNested = true
                            break
                        }
                        entry = zip.nextEntry
                    }
                }
                if (!foundNested) return false

                // Now scan the buffered nested APK with a fresh ZipInputStream.
                nestedTmp.inputStream().use { nestedStream ->
                    val nestedZip = ZipInputStream(nestedStream)
                    var nestedEntry = nestedZip.nextEntry
                    while (nestedEntry != null) {
                        if (!nestedEntry.isDirectory && nestedEntry.name == innerName) {
                            FileOutputStream(outFile).use { output -> nestedZip.copyTo(output) }
                            return true
                        }
                        nestedEntry = nestedZip.nextEntry
                    }
                }
                false
            } finally {
                nestedTmp.delete()
            }
        } else {
            // Plain entry directly inside the picked APK/zip.
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val zip = ZipInputStream(stream)
                var entry = zip.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory && entry.name == entryName) {
                        FileOutputStream(outFile).use { output -> zip.copyTo(output) }
                        return true
                    }
                    entry = zip.nextEntry
                }
            }
            false
        }
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

/**
 * Enumerates launchable installed apps with their APK paths. Readable without
 * any permission: an app's own sourceDir/splitSourceDirs stay accessible to
 * other apps on Android 11+ even without <queries> entries — only the *list*
 * of other apps needs the queries declaration, which the manifest carries.
 */
private fun loadInstalledApps(pm: android.content.pm.PackageManager): List<InstalledApp> {
    val intent = android.content.Intent(android.content.Intent.ACTION_MAIN).apply {
        addCategory(android.content.Intent.CATEGORY_LAUNCHER)
    }
    val resolved = pm.queryIntentActivities(intent, 0)
    return resolved.asSequence()
        .map { it.activityInfo.applicationInfo }
        .filterNotNull()
        .distinctBy { it.packageName }
        .filter { it.packageName != "io.elftrace.app" }
        .map { appInfo ->
            val paths = buildList {
                appInfo.sourceDir?.let { add(it) }
                appInfo.splitSourceDirs?.let { addAll(it.filterNotNull()) }
            }
            InstalledApp(
                label = pm.getApplicationLabel(appInfo)?.toString() ?: appInfo.packageName,
                pkg = appInfo.packageName,
                apkPaths = paths
            )
        }
        .filter { it.apkPaths.isNotEmpty() }
        .sortedBy { it.label.lowercase() }
        .toList()
}

/**
 * Extracts a .so entry straight from an installed APK path with ZipFile
 * (random access — no full-archive copy).
 */
private fun extractSoFromFile(apkPath: String, entryName: String, outFile: File): Boolean {
    return try {
        java.util.zip.ZipFile(apkPath).use { zip ->
            val entry = zip.getEntry(entryName) ?: return false
            zip.getInputStream(entry).use { input ->
                outFile.outputStream().use { output -> input.copyTo(output) }
            }
            true
        }
    } catch (_: Exception) {
        false
    }
}
