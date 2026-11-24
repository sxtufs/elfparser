package io.elftrace.app.viewmodel

import android.app.Application
import android.content.Context
import android.os.Environment
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.elftrace.app.core.JNIBridge
import io.elftrace.app.core.models.*
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class Screen {
    object Files : Screen()
    object Code : Screen()
    object Analysis : Screen()
    object Plugins : Screen()
}

class ELFTraceViewModel(app: Application) : AndroidViewModel(app) {

    // `application` is private in AndroidViewModel (newer lifecycle), so keep
    // our own reference for asset loading.
    private val appContext: Application = app

    /// Single-threaded dispatcher for all native (JNI) calls. `ElfContext` and
    /// its Unicorn engine are not thread-safe; one thread avoids data races and
    /// concurrent `&`/`&mut` aliasing.
    private val nativeDispatcher = Dispatchers.IO.limitedParallelism(1)

    private val _bridge = MutableStateFlow<JNIBridge?>(null)
    val bridge: StateFlow<JNIBridge?> = _bridge.asStateFlow()

    private val _currentScreen = MutableStateFlow<Screen>(Screen.Files)
    val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

    val codeSubTab = MutableStateFlow(0) // 0: Disasm, 1: Decompile, 2: Flowchart, 3: Hex View
    val analysisSubTab = MutableStateFlow(0) // 0: Strings, 1: Entropy Radar

    val isDarkMode = MutableStateFlow(true) // Light / Dark mode toggle

    val currentFileName = MutableStateFlow("")

    private val _entropyReport = MutableStateFlow<EntropyReport?>(null)
    val entropyReport: StateFlow<EntropyReport?> = _entropyReport.asStateFlow()

    fun refreshEntropyReport() {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            _entropyReport.value = b.getEntropyReport()
        }
    }

    private val _hexBytes = MutableStateFlow<ByteArray>(ByteArray(0))
    val hexBytes: StateFlow<ByteArray> = _hexBytes.asStateFlow()

    private val _hexStartAddress = MutableStateFlow(0L)
    val hexStartAddress: StateFlow<Long> = _hexStartAddress.asStateFlow()

    fun loadHexDump(address: Long, length: Int = 2048) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            val safeAddr = address.coerceAtLeast(0L)
            val alignedAddr = safeAddr - (safeAddr % 16)
            val bytes = b.readBytes(alignedAddr, length)
            _hexStartAddress.value = alignedAddr
            _hexBytes.value = bytes
        }
    }

    fun patchHexBytes(address: Long, bytes: ByteArray, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(false) }
                return@launch
            }
            val ok = b.patchBytes(address, bytes)
            if (ok) _undoDepth.value = b.undoLen()
            // Refresh the hex window / views regardless: on failure nothing
            // changed, but re-reading keeps the display consistent with the
            // actual buffer. The caller now sees the real success status.
            val alignedAddr = _hexStartAddress.value
            _hexBytes.value = b.readBytes(alignedAddr, 2048)
            if (_currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(ok) }
        }
    }

    /**
     * Result of an export operation.
     * [Public] — written into the shared Download/ collection.
     * [Failed] — could not write.
     */
    sealed class SaveOutcome {
        data class Public(val path: String) : SaveOutcome()
        object Failed : SaveOutcome()
    }

    fun savePatchedBinary(context: Context, onResult: (SaveOutcome) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onResult(SaveOutcome.Failed) }
                return@launch
            }
            val bytes = b.saveBinary()
            if (bytes.isEmpty()) {
                launch(Dispatchers.Main) { onResult(SaveOutcome.Failed) }
                return@launch
            }
            val origName = currentFileName.value.ifEmpty { "libtarget.so" }.removeSuffix(".so")
            val patchedFileName = "${origName}_patched.so"

            // Always export to the real public Download/ folder — no app-scoped
            // fallback and no runtime permission. On API 29+ a MediaStore insert
            // into the Downloads collection needs zero permissions. On API < 29
            // (minSdk 24) we use the legacy public dir + WRITE_EXTERNAL_STORAGE.
            val outcome: SaveOutcome = try {
                if (android.os.Build.VERSION.SDK_INT >= 29) {
                    writeViaMediaStore(context, patchedFileName, bytes)
                } else {
                    val outDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                    val f = File(outDir, patchedFileName)
                    FileOutputStream(f).use { it.write(bytes) }
                    SaveOutcome.Public(f.absolutePath)
                }
            } catch (_: Exception) {
                SaveOutcome.Failed
            }
            launch(Dispatchers.Main) { onResult(outcome) }
        }
    }

    /**
     * Insert the bytes into the shared Download/ collection via MediaStore.
     * Requires no runtime permission on API 29+. If a file with the same name
     * already exists (owned by this app), it is replaced so repeated exports
     * don't accumulate duplicates.
     */
    private fun writeViaMediaStore(context: Context, displayName: String, bytes: ByteArray): SaveOutcome {
        val resolver = context.contentResolver
        val collection = android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI

        // Remove a previous export we own with the same display name.
        try {
            resolver.delete(
                collection,
                "${android.provider.MediaStore.Downloads.DISPLAY_NAME} = ?",
                arrayOf(displayName)
            )
        } catch (_: Exception) {
        }

        val values = android.content.ContentValues().apply {
            put(android.provider.MediaStore.Downloads.DISPLAY_NAME, displayName)
            put(android.provider.MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
            put(android.provider.MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            put(android.provider.MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri = resolver.insert(collection, values) ?: return SaveOutcome.Failed
        resolver.openOutputStream(uri)?.use { os -> os.write(bytes) } ?: return SaveOutcome.Failed
        values.clear()
        values.put(android.provider.MediaStore.Downloads.IS_PENDING, 0)
        resolver.update(uri, values, null, null)
        return SaveOutcome.Public("Download/$displayName")
    }

    fun resolveIl2CppMetadata(path: String, onComplete: (Int) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(-1) }
                return@launch
            }
            val count = if (path.endsWith(".json", ignoreCase = true)) {
                b.loadScriptJson(path)      // script.json: returns real count
            } else {
                val status = b.loadGlobalMetadata(path)  // .dat: 0=validated, -1=error
                if (status < 0) return@launch run { launch(Dispatchers.Main) { onComplete(-1) } }
                0
            }
            if (count > 0) {
                val info = b.getInfo()
                _elfInfo.value = info
            }
            launch(Dispatchers.Main) { onComplete(count) }
        }
    }

    fun toggleTheme() {
        isDarkMode.value = !isDarkMode.value
    }

    private val _elfInfo = MutableStateFlow<ElfInfo?>(null)
    val elfInfo: StateFlow<ElfInfo?> = _elfInfo.asStateFlow()

    private val _instructions = MutableStateFlow<List<Instruction>>(emptyList())
    val instructions: StateFlow<List<Instruction>> = _instructions.asStateFlow()

    /// Number of reversible patches recorded on the native side. Drives the
    /// Undo button's enabled state. Refreshed after every patch/undo.
    private val _undoDepth = MutableStateFlow(0)
    val undoDepth: StateFlow<Int> = _undoDepth.asStateFlow()

    private val _decompileText = MutableStateFlow("")
    val decompileText: StateFlow<String> = _decompileText.asStateFlow()

    private val _flowchartText = MutableStateFlow("")
    val flowchartText: StateFlow<String> = _flowchartText.asStateFlow()

    private val _stringsList = MutableStateFlow<List<StringItem>>(emptyList())
    val stringsList: StateFlow<List<StringItem>> = _stringsList.asStateFlow()

    private val _scanReport = MutableStateFlow<ScanReport?>(null)
    val scanReport: StateFlow<ScanReport?> = _scanReport.asStateFlow()

    private val _currentAddress = MutableStateFlow<Long>(0)
    val currentAddress: StateFlow<Long> = _currentAddress.asStateFlow()

    private val _selectedSymbolName = MutableStateFlow("")
    val selectedSymbolName: StateFlow<String> = _selectedSymbolName.asStateFlow()

    fun navigateTo(screen: Screen) {
        _currentScreen.value = screen
    }

    override fun onCleared() {
        super.onCleared()
        // Release the native ElfContext deterministically instead of waiting
        // for the GC to run a (removed) finalizer. This runs on the main thread
        // but is the only remaining reference, so no native call can be in
        // flight on the dispatcher once the ViewModel is being cleared.
        try {
            _bridge.value?.close()
        } catch (_: Throwable) {
        }
        _bridge.value = null
    }

    fun loadElf(path: String, fileName: String = "") {
        viewModelScope.launch(nativeDispatcher) {
            currentFileName.value = if (fileName.isNotEmpty()) fileName else File(path).name
            val newBridge = JNIBridge.open(path) ?: return@launch
            // We are already on the single native thread, so no lock is needed.
            // Close the previous bridge before swapping it out.
            val old = _bridge.value
            _bridge.value = newBridge
            try { old?.close() } catch (_: Throwable) {}
            val b = newBridge
            val info = b.getInfo()
            _elfInfo.value = info

            // Pick the first symbol that is actually executable code. The symbol
            // table often starts with undefined imports (address 0, e.g. strchr).
            val firstSym = info.syms.firstOrNull { it.value != 0L }
            val firstAddr = firstSym?.value ?: info.entry
            val firstName = firstSym?.displayName ?: "entry"
            selectFunction(firstAddr, firstName)
            _stringsList.value = b.getStrings()
            _entropyReport.value = b.getEntropyReport()
        }
    }

    fun selectFunction(address: Long, name: String) {
        // These are StateFlow writes — non-blocking, safe on the UI thread.
        _currentAddress.value = address
        _selectedSymbolName.value = name
        // Everything else runs on the single native thread. No `synchronized`
        // here: blocking the UI thread on the native lock causes ANRs.
        viewModelScope.launch(nativeDispatcher) {
            if (address == 0L) {
                // Address 0 is an undefined import, not executable code.
                _instructions.value = emptyList()
                _decompileText.value = "// selected symbol is an unresolved import (address 0)"
                _flowchartText.value = ""
                return@launch
            }
            val b = _bridge.value ?: return@launch
            _instructions.value = b.disassemble(address, 256)
            _decompileText.value = b.decompile(address)
            _flowchartText.value = b.getFlowchartText(address)
            loadHexDump(address, 2048)
        }
    }

    fun applyQuickPatch(address: Long, patchType: Int, isThumb: Boolean = false, onComplete: (PatchResult) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            val res = b.quickPatch(address, patchType, isThumb)
            if (res.success) {
                _undoDepth.value = b.undoLen()
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) {
                onComplete(res)
            }
        }
    }

    /// Revert the most recent patch (quick, assemble, plugin, propagate, or hex).
    /// Returns the reverted address, or -1 if nothing to undo.
    fun undoLastPatch(onComplete: (Long) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(-1L) }
                return@launch
            }
            val addr = b.undoLast()
            _undoDepth.value = b.undoLen()
            if (addr >= 0) {
                _hexBytes.value = b.readBytes(_hexStartAddress.value, 2048)
                if (_currentAddress.value != 0L) {
                    _instructions.value = b.disassemble(_currentAddress.value, 256)
                    _decompileText.value = b.decompile(_currentAddress.value)
                    _flowchartText.value = b.getFlowchartText(_currentAddress.value)
                }
            }
            launch(Dispatchers.Main) { onComplete(addr) }
        }
    }

    /// Suspending variant that always runs on the single native thread.
    /// Never call JNIBridge native methods directly from the UI thread.
    suspend fun getXrefsFor(address: Long): List<XRefItem> =
        withContext(nativeDispatcher) {
            _bridge.value?.getXrefs(address) ?: emptyList()
        }

    fun loadXrefsFor(address: Long, onResult: (List<XRefItem>) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onResult(emptyList()) }
                return@launch
            }
            val xrefs = b.getXrefs(address)
            launch(Dispatchers.Main) { onResult(xrefs) }
        }
    }

    /**
     * Neutralise every caller in [addresses] by NOP-ing the branch instruction
     * at each site. Sequential on the single native thread; each write goes
     * through the validated quick-patch path and is recorded for undo.
     */
    fun patchCallers(
        addresses: List<Long>,
        onComplete: (applied: Int, skipped: Int) -> Unit
    ) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(0, addresses.size) }
                return@launch
            }
            var applied = 0
            var skipped = 0
            for (addr in addresses) {
                val res = b.quickPatch(addr, 1 /* NOP */, false)
                if (res.success) applied++ else skipped++
            }
            _undoDepth.value = b.undoLen()
            if (_currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(applied, skipped) }
        }
    }

    /// Suspending variant that always runs on the single native thread.
    suspend fun getHierarchy(address: Long): CallHierarchy =
        withContext(nativeDispatcher) {
            _bridge.value?.getHierarchy(address) ?: CallHierarchy()
        }

    fun loadHierarchy(address: Long, onResult: (CallHierarchy) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onResult(CallHierarchy()) }
                return@launch
            }
            val hierarchy = b.getHierarchy(address)
            launch(Dispatchers.Main) { onResult(hierarchy) }
        }
    }

    fun runSecurityScan() {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            _scanReport.value = b.scanSecurity()
        }
    }

    fun refreshSecurityScan() {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            _scanReport.value = b.scanSecurity()
        }
    }

    fun renameFunction(address: Long, newName: String, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(false) }
                return@launch
            }
            val ok = b.renameFunction(address, newName)
            if (ok) {
                _selectedSymbolName.value = newName
                val info = b.getInfo()
                _elfInfo.value = info
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(ok) }
        }
    }

    fun assemblePatch(address: Long, text: String, onComplete: (PatchResult) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(PatchResult(error = "No binary loaded")) }
                return@launch
            }
            val res = b.assemblePatch(address, text)
            if (res.success) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(res) }
        }
    }

    private val gson = com.google.gson.Gson()

    // Both must be declared before _plugins: defaultBuiltInPlugins() (the
    // _plugins initializer) writes to the accumulator and publishes into the
    // flow on load failure. Kotlin initializes properties top-to-bottom;
    // declaring the flow after _plugins caused an NPE.
    private val builtInLoadErrorsAccumulator = mutableListOf<String>()
    private val _builtInLoadErrorsFlow = MutableStateFlow<List<String>>(emptyList())
    val builtInLoadErrors: StateFlow<List<String>> = _builtInLoadErrorsFlow.asStateFlow()

    private val _plugins = MutableStateFlow<List<LoadedPlugin>>(defaultBuiltInPlugins())
    val plugins: StateFlow<List<LoadedPlugin>> = _plugins.asStateFlow()

    private val _isRunningPlugins = MutableStateFlow(false)
    val isRunningPlugins: StateFlow<Boolean> = _isRunningPlugins.asStateFlow()

    private fun defaultBuiltInPlugins(): List<LoadedPlugin> {
        // Load plugin manifests from assets/plugins/*.json (P1 refactor:
        // previously an ~700-line inline listOf of raw JSON strings).
        val builtInJsons: List<String> = try {
            val names = appContext.assets.list("plugins")
                ?.filter { it.endsWith(".json") }
                ?.sorted()
                ?: emptyList()
            names.mapNotNull { name ->
                try {
                    appContext.assets.open("plugins/$name")
                        .bufferedReader().use { it.readText() }
                } catch (e: Exception) {
                    builtInLoadErrorsAccumulator.add(
                        "$name: ${e.message ?: e.javaClass.simpleName}"
                    )
                    null
                }
            }
        } catch (e: Exception) {
            builtInLoadErrorsAccumulator.add(
                "assets/plugins: ${e.message ?: e.javaClass.simpleName}"
            )
            emptyList()
        }
        val loaded = builtInJsons.mapNotNull { raw ->
            try {
                val manifest = gson.fromJson(raw, PluginManifest::class.java)
                LoadedPlugin(
                    manifest = manifest,
                    rawJson = raw,
                    enabled = manifest.defaultEnabled,
                    isBuiltIn = true
                )
            } catch (e: Exception) {
                // Best-effort plugin id for the error message; the JSON is broken
                // so gson can't produce a manifest, but the id often still parses.
                val guessId = Regex("\"id\"\\s*:\\s*\"([^\"]+)\"")
                    .find(raw)?.groupValues?.getOrNull(1) ?: "<unknown>"
                builtInLoadErrorsAccumulator.add("$guessId: ${e.message ?: e.javaClass.simpleName}")
                null
            }
        }
        // Publish the collected errors (field set happened during this init).
        _builtInLoadErrorsFlow.value = builtInLoadErrorsAccumulator.toList()
        return loaded
    }

    fun importPluginJson(rawInput: String, defaultName: String = "Custom Rhai Script"): Result<PluginManifest> {
        return try {
            val trimmed = rawInput.trim()
            val (manifest, finalJson) = if (trimmed.startsWith("{")) {
                val m = gson.fromJson(trimmed, PluginManifest::class.java)
                    ?: return Result.failure(IllegalArgumentException("Empty plugin JSON"))
                if (m.id.isBlank() || m.name.isBlank()) {
                    return Result.failure(IllegalArgumentException("Plugin must have non-empty 'id' and 'name'"))
                }
                m to trimmed
            } else {
                if (trimmed.isEmpty()) {
                    return Result.failure(IllegalArgumentException("Empty script"))
                }
                val id = "rhai-${System.currentTimeMillis()}"
                val m = PluginManifest(
                    id = id,
                    name = defaultName,
                    version = "1.0",
                    author = "User",
                    description = "Custom Rhai analysis script",
                    script = trimmed
                )
                m to gson.toJson(m)
            }
            val newPlugin = LoadedPlugin(
                manifest = manifest,
                rawJson = finalJson,
                enabled = true,
                isBuiltIn = false
            )
            val current = _plugins.value.toMutableList()
            val existingIdx = current.indexOfFirst { it.manifest.id == manifest.id }
            if (existingIdx >= 0) {
                current[existingIdx] = newPlugin
            } else {
                current.add(0, newPlugin)
            }
            _plugins.value = current
            Result.success(manifest)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun togglePlugin(id: String) {
        _plugins.value = _plugins.value.map {
            if (it.manifest.id == id) it.copy(enabled = !it.enabled) else it
        }
    }

    fun removePlugin(id: String) {
        _plugins.value = _plugins.value.filterNot { it.manifest.id == id && !it.isBuiltIn }
    }

    fun runPlugin(id: String) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            val target = _plugins.value.firstOrNull { it.manifest.id == id } ?: return@launch
            _isRunningPlugins.value = true
            val report = b.runPlugin(target.rawJson)
            _plugins.value = _plugins.value.map {
                if (it.manifest.id == id) it.copy(lastReport = report) else it
            }
            _isRunningPlugins.value = false
        }
    }

    fun runAllEnabledPlugins() {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            _isRunningPlugins.value = true
            val updated = _plugins.value.map { plugin ->
                if (plugin.enabled) {
                    plugin.copy(lastReport = b.runPlugin(plugin.rawJson))
                } else {
                    plugin
                }
            }
            _plugins.value = updated
            _isRunningPlugins.value = false
        }
    }

    fun applyPluginPatch(address: Long, patch: PluginPatch, onComplete: (PatchResult) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(PatchResult(error = "No binary loaded")) }
                return@launch
            }
            val targetAddr = address + patch.offset
            val res = b.applyPluginPatch(targetAddr, patch.mode, patch.value)
            if (res.success) {
                _undoDepth.value = b.undoLen()
                if (_currentAddress.value != 0L) {
                    _instructions.value = b.disassemble(_currentAddress.value, 256)
                    _decompileText.value = b.decompile(_currentAddress.value)
                    _flowchartText.value = b.getFlowchartText(_currentAddress.value)
                }
            }
            launch(Dispatchers.Main) { onComplete(res) }
        }
    }

    /**
     * Apply every finding's patch in one batch (the plugin already produced the
     * finding list). Runs sequentially on the single native thread; each patch
     * goes through the same validated path as a manual plugin patch, and the
     * native undo stack records all of them. Reports how many applied/skipped.
     */
    fun applyAllPluginPatches(
        findings: List<PluginFinding>,
        onComplete: (applied: Int, skipped: Int) -> Unit
    ) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(0, findings.size) }
                return@launch
            }
            var applied = 0
            var skipped = 0
            for (f in findings) {
                val patch = f.patch ?: continue
                val res = b.applyPluginPatch(f.address + patch.offset, patch.mode, patch.value)
                if (res.success) applied++ else skipped++
            }
            _undoDepth.value = b.undoLen()
            if (_currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(applied, skipped) }
        }
    }

    /**
     * Spread one seed patch across the binary (ExactClone = 1, Callers = 2).
     * Run with dryRun = true first to populate a review dialog; then call again
     * with dryRun = false for the confirmed subset (the native side re-applies
     * the seed at every matched address through the same validation gate).
     */
    fun propagatePatch(
        seedAddr: Long,
        mode: Int,
        patchMode: String,
        patchValue: String,
        dryRun: Boolean,
        onComplete: (PatchPropagationReport) -> Unit
    ) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) {
                    onComplete(PatchPropagationReport(error = "No binary loaded"))
                }
                return@launch
            }
            val report = b.propagatePatch(seedAddr, mode, patchMode, patchValue, dryRun)
            if (!dryRun && report.applied > 0 && _currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(report) }
        }
    }
}
