package io.elftrace.app.viewmodel

import android.app.Application
import android.content.Context
import android.os.Environment
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.elftrace.app.core.JNIBridge
import io.elftrace.app.core.db.BookmarkRecord
import io.elftrace.app.core.db.SessionRecord
import io.elftrace.app.core.db.WorkspaceStore
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

    /** Workspace storage: recent files, last position, renames, bookmarks, journal. */
    private val store = WorkspaceStore.create(app)

    /** Content-hash key of the open binary; empty until [loadElf] succeeds. */
    private var sessionKey: String = ""

    private val _recentSessions = MutableStateFlow<List<SessionRecord>>(emptyList())
    val recentSessions: StateFlow<List<SessionRecord>> = _recentSessions.asStateFlow()

    private val _bookmarks = MutableStateFlow<List<BookmarkRecord>>(emptyList())
    val bookmarks: StateFlow<List<BookmarkRecord>> = _bookmarks.asStateFlow()

    /** One entry of the in-session navigation history. */
    data class NavPoint(val address: Long, val name: String)

    private val _navStack = MutableStateFlow<List<NavPoint>>(emptyList())
    val navStack: StateFlow<List<NavPoint>> = _navStack.asStateFlow()

    private val _canGoBack = MutableStateFlow(false)
    val canGoBack: StateFlow<Boolean> = _canGoBack.asStateFlow()

    init {
        viewModelScope.launch(nativeDispatcher) {
            _recentSessions.value = store.recentSessions()
        }
    }

    private val _bridge = MutableStateFlow<JNIBridge?>(null)
    val bridge: StateFlow<JNIBridge?> = _bridge.asStateFlow()

    private val _currentScreen = MutableStateFlow<Screen>(Screen.Files)
    val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

    val codeSubTab = MutableStateFlow(0) // 0: Disasm, 1: Decompile, 2: Flowchart, 3: Hex View

    // Plugins tab scroll position and expanded card live here, not in the screen:
    // jumping to a finding swaps PluginsScreen out of composition, which would
    // otherwise reset the list to the top on return.
    val pluginsListState = androidx.compose.foundation.lazy.LazyListState()
    val expandedPluginId = MutableStateFlow<String?>(null)

    /** Persisted across launches in a private SharedPreferences file. */
    private val prefs = app.getSharedPreferences("elftrace_prefs", Context.MODE_PRIVATE)
    val isDarkMode = MutableStateFlow(prefs.getBoolean(KEY_DARK_MODE, true)) // Light / Dark mode toggle

    val currentFileName = MutableStateFlow("")
    /** One-shot error when a binary fails to open, shown as a toast. */
    val openError = MutableStateFlow<String?>(null)

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
            val original = if (sessionKey.isNotEmpty()) {
                try { b.readBytes(address, bytes.size) } catch (_: Exception) { ByteArray(0) }
            } else {
                ByteArray(0)
            }
            val ok = b.patchBytes(address, bytes)
            if (ok) {
                _undoDepth.value = b.undoLen()
                recordJournal(address, "hex", original, bytes)
            }
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
        prefs.edit().putBoolean(KEY_DARK_MODE, isDarkMode.value).apply()
    }

    private companion object {
        const val KEY_DARK_MODE = "dark_mode"
        const val MAX_BOOKMARKS = 50
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

    /// Structured decompiler output (mode 4). Fetched lazily the first time the
    /// user selects Structured, and refreshed whenever the selected function
    /// changes while Structured is active, so we never pay the extra native
    /// cost for users who stay on the linear view.
    private val _decompileStructured = MutableStateFlow("")
    val decompileStructured: StateFlow<String> = _decompileStructured.asStateFlow()

    /// 1 = Linear-Clean, 2 = Structured (Raw was removed from the UI).
    private val _decompileMode = MutableStateFlow(1)
    val decompileMode: StateFlow<Int> = _decompileMode.asStateFlow()

    /// Address the structured text currently corresponds to; used to avoid
    /// re-fetching when the mode is re-selected without an address change.
    private var structuredForAddress: Long = -1

    fun setDecompileMode(mode: Int) {
        _decompileMode.value = mode.coerceIn(0, 2)
        if (mode == 2) ensureStructuredForCurrent()
    }

    /// Fetch mode-4 output for the current address if it is stale/missing.
    private fun ensureStructuredForCurrent() {
        val addr = _currentAddress.value
        if (addr == 0L || addr == structuredForAddress) return
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            val out = b.decompileStructured(addr)
            structuredForAddress = addr
            _decompileStructured.value = out
        }
    }

    private val _flowchartText = MutableStateFlow("")
    val flowchartText: StateFlow<String> = _flowchartText.asStateFlow()

    private val _stringsList = MutableStateFlow<List<StringItem>>(emptyList())
    val stringsList: StateFlow<List<StringItem>> = _stringsList.asStateFlow()

    private val _binaryFacts = MutableStateFlow<BinaryFacts?>(null)
    val binaryFacts: StateFlow<BinaryFacts?> = _binaryFacts.asStateFlow()

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
        try { store.close() } catch (_: Throwable) {}
    }

    fun loadElf(path: String, fileName: String = "", knownKey: String? = null) {
        viewModelScope.launch(nativeDispatcher) {
            currentFileName.value = if (fileName.isNotEmpty()) fileName else File(path).name
            val newBridge = JNIBridge.open(path) ?: run {
                openError.value = "Could not open ${File(path).name} — unsupported format or not enough memory"
                return@launch
            }
            // We are already on the single native thread, so no lock is needed.
            // Close the previous bridge before swapping it out.
            val old = _bridge.value
            _bridge.value = newBridge
            try { old?.close() } catch (_: Throwable) {}
            val b = newBridge

            _navStack.value = emptyList()
            _canGoBack.value = false

            // Drop reports from the previous binary so the Plugins tab starts
            // clean instead of showing stale findings until the next run.
            _plugins.value = _plugins.value.map { it.copy(lastReport = null) }

            // Key the workspace by content, not by path: the picker copies every
            // file to the same cache path, so a path key would mix binaries.
            sessionKey = knownKey ?: try {
                WorkspaceStore.fileKey(File(path))
            } catch (_: Exception) {
                ""
            }

            // Restore this binary's workspace. Renames first, then the patch
            // journal: replaying through the normal native path keeps undo and
            // the views consistent with what the user left behind.
            if (sessionKey.isNotEmpty()) {
                for (r in store.renames(sessionKey)) b.renameFunction(r.address, r.name)
                for (j in store.journal(sessionKey)) {
                    if (j.patched.isNotEmpty()) b.patchBytes(j.address, j.patched)
                }
                _undoDepth.value = b.undoLen()
            }

            val info = b.getInfo()
            _elfInfo.value = info
            _bookmarks.value = if (sessionKey.isNotEmpty()) store.bookmarks(sessionKey) else emptyList()

            val previous = if (sessionKey.isNotEmpty()) {
                store.recentSessions(20).firstOrNull { it.fileKey == sessionKey }
            } else {
                null
            }
            if (sessionKey.isNotEmpty()) store.touchSession(sessionKey, path, currentFileName.value)
            _recentSessions.value = store.recentSessions()

            // Pick the first symbol that is actually executable code. The symbol
            // table often starts with undefined imports (address 0, e.g. strchr).
            val firstSym = info.syms.firstOrNull { it.value != 0L }
            val restored = previous?.takeIf { it.lastAddress != 0L }
            val firstAddr = restored?.lastAddress ?: firstSym?.value ?: info.entry
            val firstName = restored?.lastName?.takeIf { it.isNotEmpty() }
                ?: firstSym?.displayName ?: "entry"
            selectFunction(firstAddr, firstName, pushHistory = false)
            _stringsList.value = b.getStrings()
            _binaryFacts.value = b.getBinaryFacts()
        }
    }

    /**
     * Show [address]. A user-driven selection pushes the previous position onto
     * the navigation stack so [goBack] can return to it; restoring a position
     * (file open, back navigation) passes `pushHistory = false`.
     */
    fun selectFunction(address: Long, name: String, pushHistory: Boolean = true) {
        if (pushHistory) {
            val prevAddr = _currentAddress.value
            if (prevAddr != 0L && prevAddr != address) {
                _navStack.value = (_navStack.value + NavPoint(prevAddr, _selectedSymbolName.value))
                    .takeLast(64)
                _canGoBack.value = true
            }
        }
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
                _decompileStructured.value = ""
                structuredForAddress = -1
                _flowchartText.value = ""
                return@launch
            }
            val b = _bridge.value ?: return@launch
            _instructions.value = b.disassemble(address, 256)
            _decompileText.value = b.decompile(address)
            _flowchartText.value = b.getFlowchartText(address)
            // Structured output is address-specific; invalidate and refetch if
            // the user is currently viewing the Structured mode.
            if (structuredForAddress != address) {
                structuredForAddress = -1
                _decompileStructured.value = ""
            }
            if (_decompileMode.value == 2) {
                val out = b.decompileStructured(address)
                structuredForAddress = address
                _decompileStructured.value = out
            }
            loadHexDump(address, 2048)
            if (sessionKey.isNotEmpty()) store.savePosition(sessionKey, address, name)
        }
    }

    /** Leave the current function and show the previous one. */
    fun goBack(): Boolean {
        val stack = _navStack.value
        if (stack.isEmpty()) return false
        val prev = stack.last()
        _navStack.value = stack.dropLast(1)
        _canGoBack.value = _navStack.value.isNotEmpty()
        selectFunction(prev.address, prev.name, pushHistory = false)
        return true
    }

    /**
     * Recover function starts in a stripped binary. The recovered functions are
     * installed as `sub_XXXXXXXX` symbols, so the symbol list, xrefs and call
     * hierarchy all see them; [getInfo] is refreshed on success.
     */
    /** String xrefs from function discovery: string vaddr -> referencing code addr. */
    private val _stringXrefs = MutableStateFlow<List<StringXref>>(emptyList())
    val stringXrefs: StateFlow<List<StringXref>> = _stringXrefs.asStateFlow()

    /**
     * Jump to the function containing the code that references [stringAddr].
     * Falls back to selecting the code address directly when no function
     * contains it.
     */
    fun jumpToStringReference(stringAddr: Long) {
        val code = _stringXrefs.value.firstOrNull { it.strAddr == stringAddr }?.codeAddr ?: return
        val fn = _elfInfo.value?.syms
            ?.filter { it.value <= code && it.value + (it.size.takeIf { s -> s > 0 } ?: 1) > code && it.value != 0L }
            ?.maxByOrNull { it.value }
        selectFunction(fn?.value ?: code, fn?.displayName ?: "sub_%08X".format(code))
    }

    fun recoverFunctions(onComplete: (DiscoveryResult) -> Unit = {}) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(DiscoveryResult(error = "No binary loaded")) }
                return@launch
            }
            val res = b.discoverFunctions()
            if (res.error == null) {
                _stringXrefs.value = res.stringRefs
                if (res.added > 0) {
                    _elfInfo.value = b.getInfo()
                }
            }
            launch(Dispatchers.Main) { onComplete(res) }
        }
    }

    fun toggleBookmark(address: Long, name: String) {
        if (sessionKey.isEmpty() || address == 0L) return
        viewModelScope.launch(nativeDispatcher) {
            if (_bookmarks.value.any { it.address == address }) {
                store.removeBookmark(sessionKey, address)
            } else if (_bookmarks.value.size >= MAX_BOOKMARKS) {
                openError.value = "Bookmark limit reached ($MAX_BOOKMARKS) — remove one to add another"
            } else {
                store.addBookmark(sessionKey, address, name)
            }
            _bookmarks.value = store.bookmarks(sessionKey)
        }
    }

    fun removeBookmark(id: Long) {
        if (sessionKey.isEmpty()) return
        viewModelScope.launch(nativeDispatcher) {
            val record = _bookmarks.value.firstOrNull { it.id == id } ?: return@launch
            store.removeBookmark(record.fileKey, record.address)
            _bookmarks.value = store.bookmarks(sessionKey)
        }
    }

    /**
     * Re-open a file from the Recent list. The picker copies every binary to the
     * same cache path, so a session whose content hash no longer matches is
     * dropped instead of opening the wrong binary under the wrong name.
     */
    fun openRecent(session: SessionRecord, onComplete: (Boolean) -> Unit = {}) {
        viewModelScope.launch(nativeDispatcher) {
            val file = File(session.path)
            val key = if (file.exists()) {
                try { WorkspaceStore.fileKey(file) } catch (_: Exception) { null }
            } else {
                null
            }
            val ok = key != null && key == session.fileKey
            if (ok) {
                loadElf(session.path, session.displayName, knownKey = key)
            } else {
                store.forgetSession(session.fileKey)
                _recentSessions.value = store.recentSessions()
            }
            launch(Dispatchers.Main) { onComplete(ok) }
        }
    }

    fun forgetRecent(fileKey: String) {
        viewModelScope.launch(nativeDispatcher) {
            store.forgetSession(fileKey)
            _recentSessions.value = store.recentSessions()
        }
    }

    private fun List<Int>.asBytes(): ByteArray = ByteArray(size) { this[it].toByte() }

    /**
     * Persist one applied patch so it survives a re-open and can be undone.
     * The native undo stack is in-memory only; this table is the durable copy.
     */
    private suspend fun recordJournal(
        address: Long,
        kind: String,
        original: ByteArray,
        patched: ByteArray
    ) {
        if (sessionKey.isEmpty() || address == 0L) return
        if (original.isEmpty() || patched.isEmpty()) return
        store.appendJournal(sessionKey, address, kind, original, patched)
    }

    fun applyQuickPatch(address: Long, patchType: Int, isThumb: Boolean = false, onComplete: (PatchResult) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
            val b = _bridge.value ?: return@launch
            val res = b.quickPatch(address, patchType, isThumb)
            if (res.success) {
                _undoDepth.value = b.undoLen()
                recordJournal(address, "quick", res.original_bytes.asBytes(), res.patched_bytes.asBytes())
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
                if (sessionKey.isNotEmpty()) store.removeLatestJournalAt(sessionKey, addr)
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
                if (res.success) {
                    recordJournal(addr, "nop-caller", res.original_bytes.asBytes(), res.patched_bytes.asBytes())
                    applied++
                } else {
                    skipped++
                }
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
                if (sessionKey.isNotEmpty()) store.saveRename(sessionKey, address, newName)
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
                _undoDepth.value = b.undoLen()
                recordJournal(address, "assemble", res.original_bytes.asBytes(), res.patched_bytes.asBytes())
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
        // LazyColumn keys rows on manifest.id; a duplicate would crash the
        // Plugins tab, so later files with an already-seen id are skipped.
        val loaded = mutableListOf<LoadedPlugin>()
        builtInJsons.forEach { raw ->
            try {
                val manifest = gson.fromJson(raw, PluginManifest::class.java)
                if (loaded.any { it.manifest.id == manifest.id }) {
                    builtInLoadErrorsAccumulator.add("${manifest.id}: duplicate plugin id, skipped")
                } else {
                    loaded.add(
                        LoadedPlugin(
                            manifest = manifest,
                            rawJson = raw,
                            enabled = manifest.defaultEnabled,
                            isBuiltIn = true
                        )
                    )
                }
            } catch (e: Exception) {
                // Best-effort plugin id for the error message; the JSON is broken
                // so gson can't produce a manifest, but the id often still parses.
                val guessId = Regex("\"id\"\\s*:\\s*\"([^\"]+)\"")
                    .find(raw)?.groupValues?.getOrNull(1) ?: "<unknown>"
                builtInLoadErrorsAccumulator.add("$guessId: ${e.message ?: e.javaClass.simpleName}")
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
            var seen = HashSet<String>()
            val updated = _plugins.value.map { plugin ->
                if (plugin.enabled) {
                    val report = b.runPlugin(plugin.rawJson)
                    // Cross-plugin dedupe: keep only the first report of an
                    // identical (address, rule, severity, patch) finding when
                    // several plugins surface the same thing.
                    val deduped = report.findings.filter { f ->
                        val key = "${f.rule_type}:${f.address}:${f.severity}:" +
                            (f.patch?.let { "${it.mode}=${it.value}@${it.offset}" } ?: "")
                        seen.add(key)
                    }
                    plugin.copy(
                        lastReport = if (deduped.size == report.findings.size) report
                        else report.copy(findings = deduped, total_findings = deduped.size)
                    )
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
                recordJournal(targetAddr, "plugin", res.original_bytes.asBytes(), res.patched_bytes.asBytes())
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
                val targetAddr = f.address + patch.offset
                val res = b.applyPluginPatch(targetAddr, patch.mode, patch.value)
                if (res.success) {
                    recordJournal(targetAddr, "plugin", res.original_bytes.asBytes(), res.patched_bytes.asBytes())
                    applied++
                } else {
                    skipped++
                }
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
            if (!dryRun && report.applied > 0) {
                for (e in report.entries) {
                    if (e.status == "applied") {
                        recordJournal(e.address, "propagate", e.original_bytes.asBytes(), e.patched_bytes.asBytes())
                    }
                }
            }
            if (!dryRun && report.applied > 0 && _currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(report) }
        }
    }
}
