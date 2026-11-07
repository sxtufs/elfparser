package io.elftrace.app.viewmodel

import android.content.Context
import android.os.Environment
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.elftrace.app.core.JNIBridge
import io.elftrace.app.core.models.*
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class Screen {
    object Files : Screen()
    object Code : Screen()
    object Tracer : Screen()
    object Analysis : Screen()
}

class ELFTraceViewModel : ViewModel() {

    private val _bridge = MutableStateFlow<JNIBridge?>(null)
    val bridge: StateFlow<JNIBridge?> = _bridge.asStateFlow()

    private val _currentScreen = MutableStateFlow<Screen>(Screen.Files)
    val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

    val codeSubTab = MutableStateFlow(0) // 0: Disasm, 1: Decompile, 2: Flowchart, 3: Hex View
    val analysisSubTab = MutableStateFlow(0) // 0: Strings, 1: Security, 2: Entropy Radar

    val isDarkMode = MutableStateFlow(true) // Light / Dark mode toggle

    val currentFileName = MutableStateFlow("")

    companion object {
        const val MAX_BOOKMARKS = 50
    }

    private val _bookmarks = MutableStateFlow<List<FunctionBookmark>>(emptyList())
    val bookmarks: StateFlow<List<FunctionBookmark>> = _bookmarks.asStateFlow()

    fun loadBookmarksForCurrentFile(context: Context) {
        val fileName = currentFileName.value.ifEmpty { "default_target" }
        val prefs = context.getSharedPreferences("elftrace_bookmarks", Context.MODE_PRIVATE)
        val json = prefs.getString("bookmarks_$fileName", null)
        if (!json.isNullOrEmpty()) {
            try {
                val listType = object : com.google.gson.reflect.TypeToken<List<FunctionBookmark>>() {}.type
                val list: List<FunctionBookmark> = com.google.gson.Gson().fromJson(json, listType) ?: emptyList()
                _bookmarks.value = list.take(MAX_BOOKMARKS)
            } catch (_: Exception) {
                _bookmarks.value = emptyList()
            }
        } else {
            _bookmarks.value = emptyList()
        }
    }

    fun addBookmark(context: Context, address: Long, name: String, note: String): Boolean {
        val fileName = currentFileName.value.ifEmpty { "default_target" }
        val current = _bookmarks.value.toMutableList()
        if (current.size >= MAX_BOOKMARKS && current.none { it.address == address }) {
            return false // Limit reached!
        }
        current.removeAll { it.address == address }
        current.add(0, FunctionBookmark(address, name, note))
        val updated = current.take(MAX_BOOKMARKS)
        _bookmarks.value = updated

        val prefs = context.getSharedPreferences("elftrace_bookmarks", Context.MODE_PRIVATE)
        prefs.edit().putString("bookmarks_$fileName", com.google.gson.Gson().toJson(updated)).apply()
        return true
    }

    fun removeBookmark(context: Context, address: Long) {
        val fileName = currentFileName.value.ifEmpty { "default_target" }
        val updated = _bookmarks.value.filter { it.address != address }
        _bookmarks.value = updated
        val prefs = context.getSharedPreferences("elftrace_bookmarks", Context.MODE_PRIVATE)
        prefs.edit().putString("bookmarks_$fileName", com.google.gson.Gson().toJson(updated)).apply()
    }

    fun isBookmarked(address: Long): Boolean {
        return _bookmarks.value.any { it.address == address }
    }

    fun getBookmarkNote(address: Long): String {
        return _bookmarks.value.firstOrNull { it.address == address }?.note ?: ""
    }

    private val _entropyReport = MutableStateFlow<EntropyReport?>(null)
    val entropyReport: StateFlow<EntropyReport?> = _entropyReport.asStateFlow()

    fun refreshEntropyReport() {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            _entropyReport.value = b.getEntropyReport()
        }
    }

    private val _hexBytes = MutableStateFlow<ByteArray>(ByteArray(0))
    val hexBytes: StateFlow<ByteArray> = _hexBytes.asStateFlow()

    private val _hexStartAddress = MutableStateFlow(0L)
    val hexStartAddress: StateFlow<Long> = _hexStartAddress.asStateFlow()

    fun loadHexDump(address: Long, length: Int = 2048) {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            val alignedAddr = address - (address % 16)
            val bytes = b.readBytes(alignedAddr, length)
            _hexStartAddress.value = alignedAddr
            _hexBytes.value = bytes
        }
    }

    fun savePatchedBinary(context: Context, onResult: (String?) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onResult(null) }
                return@launch
            }
            val bytes = b.saveBinary()
            if (bytes.isEmpty()) {
                launch(Dispatchers.Main) { onResult(null) }
                return@launch
            }
            val origName = currentFileName.value.ifEmpty { "libtarget.so" }.removeSuffix(".so")
            val patchedFileName = "${origName}_patched.so"
            try {
                val outDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val outFile = File(outDir, patchedFileName)
                FileOutputStream(outFile).use { it.write(bytes) }
                launch(Dispatchers.Main) { onResult(outFile.absolutePath) }
            } catch (_: Exception) {
                try {
                    val fallback = File(context.cacheDir, patchedFileName)
                    FileOutputStream(fallback).use { it.write(bytes) }
                    launch(Dispatchers.Main) { onResult(fallback.absolutePath) }
                } catch (_: Exception) {
                    launch(Dispatchers.Main) { onResult(null) }
                }
            }
        }
    }

    fun resolveIl2CppMetadata(path: String, onComplete: (Int) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onComplete(0) }
                return@launch
            }
            val count = if (path.endsWith(".json", ignoreCase = true)) {
                b.loadScriptJson(path)
            } else {
                b.loadGlobalMetadata(path)
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

    private val _decompileText = MutableStateFlow("")
    val decompileText: StateFlow<String> = _decompileText.asStateFlow()

    private val _flowchartText = MutableStateFlow("")
    val flowchartText: StateFlow<String> = _flowchartText.asStateFlow()

    private val _stringsList = MutableStateFlow<List<StringItem>>(emptyList())
    val stringsList: StateFlow<List<StringItem>> = _stringsList.asStateFlow()

    private val _scanReport = MutableStateFlow<ScanReport?>(null)
    val scanReport: StateFlow<ScanReport?> = _scanReport.asStateFlow()

    private val _traceState = MutableStateFlow<TraceState?>(null)
    val traceState: StateFlow<TraceState?> = _traceState.asStateFlow()

    private val _currentAddress = MutableStateFlow<Long>(0)
    val currentAddress: StateFlow<Long> = _currentAddress.asStateFlow()

    private val _selectedSymbolName = MutableStateFlow("")
    val selectedSymbolName: StateFlow<String> = _selectedSymbolName.asStateFlow()

    fun navigateTo(screen: Screen) {
        _currentScreen.value = screen
    }

    fun loadElf(path: String, fileName: String = "") {
        viewModelScope.launch(Dispatchers.IO) {
            currentFileName.value = if (fileName.isNotEmpty()) fileName else File(path).name
            val b = JNIBridge.open(path) ?: return@launch
            _bridge.value = b
            val info = b.getInfo()
            _elfInfo.value = info

            val firstAddr = info.syms.firstOrNull()?.value ?: info.entry
            val firstName = info.syms.firstOrNull()?.displayName ?: "entry"
            selectFunction(firstAddr, firstName)
            _stringsList.value = b.getStrings()
            _scanReport.value = b.scanSecurity()
            _entropyReport.value = b.getEntropyReport()
        }
    }

    fun selectFunction(address: Long, name: String) {
        _currentAddress.value = address
        _selectedSymbolName.value = name
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            _instructions.value = b.disassemble(address, 256)
            _decompileText.value = b.decompile(address)
            _flowchartText.value = b.getFlowchartText(address)
            loadHexDump(address, 2048)
            b.startTrace(address)
            val firstInsn = _instructions.value.firstOrNull()
            val initialInsn = if (firstInsn != null) "${firstInsn.mnemonic} ${firstInsn.op_str}" else "Entry Point"
            _traceState.value = TraceState(pc = address, current_insn = initialInsn)
        }
    }

    fun applyQuickPatch(address: Long, patchType: Int, isThumb: Boolean = false, onComplete: (PatchResult) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            val res = b.quickPatch(address, patchType, isThumb)
            if (res.success) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) {
                onComplete(res)
            }
        }
    }

    fun getXrefsFor(address: Long): List<XRefItem> {
        val b = _bridge.value ?: return emptyList()
        return b.getXrefs(address)
    }

    fun loadXrefsFor(address: Long, onResult: (List<XRefItem>) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onResult(emptyList()) }
                return@launch
            }
            val xrefs = b.getXrefs(address)
            launch(Dispatchers.Main) { onResult(xrefs) }
        }
    }

    fun getHierarchy(address: Long): CallHierarchy {
        val b = _bridge.value ?: return CallHierarchy()
        return b.getHierarchy(address)
    }

    fun loadHierarchy(address: Long, onResult: (CallHierarchy) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: run {
                launch(Dispatchers.Main) { onResult(CallHierarchy()) }
                return@launch
            }
            val hierarchy = b.getHierarchy(address)
            launch(Dispatchers.Main) { onResult(hierarchy) }
        }
    }

    fun runSecurityScan() {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            _scanReport.value = b.scanSecurity()
        }
    }

    fun stepTrace() {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            val nextState = b.stepTrace()
            _traceState.value = nextState
        }
    }

    fun stepBackTrace() {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            val prevState = b.stepBackTrace()
            _traceState.value = prevState
        }
    }

    fun resetTrace() {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            val addr = _currentAddress.value
            b.startTrace(addr)
            val firstInsn = _instructions.value.firstOrNull()
            val initialInsn = if (firstInsn != null) "${firstInsn.mnemonic} ${firstInsn.op_str}" else "Entry Point"
            _traceState.value = TraceState(pc = addr, current_insn = initialInsn)
        }
    }

    fun refreshSecurityScan() {
        viewModelScope.launch(Dispatchers.IO) {
            val b = _bridge.value ?: return@launch
            _scanReport.value = b.scanSecurity()
        }
    }

    fun renameFunction(address: Long, newName: String, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
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
        viewModelScope.launch(Dispatchers.IO) {
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
}
