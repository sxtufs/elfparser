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
    object Branches : Screen()
    object Analysis : Screen()
}

class ELFTraceViewModel : ViewModel() {

    /// Single-threaded dispatcher for ALL native (JNI) calls. The native
    /// `ElfContext` — and especially the Unicorn engine inside it — is not
    /// thread-safe. Running every native call on exactly one thread eliminates
    /// data races, concurrent `&`/`&mut` aliasing, and the segfaults they cause.
    private val nativeDispatcher = Dispatchers.IO.limitedParallelism(1)

    private val _bridge = MutableStateFlow<JNIBridge?>(null)
    val bridge: StateFlow<JNIBridge?> = _bridge.asStateFlow()

    private val _currentScreen = MutableStateFlow<Screen>(Screen.Files)
    val currentScreen: StateFlow<Screen> = _currentScreen.asStateFlow()

    val codeSubTab = MutableStateFlow(0) // 0: Disasm, 1: Decompile, 2: Flowchart, 3: Hex View
    val analysisSubTab = MutableStateFlow(0) // 0: Strings, 1: Security, 2: Entropy Radar

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
            val alignedAddr = address - (address % 16)
            val bytes = b.readBytes(alignedAddr, length)
            _hexStartAddress.value = alignedAddr
            _hexBytes.value = bytes
        }
    }

    fun savePatchedBinary(context: Context, onResult: (String?) -> Unit) {
        viewModelScope.launch(nativeDispatcher) {
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

    /// A larger disassembly window of the current function, used only by the
    /// Branches analyzer (so it sees the whole function, not just 256 bytes).
    private val _analysisInstructions = MutableStateFlow<List<Instruction>>(emptyList())
    val analysisInstructions: StateFlow<List<Instruction>> = _analysisInstructions.asStateFlow()

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
            _scanReport.value = b.scanSecurity()
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
            // Full-function window for the Branches analyzer. Prefer the exact
            // symbol size; if unknown, clamp to the next symbol so we never
            // disassemble into the neighbouring function (that produced phantom
            // branches and false loops).
            val syms = _elfInfo.value?.syms ?: emptyList()
            val symSize = syms.firstOrNull { it.value == address }?.size ?: 0L
            val analysisWindow = when {
                symSize in 4L..(1024L * 1024L) -> symSize + 16
                else -> {
                    val nextStart = syms.asSequence()
                        .map { it.value }
                        .filter { it > address }
                        .minOrNull()
                    if (nextStart != null && nextStart - address in 4L..(1024L * 1024L)) {
                        nextStart - address
                    } else {
                        512L   // conservative cap when the bound is unknown
                    }
                }
            }
            _analysisInstructions.value = b.disassemble(address, analysisWindow)
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
        viewModelScope.launch(nativeDispatcher) {
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
}
