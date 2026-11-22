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
            b.patchBytes(address, bytes)
            val alignedAddr = _hexStartAddress.value
            _hexBytes.value = b.readBytes(alignedAddr, 2048)
            if (_currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(true) }
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
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) {
                onComplete(res)
            }
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

    // ==========================================
    // Plugins (JSON Signature & Patch Recipes)
    // ==========================================

    private val gson = com.google.gson.Gson()

    // Accumulates built-in plugin load failures. Declared BEFORE _plugins so it
    // is initialized first (defaultBuiltInPlugins() writes into it). Previously
    // a malformed built-in JSON was silently dropped by mapNotNull{ try/catch }.
    private val builtInLoadErrorsAccumulator = mutableListOf<String>()

    // Declared BEFORE _plugins: defaultBuiltInPlugins() (the _plugins initializer)
    // writes into this flow on load failure, so it must already be constructed.
    // Kotlin initializes properties top-to-bottom; referencing it below _plugins
    // caused a NullPointerException at ViewModel construction.
    private val _builtInLoadErrorsFlow = MutableStateFlow<List<String>>(emptyList())
    val builtInLoadErrors: StateFlow<List<String>> = _builtInLoadErrorsFlow.asStateFlow()

    private val _plugins = MutableStateFlow<List<LoadedPlugin>>(defaultBuiltInPlugins())
    val plugins: StateFlow<List<LoadedPlugin>> = _plugins.asStateFlow()

    private val _isRunningPlugins = MutableStateFlow(false)
    val isRunningPlugins: StateFlow<Boolean> = _isRunningPlugins.asStateFlow()

    private fun defaultBuiltInPlugins(): List<LoadedPlugin> {
        val builtInJsons = listOf(
            """
            {
              "id": "builtin-ssl-pinning",
              "name": "SSL Pinning & TLS Hooks",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects BoringSSL/OpenSSL certificate verification hooks and pinning strings.",
              "rules": [
                {
                  "name": "SSL_CTX_set_custom_verify",
                  "type": "symbol",
                  "pattern": "SSL_CTX_set_custom_verify",
                  "severity": "HIGH",
                  "description": "BoringSSL custom certificate verification callback",
                  "patch": { "mode": "quick", "value": "ret_void", "offset": 0 }
                },
                {
                  "name": "SSL_CTX_set_verify",
                  "type": "symbol",
                  "pattern": "SSL_CTX_set_verify",
                  "severity": "HIGH",
                  "description": "OpenSSL/Cronet/gRPC certificate verification setup"
                },
                {
                  "name": "SSL_get_verify_result",
                  "type": "symbol",
                  "pattern": "SSL_get_verify_result",
                  "severity": "HIGH",
                  "description": "OpenSSL/BoringSSL verification result check",
                  "patch": { "mode": "quick", "value": "ret_false", "offset": 0 }
                },
                {
                  "name": "X509_verify_cert",
                  "type": "symbol",
                  "pattern": "X509_verify_cert",
                  "severity": "MEDIUM",
                  "description": "X.509 certificate chain verification",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "Pinning String Indicator",
                  "type": "string",
                  "pattern": "sha256/",
                  "severity": "INFO",
                  "description": "Potential certificate pin hash string"
                },
                {
                  "name": "SSL_CTX_set_verify_callback",
                  "type": "symbol",
                  "pattern": "SSL_CTX_set_verify_callback",
                  "severity": "HIGH",
                  "description": "Companion verify callback setter (paired with custom_verify)"
                },
                {
                  "name": "SSL_get_peer_certificate",
                  "type": "symbol",
                  "pattern": "SSL_get_peer_certificate",
                  "severity": "MEDIUM",
                  "description": "Peer certificate retrieval, often near pin checks"
                },
                {
                  "name": "Cronet Verify Path",
                  "type": "string",
                  "pattern": "cronet",
                  "severity": "INFO",
                  "description": "Cronet TLS stack marker (higher-signal pinning context)"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-anti-tamper",
              "name": "Root, Frida & Anti-Debug",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Finds common root, Frida, Xposed, and ptrace anti-tamper indicators.",
              "rules": [
                {
                  "name": "ptrace Symbol",
                  "type": "symbol",
                  "pattern": "ptrace",
                  "severity": "HIGH",
                  "description": "Anti-debug ptrace call"
                },
                {
                  "name": "Frida String",
                  "type": "string",
                  "pattern": "frida",
                  "case_sensitive": true,
                  "severity": "HIGH",
                  "description": "Frida detection string (case-sensitive to avoid matching 'Friday')"
                },
                {
                  "name": "Frida Agent Artifact",
                  "type": "string",
                  "pattern": "frida-agent",
                  "severity": "HIGH",
                  "description": "Frida agent library loaded"
                },
                {
                  "name": "Frida Gadget Artifact",
                  "type": "string",
                  "pattern": "frida-gadget",
                  "severity": "HIGH",
                  "description": "Frida gadget library loaded"
                },
                {
                  "name": "Frida Server Artifact",
                  "type": "string",
                  "pattern": "frida-server",
                  "severity": "HIGH",
                  "description": "Frida server binary path"
                },
                {
                  "name": "Frida RPC Artifact",
                  "type": "string",
                  "pattern": "frida:rpc",
                  "severity": "HIGH",
                  "description": "Frida JS RPC channel"
                },
                {
                  "name": "Frida Java Bridge",
                  "type": "string",
                  "pattern": "re.frida.",
                  "severity": "MEDIUM",
                  "description": "Frida Java bridge class/package namespace"
                },
                {
                  "name": "Frida Thread (gum-js-loop)",
                  "type": "string",
                  "pattern": "gum-js-loop",
                  "severity": "HIGH",
                  "description": "Anti-Frida thread name scan"
                },
                {
                  "name": "Frida Thread (gmain)",
                  "type": "string",
                  "pattern": "gmain",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Anti-Frida GLib main thread scan (exact token)"
                },
                {
                  "name": "Frida Default Port (27042)",
                  "type": "string",
                  "pattern": "27042",
                  "match_mode": "word_boundary",
                  "severity": "INFO",
                  "description": "Frida server default TCP port (numeric token only; low signal)"
                },
                {
                  "name": "Magisk / Su String",
                  "type": "string",
                  "pattern": "/system/bin/su",
                  "severity": "MEDIUM",
                  "description": "Root binary path check"
                },
                {
                  "name": "TracerPid Check",
                  "type": "string",
                  "pattern": "TracerPid",
                  "severity": "MEDIUM",
                  "description": "/proc/self/status TracerPid anti-debug check"
                },
                {
                  "name": "proc self status",
                  "type": "string",
                  "pattern": "/proc/self/status",
                  "severity": "MEDIUM",
                  "description": "Reads process status (TracerPid/State) for anti-debug"
                },
                {
                  "name": "dlopen",
                  "type": "symbol",
                  "pattern": "dlopen",
                  "severity": "MEDIUM",
                  "description": "Dynamic library loader (runtime/decrypted loading = packing behavior)"
                },
                {
                  "name": "dlsym",
                  "type": "symbol",
                  "pattern": "dlsym",
                  "severity": "LOW",
                  "description": "Dynamic symbol resolver"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-jni-entrypoints",
              "name": "JNI & Native Entrypoints",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Locates JNI_OnLoad, RegisterNatives, and exported Java_* methods.",
              "rules": [
                {
                  "name": "JNI_OnLoad",
                  "type": "symbol",
                  "pattern": "JNI_OnLoad",
                  "severity": "INFO",
                  "description": "Native library initialization entrypoint"
                },
                {
                  "name": "Java_ Export",
                  "type": "symbol",
                  "pattern": "Java_",
                  "severity": "INFO",
                  "description": "Static JNI method export"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-liapp",
              "name": "LIAPP Protector",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects Lockin LIAPP loader entries, anti-dump watchers, and traces callers to decision points.",
              "script": "let strs = find_strings(\"libliapp.so\");\nfor st in strs {\n  report(\"LIAPP Identifier\", st.address, \"HIGH\", st.value);\n}\nlet is_liapp = strs.len() > 0 || find_symbols(\"inotify_rm_watch\").len() > 0;\nif is_liapp {\n  let inits = find_symbols(\"init_array_\");\n  for ini in inits {\n    report(\"LIAPP Loader Entry (\" + ini.name + \")\", ini.address, \"HIGH\", \"Constructor in .init_array (unpacks DEX & starts checks)\");\n  }\n  let apis = [\"inotify_rm_watch\", \"dl_iterate_phdr\", \"fork\", \"prctl\"];\n  for api in apis {\n    let syms = find_symbols(api);\n    for s in syms {\n      if s.name == api && s.address > 0 {\n        let xrefs = get_xrefs(s.address);\n        if xrefs.len() == 0 {\n          report(\"LIAPP Import: \" + api, s.address, \"MEDIUM\", \"PLT stub (called indirectly or via wrapper)\");\n        }\n        for x in xrefs {\n          report(\"LIAPP Calls \" + api, x.from, \"HIGH\", x.instruction);\n          if x.kind == \"Jump\" && x.from > 64 {\n            let win = disasm(x.from - 64, 64);\n            let wrap_start = -1;\n            let idx = 0;\n            while idx + 1 < win.len() {\n              let ins = win[idx];\n              let nxt = win[idx + 1];\n              let is_end = ins.mnemonic == \"b\" || ins.mnemonic == \"jmp\" || (ins.mnemonic == \"bx\" && ins.op_str == \"lr\") || (ins.mnemonic == \"ret\" && !nxt.op_str.contains(\"x30\") && !nxt.op_str.contains(\"lr\"));\n              if is_end {\n                wrap_start = nxt.address;\n              }\n              idx += 1;\n            }\n            if wrap_start > 0 {\n              let callers = get_xrefs(wrap_start);\n              for c in callers {\n                report(\"LIAPP Decision Site (\" + api + \")\", c.from, \"HIGH\", \"Calls wrapper \" + hex(wrap_start) + \" -> \" + c.instruction);\n              }\n            }\n          }\n        }\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-direct-syscalls",
              "name": "Direct Syscall Tracer",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Finds raw svc #0 / syscall instructions that bypass libc hooks and decodes the Linux syscall number.",
              "script": "let a = arch();\nlet pat = \"\";\nlet mnem = \"svc\";\nlet reg = \"w8\";\nif a == \"aarch64\" { pat = \"01 00 00 D4\"; mnem = \"svc\"; reg = \"w8\"; }\nelse if a == \"arm\" { pat = \"00 00 00 EF\"; mnem = \"svc\"; reg = \"r7\"; }\nelse if a == \"x86_64\" { pat = \"0F 05\"; mnem = \"syscall\"; reg = \"eax\"; }\nelse if a == \"x86\" { pat = \"CD 80\"; mnem = \"int\"; reg = \"eax\"; }\nif pat != \"\" {\n  let hits = find_bytes(pat);\n  for addr in hits {\n    let chk = disasm(addr, 4);\n    if chk.len() > 0 && chk[0].mnemonic == mnem && (a != \"x86\" || chk[0].op_str.contains(\"0x80\")) {\n      let nr = -1;\n      if addr > 24 {\n        let win = disasm(addr - 24, 24);\n        for ins in win {\n          if (ins.mnemonic == \"mov\" || ins.mnemonic == \"movz\") && (ins.op_str.starts_with(reg + \",\") || (a == \"aarch64\" && ins.op_str.starts_with(\"x8,\")) || (a == \"x86_64\" && ins.op_str.starts_with(\"rax,\"))) {\n            let parts = ins.op_str.split(\",\");\n            if parts.len() >= 2 {\n              let imm = parts[1];\n              imm.trim();\n              if imm.starts_with(\"#\") { imm = imm.sub_string(1); }\n              let is_hex = imm.starts_with(\"0x\") || imm.starts_with(\"0X\");\n              if is_hex { imm = imm.sub_string(2); }\n              let v = 0;\n              let ok = imm.len() > 0;\n              let base = if is_hex { 16 } else { 10 };\n              imm.to_lower();\n              let hex_digits = \"0123456789abcdef\";\n              for ch in imm.chars() {\n                let d = hex_digits.index_of(ch);\n                if d < 0 || (!is_hex && d >= 10) { ok = false; break; }\n                v = v * base + d;\n              }\n              if ok { nr = v; }\n            }\n          }\n        }\n      }\n      let name = \"\";\n      if a == \"aarch64\" {\n        if nr == 48 { name = \"faccessat\"; }\n        else if nr == 56 { name = \"openat\"; }\n        else if nr == 57 { name = \"close\"; }\n        else if nr == 63 { name = \"read\"; }\n        else if nr == 78 { name = \"readlinkat\"; }\n        else if nr == 79 { name = \"newfstatat\"; }\n        else if nr == 93 { name = \"exit\"; }\n        else if nr == 94 { name = \"exit_group\"; }\n        else if nr == 117 { name = \"ptrace\"; }\n        else if nr == 129 { name = \"kill\"; }\n        else if nr == 130 { name = \"tkill\"; }\n        else if nr == 131 { name = \"tgkill\"; }\n        else if nr == 167 { name = \"prctl\"; }\n        else if nr == 172 { name = \"getpid\"; }\n        else if nr == 174 { name = \"getuid\"; }\n        else if nr == 198 { name = \"socket\"; }\n        else if nr == 203 { name = \"connect\"; }\n        else if nr == 220 { name = \"clone\"; }\n        else if nr == 221 { name = \"execve\"; }\n        else if nr == 222 { name = \"mmap\"; }\n        else if nr == 226 { name = \"mprotect\"; }\n        else if nr == 279 { name = \"memfd_create\"; }\n      } else if a == \"x86_64\" {\n        if nr == 0 { name = \"read\"; }\n        else if nr == 3 { name = \"close\"; }\n        else if nr == 9 { name = \"mmap\"; }\n        else if nr == 10 { name = \"mprotect\"; }\n        else if nr == 39 { name = \"getpid\"; }\n        else if nr == 56 { name = \"clone\"; }\n        else if nr == 59 { name = \"execve\"; }\n        else if nr == 60 { name = \"exit\"; }\n        else if nr == 62 { name = \"kill\"; }\n        else if nr == 101 { name = \"ptrace\"; }\n        else if nr == 157 { name = \"prctl\"; }\n        else if nr == 231 { name = \"exit_group\"; }\n        else if nr == 257 { name = \"openat\"; }\n        else if nr == 269 { name = \"faccessat\"; }\n        else if nr == 319 { name = \"memfd_create\"; }\n      } else if a == \"arm\" || a == \"x86\" {\n        if nr == 1 { name = \"exit\"; }\n        else if nr == 3 { name = \"read\"; }\n        else if nr == 6 { name = \"close\"; }\n        else if nr == 11 { name = \"execve\"; }\n        else if nr == 20 { name = \"getpid\"; }\n        else if nr == 26 { name = \"ptrace\"; }\n        else if nr == 37 { name = \"kill\"; }\n        else if nr == 120 { name = \"clone\"; }\n        else if nr == 125 { name = \"mprotect\"; }\n        else if nr == 172 { name = \"prctl\"; }\n        else if nr == 192 { name = \"mmap2\"; }\n        else if nr == 248 { name = \"exit_group\"; }\n        else if nr == 322 { name = \"openat\"; }\n        else if nr == 334 { name = \"faccessat\"; }\n      }\n      let title = if name != \"\" { \"Direct Syscall: \" + name + \" (\" + nr + \")\" } else if nr >= 0 { \"Direct Syscall #\" + nr } else { \"Direct Syscall (\" + mnem + \")\" };\n      let sev = if name == \"ptrace\" || name == \"kill\" || name == \"tgkill\" || name == \"tkill\" || name == \"exit\" || name == \"exit_group\" || name == \"prctl\" { \"HIGH\" } else { \"MEDIUM\" };\n      if name == \"kill\" || name == \"tgkill\" || name == \"tkill\" || name == \"exit\" || name == \"exit_group\" {\n        report_patch(title, addr, sev, chk[0].mnemonic + \" \" + chk[0].op_str, \"quick\", \"nop\", 0);\n      } else {\n        report(title, addr, sev, chk[0].mnemonic + \" \" + chk[0].op_str);\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-packers",
              "name": "Packers & Protectors",
              "version": "1.1",
              "author": "ELFTrace",
              "description": "Detects DexProtector (DPLF & modern native VM), 360 Jiagu, Tencent Legu, Bangcle, and dynamic DEX loaders.",
              "script": "let dplf = find_bytes(\"44 50 4C 46\");\nfor addr in dplf {\n  report(\"DexProtector Payload (DPLF)\", addr, \"HIGH\", \"Embedded DPLF packed-library magic\");\n}\nlet str_sigs = [\n  [\"libjiagu\", \"360 Jiagu Indicator\", \"HIGH\", \"360 Jiagu packer library reference\"],\n  [\"libshell\", \"Tencent Legu Indicator\", \"HIGH\", \"Tencent Legu packer stub reference\"],\n  [\"libsecexe\", \"Bangcle / SecNeo Indicator\", \"HIGH\", \"Bangcle packer library reference\"],\n  [\"libDexHelper\", \"Alibaba DexHelper Indicator\", \"HIGH\", \"Alibaba DexHelper packer library reference\"],\n  [\"libmobisec\", \"Alibaba MobiSec Indicator\", \"HIGH\", \"Alibaba MobiSec protector library reference\"],\n  [\"libnesec\", \"NetEase Sec Indicator\", \"HIGH\", \"NetEase (libnesec) protector library reference\"],\n  [\"libbaiduprotect\", \"Baidu Protect Indicator\", \"HIGH\", \"Baidu protect packer library reference\"],\n  [\"DexClassLoader\", \"ART DexClassLoader\", \"MEDIUM\", \"Dynamic DEX loading / unpacking indicator\"]\n];\nlet pairip_vm = find_symbols(\"ExecuteProgram\");\nfor s in pairip_vm {\n  if s.name == \"ExecuteProgram\" && s.address > 0 {\n    report(\"PairIP VM Entrypoint (ExecuteProgram)\", s.address, \"HIGH\", \"PairIP bytecode VM interpreter called by VMRunner\");\n  }\n}\nfor sig in str_sigs {\n  let hits = find_strings(sig[0]);\n  for h in hits {\n    report(sig[1], h.address, sig[2], h.value + \" (\" + sig[3] + \")\");\n  }\n}\nlet jni = find_symbols(\"JNI_OnLoad\");\nfor s in jni {\n  let insns = disasm(s.address, 24);\n  if insns.len() >= 3 && insns[0].mnemonic == \"adr\" && insns[2].mnemonic == \"br\" {\n    report(\"DexProtector Obfuscated JNI_OnLoad\", s.address, \"HIGH\", \"Indirect branch trampoline (\" + insns[0].op_str + \" -> br)\");\n  }\n}\nlet has_aux = find_symbols(\"getauxval\").len() > 0;\nlet has_fork = find_symbols(\"__register_atfork\").len() > 0;\nlet sys_syms = find_symbols(\"syscall\");\nif has_aux && has_fork && sys_syms.len() > 0 {\n  for s in sys_syms {\n    if s.name == \"syscall\" && s.address > 0 {\n      report(\"DexProtector / RASP Syscall Import\", s.address, \"HIGH\", \"Combined getauxval + __register_atfork + syscall anti-tamper profile\");\n      let xrefs = get_xrefs(s.address);\n      for x in xrefs {\n        report(\"Direct syscall() Call Site\", x.from, \"HIGH\", x.instruction);\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-flutter-rn",
              "name": "Flutter & React Native",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects Flutter SSL pinning, Dart AOT snapshots (libapp.so), and React Native Hermes/JSI.",
              "rules": [
                {
                  "name": "Flutter SSL Verify",
                  "type": "symbol",
                  "pattern": "ssl_crypto_x509_session_verify_cert_chain",
                  "severity": "HIGH",
                  "description": "Flutter BoringSSL certificate chain verification (libflutter.so)",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "Dart Isolate Instructions",
                  "type": "symbol",
                  "pattern": "_kDartIsolateSnapshotInstructions",
                  "severity": "INFO",
                  "description": "Dart AOT compiled code entry in libapp.so"
                },
                {
                  "name": "Dart VM Snapshot Data",
                  "type": "symbol",
                  "pattern": "_kDartVmSnapshotData",
                  "severity": "INFO",
                  "description": "Dart VM snapshot metadata in libapp.so"
                },
                {
                  "name": "Hermes Runtime",
                  "type": "symbol",
                  "pattern": "hermes",
                  "severity": "INFO",
                  "description": "React Native Hermes JS engine symbol"
                },
                {
                  "name": "React Native JSI",
                  "type": "symbol",
                  "pattern": "facebook::jsi",
                  "severity": "INFO",
                  "description": "React Native JavaScript Interface (JSI) bridge"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-il2cpp-game",
              "name": "Unity Il2Cpp & Game Engine",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects Unity Il2Cpp runtime exports and Unreal Engine (UE4/UE5) symbols.",
              "rules": [
                {
                  "name": "il2cpp_init",
                  "type": "symbol",
                  "pattern": "il2cpp_init",
                  "severity": "INFO",
                  "description": "Unity Il2Cpp runtime initialization"
                },
                {
                  "name": "il2cpp_runtime_invoke",
                  "type": "symbol",
                  "pattern": "il2cpp_runtime_invoke",
                  "severity": "INFO",
                  "description": "Unity Il2Cpp managed method invoker"
                },
                {
                  "name": "il2cpp_string_new",
                  "type": "symbol",
                  "pattern": "il2cpp_string_new",
                  "severity": "INFO",
                  "description": "Unity Il2Cpp string allocator"
                },
                {
                  "name": "il2cpp_domain_get",
                  "type": "symbol",
                  "pattern": "il2cpp_domain_get",
                  "severity": "INFO",
                  "description": "Unity Il2Cpp domain access (common modding hook)"
                },
                {
                  "name": "il2cpp_class_from_name",
                  "type": "symbol",
                  "pattern": "il2cpp_class_from_name",
                  "severity": "INFO",
                  "description": "Unity Il2Cpp class resolution by name (modding hook)"
                },
                {
                  "name": "il2cpp_resolve_icall",
                  "type": "symbol",
                  "pattern": "il2cpp_resolve_icall",
                  "severity": "INFO",
                  "description": "Unity Il2Cpp internal-call resolution path"
                },
                {
                  "name": "Unreal GWorld / GUObjectArray",
                  "type": "string",
                  "pattern": "GUObjectArray",
                  "severity": "INFO",
                  "description": "Unreal Engine global object array indicator"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-crypto-keys",
              "name": "Crypto & Key Material",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Locates embedded key material and hardcoded crypto tables (AES S-box, SHA-256/MD5 constants).",
              "rules": [
                {
                  "name": "PEM Public Key",
                  "type": "string",
                  "pattern": "-----BEGIN PUBLIC KEY-----",
                  "severity": "HIGH",
                  "description": "Embedded PEM public key"
                },
                {
                  "name": "PEM RSA Key",
                  "type": "string",
                  "pattern": "-----BEGIN RSA",
                  "severity": "HIGH",
                  "description": "Embedded RSA key material"
                },
                {
                  "name": "AES S-Box Table",
                  "type": "byte_pattern",
                  "pattern": "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76",
                  "severity": "MEDIUM",
                  "description": "Standard AES-128/256 substitution table"
                },
                {
                  "name": "AES Inverse S-Box Table",
                  "type": "byte_pattern",
                  "pattern": "52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB",
                  "severity": "MEDIUM",
                  "description": "Standard AES decryption table"
                },
                {
                  "name": "SHA-256 Round Constants",
                  "type": "byte_pattern",
                  "pattern": "98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9",
                  "severity": "LOW",
                  "description": "Standard SHA-256 hashing constants"
                },
                {
                  "name": "MD5 Init Constants",
                  "type": "byte_pattern",
                  "pattern": "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10",
                  "severity": "LOW",
                  "description": "Standard MD5 initialization vector"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-iap-license",
              "name": "License, IAP & Premium Checks",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Locates common entitlement, subscription, and license verification symbols.",
              "rules": [
                {
                  "name": "isPremium / isPro",
                  "type": "symbol",
                  "pattern": "isPremium",
                  "severity": "HIGH",
                  "description": "Premium entitlement check",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "isSubscribed",
                  "type": "symbol",
                  "pattern": "isSubscribed",
                  "severity": "HIGH",
                  "description": "Subscription status check",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "checkLicense",
                  "type": "symbol",
                  "pattern": "checkLicense",
                  "severity": "HIGH",
                  "description": "License verification routine",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "verifyPurchase",
                  "type": "symbol",
                  "pattern": "verifyPurchase",
                  "severity": "HIGH",
                  "description": "In-app purchase verification",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-integrity-tamper",
              "name": "Integrity, Signature & Emulator",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects APK signature checks, /proc/self/maps memory integrity, and emulator/hook checks.",
              "rules": [
                {
                  "name": "checkSignature",
                  "type": "symbol",
                  "pattern": "checkSignature",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Potential APK/binary signature check routine (inspect before patching)"
                },
                {
                  "name": "verifySignature",
                  "type": "symbol",
                  "pattern": "verifySignature",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Potential APK/binary signature verification routine (inspect before patching)"
                },
                {
                  "name": "Tamper Check Symbol",
                  "type": "symbol",
                  "pattern": "Tamper",
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Potential anti-tamper check function (inspect before patching)"
                },
                {
                  "name": "/proc/self/maps Scan",
                  "type": "string",
                  "pattern": "/proc/self/maps",
                  "severity": "MEDIUM",
                  "description": "Memory map inspection (Frida/Xposed/hook detection)"
                },
                {
                  "name": "classes.dex Integrity",
                  "type": "string",
                  "pattern": "classes.dex",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "INFO",
                  "description": "DEX file reference (common; not proof of an integrity check)"
                },
                {
                  "name": "JNI getPackageManager",
                  "type": "string",
                  "pattern": "getPackageManager",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Native JNI reference to PackageManager (often benign; check context)"
                },
                {
                  "name": "JNI getPackageInfo",
                  "type": "string",
                  "pattern": "getPackageInfo",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Native JNI reference to getPackageInfo (often benign; check context)"
                },
                {
                  "name": "JNI Signature toByteArray",
                  "type": "string",
                  "pattern": "toByteArray",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "INFO",
                  "description": "toByteArray reference (ubiquitous; not proof of signature hashing)"
                },
                {
                  "name": "JNI MessageDigest",
                  "type": "string",
                  "pattern": "MessageDigest",
                  "case_sensitive": true,
                  "match_mode": "word_boundary",
                  "severity": "INFO",
                  "description": "MessageDigest reference (common; hashing, not necessarily signature)"
                },
                {
                  "name": "CRC32 Routine",
                  "type": "symbol",
                  "pattern": "crc32",
                  "match_mode": "word_boundary",
                  "severity": "INFO",
                  "description": "CRC32 routine (common; possible integrity check)"
                },
                {
                  "name": "Xposed / Substrate Indicator",
                  "type": "string",
                  "pattern": "xposed",
                  "severity": "MEDIUM",
                  "description": "Xposed framework detection string"
                },
                {
                  "name": "QEMU / Emulator Check",
                  "type": "string",
                  "pattern": "ro.kernel.qemu",
                  "severity": "LOW",
                  "description": "Android emulator property check"
                },
                {
                  "name": "SafetyNet Attest Symbol",
                  "type": "symbol",
                  "pattern": "SafetyNet",
                  "severity": "MEDIUM",
                  "description": "SafetyNet attestation API reference"
                },
                {
                  "name": "Play Integrity Symbol",
                  "type": "symbol",
                  "pattern": "IntegrityToken",
                  "severity": "MEDIUM",
                  "description": "Play Integrity token request reference"
                },
                {
                  "name": "attest Symbol",
                  "type": "symbol",
                  "pattern": "attest",
                  "match_mode": "word_boundary",
                  "severity": "MEDIUM",
                  "description": "Attestation routine (SafetyNet/Play Integrity native path)"
                },
                {
                  "name": "__system_property_get",
                  "type": "symbol",
                  "pattern": "__system_property_get",
                  "severity": "LOW",
                  "description": "Property read (root/emulator property checks)"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-secrets",
              "name": "Rhai: Hardcoded Secrets & Tokens",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Rhai script scanning strings for API keys, bearer tokens, and private keys.",
              "script": "let exact = [\"sk_live_\", \"sk_test_\", \"AKIA\", \"AIza\", \"-----BEGIN\", \"Bearer \"];\nfor k in exact {\n  let hits = find_strings(k);\n  for h in hits {\n    if h.value.contains(k) {\n      report(\"Secret: \" + k, h.address, \"HIGH\", h.value);\n    }\n  }\n}\nlet loose = [\"api_key\", \"apikey\", \"secret\"];\nfor k in loose {\n  let hits = find_strings(k);\n  for h in hits {\n    if h.value.len() <= 96 {\n      report(\"Possible Secret: \" + k, h.address, \"MEDIUM\", h.value);\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-jni-table",
              "name": "Rhai: JNI Method Table",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Scans .data/.data.rel.ro for hidden RegisterNatives (name, sig, fnPtr) triplets.",
              "script": "let methods = find_jni_methods();\nfor m in methods {\n  report(\"JNI: \" + m.name, m.address, \"HIGH\", m.signature);\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-register-natives",
              "name": "Rhai: RegisterNatives Finder",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Locates JNI RegisterNatives vtable calls (0x6b8/0x35c), indirect blr sites in JNI_OnLoad, and RegisterNatives strings.",
              "script": "let jni = find_symbols(\"JNI_OnLoad\");\nfor s in jni {\n  let insns = disasm(s.address, 512);\n  for ins in insns {\n    if ins.op_str.contains(\"0x6b8\") || ins.op_str.contains(\"0x35c\") {\n      report(\"RegisterNatives VTable\", ins.address, \"HIGH\", ins.mnemonic + \" \" + ins.op_str);\n    }\n  }\n}\nlet strs = find_strings(\"RegisterNatives\");\nfor st in strs {\n  report(\"RegisterNatives String\", st.address, \"INFO\", st.value);\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-jni-inspector",
              "name": "Rhai: JNI_OnLoad Calls",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Rhai script that disassembles JNI_OnLoad and lists its outgoing branch/call targets.",
              "script": "let syms = find_symbols(\"JNI_OnLoad\");\nfor s in syms {\n  report(\"JNI_OnLoad Entry\", s.address, \"INFO\", \"Size: \" + s.size + \" bytes\");\n  let insns = disasm(s.address, 128);\n  for ins in insns {\n    if ins.mnemonic == \"bl\" || ins.mnemonic == \"blr\" || ins.mnemonic == \"call\" {\n      report(\"JNI_OnLoad Call\", ins.address, \"INFO\", ins.mnemonic + \" \" + ins.op_str);\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-watchdog",
              "name": "Rhai: Watchdog & Abort",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Traces pthread_create watchdog spawns and abort/kill/raise termination call sites.",
              "script": "let a = arch();\nlet targets = [\"pthread_create\", \"abort\", \"kill\", \"raise\", \"_exit\", \"exit\"];\nfor t in targets {\n  let syms = find_symbols(t);\n  for s in syms {\n    if s.name == t || s.name.ends_with(\"::\" + t) {\n      let xrefs = get_xrefs(s.address);\n      for x in xrefs {\n        let sev = if t == \"pthread_create\" { \"INFO\" } else { \"HIGH\" };\n        let desc = if x.caller != \"\" { x.caller + \" -> \" + x.instruction } else { x.instruction };\n        let can_nop = false;\n        if t == \"kill\" || t == \"raise\" || t == \"_exit\" || t == \"exit\" {\n          let after = disasm(x.from + 4, 44);\n          for ins in after {\n            if ins.mnemonic == \"ret\" || ins.mnemonic == \"b\" || ins.mnemonic == \"jmp\" || (ins.mnemonic == \"bx\" && ins.op_str == \"lr\") || (ins.mnemonic == \"pop\" && ins.op_str.contains(\"pc\")) {\n              can_nop = true;\n              break;\n            }\n            if (ins.mnemonic == \"stp\" && ins.op_str.contains(\"x29\")) || (ins.mnemonic == \"push\" && (ins.op_str == \"rbp\" || ins.op_str == \"ebp\" || ins.op_str.contains(\"lr\"))) {\n              break;\n            }\n          }\n        }\n        if can_nop {\n          report_patch(\"Calls \" + t, x.from, sev, desc, \"quick\", \"nop\");\n        } else {\n          report(\"Calls \" + t, x.from, sev, desc);\n        }\n        if t == \"pthread_create\" && x.from > 48 {\n          let win = disasm(x.from - 48, 48);\n          let adrp_x2 = -1;\n          let pc_deltas = #{};\n          for ins in win {\n            if a == \"aarch64\" && ins.mnemonic == \"adrp\" && ins.op_str.starts_with(\"x2,\") {\n              adrp_x2 = parse_addr(ins.op_str);\n            } else if a == \"aarch64\" && adrp_x2 > 0 && ins.mnemonic == \"add\" && ins.op_str.starts_with(\"x2, x2,\") {\n              let off = parse_addr(ins.op_str);\n              if off >= 0 {\n                report_patch(\"Watchdog Thread Entry\", adrp_x2 + off, \"HIGH\", \"Thread start_routine (adrp+add) passed to pthread_create at \" + hex(x.from), \"quick\", \"ret_void\");\n              }\n              adrp_x2 = -1;\n            } else if a == \"arm\" && ins.mnemonic.starts_with(\"ldr\") && ins.op_str.contains(\"[pc,\") {\n              let parts = ins.op_str.split(\",\");\n              let reg = parts[0];\n              reg.trim();\n              let off = parse_addr(ins.op_str);\n              if off >= 0 {\n                let pc_base = if ins.thumb { (ins.address + 4) & -4 } else { ins.address + 8 };\n                let val = read_u32(pc_base + off);\n                if val >= 0 {\n                  pc_deltas[reg] = if val > 2147483647 { val - 4294967296 } else { val };\n                }\n              }\n            } else if a == \"arm\" && ins.mnemonic == \"add\" && ins.op_str.starts_with(\"r2, pc\") {\n              let parts = ins.op_str.split(\",\");\n              let src_reg = if parts.len() >= 3 { parts[2] } else { \"r2\" };\n              src_reg.trim();\n              if pc_deltas.contains(src_reg) {\n                let pc_val = if ins.thumb { ins.address + 4 } else { ins.address + 8 };\n                let fn_addr = pc_val + pc_deltas[src_reg];\n                if fn_addr > 0 {\n                  report_patch(\"Watchdog Thread Entry\", fn_addr, \"HIGH\", \"Thread start_routine (PIC) passed to pthread_create at \" + hex(x.from), \"quick\", \"ret_void\");\n                }\n              }\n            } else {\n              let is_entry = (a == \"aarch64\" && ins.mnemonic == \"adr\" && ins.op_str.starts_with(\"x2,\")) || (a == \"x86_64\" && ins.mnemonic == \"lea\" && ins.op_str.starts_with(\"rdx,\")) || (a == \"arm\" && (ins.mnemonic == \"adr\" || ins.mnemonic == \"add\") && ins.op_str.starts_with(\"r2,\"));\n              if is_entry {\n                let fn_addr = parse_addr(ins.op_str);\n                if fn_addr > 0 {\n                  report_patch(\"Watchdog Thread Entry\", fn_addr, \"HIGH\", \"Thread start_routine passed to pthread_create at \" + hex(x.from), \"quick\", \"ret_void\");\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-xref-tracer",
              "name": "Rhai: Anti-Debug XRefs",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Rhai script that traces callers of ptrace/kill/exit and suggests NOP patches.",
              "script": "let targets = [\"ptrace\", \"prctl\"];\nfor t in targets {\n  let syms = find_symbols(t);\n  for s in syms {\n    if s.name == t || s.name.ends_with(\"::\" + t) {\n      let xrefs = get_xrefs(s.address);\n      for x in xrefs {\n        report_patch(\"Caller of \" + s.name, x.from, \"HIGH\", \"Calls \" + s.name + \" via \" + x.instruction, \"quick\", \"nop\");\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-play-integrity",
              "name": "Play Integrity & Pairip",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects Google Play Integrity API and Pairip (AIP) native markers. Pairip indicates native VM code protection; the API alone only attests app/environment integrity.",
              "rules": [
                {
                  "name": "AIP / Pairip native marker",
                  "type": "string",
                  "pattern": "pairip",
                  "severity": "HIGH",
                  "description": "Google Automatic Integrity Protection (Pairip) native VM / core library (libpairipcore.so). NOT the developer Play Integrity API (com.google.android.play.core.integrity)."
                },
                {
                  "name": "Play Integrity API namespace",
                  "type": "string",
                  "pattern": "com/google/android/play/core/integrity",
                  "severity": "MEDIUM",
                  "description": "Play Integrity API library namespace present in the native blob (embedded DEX/path reference)."
                },
                {
                  "name": "Play Integrity Classic hint (nonce)",
                  "type": "string",
                  "pattern": "setNonce",
                  "severity": "INFO",
                  "description": "Classic request hint: setNonce() reference. Static hint only — obfuscation can hide it."
                },
                {
                  "name": "Play Integrity Standard hint (requestHash)",
                  "type": "string",
                  "pattern": "requestHash",
                  "severity": "INFO",
                  "description": "Standard request hint: requestHash reference. Static hint only — obfuscation can hide it."
                },
                {
                  "name": "StandardIntegrityManager",
                  "type": "string",
                  "pattern": "StandardIntegrityManager",
                  "severity": "INFO",
                  "description": "Standard request path class reference (likely Standard). Static hint only."
                },
                {
                  "name": "IntegrityManager (classic)",
                  "type": "string",
                  "pattern": "requestIntegrityToken",
                  "severity": "INFO",
                  "description": "Classic request path method reference (likely Classic). Static hint only."
                }
              ]
            }
            """.trimIndent()
        )
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
            if (res.success && _currentAddress.value != 0L) {
                _instructions.value = b.disassemble(_currentAddress.value, 256)
                _decompileText.value = b.decompile(_currentAddress.value)
                _flowchartText.value = b.getFlowchartText(_currentAddress.value)
            }
            launch(Dispatchers.Main) { onComplete(res) }
        }
    }
}
