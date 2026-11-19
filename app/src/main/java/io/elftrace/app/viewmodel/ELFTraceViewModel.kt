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

    // ==========================================
    // Plugins (JSON Signature & Patch Recipes)
    // ==========================================

    private val gson = com.google.gson.Gson()

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
                  "description": "OpenSSL/Cronet/gRPC certificate verification setup",
                  "patch": { "mode": "quick", "value": "ret_void", "offset": 0 }
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
                  "severity": "HIGH",
                  "description": "Frida detection string"
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
                  "severity": "MEDIUM",
                  "description": "Anti-Frida GLib main thread scan"
                },
                {
                  "name": "Frida Default Port (27042)",
                  "type": "string",
                  "pattern": "27042",
                  "severity": "MEDIUM",
                  "description": "Frida server default TCP port check"
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
              "id": "builtin-packers",
              "name": "Packers & Protectors",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects DexProtector, 360 Jiagu, Tencent Legu, Bangcle, and dynamic DEX loaders.",
              "rules": [
                {
                  "name": "DexProtector Payload (DPLF)",
                  "type": "byte_pattern",
                  "pattern": "44 50 4C 46",
                  "severity": "HIGH",
                  "description": "DexProtector embedded DPLF packed-library magic"
                },
                {
                  "name": "360 Jiagu Indicator",
                  "type": "string",
                  "pattern": "libjiagu",
                  "severity": "HIGH",
                  "description": "360 Jiagu packer library reference"
                },
                {
                  "name": "Tencent Legu Indicator",
                  "type": "string",
                  "pattern": "libshell",
                  "severity": "HIGH",
                  "description": "Tencent Legu packer stub reference"
                },
                {
                  "name": "Bangcle / SecNeo Indicator",
                  "type": "string",
                  "pattern": "libsecexe",
                  "severity": "HIGH",
                  "description": "Bangcle packer library reference"
                },
                {
                  "name": "ART DefineClass / DexClassLoader",
                  "type": "string",
                  "pattern": "DexClassLoader",
                  "severity": "MEDIUM",
                  "description": "Dynamic DEX loading / unpacking indicator"
                }
              ]
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
              "description": "Finds OpenSSL/BoringSSL/mbedTLS cipher routines and embedded PEM keys.",
              "rules": [
                {
                  "name": "AES_set_encrypt_key",
                  "type": "symbol",
                  "pattern": "AES_set_encrypt_key",
                  "severity": "MEDIUM",
                  "description": "AES key schedule setup"
                },
                {
                  "name": "EVP_DecryptInit",
                  "type": "symbol",
                  "pattern": "EVP_DecryptInit",
                  "severity": "MEDIUM",
                  "description": "OpenSSL EVP decryption initialization"
                },
                {
                  "name": "mbedtls_aes",
                  "type": "symbol",
                  "pattern": "mbedtls_aes",
                  "severity": "MEDIUM",
                  "description": "mbedTLS AES routine"
                },
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
                  "severity": "HIGH",
                  "description": "Potential APK/binary signature check routine",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "verifySignature",
                  "type": "symbol",
                  "pattern": "verifySignature",
                  "severity": "HIGH",
                  "description": "Potential APK/binary signature verification routine",
                  "patch": { "mode": "quick", "value": "ret_true", "offset": 0 }
                },
                {
                  "name": "Tamper Check Symbol",
                  "type": "symbol",
                  "pattern": "Tamper",
                  "severity": "HIGH",
                  "description": "Potential anti-tamper check function",
                  "patch": { "mode": "quick", "value": "ret_false", "offset": 0 }
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
                  "severity": "MEDIUM",
                  "description": "DEX file integrity or CRC verification reference"
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
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-network-endpoints",
              "name": "Network, URLs & Sockets",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Surfaces hardcoded HTTP/HTTPS/WebSocket URLs and raw socket/TLS calls.",
              "rules": [
                {
                  "name": "HTTPS URL",
                  "type": "string",
                  "pattern": "https://",
                  "severity": "INFO",
                  "description": "Hardcoded HTTPS endpoint"
                },
                {
                  "name": "HTTP URL (Cleartext)",
                  "type": "string",
                  "pattern": "http://",
                  "severity": "MEDIUM",
                  "description": "Hardcoded cleartext HTTP endpoint"
                },
                {
                  "name": "WebSocket URL",
                  "type": "string",
                  "pattern": "wss://",
                  "severity": "INFO",
                  "description": "Hardcoded WebSocket endpoint"
                },
                {
                  "name": "Raw Socket Connect",
                  "type": "symbol",
                  "pattern": "connect",
                  "severity": "INFO",
                  "description": "POSIX socket connect() symbol"
                },
                {
                  "name": "SSL_write",
                  "type": "symbol",
                  "pattern": "SSL_write",
                  "severity": "INFO",
                  "description": "OpenSSL/BoringSSL encrypted write"
                }
              ]
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-dynamic-loading",
              "name": "Dynamic Loading & JNI Reflection",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Finds dlopen/dlsym dynamic loading and native-to-Java reflection calls.",
              "rules": [
                {
                  "name": "dlopen",
                  "type": "symbol",
                  "pattern": "dlopen",
                  "severity": "MEDIUM",
                  "description": "Dynamic shared library loader"
                },
                {
                  "name": "dlsym",
                  "type": "symbol",
                  "pattern": "dlsym",
                  "severity": "MEDIUM",
                  "description": "Dynamic symbol resolver"
                },
                {
                  "name": "RegisterNatives",
                  "type": "string",
                  "pattern": "RegisterNatives",
                  "severity": "INFO",
                  "description": "Dynamic JNI method registration indicator"
                },
                {
                  "name": "FindClass",
                  "type": "string",
                  "pattern": "FindClass",
                  "severity": "INFO",
                  "description": "JNI Java class lookup"
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
              "script": "let keys = [\"api_key\", \"apikey\", \"secret\", \"Bearer \", \"AIza\", \"-----BEGIN\"];\nfor k in keys {\n  let hits = find_strings(k);\n  for h in hits {\n    report(\"Secret Indicator: \" + k, h.address, \"HIGH\", h.value);\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-raw-syscalls",
              "name": "Raw Syscalls (svc #0)",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Detects aligned svc #0 syscalls in executable code used to bypass libc/Frida hooks.",
              "script": "let a = arch();\nlet pat = if a == \"aarch64\" { \"01 00 00 D4\" } else if a == \"arm\" { \"00 00 00 EF\" } else if a == \"x86_64\" { \"0F 05\" } else if a == \"x86\" { \"CD 80\" } else { \"\" };\nlet target_mnem = if a == \"x86_64\" { \"syscall\" } else if a == \"x86\" { \"int\" } else { \"svc\" };\nlet align = if a == \"aarch64\" || a == \"arm\" { 4 } else { 1 };\nif pat != \"\" {\n  let hits = find_bytes(pat);\n  for addr in hits {\n    if (addr % align) == 0 {\n      let ins = disasm(addr, 4);\n      if ins.len() > 0 && ins[0].mnemonic == target_mnem {\n        report(target_mnem + \" (\" + a + \")\", addr, \"HIGH\", \"Direct supervisor/syscall (bypasses libc hooks)\");\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-jni-table",
              "name": "Rhai: JNINativeMethod Table Recovery",
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
              "script": "let jni = find_symbols(\"JNI_OnLoad\");\nfor s in jni {\n  let insns = disasm(s.address, 512);\n  for ins in insns {\n    if ins.op_str.contains(\"0x6b8\") || ins.op_str.contains(\"0x35c\") {\n      report(\"RegisterNatives VTable\", ins.address, \"HIGH\", ins.mnemonic + \" \" + ins.op_str);\n    } else if ins.mnemonic == \"blr\" || ins.mnemonic == \"blx\" || (ins.mnemonic == \"call\" && !ins.op_str.starts_with(\"0x\")) {\n      report(\"JNI Indirect Call (\" + ins.mnemonic + \")\", ins.address, \"MEDIUM\", ins.mnemonic + \" \" + ins.op_str);\n    }\n  }\n}\nlet strs = find_strings(\"RegisterNatives\");\nfor st in strs {\n  report(\"RegisterNatives String\", st.address, \"INFO\", st.value);\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-jni-inspector",
              "name": "Rhai: JNI_OnLoad Call Inspector",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Rhai script that disassembles JNI_OnLoad and lists its outgoing branch/call targets.",
              "script": "let syms = find_symbols(\"JNI_OnLoad\");\nfor s in syms {\n  report(\"JNI_OnLoad Entry\", s.address, \"INFO\", \"Size: \" + s.size + \" bytes\");\n  let insns = disasm(s.address, 128);\n  for ins in insns {\n    if ins.mnemonic == \"bl\" || ins.mnemonic == \"blr\" || ins.mnemonic == \"call\" {\n      report(\"JNI_OnLoad Call\", ins.address, \"INFO\", ins.mnemonic + \" \" + ins.op_str);\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-watchdog",
              "name": "Rhai: Watchdog Thread & Abort Tracer",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Traces pthread_create watchdog spawns and abort/kill/raise termination call sites.",
              "script": "let a = arch();\nlet targets = [\"pthread_create\", \"abort\", \"kill\", \"raise\", \"_exit\", \"exit\"];\nfor t in targets {\n  let syms = find_symbols(t);\n  for s in syms {\n    if s.name == t || s.name.ends_with(\"::\" + t) {\n      let xrefs = get_xrefs(s.address);\n      for x in xrefs {\n        let sev = if t == \"pthread_create\" { \"MEDIUM\" } else { \"HIGH\" };\n        let desc = if x.caller != \"\" { x.caller + \" -> \" + x.instruction } else { x.instruction };\n        let can_nop = false;\n        if t == \"kill\" || t == \"raise\" || t == \"_exit\" || t == \"exit\" {\n          let after = disasm(x.from + 4, 44);\n          for ins in after {\n            if ins.mnemonic == \"ret\" || ins.mnemonic == \"b\" {\n              can_nop = true;\n              break;\n            }\n            if ins.mnemonic == \"stp\" && ins.op_str.contains(\"x29\") {\n              break;\n            }\n          }\n        }\n        if can_nop {\n          report_patch(\"Calls \" + t, x.from, sev, desc, \"quick\", \"nop\");\n        } else {\n          report(\"Calls \" + t, x.from, sev, desc);\n        }\n        if t == \"pthread_create\" && x.from > 32 {\n          let win = disasm(x.from - 32, 32);\n          for ins in win {\n            let is_entry = (a == \"aarch64\" && ins.mnemonic == \"adr\" && ins.op_str.starts_with(\"x2,\")) || (a == \"x86_64\" && ins.mnemonic == \"lea\" && ins.op_str.starts_with(\"rdx,\")) || (a == \"arm\" && (ins.mnemonic == \"adr\" || ins.mnemonic == \"add\") && ins.op_str.starts_with(\"r2,\"));\n            if is_entry {\n              let fn_addr = parse_addr(ins.op_str);\n              if fn_addr > 0 {\n                report_patch(\"Watchdog Thread Entry\", fn_addr, \"HIGH\", \"Thread start_routine passed to pthread_create at \" + hex(x.from), \"quick\", \"ret_void\");\n              }\n            }\n          }\n        }\n      }\n    }\n  }\n}"
            }
            """.trimIndent(),
            """
            {
              "id": "builtin-rhai-xref-tracer",
              "name": "Rhai: Anti-Debug XRef Tracer",
              "version": "1.0",
              "author": "ELFTrace",
              "description": "Rhai script that traces callers of ptrace/kill/exit and suggests NOP patches.",
              "script": "let targets = [\"ptrace\", \"prctl\"];\nfor t in targets {\n  let syms = find_symbols(t);\n  for s in syms {\n    if s.name == t || s.name.ends_with(\"::\" + t) {\n      let xrefs = get_xrefs(s.address);\n      for x in xrefs {\n        report_patch(\"Caller of \" + s.name, x.from, \"HIGH\", \"Calls \" + s.name + \" via \" + x.instruction, \"quick\", \"nop\");\n      }\n    }\n  }\n}"
            }
            """.trimIndent()
        )
        return builtInJsons.mapNotNull { raw ->
            try {
                val manifest = gson.fromJson(raw, PluginManifest::class.java)
                LoadedPlugin(manifest = manifest, rawJson = raw, enabled = true, isBuiltIn = true)
            } catch (_: Exception) {
                null
            }
        }
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
