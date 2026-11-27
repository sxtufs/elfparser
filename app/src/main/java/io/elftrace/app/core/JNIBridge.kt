package io.elftrace.app.core

import io.elftrace.app.core.models.*
import com.google.gson.Gson

class JNIBridge private constructor(val handle: Long, val path: String) : java.io.Closeable {

    private val gson = Gson()
    private var isClosed = false

    companion object {
        init {
            System.loadLibrary("elftrace")
        }

        fun open(path: String): JNIBridge? {
            val handle = init0(path)
            return if (handle != 0L) JNIBridge(handle, path) else null
        }

        // In-app MCP server: the same HTTP transport the desktop binary serves,
        // started and stopped from the UI. Returns JSON.
        @JvmStatic private external fun startMcp0(addr: String, token: String): String
        @JvmStatic private external fun stopMcp0(): Boolean
        @JvmStatic private external fun mcpStatus0(): String

        fun startMcp(addr: String, token: String): String = startMcp0(addr, token)
        fun stopMcp(): Boolean = stopMcp0()
        fun mcpStatus(): String = mcpStatus0()

        @JvmStatic private external fun init0(path: String): Long
        @JvmStatic private external fun finalize0(handle: Long)
        @JvmStatic private external fun info0(handle: Long, flag: Boolean): String
        @JvmStatic private external fun disasm0(handle: Long, address: Long, size: Long, thumb: Boolean): String
        @JvmStatic private external fun dec0(mode: Int, handle: Long, address: Long): String
        @JvmStatic private external fun strings0(handle: Long): String
        @JvmStatic private external fun write0(handle: Long, address: Long, bytes: ByteArray): Boolean
        @JvmStatic private external fun save0(handle: Long): ByteArray
        @JvmStatic private external fun readBytes0(handle: Long, address: Long, length: Int): ByteArray

        // Native Cross-References (XREF) & Call Hierarchy
        @JvmStatic private external fun getXrefs(handle: Long, address: Long): String
        @JvmStatic private external fun getHierarchy(handle: Long, address: Long): String

        // Quick Patcher & Security Scanner
        @JvmStatic private external fun quickPatch(handle: Long, address: Long, patchType: Int, thumb: Boolean): String
        @JvmStatic private external fun scanSecurity(handle: Long): String
        @JvmStatic private external fun getEntropyReport(handle: Long): String
        @JvmStatic private external fun getBinaryFacts(handle: Long): String

        // Unity Il2Cpp Metadata Resolvers
        @JvmStatic private external fun loadScriptJson(handle: Long, path: String): Int
        @JvmStatic private external fun loadGlobalMetadata(handle: Long, path: String): Int

        // Function Renaming
        @JvmStatic private external fun renameFunction(handle: Long, address: Long, newName: String): Boolean

        // In-Place Instruction Assembler
        @JvmStatic private external fun assemblePatch(handle: Long, address: Long, text: String): String

        // JSON Signature & Patch Plugins
        @JvmStatic private external fun runPlugin(handle: Long, pluginJson: String): String
        @JvmStatic private external fun applyPluginPatch(handle: Long, address: Long, mode: String, value: String): String

        // Patch Propagation (ExactClone / Callers)
        @JvmStatic private external fun propagatePatch(
            handle: Long,
            seedAddr: Long,
            mode: Int,
            patchMode: String,
            patchValue: String,
            dryRun: Boolean
        ): String

        // Undo: revert the most recent in-place patch.
        @JvmStatic private external fun undoLast(handle: Long): Long
        @JvmStatic private external fun undoLen(handle: Long): Int

        // Function discovery for stripped binaries (recovers sub_XXXXXXXX).
        @JvmStatic private external fun discoverFunctions(handle: Long, maxScanned: Long): String
    }

    fun assemblePatch(address: Long, text: String): PatchResult {
        val json = assemblePatch(handle, address, text)
        return try {
            gson.fromJson(json, PatchResult::class.java) ?: PatchResult(error = "Unknown error")
        } catch (e: Exception) {
            PatchResult(error = e.message)
        }
    }

    fun getInfo(evaluateYara: Boolean = false): ElfInfo {
        val json = info0(handle, evaluateYara)
        return try {
            gson.fromJson(json, ElfInfo::class.java) ?: ElfInfo()
        } catch (e: Exception) {
            ElfInfo()
        }
    }

    fun disassemble(address: Long, size: Long = 128, thumb: Boolean = false): List<Instruction> {
        val json = disasm0(handle, address, size, thumb)
        return try {
            gson.fromJson(json, CodeIns::class.java)?.data ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun decompile(address: Long): String {
        return dec0(1, handle, address) // Mode 1: C pseudocode (linear)
    }

    /** Structured C pseudocode: real if/while and recovered `switch` (mode 4). */
    fun decompileStructured(address: Long): String {
        return dec0(4, handle, address)
    }

    fun getDisassemblyText(address: Long): String {
        return dec0(2, handle, address) // Mode 2: Annotated disassembly
    }

    fun getFlowchartText(address: Long): String {
        return dec0(3, handle, address) // Mode 3: Control flow graph
    }

    fun getStrings(): List<StringItem> {
        val json = strings0(handle)
        return try {
            gson.fromJson(json, SData::class.java)?.data ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Returns true only if the native patch actually landed (mapped + in-bounds). */
    fun patchBytes(address: Long, bytes: ByteArray): Boolean {
        return write0(handle, address, bytes)
    }

    fun saveBinary(): ByteArray {
        return save0(handle)
    }

    fun readBytes(address: Long, length: Int = 1024): ByteArray {
        return readBytes0(handle, address, length)
    }

    fun getXrefs(address: Long): List<XRefItem> {
        val json = getXrefs(handle, address)
        return try {
            gson.fromJson(json, XRefResponse::class.java)?.refs ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun getHierarchy(address: Long): CallHierarchy {
        val json = getHierarchy(handle, address)
        return try {
            gson.fromJson(json, CallHierarchy::class.java) ?: CallHierarchy()
        } catch (e: Exception) {
            CallHierarchy()
        }
    }

    fun quickPatch(address: Long, patchType: Int, isThumb: Boolean = false): PatchResult {
        val json = quickPatch(handle, address, patchType, isThumb)
        return try {
            gson.fromJson(json, PatchResult::class.java) ?: PatchResult(error = "Unknown error")
        } catch (e: Exception) {
            PatchResult(error = e.message)
        }
    }

    fun scanSecurity(): ScanReport {
        val json = scanSecurity(handle)
        return try {
            gson.fromJson(json, ScanReport::class.java) ?: ScanReport()
        } catch (e: Exception) {
            ScanReport()
        }
    }

    fun getEntropyReport(): EntropyReport {
        val json = getEntropyReport(handle)
        return try {
            gson.fromJson(json, EntropyReport::class.java) ?: EntropyReport()
        } catch (e: Exception) {
            EntropyReport()
        }
    }

    fun getBinaryFacts(): BinaryFacts {
        val json = getBinaryFacts(handle)
        return try {
            gson.fromJson(json, BinaryFacts::class.java) ?: BinaryFacts()
        } catch (e: Exception) {
            BinaryFacts()
        }
    }

    fun loadScriptJson(path: String): Int {
        return loadScriptJson(handle, path)
    }

    fun loadGlobalMetadata(path: String): Int {
        return loadGlobalMetadata(handle, path)
    }

    fun renameFunction(address: Long, newName: String): Boolean {
        return renameFunction(handle, address, newName)
    }

    /**
     * Recover function starts from direct call instructions and install them as
     * `sub_XXXXXXXX` symbols. `maxScanned` bounds how much executable code is
     * decoded (default 32 MiB). Call [getInfo] afterwards to see them.
     */
    fun discoverFunctions(maxScanned: Long = 32L * 1024 * 1024): DiscoveryResult {
        val json = discoverFunctions(handle, maxScanned)
        return try {
            gson.fromJson(json, DiscoveryResult::class.java)
                ?: DiscoveryResult(error = "Empty discovery response")
        } catch (e: Exception) {
            DiscoveryResult(error = e.message)
        }
    }

    fun runPlugin(pluginJson: String): PluginReport {
        val json = runPlugin(handle, pluginJson)
        return try {
            gson.fromJson(json, PluginReport::class.java) ?: PluginReport(error = "Empty plugin response")
        } catch (e: Exception) {
            PluginReport(error = e.message)
        }
    }

    fun applyPluginPatch(address: Long, mode: String, value: String): PatchResult {
        val json = applyPluginPatch(handle, address, mode, value)
        return try {
            gson.fromJson(json, PatchResult::class.java) ?: PatchResult(error = "Unknown error")
        } catch (e: Exception) {
            PatchResult(error = e.message)
        }
    }

    /**
     * Patch Propagation. `mode` 1 = ExactClone, 2 = Callers. `dryRun` returns
     * candidates without writing. Never blind-applies: the UI reviews first.
     */
    fun propagatePatch(
        seedAddr: Long,
        mode: Int,
        patchMode: String,
        patchValue: String,
        dryRun: Boolean = false
    ): PatchPropagationReport {
        val json = propagatePatch(handle, seedAddr, mode, patchMode, patchValue, dryRun)
        return try {
            gson.fromJson(json, PatchPropagationReport::class.java)
                ?: PatchPropagationReport(error = "Empty propagation response")
        } catch (e: Exception) {
            PatchPropagationReport(error = e.message)
        }
    }

    /** Returns the reverted address, or -1 if nothing to undo. */
    fun undoLast(): Long = undoLast(handle)

    /** Number of reversible patches recorded (0 = nothing to undo). */
    fun undoLen(): Int = undoLen(handle)

    override fun close() {
        // Not synchronized: close() is only called from the single native
        // dispatcher thread (ViewModel) or from onCleared(), never concurrently.
        if (!isClosed && handle != 0L) {
            finalize0(handle)
            isClosed = true
        }
    }

    // NOTE: no Kotlin finalize() override. It ran on the GC finalizer thread,
    // racing the native dispatcher and causing use-after-free on ElfContext.
    // Callers must call close() explicitly (the ViewModel does this in
    // loadElf() and onCleared()).
}
