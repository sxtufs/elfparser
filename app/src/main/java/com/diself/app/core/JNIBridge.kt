package com.diself.app.core

import com.diself.app.core.models.*
import com.google.gson.Gson

class JNIBridge private constructor(val handle: Long, val path: String) {

    private val gson = Gson()

    companion object {
        init {
            System.loadLibrary("diself")
        }

        fun open(path: String): JNIBridge? {
            val handle = init0(path)
            return if (handle != 0L) JNIBridge(handle, path) else null
        }

        @JvmStatic private external fun init0(path: String): Long
        @JvmStatic private external fun finalize0(handle: Long)
        @JvmStatic private external fun info0(handle: Long, flag: Boolean): String
        @JvmStatic private external fun disasm0(handle: Long, address: Long, size: Long, thumb: Boolean): String
        @JvmStatic private external fun dec0(mode: Int, handle: Long, address: Long): String
        @JvmStatic private external fun strings0(handle: Long): String
        @JvmStatic private external fun str0(handle: Long, address: Long, len: Long): String
        @JvmStatic private external fun write0(handle: Long, address: Long, bytes: ByteArray)
        @JvmStatic private external fun save0(handle: Long): ByteArray

        // In-process Execution Tracer
        @JvmStatic private external fun traceInit(handle: Long, address: Long)
        @JvmStatic private external fun traceStep(handle: Long): String
        @JvmStatic private external fun traceBack(handle: Long): String

        // Native Cross-References (XREF)
        @JvmStatic private external fun getXrefs(handle: Long, address: Long): String
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
        return dec0(1, handle, address) // Mode 1: C pseudocode
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

    fun patchBytes(address: Long, bytes: ByteArray) {
        write0(handle, address, bytes)
    }

    fun saveBinary(): ByteArray {
        return save0(handle)
    }

    fun startTrace(address: Long) {
        traceInit(handle, address)
    }

    fun stepTrace(): TraceState {
        val json = traceStep(handle)
        return try {
            gson.fromJson(json, TraceState::class.java) ?: TraceState()
        } catch (e: Exception) {
            TraceState(error = e.message)
        }
    }

    fun stepBackTrace(): TraceState {
        val json = traceBack(handle)
        return try {
            gson.fromJson(json, TraceState::class.java) ?: TraceState()
        } catch (e: Exception) {
            TraceState(error = e.message)
        }
    }

    fun getXrefs(address: Long): List<XRefItem> {
        val json = getXrefs(handle, address)
        return try {
            gson.fromJson(json, XRefResponse::class.java)?.refs ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    protected fun finalize() {
        finalize0(handle)
    }
}
