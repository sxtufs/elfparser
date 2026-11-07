package io.elftrace.app.mcp

import android.content.Context
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import io.elftrace.app.core.models.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

object MCPTools {

    private val gson = Gson()

    fun getToolsList(): JsonArray {
        val tools = JsonArray()

        // 1. elftrace_get_status
        tools.add(createTool(
            name = "elftrace_get_status",
            description = "Get the status of ELFTrace, including the currently loaded binary name, architecture, entrypoint, selected function, and current address.",
            schema = JsonObject()
        ))

        // 2. elftrace_get_info
        tools.add(createTool(
            name = "elftrace_get_info",
            description = "Get detailed ELF header information: machine type, 64-bit flag, soname, interpreter, and imported dynamic shared libraries.",
            schema = JsonObject()
        ))

        // 3. elftrace_list_symbols
        val symSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("query", JsonObject().apply {
                addProperty("type", "string")
                addProperty("description", "Optional search string to filter symbols by method or class name")
            })
            props.add("limit", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Maximum symbols to return (default 50, max 200)")
            })
            add("properties", props)
        }
        tools.add(createTool(
            name = "elftrace_list_symbols",
            description = "List and search exported symbols, demangled C++ names, and JNI methods in the current binary.",
            schema = symSchema
        ))

        // 4. elftrace_select_function
        val selectSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address (VMA) of the function to select")
            })
            props.add("name", JsonObject().apply {
                addProperty("type", "string")
                addProperty("description", "Optional display name for the function")
            })
            add("properties", props)
            val req = JsonArray().apply { add("address") }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_select_function",
            description = "Select an active function by virtual address, updating the mobile UI, disassembler, and decompiler views.",
            schema = selectSchema
        ))

        // 5. elftrace_disassemble
        val disasmSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address (VMA) to disassemble")
            })
            props.add("count", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Number of instructions to disassemble (default 64, max 256)")
            })
            add("properties", props)
            val req = JsonArray().apply { add("address") }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_disassemble",
            description = "Disassemble machine instructions at a virtual address with in-line strings, kernel syscalls, and JNI annotations.",
            schema = disasmSchema
        ))

        // 6. elftrace_decompile
        val decSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address (VMA) of the function to decompile")
            })
            add("properties", props)
            val req = JsonArray().apply { add("address") }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_decompile",
            description = "Decompile a native routine at a virtual address into high-level C pseudocode.",
            schema = decSchema
        ))

        // 7. elftrace_get_hierarchy
        val hierSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address (VMA) of the function to inspect")
            })
            add("properties", props)
            val req = JsonArray().apply { add("address") }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_get_hierarchy",
            description = "Get the Call Hierarchy for a function: incoming Callers (who calls this function) and outgoing Callees (what functions it calls) with call counts.",
            schema = hierSchema
        ))

        // 8. elftrace_get_entropy
        tools.add(createTool(
            name = "elftrace_get_entropy",
            description = "Calculate the Shannon entropy (0.0 to 8.0) of each ELF section and get a packer detection verdict (e.g. DexProtect, VMProtect).",
            schema = JsonObject()
        ))

        // 9. elftrace_read_hex
        val hexSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address or file offset to read")
            })
            props.add("length", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Number of bytes to read (default 256, max 2048)")
            })
            add("properties", props)
            val req = JsonArray().apply { add("address") }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_read_hex",
            description = "Read raw binary memory bytes at an address or file offset, formatted as an 8-byte hex dump with ASCII representation.",
            schema = hexSchema
        ))

        // 10. elftrace_patch_instruction
        val patchSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address of the instruction to patch")
            })
            props.add("assembly", JsonObject().apply {
                addProperty("type", "string")
                addProperty("description", "New assembly instruction (e.g. 'b #0x37d58', 'ret', 'nop', 'mov w0, #1') or raw hex bytes (e.g. 'C4 26 00 14')")
            })
            add("properties", props)
            val req = JsonArray().apply {
                add("address")
                add("assembly")
            }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_patch_instruction",
            description = "Assemble and patch an instruction in-place in binary memory on the device.",
            schema = patchSchema
        ))

        // 11. elftrace_quick_patch
        val qpSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Virtual memory address to patch")
            })
            props.add("patchType", JsonObject().apply {
                addProperty("type", "string")
                addProperty("description", "Preset patch type: 'nop', 'return_true', 'return_false', or 'return_void'")
            })
            add("properties", props)
            val req = JsonArray().apply {
                add("address")
                add("patchType")
            }
            add("required", req)
        }
        tools.add(createTool(
            name = "elftrace_quick_patch",
            description = "Apply a preset reverse-engineering patch (NOP, Force Return True, Force Return False, Return Void) to neutralize checks.",
            schema = qpSchema
        ))

        // 12. elftrace_scan_security
        tools.add(createTool(
            name = "elftrace_scan_security",
            description = "Run the Security & Cryptography Scanner to identify anti-debugging (TracerPid, ptrace), root detection, and crypto algorithm constants.",
            schema = JsonObject()
        ))

        // 13. elftrace_trace_step
        val traceSchema = JsonObject().apply {
            addProperty("type", "object")
            val props = JsonObject()
            props.add("address", JsonObject().apply {
                addProperty("type", "integer")
                addProperty("description", "Optional address to initialize trace at before stepping")
            })
            add("properties", props)
        }
        tools.add(createTool(
            name = "elftrace_trace_step",
            description = "Step one instruction forward in the in-process ARM64 virtual CPU emulator and inspect live registers (X0-X30, SP, PC) and condition flags (Z, N, C, V).",
            schema = traceSchema
        ))

        // 14. elftrace_export_binary
        tools.add(createTool(
            name = "elftrace_export_binary",
            description = "Export the modified/patched ELF binary from memory to the device Downloads folder.",
            schema = JsonObject()
        ))

        return tools
    }

    fun executeTool(
        name: String,
        arguments: JsonObject,
        viewModel: ELFTraceViewModel,
        context: Context
    ): String {
        val bridge = viewModel.bridge.value ?: return "Error: No binary is currently loaded in ELFTrace."

        return try {
            when (name) {
                "elftrace_get_status" -> {
                    val status = JsonObject().apply {
                        addProperty("fileName", viewModel.currentFileName.value)
                        addProperty("currentAddress", "0x%08X".format(viewModel.currentAddress.value))
                        addProperty("selectedSymbol", viewModel.selectedSymbolName.value)
                        addProperty("totalSymbols", viewModel.elfInfo.value?.syms?.size ?: 0)
                        addProperty("architecture", viewModel.elfInfo.value?.e_machine ?: 0)
                        addProperty("is64Bit", viewModel.elfInfo.value?.is_64 ?: true)
                    }
                    gson.toJson(status)
                }

                "elftrace_get_info" -> {
                    val info = bridge.getInfo()
                    gson.toJson(info)
                }

                "elftrace_list_symbols" -> {
                    val query = if (arguments.has("query")) arguments.get("query").asString else ""
                    val limit = if (arguments.has("limit")) arguments.get("limit").asInt.coerceIn(1, 200) else 50
                    val syms = bridge.getInfo().syms
                    val filtered = if (query.isEmpty()) {
                        syms.take(limit)
                    } else {
                        syms.filter { it.displayName.contains(query, ignoreCase = true) }.take(limit)
                    }
                    gson.toJson(filtered)
                }

                "elftrace_select_function" -> {
                    val address = arguments.get("address").asLong
                    val funcName = if (arguments.has("name")) arguments.get("name").asString else "sub_%08X".format(address)
                    viewModel.selectFunction(address, funcName)
                    "Selected function: $funcName @ 0x%08X".format(address)
                }

                "elftrace_disassemble" -> {
                    val address = arguments.get("address").asLong
                    val count = if (arguments.has("count")) arguments.get("count").asLong.coerceIn(1, 256) else 64L
                    val insns = bridge.disassemble(address, count)
                    val sb = StringBuilder()
                    for (ins in insns) {
                        sb.append("0x%08X   %-12s %-7s %s".format(ins.address, ins.bytesHex, ins.mnemonic, ins.op_str))
                        if (!ins.comment.isNullOrEmpty()) {
                            sb.append("    ").append(ins.comment)
                        }
                        sb.append("\n")
                    }
                    sb.toString()
                }

                "elftrace_decompile" -> {
                    val address = arguments.get("address").asLong
                    bridge.decompile(address)
                }

                "elftrace_get_hierarchy" -> {
                    val address = arguments.get("address").asLong
                    val hier = bridge.getHierarchy(address)
                    gson.toJson(hier)
                }

                "elftrace_get_entropy" -> {
                    val report = bridge.getEntropyReport()
                    gson.toJson(report)
                }

                "elftrace_read_hex" -> {
                    val address = arguments.get("address").asLong
                    val length = if (arguments.has("length")) arguments.get("length").asInt.coerceIn(1, 2048) else 256
                    val bytes = bridge.readBytes(address, length)
                    val sb = StringBuilder()
                    for (i in bytes.indices step 8) {
                        val rowAddr = address + i
                        val chunkLen = minOf(8, bytes.size - i)
                        val chunk = bytes.sliceArray(i until i + chunkLen)
                        val hexStr = chunk.joinToString(" ") { "%02X".format(it) }
                        val asciiStr = chunk.map { b ->
                            val c = (b.toInt() and 0xFF).toChar()
                            if (c in ' '..'~') c else '.'
                        }.joinToString("")
                        sb.append("%08X  %-24s  |%s|\n".format(rowAddr, hexStr, asciiStr))
                    }
                    sb.toString()
                }

                "elftrace_patch_instruction" -> {
                    val address = arguments.get("address").asLong
                    val asm = arguments.get("assembly").asString
                    val res = bridge.assemblePatch(address, asm)
                    if (res.success) {
                        "Successfully patched 0x%08X -> %s. Bytes: %s".format(
                            address,
                            res.patch_type,
                            res.patched_bytes.joinToString(" ") { "%02X".format(it) }
                        )
                    } else {
                        "Patch failed at 0x%08X: %s".format(address, res.error)
                    }
                }

                "elftrace_quick_patch" -> {
                    val address = arguments.get("address").asLong
                    val ptype = arguments.get("patchType").asString.lowercase()
                    val typeInt = when (ptype) {
                        "nop" -> 1
                        "return_true" -> 2
                        "return_false" -> 3
                        "return_void" -> 4
                        else -> 1
                    }
                    val isThumb = bridge.getInfo().e_machine == 40 && (address and 1L != 0L)
                    val res = bridge.quickPatch(address, typeInt, isThumb)
                    if (res.success) {
                        "Applied %s at 0x%08X. New bytes: %s".format(
                            res.patch_type,
                            address,
                            res.patched_bytes.joinToString(" ") { "%02X".format(it) }
                        )
                    } else {
                        "Quick patch failed: %s".format(res.error)
                    }
                }

                "elftrace_scan_security" -> {
                    val report = bridge.scanSecurity()
                    gson.toJson(report)
                }

                "elftrace_trace_step" -> {
                    if (arguments.has("address")) {
                        val addr = arguments.get("address").asLong
                        bridge.startTrace(addr)
                    }
                    val state = bridge.stepTrace()
                    gson.toJson(state)
                }

                "elftrace_export_binary" -> {
                    var outPath: String? = null
                    val latch = java.util.concurrent.CountDownLatch(1)
                    viewModel.savePatchedBinary(context) { path ->
                        outPath = path
                        latch.countDown()
                    }
                    latch.await(5, java.util.concurrent.TimeUnit.SECONDS)
                    if (outPath != null) {
                        "Binary exported successfully to: $outPath"
                    } else {
                        "Failed to export patched binary."
                    }
                }

                else -> "Error: Unknown tool '$name'"
            }
        } catch (e: Exception) {
            "Tool execution error: ${e.message}"
        }
    }

    private fun createTool(name: String, description: String, schema: JsonObject): JsonObject {
        return JsonObject().apply {
            addProperty("name", name)
            addProperty("description", description)
            add("inputSchema", schema)
        }
    }
}
