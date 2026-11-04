package com.diself.app.core.models

import com.google.gson.annotations.SerializedName

data class ElfInfo(
    val e_machine: Int = 0,
    val entry: Long = 0,
    val is_64: Boolean = true,
    val soname: String = "",
    val interpreter: String? = null,
    val libraries: List<String> = emptyList(),
    val syms: List<SymsDTO> = emptyList(),
    val yara: List<YaraDTO> = emptyList()
)

data class SymsDTO(
    val sym: String = "",
    val value: Long = 0,
    val size: Long = 0,
    val thumb: Boolean = false
)

data class YaraDTO(
    val name: String = "",
    val info: String = ""
)

data class CodeIns(
    val data: List<Instruction> = emptyList()
)

data class Instruction(
    val address: Long = 0,
    val bytes: List<Int> = emptyList(),
    val mnemonic: String = "",
    val op_str: String = ""
) {
    val bytesHex: String
        get() = bytes.joinToString(" ") { "%02X".format(it and 0xFF) }
}

data class SData(
    val data: List<StringItem> = emptyList()
)

data class StringItem(
    val paddr: Long = 0,
    val vaddr: Long = 0,
    val size: Int = 0,
    val string: String = ""
)

data class TraceState(
    val pc: Long = 0,
    val sp: Long = 0,
    val x: List<Long> = emptyList(),
    val n: Boolean = false,
    val z: Boolean = false,
    val c: Boolean = false,
    val v: Boolean = false,
    val current_insn: String = "",
    val mnemonic: String = "",
    val op_str: String = "",
    val changed_regs: List<String> = emptyList(),
    val error: String? = null
)
