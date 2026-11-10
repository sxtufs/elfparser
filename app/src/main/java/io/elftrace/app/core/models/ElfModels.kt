package io.elftrace.app.core.models

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
    val thumb: Boolean = false,
    val demangled: String? = null,
    val jni_class: String? = null,
    val jni_method: String? = null
) {
    val displayName: String
        get() = demangled ?: jni_method?.let { "$jni_class -> $it" } ?: sym

    val isJni: Boolean
        get() = jni_method != null || sym.startsWith("Java_") || sym.contains("JNI_OnLoad")
}

data class YaraDTO(
    val name: String = "",
    val info: String = ""
)

data class PatchResult(
    val address: Long = 0,
    val original_bytes: List<Int> = emptyList(),
    val patched_bytes: List<Int> = emptyList(),
    val patch_type: String = "",
    val success: Boolean = false,
    val error: String? = null
)

data class SecurityFinding(
    val category: String = "",
    val name: String = "",
    val address: Long = 0,
    val offset: Long = 0,
    val matched_value: String = "",
    val severity: String = "",
    val description: String = ""
)

data class ScanReport(
    val total_findings: Int = 0,
    val findings: List<SecurityFinding> = emptyList()
)

data class SectionEntropy(
    val name: String = "",
    val address: Long = 0,
    val size: Long = 0,
    val entropy: Double = 0.0,
    val is_executable: Boolean = false,
    val is_high_entropy: Boolean = false,
    val status: String = ""
)

data class EntropyReport(
    val overall_entropy: Double = 0.0,
    val overall_verdict: String = "",
    val is_likely_packed: Boolean = false,
    val sections: List<SectionEntropy> = emptyList()
)

data class CodeIns(
    val data: List<Instruction> = emptyList()
)

data class Instruction(
    val address: Long = 0,
    val bytes: List<Int> = emptyList(),
    val mnemonic: String = "",
    val op_str: String = "",
    val comment: String? = null
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

data class XRefItem(
    val from_address: Long = 0,
    val to_address: Long = 0,
    val kind: String = "",
    val instruction: String = "",
    val caller_func: String? = null
)

data class XRefResponse(
    val target_address: Long = 0,
    val refs: List<XRefItem> = emptyList()
)

data class CalleeItem(
    val target_address: Long = 0,
    val target_name: String = "",
    val instruction: String = "",
    val call_count: Int = 0
)

data class CallHierarchy(
    val function_address: Long = 0,
    val function_name: String = "",
    val callers: List<XRefItem> = emptyList(),
    val callees: List<CalleeItem> = emptyList()
)

