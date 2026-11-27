package io.elftrace.app.core.models

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ElfModelsTest {

    private val gson = Gson()

    // --- SymsDTO derived properties -------------------------------------

    @Test
    fun `displayName prefers demangled then jni then raw symbol`() {
        assertEquals(
            "demangled",
            SymsDTO(sym = "raw", demangled = "demangled", jni_method = "m", jni_class = "C").displayName
        )
        assertEquals(
            "C -> m",
            SymsDTO(sym = "raw", jni_method = "m", jni_class = "C").displayName
        )
        assertEquals("raw", SymsDTO(sym = "raw").displayName)
    }

    @Test
    fun `isJni recognises jni methods and java entry points`() {
        assertTrue(SymsDTO(sym = "x", jni_method = "m").isJni)
        assertTrue(SymsDTO(sym = "Java_io_elftrace_app_MainActivity_nativeInit").isJni)
        assertTrue(SymsDTO(sym = "JNI_OnLoad").isJni)
        assertFalse(SymsDTO(sym = "pthread_create").isJni)
    }

    // --- Instruction.bytesHex -------------------------------------------

    @Test
    fun `bytesHex masks signed bytes to two uppercase hex digits`() {
        val ins = Instruction(bytes = listOf(0x0f, 0xff, -1, 0x00))
        assertEquals("0F FF FF 00", ins.bytesHex)
    }

    @Test
    fun `bytesHex of empty list is empty`() {
        assertEquals("", Instruction().bytesHex)
    }

    // --- Gson wire contract ---------------------------------------------
    // These guard the JSON field names the Rust side emits: a rename here
    // silently blanks a screen without any other test failing.

    @Test
    fun `security finding keeps snake_case wire keys`() {
        val json = """
            {"category":"protector","name":"Legu","address":4096,"offset":16,
             "matched_value":"libshell","severity":"HIGH","description":"packed"}
        """.trimIndent()
        val f = gson.fromJson(json, SecurityFinding::class.java)
        assertEquals("protector", f.category)
        assertEquals(4096L, f.address)
        assertEquals("libshell", f.matched_value)
        assertEquals("HIGH", f.severity)
    }

    @Test
    fun `string xref keeps short wire keys`() {
        val x = gson.fromJson("""{"str":8192,"code":12288}""", StringXref::class.java)
        assertEquals(8192L, x.strAddr)
        assertEquals(12288L, x.codeAddr)
    }

    @Test
    fun `discovery result maps scanned_bytes and string_refs`() {
        val json = """{"added":3,"known":1,"scanned_bytes":65536,"truncated":true,
                       "string_refs":[{"str":1,"code":2}]}"""
        val r = gson.fromJson(json, DiscoveryResult::class.java)
        assertEquals(3, r.added)
        assertEquals(65536L, r.scannedBytes)
        assertTrue(r.truncated)
        assertEquals(1, r.stringRefs.size)
        assertEquals(2L, r.stringRefs[0].codeAddr)
    }

    @Test
    fun `plugin manifest maps case_sensitive and default_enabled`() {
        val json = """
            {"id":"p","name":"P","rules":[{"name":"r","type":"symbol","pattern":"x",
             "case_sensitive":true,"match_mode":"exact"}],
             "default_enabled":false}
        """.trimIndent()
        val m = gson.fromJson(json, PluginManifest::class.java)
        assertFalse(m.defaultEnabled)
        assertTrue(m.rules[0].caseSensitive)
        assertEquals("exact", m.rules[0].matchMode)
        assertNull(m.script)
    }

    @Test
    fun `plugin report keeps nested finding names`() {
        val json = """
            {"plugin_id":"p","plugin_name":"P","total_findings":1,"truncated":false,
             "findings":[{"rule_name":"r","rule_type":"string","address":16,
             "severity":"INFO","symbol_name":"sym"}]}
        """.trimIndent()
        val rep = gson.fromJson(json, PluginReport::class.java)
        assertEquals("p", rep.plugin_id)
        assertEquals(1, rep.total_findings)
        assertEquals("r", rep.findings[0].rule_name)
        assertEquals("sym", rep.findings[0].symbol_name)
    }
}
