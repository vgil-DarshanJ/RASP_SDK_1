package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * # UNIT TESTS — hook-detection classification logic
 *
 * Executes the real production classifier in [RaspHookAnalysis] on the JVM.
 * Fixtures are realistic `/proc/self/maps` shapes; nothing is launched,
 * installed, or contacted.
 *
 * The device-I/O half is covered separately by
 * `src/androidTest/.../RaspHookProbesInstrumentedTest`.
 */
class RaspHookAnalysisTest {

    private val cleanMaps = """
        12c00000-12e00000 rw-p 00000000 00:00 0                  [anon:dalvik-main space]
        7f8a2c1000-7f8a2c3000 r--p 00000000 fd:00 1234           /system/lib64/libc.so
        7f8a2c3000-7f8a2c9000 r-xp 00002000 fd:00 1234           /system/lib64/libc.so
        7f8a2d0000-7f8a2d4000 r-xp 00000000 fd:00 5678           /system/lib64/libart.so
        7fff1a2000-7fff1c3000 rw-p 00000000 00:00 0              [stack]
    """.trimIndent()

    private val lsposedMaps = """
        7f8a2c1000-7f8a2c3000 r--p 00000000 fd:00 1234           /system/lib64/libc.so
        7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999           /data/adb/lspd/lib/libriru_lsposed.so
    """.trimIndent()

    private val substrateMaps = """
        7f8a2c1000-7f8a2c3000 r--p 00000000 fd:00 1234           /system/lib64/libc.so
        7f9c001000-7f9c200000 r-xp 00000000 fd:00 8888           /system/lib/libsubstrate.so
    """.trimIndent()

    private val tmpExecMaps = """
        7f8a2c1000-7f8a2c3000 r--p 00000000 fd:00 1234           /system/lib64/libc.so
        7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777           /data/local/tmp/libpayload.so
    """.trimIndent()

    // ── Clean environment ─────────────────────────────────────────────────

    @Test
    fun `clean maps indicate no hooking framework`() {
        assertFalse(RaspHookAnalysis.mapsIndicateHookFramework(cleanMaps))
        assertTrue(RaspHookAnalysis.hookFrameworksIn(cleanMaps).isEmpty())
    }

    @Test
    fun `clean maps have no suspicious executable mappings`() {
        assertTrue(RaspHookAnalysis.suspiciousExecutableMappings(cleanMaps).isEmpty())
    }

    @Test
    fun `no signals means no hook verdict`() {
        assertFalse(RaspHookAnalysis.hookVerdict(emptyList()))
        assertEquals("none", RaspHookAnalysis.severityFor(emptyList()))
        assertEquals(0, RaspHookAnalysis.confidenceFor(emptyList()))
    }

    // ── Suspicious library ────────────────────────────────────────────────

    @Test
    fun `LSPosed is detected from its mapped library`() {
        assertTrue(RaspHookAnalysis.mapsIndicateHookFramework(lsposedMaps))
        val found = RaspHookAnalysis.hookFrameworksIn(lsposedMaps)
        assertTrue("should name the framework seen", found.contains("lsposed"))
    }

    @Test
    fun `Substrate is detected from its mapped library`() {
        assertTrue(RaspHookAnalysis.mapsIndicateHookFramework(substrateMaps))
        assertTrue(RaspHookAnalysis.hookFrameworksIn(substrateMaps).contains("substrate"))
    }

    @Test
    fun `framework detection covers the major hooking families`() {
        listOf("xposed", "lsposed", "riru", "zygisk", "yahfa", "substrate", "dobby", "whale")
            .forEach {
                assertTrue("'$it' should be a known marker",
                    RaspHookAnalysis.hookFrameworkMarkers.contains(it))
            }
    }

    @Test
    fun `framework matching is case-insensitive`() {
        assertTrue(RaspHookAnalysis.mapsIndicateHookFramework("/data/adb/LSPosed/lib.so"))
    }

    // ── Suspicious mapping ────────────────────────────────────────────────

    @Test
    fun `executable code mapped from tmp is suspicious`() {
        val found = RaspHookAnalysis.suspiciousExecutableMappings(tmpExecMaps)
        assertEquals(listOf("/data/local/tmp/libpayload.so"), found)
    }

    @Test
    fun `a NON-executable mapping from tmp is not suspicious`() {
        // Apps legitimately read data files from writable storage. Flagging
        // those would fire on nearly every device.
        val dataOnly =
            "7f9d001000-7f9d100000 r--p 00000000 fd:00 7777           /data/local/tmp/config.json"
        assertFalse(RaspHookAnalysis.isSuspiciousExecutableMapping(dataOnly))
    }

    @Test
    fun `system libraries are never suspicious mappings`() {
        assertFalse(RaspHookAnalysis.isSuspiciousExecutableMapping(
            "7f8a2c3000-7f8a2c9000 r-xp 00002000 fd:00 1234           /system/lib64/libc.so"))
    }

    // ── RWX / runtime modification ────────────────────────────────────────

    @Test
    fun `an rwx mapping is recognised`() {
        assertTrue(RaspHookAnalysis.isRwxMapping(
            "7f9e000000-7f9e100000 rwxp 00000000 00:00 0"))
        assertFalse(RaspHookAnalysis.isRwxMapping(
            "7f8a2c3000-7f8a2c9000 r-xp 00002000 fd:00 1234 /system/lib64/libc.so"))
    }

    @Test
    fun `a normal JIT footprint stays under the rwx threshold`() {
        // ART's JIT creates RWX regions legitimately; the signal must describe
        // an *unusual* amount of patching surface, not the runtime existing.
        assertEquals(0, RaspHookAnalysis.countRwxMappings(cleanMaps))
        assertTrue(RaspHookAnalysis.RWX_MAPPING_THRESHOLD >= 8)
    }

    @Test
    fun `rwx mappings are counted across a dump`() {
        val many = (1..5).joinToString("\n") {
            "7f9e00${it}000-7f9e10${it}000 rwxp 00000000 00:00 0"
        }
        assertEquals(5, RaspHookAnalysis.countRwxMappings(many))
    }

    // ── Multiple signals / thresholds ─────────────────────────────────────

    @Test
    fun `a hooked native method convicts on its own and is critical`() {
        val signals = listOf("hook_native_method")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `a resident framework convicts on its own and is high`() {
        val signals = listOf("hook_framework_lib")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("high", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `one soft signal alone never convicts`() {
        assertFalse(RaspHookAnalysis.hookVerdict(listOf("hook_rwx_mapping")))
        assertFalse(RaspHookAnalysis.hookVerdict(listOf("hook_suspicious_lib_path")))
    }

    @Test
    fun `two soft signals together do convict`() {
        val signals = listOf("hook_rwx_mapping", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("medium", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `exactly the two documented signals are soft`() {
        assertEquals(
            setOf("hook_rwx_mapping", "hook_suspicious_lib_path"),
            RaspHookAnalysis.softHookSignals,
        )
    }

    @Test
    fun `confidence rises with corroborating families and is capped`() {
        assertEquals(0, RaspHookAnalysis.confidenceFor(emptyList()))
        assertTrue(
            RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib")) <
                RaspHookAnalysis.confidenceFor(
                    listOf("hook_framework_lib", "hook_native_method")),
        )
        assertTrue(RaspHookAnalysis.confidenceFor(
            listOf("hook_framework_lib", "hook_native_method",
                   "hook_rwx_mapping", "hook_suspicious_lib_path")) <= 100)
    }

    @Test
    fun `a hard signal outranks soft ones in severity`() {
        assertEquals("critical", RaspHookAnalysis.severityFor(
            listOf("hook_rwx_mapping", "hook_native_method")))
    }

    // ── False positives ───────────────────────────────────────────────────

    @Test
    fun `ordinary system libraries are not mistaken for hooking frameworks`() {
        listOf(
            "/system/lib64/libc.so",
            "/system/lib64/libart.so",
            "/system/lib64/libandroid_runtime.so",
            "/apex/com.android.runtime/lib64/bionic/libdl.so",
        ).forEach {
            assertFalse("'$it' must not look like a hooking framework",
                RaspHookAnalysis.mapsIndicateHookFramework(it))
        }
    }

    @Test
    fun `an ordinary clean process produces no verdict end to end`() {
        val signals = buildList {
            if (RaspHookAnalysis.mapsIndicateHookFramework(cleanMaps)) add("hook_framework_lib")
            if (RaspHookAnalysis.suspiciousExecutableMappings(cleanMaps).isNotEmpty()) {
                add("hook_suspicious_lib_path")
            }
            if (RaspHookAnalysis.countRwxMappings(cleanMaps) >
                RaspHookAnalysis.RWX_MAPPING_THRESHOLD
            ) add("hook_rwx_mapping")
        }
        assertTrue("clean process should produce no signals", signals.isEmpty())
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
    }
}
