package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hook detection verdict logic tests.
 *
 * Tests the rule: DETECTED = at least one HARD signal OR at least two SOFT signals.
 * Hard signal: hook_framework_lib (known hooking library in /proc/self/maps)
 * Soft signals: hook_rwx_mapping, hook_suspicious_lib_path, hook_native_method
 */
class RaspHookDetectionTest {

    @Test
    fun `single hard signal framework_lib is DETECTED`() {
        val signals = listOf("hook_framework_lib")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("high", RaspHookAnalysis.severityFor(signals)) // Single hard = high
    }

    @Test
    fun `two soft signals is DETECTED`() {
        val signals = listOf("hook_rwx_mapping", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("medium", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `one soft signal alone is NOT DETECTED`() {
        val signals = listOf("hook_rwx_mapping")
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `one soft signal of other type alone is NOT DETECTED`() {
        val signals = listOf("hook_suspicious_lib_path")
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `single native_method (soft) alone is NOT DETECTED`() {
        val signals = listOf("hook_native_method")
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `empty signals is NOT DETECTED`() {
        val signals = emptyList<String>()
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `framework lib + soft is DETECTED`() {
        val signals = listOf("hook_framework_lib", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals)) // Framework + corroboration = critical
    }

    @Test
    fun `framework lib + RWX is DETECTED`() {
        val signals = listOf("hook_framework_lib", "hook_rwx_mapping")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals)) // Framework + corroboration = critical
    }

    @Test
    fun `duplicate hard signal counts once`() {
        // Duplicate same signal counts as 1 for verdict
        val signals = listOf("hook_framework_lib", "hook_framework_lib")
        // Single hard signal IS detected (hard = individually conclusive)
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        // With a second distinct hard signal it also works
        val signals2 = listOf("hook_framework_lib", "hook_framework_lib")
        assertTrue(RaspHookAnalysis.hookVerdict(signals2))
    }

    @Test
    fun `clean device RWX mapping alone does not convict`() {
        // Simulates a clean device where JIT creates >12 RWX regions
        // but no framework lib, no native method, no suspicious path
        val signals = listOf("hook_rwx_mapping")
        assertFalse("RWX alone should not convict on clean device", RaspHookAnalysis.hookVerdict(signals))
    }

    @Test
    fun `clean device reflection false positive on native_method alone does not convict`() {
        // Simulates obfuscation/ART making SDK methods appear native
        // hook_native_method is now soft, so alone it should not convict
        val signals = listOf("hook_native_method")
        assertFalse("Single soft signal (native_method) should not convict on clean device", RaspHookAnalysis.hookVerdict(signals))
    }

    @Test
    fun `attacked device framework lib + RWX convicts`() {
        val signals = listOf("hook_framework_lib", "hook_rwx_mapping")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals)) // Framework + corroboration = critical
    }

    @Test
    fun `attacked device two soft signals convict`() {
        val signals = listOf("hook_native_method", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("medium", RaspHookAnalysis.severityFor(signals)) // Two soft = medium
    }

    @Test
    fun `confidence scales with unique signal families`() {
        assertEquals(0, RaspHookAnalysis.confidenceFor(emptyList()))
        assertEquals(25, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib")))
        assertEquals(25, RaspHookAnalysis.confidenceFor(listOf("hook_native_method")))
        assertEquals(50, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib", "hook_rwx_mapping")))
        assertEquals(50, RaspHookAnalysis.confidenceFor(listOf("hook_rwx_mapping", "hook_suspicious_lib_path")))
        assertEquals(75, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib", "hook_rwx_mapping", "hook_native_method")))
        assertEquals(100, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib", "hook_rwx_mapping", "hook_native_method", "hook_suspicious_lib_path")))
    }

    // ── From /proc/self/maps text to the reported result ─────────────────
    // These run the production path (RaspHookAnalysis.observe → toCheckResult)
    // on maps fixtures; only the file read and the reflection call are
    // replaced by literal inputs.

    private val cleanMaps = """
        12c00000-12e00000 rw-p 00000000 00:00 0                  [anon:dalvik-main space]
        7f8a2c3000-7f8a2c9000 r-xp 00002000 fd:00 1234           /system/lib64/libc.so
        7f8a2d0000-7f8a2d4000 r-xp 00000000 fd:00 5678           /apex/com.android.art/lib64/libart.so
        7f8a2e0000-7f8a2e4000 r--p 00000000 fd:00 5679           /system/framework/oplus-epicenter.jar
        7f8a2f0000-7f8a2f4000 r-xp 00000000 fd:00 5680           /vendor/lib64/libwhalesong_dsp.so
        7f8a300000-7f8a304000 r-xp 00000000 fd:00 5681           /system/lib64/libinputinjector_oem.so
        7f8a310000-7f8a314000 rwxp 00000000 00:00 0              [anon:dalvik-jit-code-cache]
        7fff1a2000-7fff1c3000 rw-p 00000000 00:00 0              [stack]
    """.trimIndent()

    /** [RaspHookAnalysis.RWX_MAPPING_THRESHOLD] + 1 rwx regions: the soft rwx signal. */
    private val manyRwx = (1..RaspHookAnalysis.RWX_MAPPING_THRESHOLD + 1).joinToString("\n") {
        "7f9e%04x000-7f9e%04x000 rwxp 00000000 00:00 0".format(it, it + 1)
    }

    private val tmpExec = "7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777   /data/local/tmp/libpayload.so"
    private val lsposedLib = "7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999   /data/adb/lspd/lib/liblspd.so"

    private fun result(maps: String?, nativeHooked: Boolean? = false) =
        RaspHookAnalysis.toCheckResult(RaspHookAnalysis.observe(maps, nativeHooked))

    private fun firedSignals(r: RaspCheckResult) =
        r.evidence.filter { it.key == "hook_signal" }.map { it.value as String }

    @Test
    fun `clean OEM maps produce no signal and SECURE`() {
        val r = result(cleanMaps)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertTrue(firedSignals(r).isEmpty())
        // names that merely contain a marker (epicenter, whalesong, inputinjector) are not hooking libraries
        assertTrue(RaspHookAnalysis.hookFrameworksIn(cleanMaps).isEmpty())
    }

    @Test
    fun `one soft signal from maps is not detected and names the signal`() {
        val r = result(cleanMaps + "\n" + manyRwx)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf("hook_rwx_mapping"), firedSignals(r))
        assertEquals("soft", r.evidence.first { it.key == "hook_signal" }.note)
    }

    @Test
    fun `one soft signal from reflection alone is not detected`() {
        val r = result(cleanMaps, nativeHooked = true)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf("hook_native_method"), firedSignals(r))
    }

    @Test
    fun `two soft signals from maps are detected and both are named`() {
        val r = result(cleanMaps + "\n" + manyRwx + "\n" + tmpExec)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(setOf("hook_rwx_mapping", "hook_suspicious_lib_path"), firedSignals(r).toSet())
    }

    @Test
    fun `soft maps signal plus soft reflection signal is detected`() {
        val r = result(cleanMaps + "\n" + tmpExec, nativeHooked = true)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(setOf("hook_suspicious_lib_path", "hook_native_method"), firedSignals(r).toSet())
    }

    @Test
    fun `hard signal alone is detected and names the library marker`() {
        val r = result(cleanMaps + "\n" + lsposedLib)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("hook_framework_lib"), firedSignals(r))
        assertEquals("hard", r.evidence.first { it.key == "hook_signal" }.note)
        assertTrue(r.evidence.any { it.key == "hook_framework" && it.value == "lspd" })
    }

    @Test
    fun `hooking library names are matched as path tokens`() {
        assertEquals(listOf("xposed"), RaspHookAnalysis.hookFrameworksIn("r-xp 0 0 0 /system/framework/XposedBridge.jar"))
        assertEquals(listOf("riru"), RaspHookAnalysis.hookFrameworksIn("r-xp 0 0 0 /system/lib64/libriru_core.so"))
        assertEquals(listOf("zygisk"), RaspHookAnalysis.hookFrameworksIn("r-xp 0 0 0 /data/adb/modules/x/zygisk/arm64-v8a.so"))
        assertTrue(RaspHookAnalysis.hookFrameworksIn("r-xp 0 0 0 /data/app/x/lib/arm64/libepic.so").contains("epic"))
    }

    @Test
    fun `unreadable maps with no conviction is UNKNOWN, never SECURE`() {
        val r = result(null, nativeHooked = false)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertTrue(r.evidence.any { it.key == "maps_readable" && it.value == false })
    }

    // ── Task 4.7: which signals and lines produced the verdict ──────────

    private fun lines(r: RaspCheckResult, signal: String) =
        r.evidence.filter { it.key == "hook_signal_line" && it.note == signal }.map { it.value as String }

    @Test
    fun `DETECTED by the hard signal names it and the matching maps line`() {
        val r = result(cleanMaps + "\n" + lsposedLib)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("hook_framework_lib"), r.evidence.first { it.key == "detected_by" }.value)
        val matched = lines(r, "hook_framework_lib")
        assertEquals(1, matched.size)
        assertTrue(matched.single(), matched.single().endsWith("/data/adb/lspd/lib/liblspd.so"))
        assertTrue(matched.single().length <= RaspHookAnalysis.EVIDENCE_LINE_MAX)
    }

    @Test
    fun `DETECTED by two soft signals names both, with at most 3 lines each`() {
        val r = result(cleanMaps + "\n" + manyRwx + "\n" + tmpExec)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("hook_suspicious_lib_path", "hook_rwx_mapping"), r.evidence.first { it.key == "detected_by" }.value)
        assertEquals(listOf("7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777 /data/local/tmp/libpayload.so"),
            lines(r, "hook_suspicious_lib_path"))
        val rwx = lines(r, "hook_rwx_mapping")
        assertEquals(RaspHookAnalysis.LINES_PER_SIGNAL, rwx.size) // 13 matched, 3 kept
        assertTrue(rwx.all { it.contains(" rwxp ") })
    }

    @Test
    fun `a hooked method is named in the evidence`() {
        val r = RaspHookAnalysis.toCheckResult(
            RaspHookAnalysis.observe(cleanMaps + "\n" + tmpExec, true, listOf("RaspHookProbes.isHookingDetected")),
        )
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("native method: RaspHookProbes.isHookingDetected"), lines(r, "hook_native_method"))
    }

    @Test
    fun `a single soft signal shows its line but no detected_by`() {
        val r = result(cleanMaps + "\n" + manyRwx)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertTrue(r.evidence.none { it.key == "detected_by" })
        assertEquals(3, lines(r, "hook_rwx_mapping").size)
    }

    @Test
    fun `evidence lines are at most 80 chars and keep both the start and the path end`() {
        val long = "7f8a2c3000000-7f8a2c9000000 r-xp 00002000 fd:00 123456789     " +
            "/data/app/~~AbCdEfGhIjKl==/com.example.someverylongpackagename-XyZ==/lib/arm64/libsomething_long.so"
        val shown = RaspHookAnalysis.evidenceLine(long)
        assertEquals(RaspHookAnalysis.EVIDENCE_LINE_MAX, shown.length)
        assertTrue(shown, shown.startsWith("7f8a2c3000000-7f8a2c9000000 r-"))
        assertTrue(shown, shown.endsWith("/lib/arm64/libsomething_long.so"))
        assertTrue(shown.contains("…"))
        // Short lines only lose their alignment padding.
        assertEquals("7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777 /data/local/tmp/libpayload.so",
            RaspHookAnalysis.evidenceLine(tmpExec))
    }

    @Test
    fun `thresholds and verdict rule are unchanged`() {
        assertEquals(12, RaspHookAnalysis.RWX_MAPPING_THRESHOLD)
        fun rwxLines(n: Int) = (1..n).joinToString("\n") { "7f9e%04x000-7f9e%04x000 rwxp 00000000 00:00 0".format(it, it + 1) }
        assertTrue("12 rwx regions do not fire", result(rwxLines(12)).evidence.none { it.key == "hook_signal" })
        assertEquals(listOf("hook_rwx_mapping"), result(rwxLines(13)).evidence.filter { it.key == "hook_signal" }.map { it.value })
        assertEquals(setOf("hook_framework_lib"), RaspHookAnalysis.hardHookSignals)
        assertEquals(setOf("hook_rwx_mapping", "hook_suspicious_lib_path", "hook_native_method"), RaspHookAnalysis.softHookSignals)
    }

    @Test
    fun `unreadable maps and no resolvable methods is UNKNOWN`() {
        val r = result(null, nativeHooked = null)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertTrue(r.evidence.any { it.key == "method_integrity" && it.value == "unavailable" })
    }
}