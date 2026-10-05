package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * hook_detection on the real OnePlus CPH2649 / Android 16 profile from
 * docs/PHONE_RESULTS.md (Task 5.1): the ART boot image in
 * /data/misc/apexdata/com.android.art/dalvik-cache/ is not a suspicious path,
 * `[anon:dart-code]` regions are not counted as RWX, the threshold stays 12,
 * and real hooks are still DETECTED.
 *
 * Real: RaspHookAnalysis.observe → toCheckResult on maps text. The maps lines
 * below are copied verbatim from that phone (/proc/<pid>/maps of the trial app).
 */
class RaspHookPhoneProfileTest {

    /** The three lines that fired hook_suspicious_lib_path on the phone. */
    private val artLines = listOf(
        "71670000-7241b000 r-xp 00424000 fe:4d 69355                              /data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot.oat",
        "72594000-725b0000 r-xp 00020000 fe:4d 69382                              /data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot-framework-adservices.oat",
        "78420e6000-78420ec000 r-xp 00008000 fe:4d 69395                          /data/misc/apexdata/com.android.art/dalvik-cache/arm64/system@framework@com.android.location.provider.jar@classes.odex",
    )

    /** The phone's 11 RWX regions, all the Dart VM's own code pages (debug build). */
    private val dartCodeLines = listOf(
        "771fb80000-771fc00000", "772fc80000-772fe00000", "772ff00000-7730000000", "7731d80000-7731e00000",
        "77c0300000-77c0880000", "77c9680000-77c9700000", "77d0c00000-77d0c80000", "77e7f80000-77e7f91000",
        "77e8000000-77e8011000", "786e380000-786e400000", "7878c80000-7878d80000",
    ).map { "$it rwxp 00000000 00:00 0                                  [anon:dart-code]" }

    private val ordinary = listOf(
        "12c00000-12e00000 rw-p 00000000 00:00 0                  [anon:dalvik-main space]",
        "7f8a2c3000-7f8a2c9000 r-xp 00002000 fd:00 1234           /system/lib64/libc.so",
        "7f8a2d0000-7f8a2d4000 r-xp 00000000 fd:00 5678           /apex/com.android.art/lib64/libart.so",
    )

    /** Real RWX regions that are not the Dart VM's (anonymous, unnamed). */
    private fun realRwx(n: Int) = (1..n).map { "7f9e%04x000-7f9e%04x000 rwxp 00000000 00:00 0".format(it, it + 1) }

    private fun result(lines: List<String>, nativeHooked: Boolean? = false) =
        RaspHookAnalysis.toCheckResult(RaspHookAnalysis.observe(lines.joinToString("\n"), nativeHooked))

    private fun RaspCheckResult.values(key: String) = evidence.filter { it.key == key }.map { it.value }

    @Test fun `the clean Flutter debug phone profile is SECURE with no signal`() {
        val r = result(ordinary + artLines + dartCodeLines)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(emptyList<Any?>(), r.values("hook_signal"))
        assertEquals(listOf<Any?>(0), r.values("rwx_mapping_count"))
        assertEquals(listOf<Any?>(0), r.values("suspicious_exec_mapping_count"))
        assertTrue(r.evidence.first { it.key == "rwx_mapping_count" }.note!!.contains("11 [anon:dart-code] regions not counted"))
        assertEquals("not near the threshold", emptyList<Any?>(), r.values("hook_near_threshold"))
    }

    @Test fun `the ART dalvik-cache lines are not suspicious, other data-misc code still is`() {
        artLines.forEach { assertFalse(it, RaspHookAnalysis.isSuspiciousExecutableMapping(it)) }
        assertTrue(RaspHookAnalysis.isSuspiciousExecutableMapping(
            "7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777   /data/misc/other/libx.so"))
        // The trusted folder must be where the path starts, not somewhere inside it.
        assertTrue(RaspHookAnalysis.isSuspiciousExecutableMapping(
            "7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777   /data/local/tmp/data/misc/apexdata/com.android.art/dalvik-cache/evil.so"))
        assertTrue(RaspHookAnalysis.isSuspiciousExecutableMapping(
            "7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777   /data/misc/apexdata/com.android.art/dalvik-cache/../../evil/libx.so"))
    }

    @Test fun `dart-code regions are not counted, every other RWX region is`() {
        assertEquals(0, RaspHookAnalysis.countRwxMappings(dartCodeLines.joinToString("\n")))
        assertEquals(11, RaspHookAnalysis.countDartCodeRwxRegions(dartCodeLines.joinToString("\n")))
        assertEquals(13, RaspHookAnalysis.countRwxMappings((dartCodeLines + realRwx(13)).joinToString("\n")))
        assertTrue(RaspHookAnalysis.isRwxMapping(dartCodeLines.first()))
    }

    @Test fun `the threshold is still 12 - 12 real RWX regions do not fire, 13 do`() {
        assertEquals(12, RaspHookAnalysis.RWX_MAPPING_THRESHOLD)
        assertEquals(emptyList<Any?>(), result(ordinary + dartCodeLines + realRwx(12)).values("hook_signal"))
        assertEquals(listOf<Any?>("hook_rwx_mapping"), result(ordinary + dartCodeLines + realRwx(13)).values("hook_signal"))
    }

    @Test fun `13 real RWX regions plus a suspicious-path library are still DETECTED`() {
        val r = result(ordinary + artLines + dartCodeLines + realRwx(13) +
            "7f9d001000-7f9d100000 r-xp 00000000 fd:00 7777   /data/local/tmp/libpayload.so")
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>(listOf("hook_suspicious_lib_path", "hook_rwx_mapping")), r.values("detected_by"))
        // The evidence lines are the real RWX regions, not the Dart code pages.
        val rwxLines = r.evidence.filter { it.key == "hook_signal_line" && it.note == "hook_rwx_mapping" }.map { it.value as String }
        assertTrue(rwxLines.isNotEmpty())
        assertTrue(rwxLines.none { it.contains("dart-code") })
    }

    @Test fun `an Xposed or LSPosed library line is still DETECTED by hook_detection on the phone profile`() {
        for (lib in listOf(
            "7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999   /system/framework/XposedBridge.jar",
            "7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999   /data/adb/lspd/lib/liblspd.so",
        )) {
            val r = result(ordinary + artLines + dartCodeLines + lib)
            assertEquals(lib, RaspCheckStatus.DETECTED, r.status)
            assertEquals(lib, listOf<Any?>(listOf("hook_framework_lib")), r.values("detected_by"))
        }
    }

    @Test fun `a Frida library line on the phone profile is still caught by the frida detector's maps check`() {
        // Frida is the `frida` detector's job (frida_maps), not hook_detection's
        // hook_framework_lib list; the fix must not hide it from either.
        val profile = (ordinary + artLines + dartCodeLines).joinToString("\n")
        assertFalse(RaspSignalAnalysis.mapsIndicateInstrumentation(profile))
        assertTrue(RaspSignalAnalysis.mapsIndicateInstrumentation(
            profile + "\n7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999   /data/local/tmp/frida-agent-64.so"))
    }

    @Test fun `hook_near_threshold is added when the count is within 2 of the limit`() {
        for (n in 10..12) {
            val r = result(ordinary + dartCodeLines + realRwx(n))
            assertEquals("$n", listOf<Any?>(true), r.values("hook_near_threshold"))
            assertTrue(r.evidence.first { it.key == "hook_near_threshold" }.note!!.contains("$n"))
        }
        for (n in listOf(0, 9, 13)) {
            assertEquals("$n", emptyList<Any?>(), result(ordinary + realRwx(n)).values("hook_near_threshold"))
        }
    }
}
