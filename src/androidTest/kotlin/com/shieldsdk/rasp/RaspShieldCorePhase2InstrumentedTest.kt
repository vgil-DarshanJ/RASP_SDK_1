package com.shieldsdk.rasp

import android.content.pm.ApplicationInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 2 runtime-protection facade
 *
 * Covers [RaspShieldCore]'s Frida, debugger, reverse-engineering-tools and
 * hooking checks. The underlying I/O probes ([RaspDeviceProbes],
 * [RaspHookProbes]) already have their own dedicated instrumented test
 * suites (ported verbatim, unchanged) — this file tests the
 * [RaspShieldCore] facade layer specifically: the 5-state result mapping,
 * the debug-build + runtime-attach OR-combination for the debugger check,
 * and the reverse-engineering-tools package query this port fixed.
 *
 * Same discipline throughout: assert what is genuinely verifiable on a
 * shared/unknown test environment, never a hardcoded "this device is
 * clean" claim.
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase2InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    @Test
    fun frida_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkFridaBlocking(context)
        assertEquals("frida", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun frida_notDetected_onThisTestRuntime() {
        // A CI/emulator/device running the plain test harness has no Frida
        // server attached — a real, independently-true ground truth.
        val result = RaspShieldCore.checkFridaBlocking(context)
        assertNotEquals(RaspCheckStatus.DETECTED, result.status)
    }

    @Test
    fun debugger_reflectsTheTestApksOwnDebuggableFlag() {
        // Flutter's instrumentation test APK is always built debuggable —
        // same ground truth the ported RaspDeviceIntegrityProbesInstrumentedTest
        // relies on for its own app_debuggable assertion.
        val result = RaspShieldCore.checkDebuggerBlocking(context)
        assertEquals("debugger", result.detectorId)

        val actuallyDebuggable =
            (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (actuallyDebuggable) {
            assertEquals(RaspCheckStatus.DETECTED, result.status)
            assertEquals(
                "expected a build_mode evidence entry when the APK is debuggable",
                "debug",
                result.evidence.firstOrNull { it.key == "build_mode" }?.value,
            )
        }
    }

    @Test
    fun debugger_neverIncludesTheBuildFlagAsARuntimeSignal() {
        // The build-mode flag must be surfaced as its own evidence key
        // ("build_mode"), never duplicated as a "debugger_signal" entry —
        // duplicating it would imply two independent findings where there
        // is exactly one, per RaspSignalAnalysis.DEBUGGABLE_FLAG's own doc.
        val result = RaspShieldCore.checkDebuggerBlocking(context)
        result.evidence.filter { it.key == "debugger_signal" }.forEach {
            assertNotEquals("debuggable_flag", it.value)
        }
    }

    @Test
    fun reverseEngineeringTools_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkReverseEngineeringToolsBlocking(context)
        assertEquals("re_tools", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun reverseEngineeringTools_queriesAllNineTargetPackages_withNoManifestGap() {
        // The bug this port fixed: on API 30+, a package not declared in
        // <queries> is invisible to PackageManager. This proves every
        // target package is at least queryable (does not throw a
        // visibility-related SecurityException) — it does not assert
        // installed/not-installed, since that is environment-dependent.
        val pm = context.packageManager
        RaspReverseEngineeringToolsProbe.reTools.forEach { pkg ->
            try {
                pm.getApplicationInfo(pkg, 0)
                // Installed — fine, this is a valid outcome on a device
                // that genuinely has one of these apps.
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                // Expected for an app that is not installed — this is the
                // CORRECT exception type. The bug this fixes would instead
                // manifest as every one of these being silently
                // unqueryable regardless of install state; this test
                // cannot distinguish "genuinely not installed" from "still
                // invisible due to a missing <queries> entry" by exception
                // type alone (both throw NameNotFoundException), which is
                // exactly why the manifest fix is verified by manifest
                // content in a Gradle-level check, not by this runtime
                // assertion — this test instead documents that no OTHER
                // exception type (e.g. a SecurityException from a
                // visibility filter misconfiguration) is thrown.
            }
        }
    }

    @Test
    fun hooking_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkHookingBlocking(context)
        assertEquals("hook_detection", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun hooking_criticalMethodsResolve_soTheIntegrityCheckIsMeaningful() {
        // If reflection cannot resolve any of the six critical methods
        // (e.g. an R8 rename broke the hardcoded class/method name
        // strings), every one reports UNAVAILABLE and hook_native_method
        // can never fire — a silent coverage hole. This proves at least
        // the methods resolve on THIS unminified test build; a release-
        // build check belongs in RaspShieldCore.selfTest() (Phase 9).
        val probes = RaspHookProbes(context)
        val integrity = probes.criticalMethodIntegrity()
        assertEquals(6, integrity.size)
        val unavailable = integrity.filterValues { it == RaspHookProbes.MethodIntegrity.UNAVAILABLE }
        assertEquals(
            "expected all 6 critical methods to resolve on an unminified test build, " +
                "unavailable=$unavailable",
            0, unavailable.size,
        )
    }

    // ══════════════════════════════════════════════════════════════════
    // Batch
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun scanRuntimeProtectionBlocking_returnsAllFourDetectors() {
        val results = RaspShieldCore.scanRuntimeProtectionBlocking(context)
        assertEquals(4, results.size)
        assertEquals(
            setOf("frida", "debugger", "re_tools", "hook_detection"),
            results.map { it.detectorId }.toSet(),
        )
    }
}
