package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 9 whole-catalog orchestration
 *
 * `scanAllBlocking`/`selfTest` perform real network I/O (Phase 8's
 * high-risk-IP lookup) — a device/emulator with internet access is
 * required, same as the Phase 8 suite.
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase9InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    @Test
    fun scanAllBlocking_returnsExactlyTwentyFiveDetectors_withNoDuplicates() {
        val results = RaspShieldCore.scanAllBlocking(context)
        val ids = results.map { it.detectorId }
        assertEquals(25, ids.size)
        assertEquals(
            "detector ids must be unique across every category batch — a " +
                "duplicate would mean two categories double-counted one detector",
            ids.size, ids.toSet().size,
        )
    }

    @Test
    fun scanAllBlocking_coversEveryExpectedDetectorId() {
        val ids = RaspShieldCore.scanAllBlocking(context).map { it.detectorId }.toSet()
        val expected = setOf(
            // device integrity
            "root_jailbreak", "emulator", "device_binding", "device_fingerprint",
            "clone", "developer_mode", "adb_enabled", "usb_connection",
            "device_lock_missing", "secure_hardware_unavailable",
            // runtime protection
            "frida", "debugger", "re_tools", "hook_detection",
            // app integrity
            "tamper", "repackage", "untrusted_install_source",
            // network security
            "vpn", "mitm", "high_risk_ip",
            // privacy & screen
            "overlay", "accessibility", "external_display",
            // risky app
            "risky_app", "app_intelligence",
        )
        assertEquals(expected, ids)
    }

    @Test
    fun scanAllAsync_deliversOnMainThread_withTheSameDetectorSet() {
        val latch = java.util.concurrent.CountDownLatch(1)
        var delivered: List<RaspCheckResult>? = null
        var onMainThread = false

        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            RaspShieldCore.scanAllAsync(context) { results ->
                delivered = results
                onMainThread = android.os.Looper.myLooper() == android.os.Looper.getMainLooper()
                latch.countDown()
            }
        }

        assertTrue("scanAllAsync did not complete within 15s", latch.await(15, java.util.concurrent.TimeUnit.SECONDS))
        assertTrue(onMainThread)
        assertEquals(25, delivered?.size)
    }

    @Test
    fun selfTest_completesWithoutThrowing_andReportsReflectionIntact_onThisUnminifiedTestBuild() {
        val report = RaspShieldCore.selfTest(context)
        assertEquals(25, report.results.size)
        // The Flutter instrumentation test APK is never R8-minified, so the
        // six critical-method reflection targets must all resolve here —
        // proving the negative case (a minified release build) requires a
        // real minified build, which is a manual/CI release-pipeline check,
        // not something this on-device suite can fabricate.
        assertTrue(
            "expected critical-method reflection to be intact on an unminified test build",
            report.criticalReflectionIntact,
        )
    }

    @Test
    fun selfTest_erroredDetectorIds_isEmpty_onAHealthyTestRuntime() {
        val report = RaspShieldCore.selfTest(context)
        assertTrue(
            "no detector should ERROR on a healthy test runtime, got ${report.erroredDetectorIds}",
            report.erroredDetectorIds.isEmpty(),
        )
    }
}
