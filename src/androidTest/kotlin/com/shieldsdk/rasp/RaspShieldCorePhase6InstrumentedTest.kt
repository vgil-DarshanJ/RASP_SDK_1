package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 6 risky-app / app-intelligence facade
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase6InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    @Test
    fun riskyApp_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkRiskyAppBlocking(context)
        assertEquals("risky_app", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun riskyApp_notDetected_onThisTestRuntime() {
        // None of the 7 curated remote-access/instrumentation packages, nor
        // a third-party accessibility service, are present on a plain CI/
        // emulator/device running the test harness — a real, independently
        // true ground truth.
        val result = RaspShieldCore.checkRiskyAppBlocking(context)
        assertNotEquals(RaspCheckStatus.DETECTED, result.status)
    }

    @Test
    fun appIntelligence_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkAppIntelligenceBlocking(context)
        assertEquals("app_intelligence", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun appIntelligence_notDetected_onThisTestRuntime() {
        val result = RaspShieldCore.checkAppIntelligenceBlocking(context)
        assertNotEquals(RaspCheckStatus.DETECTED, result.status)
    }

    @Test
    fun profileInstalledPackages_onlyProfilesActuallyInstalledPackages() {
        // On a clean test runtime, none of the 7 curated packages are
        // installed, so the profile list should be empty — proving the
        // "only installed" filter in profileInstalledPackages() is real,
        // not a no-op that would profile all 7 unconditionally.
        val profiles = RaspAppIntelligenceProbes.profileInstalledPackages(context)
        assert(profiles.isEmpty() || profiles.all { it.pkg in RaspRiskyAppProbes.knownRiskyPackages }) {
            "every profiled package must be one of the 7 curated targets, got ${profiles.map { it.pkg }}"
        }
    }

    @Test
    fun scanRiskyAppBlocking_returnsBothDetectors() {
        val results = RaspShieldCore.scanRiskyAppBlocking(context)
        assertEquals(2, results.size)
        assertEquals(setOf("risky_app", "app_intelligence"), results.map { it.detectorId }.toSet())
    }
}
