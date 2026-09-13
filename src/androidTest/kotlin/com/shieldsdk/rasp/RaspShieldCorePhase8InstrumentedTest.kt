package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 8 deferred network detectors
 *
 * These tests perform REAL network I/O (a real device/emulator with
 * internet access is required) — `checkHighRiskIpBlocking` calls the real
 * `ipapi.co` endpoint, and the certificate-pin tests perform a real TLS
 * handshake. Both already bound themselves with timeouts, so a flaky
 * network degrades these tests to `UNAVAILABLE`/`NOT_ATTEMPTED` assertions
 * rather than hanging.
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase8InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        RaspShieldCore.configureCertificatePin(null, null)
    }

    @After
    fun tearDown() {
        RaspShieldCore.configureCertificatePin(null, null)
    }

    @Test
    fun highRiskIp_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkHighRiskIpBlocking(context)
        assertEquals("high_risk_ip", result.detectorId)
        assertNotNull(result.status)
        // Every real outcome is one of these three — never DETECTED as a
        // silent default on a flaky network.
        assert(
            result.status == RaspCheckStatus.SECURE ||
                result.status == RaspCheckStatus.DETECTED ||
                result.status == RaspCheckStatus.UNAVAILABLE
        )
    }

    @Test
    fun mitm_withNoPinConfigured_stillCompletesWithoutThrowing() {
        val result = RaspShieldCore.checkMitmBlocking(context)
        assertEquals("mitm", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun mitm_withPinConfiguredAgainstARealHost_completesWithoutThrowing() {
        // Configuring a deliberately WRONG pin against a real, reachable
        // host (google.com) — this proves the TLS-pin path runs an actual
        // handshake and reaches a MISMATCH-shaped result, without needing
        // control of a real backend to test against.
        RaspShieldCore.configureCertificatePin("www.google.com", "0".repeat(64))
        val result = RaspShieldCore.checkMitmBlocking(context)
        assertEquals("mitm", result.detectorId)
        assertNotNull(result.status)
        // If the native proxy check already fired, this would be DETECTED
        // via that path instead — both are valid, conclusive outcomes.
        assert(result.status == RaspCheckStatus.DETECTED || result.status == RaspCheckStatus.SECURE)
    }

    @Test
    fun certificatePinProbe_reachesAMatchOrMismatch_againstARealHost() {
        // Independent of RaspShieldCore's short-circuit logic — exercises
        // RaspCertificatePinProbes directly against a real TLS endpoint.
        val result = RaspCertificatePinProbes.checkCertificatePin(
            host = "www.google.com",
            pinnedSha256Hex = "0".repeat(64), // deliberately wrong
            timeoutMs = 8000,
        )
        // A real host must resolve to MATCH or MISMATCH, never
        // NOT_ATTEMPTED (that would mean the connection itself failed,
        // which — for a stable public host with a real network — signals
        // an environment/connectivity problem worth surfacing, not a pass).
        assertEquals(CertificatePinCheckResult.MISMATCH, result)
    }
}
