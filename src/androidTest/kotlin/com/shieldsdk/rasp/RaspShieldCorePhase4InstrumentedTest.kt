package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 4 network-security facade (native-only half)
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase4InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    @Test
    fun vpn_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkVpnBlocking(context)
        assertEquals("vpn", result.detectorId)
        assertNotNull(result.status)
        // VPN is a real, conclusive check with no "unavailable" branch —
        // it always resolves to SECURE or DETECTED.
        assert(result.status == RaspCheckStatus.SECURE || result.status == RaspCheckStatus.DETECTED)
    }

    @Test
    fun mitm_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkMitmBlocking(context)
        assertEquals("mitm", result.detectorId)
        assertNotNull(result.status)
        assert(result.status == RaspCheckStatus.SECURE || result.status == RaspCheckStatus.DETECTED)
    }

    @Test
    fun mitm_carriesSourceEvidence_whenDetected() {
        val result = RaspShieldCore.checkMitmBlocking(context)
        if (result.status == RaspCheckStatus.DETECTED) {
            assertEquals(
                "system_proxy_check",
                result.evidence.firstOrNull { it.key == "source" }?.value,
            )
        }
    }

    @Test
    fun scanNetworkSecurityBlocking_returnsAllThreeDetectors() {
        // Includes high_risk_ip (Phase 8, real network I/O) — this call is
        // intentionally heavier than other category batches; see
        // RaspShieldCore.scanNetworkSecurityBlocking's own doc.
        val results = RaspShieldCore.scanNetworkSecurityBlocking(context)
        assertEquals(3, results.size)
        assertEquals(setOf("vpn", "mitm", "high_risk_ip"), results.map { it.detectorId }.toSet())
    }
}
