package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Engine-level heartbeat and change-detection contract for the lean
 * session shipping policy. These checks live here (not in the Flutter
 * facade test) because the policy is pure Kotlin with no Android
 * dependencies — it can be unit-tested directly on the engine.
 */
class RaspLeanSessionHeartbeatTest {

    @Test
    fun `baseline result is always shipped`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val detected = RaspCheckResult.detected("adb_enabled")
        assertTrue(policy.shouldShip(detected, 0))
    }

    @Test
    fun `unchanged result is not re-shipped before heartbeat interval elapses`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val detected = RaspCheckResult.detected("adb_enabled")
        assertTrue(policy.shouldShip(detected, 0))
        assertFalse(policy.shouldShip(detected, 150))
        assertFalse(policy.shouldShip(detected, 599))
    }

    @Test
    fun `detected result is re-shipped after heartbeat interval elapses`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val detected = RaspCheckResult.detected("adb_enabled")
        assertTrue(policy.shouldShip(detected, 0))
        assertTrue(policy.shouldShip(detected, 600))
    }

    @Test
    fun `changed result is shipped immediately regardless of heartbeat interval`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val detected = RaspCheckResult.detected("adb_enabled")
        val secure = RaspCheckResult.secure("adb_enabled")
        assertTrue(policy.shouldShip(detected, 0))
        // Change from DETECTED to SECURE — should ship immediately
        assertTrue(policy.shouldShip(secure, 100))
    }

    @Test
    fun `secure result is not re-shipped when unchanged and before heartbeat`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val secure = RaspCheckResult.secure("adb_enabled")
        assertTrue(policy.shouldShip(secure, 0))
        assertFalse(policy.shouldShip(secure, 150))
        assertFalse(policy.shouldShip(secure, 599))
    }

    @Test
    fun `secure result is not re-shipped after heartbeat interval — heartbeat is threat-only`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val secure = RaspCheckResult.secure("adb_enabled")
        assertTrue(policy.shouldShip(secure, 0))
        // Heartbeat only applies to threat results; secure results are not re-shipped
        assertFalse(policy.shouldShip(secure, 600))
    }

    @Test
    fun `different detectors ship independently`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val adbDetected = RaspCheckResult.detected("adb_enabled")
        val rootDetected = RaspCheckResult.detected("root_jailbreak")
        assertTrue(policy.shouldShip(adbDetected, 0))
        assertTrue(policy.shouldShip(rootDetected, 0))
        // Each detector has its own heartbeat clock
        assertFalse(policy.shouldShip(adbDetected, 100))
        assertFalse(policy.shouldShip(rootDetected, 100))
    }

    @Test
    fun `evidence change triggers immediate re-ship`() {
        val policy = RaspLeanShippingPolicy(heartbeatIntervalMillis = 600)
        val detectedV1 = RaspCheckResult.detected("usb_connection", listOf(RaspEvidence("device_count", 1)))
        val detectedV2 = RaspCheckResult.detected("usb_connection", listOf(RaspEvidence("device_count", 2)))
        assertTrue(policy.shouldShip(detectedV1, 0))
        // Same status but different evidence — should ship
        assertTrue(policy.shouldShip(detectedV2, 100))
    }

    @Test
    fun `overlay touch-obscured is the primary DETECTED signal`() {
        val status = RaspPrivacyScreenProbes.classifyOverlaySignals(listOf(
            RaspOverlaySignal("overlay_permission_holder_present", detected = false, conclusive = false),
            RaspOverlaySignal("touch_obscured", detected = true, conclusive = true),
        ))
        assertEquals(RaspCheckStatus.DETECTED, status)
    }

    @Test
    fun `overlay permission holder alone is UNKNOWN not DETECTED`() {
        val status = RaspPrivacyScreenProbes.classifyOverlaySignals(listOf(
            RaspOverlaySignal("overlay_permission_holder_present", detected = true, conclusive = true),
            RaspOverlaySignal("touch_obscured", detected = false, conclusive = false),
        ))
        assertEquals(RaspCheckStatus.UNKNOWN, status)
    }

    @Test
    fun `overlay touch-obscured not detected is SECURE`() {
        val status = RaspPrivacyScreenProbes.classifyOverlaySignals(listOf(
            RaspOverlaySignal("overlay_permission_holder_present", detected = false, conclusive = false),
            RaspOverlaySignal("touch_obscured", detected = false, conclusive = true),
        ))
        assertEquals(RaspCheckStatus.SECURE, status)
    }

    @Test
    fun `overlay with no conclusive signal is UNKNOWN`() {
        val status = RaspPrivacyScreenProbes.classifyOverlaySignals(listOf(
            RaspOverlaySignal("overlay_permission_holder_present", detected = false, conclusive = false),
            RaspOverlaySignal("touch_obscured", detected = false, conclusive = false),
        ))
        assertEquals(RaspCheckStatus.UNKNOWN, status)
    }
}
