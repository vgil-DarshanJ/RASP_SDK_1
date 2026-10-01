package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RaspPhase1FixesTest {
    @Test fun `lean shipping sends baseline, changes, and detected heartbeats only`() {
        val policy = RaspLeanShippingPolicy(600)
        val detected = RaspCheckResult.detected("adb_enabled")
        val secure = RaspCheckResult.secure("adb_enabled")

        assertTrue(policy.shouldShip(detected, 0))
        assertFalse(policy.shouldShip(detected, 150))
        assertFalse(policy.shouldShip(detected, 599))
        assertTrue(policy.shouldShip(detected, 600))
        assertTrue(policy.shouldShip(secure, 750))
        assertFalse(policy.shouldShip(secure, 1_500))
    }

    @Test fun `an unreadable SELinux result is UNKNOWN not enforcing`() {
        assertEquals(null, RaspDeviceFingerprintProbes.parseSelinuxValue(null))
        assertEquals(null, RaspDeviceFingerprintProbes.parseSelinuxValue("denied"))
        assertEquals(true, RaspDeviceFingerprintProbes.parseSelinuxValue("Enforcing"))
        assertEquals(false, RaspDeviceFingerprintProbes.parseSelinuxValue("0"))
    }

    @Test fun `known password manager is not accessibility abuse`() {
        val assessment = RaspPrivacyScreenProbes.classifyAccessibilityService(
            "com.bitwarden",
            AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT,
        )
        assertTrue(assessment.allowlisted)
        assertFalse(assessment.detected)
    }

    @Test fun `known assistive service is not accessibility abuse`() {
        val assessment = RaspPrivacyScreenProbes.classifyAccessibilityService(
            "com.google.android.marvin.talkback",
            AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES,
        )
        assertTrue(assessment.allowlisted)
        assertFalse(assessment.detected)
    }

    @Test fun `unknown screen observing accessibility service is detected`() {
        assertTrue(RaspPrivacyScreenProbes.classifyAccessibilityService(
            "example.screen.reader",
            AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT,
        ).detected)
    }

    @Test fun `unknown gesture accessibility service is detected`() {
        assertTrue(RaspPrivacyScreenProbes.classifyAccessibilityService(
            "example.gesture.driver",
            AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES,
        ).detected)
    }

    @Test fun `test keys and debuggable posture cannot convict root`() {
        assertTrue(RaspRootAnalysis.tagsIndicateTestKeys("test-keys"))
        assertTrue(RaspRootAnalysis.propIndicatesDebuggable("1"))
        assertFalse(RaspRootAnalysis.isRooted(emptyList()))
        assertFalse(RaspRootAnalysis.allSignalIds.contains("test_keys"))
        assertFalse(RaspRootAnalysis.allSignalIds.contains("ro_debuggable"))
    }

    @Test fun `overlay permission holder alone is UNKNOWN not DETECTED`() {
        val status = RaspPrivacyScreenProbes.classifyOverlaySignals(listOf(
            RaspOverlaySignal("overlay_permission_holder_present", detected = true, conclusive = true),
            RaspOverlaySignal("touch_obscured", detected = false, conclusive = false),
        ))
        assertEquals(RaspCheckStatus.UNKNOWN, status)
    }

    @Test fun `obscured touch is the overlay DETECTED signal`() {
        val status = RaspPrivacyScreenProbes.classifyOverlaySignals(listOf(
            RaspOverlaySignal("overlay_permission_holder_present", detected = false, conclusive = false),
            RaspOverlaySignal("touch_obscured", detected = true, conclusive = true),
        ))
        assertEquals(RaspCheckStatus.DETECTED, status)
    }
}
