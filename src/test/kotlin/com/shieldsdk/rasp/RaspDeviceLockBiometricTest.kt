package com.shieldsdk.rasp

import com.shieldsdk.rasp.RaspDeviceFingerprintProbes.BiometricState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * device_lock_missing with fingerprint enrolment: an enrolled fingerprint is
 * safe, none enrolled is a (low-severity) DETECTED, unreadable is UNKNOWN.
 *
 * Real: [RaspDeviceFingerprintProbes.evaluateDeviceLock] and
 * [RaspDeviceFingerprintProbes.biometricStateOf].
 * Not exercised (needs a device): [RaspDeviceFingerprintProbes.biometricState]
 * (BiometricManager).
 */
class RaspDeviceLockBiometricTest {

    private fun verdict(secure: Boolean?, bio: BiometricState) =
        RaspDeviceFingerprintProbes.evaluateDeviceLock(secure, bio)

    @Test fun `lock and enrolled fingerprint is secure`() {
        val r = verdict(true, BiometricState.ENROLLED)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertTrue(r.evidence.any { it.key == "biometric" && it.value == "enrolled" })
    }

    @Test fun `lock without an enrolled fingerprint is detected`() {
        val r = verdict(true, BiometricState.NONE_ENROLLED)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertTrue(r.evidence.any { it.key == "biometric" && it.value == "not_enrolled" })
        assertTrue(r.evidence.any { it.key == "screen_lock" && it.value == "set" })
    }

    @Test fun `no screen lock at all is detected whatever the biometric state says`() {
        for (bio in BiometricState.values()) {
            assertEquals(RaspCheckStatus.DETECTED, verdict(false, bio).status)
        }
    }

    @Test fun `lock on a phone without biometric hardware is secure`() {
        assertEquals(RaspCheckStatus.SECURE, verdict(true, BiometricState.NO_HARDWARE).status)
    }

    @Test fun `an unreadable state is unknown and never secure`() {
        assertEquals(RaspCheckStatus.UNKNOWN, verdict(null, BiometricState.ENROLLED).status)
        assertEquals(RaspCheckStatus.UNKNOWN, verdict(true, BiometricState.UNKNOWN).status)
    }

    @Test fun `platform codes map to states and unlisted codes are unknown`() {
        assertEquals(BiometricState.ENROLLED, RaspDeviceFingerprintProbes.biometricStateOf(0))
        assertEquals(BiometricState.NONE_ENROLLED, RaspDeviceFingerprintProbes.biometricStateOf(11))
        assertEquals(BiometricState.NO_HARDWARE, RaspDeviceFingerprintProbes.biometricStateOf(12))
        for (code in listOf(1, 15, -1, -2, 99)) {
            assertEquals(BiometricState.UNKNOWN, RaspDeviceFingerprintProbes.biometricStateOf(code))
        }
        assertEquals(BiometricState.UNKNOWN, RaspDeviceFingerprintProbes.biometricStateOf(null))
    }
}
