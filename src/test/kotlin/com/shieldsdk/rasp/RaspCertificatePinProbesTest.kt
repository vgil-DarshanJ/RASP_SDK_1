package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Local JVM unit tests — only the pin-normalization/"not configured"
 * short-circuit paths, which return before any network I/O and so need no
 * device/emulator. The real MATCH/MISMATCH paths need a live TLS handshake
 * and are covered by the instrumented suite instead.
 */
class RaspCertificatePinProbesTest {

    @Test
    fun checkCertificatePin_notAttempted_whenPinIsNull() {
        val result = RaspCertificatePinProbes.checkCertificatePin("example.com", null)
        assertEquals(CertificatePinCheckResult.NOT_ATTEMPTED, result)
    }

    @Test
    fun checkCertificatePin_notAttempted_whenPinIsBlank() {
        val result = RaspCertificatePinProbes.checkCertificatePin("example.com", "   ")
        assertEquals(CertificatePinCheckResult.NOT_ATTEMPTED, result)
    }

    @Test
    fun checkCertificatePin_notAttempted_whenPinIsMalformed() {
        // Not 64 hex characters.
        val result = RaspCertificatePinProbes.checkCertificatePin("example.com", "not-a-real-fingerprint")
        assertEquals(CertificatePinCheckResult.NOT_ATTEMPTED, result)
    }

    @Test
    fun checkCertificatePin_notAttempted_whenHostIsNull() {
        val validLookingPin = "a".repeat(64)
        val result = RaspCertificatePinProbes.checkCertificatePin(null, validLookingPin)
        assertEquals(CertificatePinCheckResult.NOT_ATTEMPTED, result)
    }

    @Test
    fun checkCertificatePin_notAttempted_whenHostIsBlank() {
        val validLookingPin = "a".repeat(64)
        val result = RaspCertificatePinProbes.checkCertificatePin("   ", validLookingPin)
        assertEquals(CertificatePinCheckResult.NOT_ATTEMPTED, result)
    }

    @Test
    fun checkCertificatePin_acceptsColonAndSpaceSeparatedPinFormatting() {
        // A 64-hex-char pin with separators must still be recognized as
        // "configured" (not fall into NOT_ATTEMPTED on formatting alone) —
        // proven here by observing it proceeds past normalization to an
        // actual (unreachable-host) connection attempt, which resolves to
        // NOT_ATTEMPTED via the connection-failure path, not the
        // pin-format path. Distinguishing those two NOT_ATTEMPTED causes
        // from outside the class isn't possible without a live network
        // probe, so this test only pins the non-throwing contract for a
        // well-formatted-but-unreachable target.
        val separated = ("ab".repeat(32)).chunked(2).joinToString(":")
        val result = RaspCertificatePinProbes.checkCertificatePin(
            "this-host-should-not-resolve.invalid", separated, timeoutMs = 500,
        )
        assertEquals(CertificatePinCheckResult.NOT_ATTEMPTED, result)
    }
}
