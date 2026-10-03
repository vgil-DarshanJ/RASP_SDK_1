package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * minSdk 23 replacements (Task 4.6): SPKI pins without java.util.Base64, and
 * the API 30 managed-profile check behind an SDK_INT guard.
 *
 * Real: RaspCertificatePinProbes.spkiPin/isPin on a real X.509 certificate
 * (test resource), compared with java.util.Base64 (available on the JVM);
 * RaspCloneProbes.secondaryUserSignal. The UserManager call itself is
 * replaced by a lambda (no Android framework on the JVM).
 */
class RaspMinSdkFixesTest {

    private val cert: X509Certificate = run {
        val fixtures = RaspJson.parse(
            javaClass.classLoader!!.getResourceAsStream("attestation-fixtures.json")!!.readBytes().toString(Charsets.UTF_8),
        ) as Map<*, *>
        val der = java.util.Base64.getDecoder().decode(fixtures["lockedVerifiedStrongBox"] as String)
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    @Test fun `spkiPin equals sha256 of the SPKI in standard Base64`() {
        val expected = "sha256/" + java.util.Base64.getEncoder()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))
        assertEquals(expected, RaspCertificatePinProbes.spkiPin(cert))
    }

    @Test fun `pin syntax check accepts real pins and rejects malformed ones`() {
        assertTrue(RaspCertificatePinProbes.isPin(RaspCertificatePinProbes.spkiPin(cert)))
        // Task 4.10: only Base64 of exactly 32 bytes; "sha256/AA==" (1 byte) is no longer a pin.
        for (bad in listOf("sha256/AA==", "sha256/", "AA==", "sha1/AA==", "sha256/not base64!", "sha256/A=A")) {
            assertFalse(bad, RaspCertificatePinProbes.isPin(bad))
        }
    }

    @Test fun `managed-profile check is inconclusive below API 30 and never called there`() {
        var called = false
        val s = RaspCloneProbes.secondaryUserSignal(29) { called = true; true }
        assertFalse(s.conclusive)
        assertFalse(s.detected)
        assertEquals("managed_profile_check_needs_api_30", s.reason)
        assertFalse("UserManager.isManagedProfile must not run below API 30", called)
    }

    @Test fun `managed-profile check decides from API 30`() {
        val work = RaspCloneProbes.secondaryUserSignal(30) { true }
        assertTrue(work.conclusive)
        assertFalse(work.detected)
        val clone = RaspCloneProbes.secondaryUserSignal(34) { false }
        assertTrue(clone.conclusive)
        assertTrue(clone.detected)
        val failing = RaspCloneProbes.secondaryUserSignal(34) { throw SecurityException("x") }
        assertFalse(failing.conclusive)
    }
}
