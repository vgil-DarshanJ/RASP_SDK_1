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
 * # INSTRUMENTATION TESTS — Phase 3 app-integrity facade
 *
 * Covers tamper, repackaging/signature, and untrusted-install-source.
 *
 * ## What's genuinely verifiable here
 *
 * The test APK's own signing certificate IS this suite's real signing
 * certificate — so a test can compute the real fingerprint via
 * [RaspSigningProbes.signingCertSha256] and configure it as the "expected"
 * one, proving the match path works end-to-end without needing a second,
 * differently-signed build. Configuring an intentionally wrong fingerprint
 * then proves the mismatch path. Both are exercised against the real
 * running certificate — nothing is mocked.
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase3InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        RaspShieldCore.configureExpectedSigningCertificate(null)
    }

    @After
    fun tearDown() {
        // Never leak configuration across tests — the whole point of
        // making this explicit configuration (not reflection) is that it
        // is easy to reset deterministically.
        RaspShieldCore.configureExpectedSigningCertificate(null)
    }

    @Test
    fun repackaging_reportsUnavailable_whenNotConfigured() {
        val result = RaspShieldCore.checkRepackagingBlocking(context)
        assertEquals("repackage", result.detectorId)
        assertEquals(RaspCheckStatus.UNAVAILABLE, result.status)
        assertNotNull(result.reason)
    }

    @Test
    fun repackaging_reportsSecure_whenConfiguredWithTheRealFingerprint() {
        val realFingerprint = RaspSigningProbes.signingCertSha256(context)
        // Should always be readable on a real running app — if this is
        // empty, the test environment itself is broken, not the detector.
        assert(realFingerprint.isNotEmpty()) { "test APK's own signing cert must be readable" }

        RaspShieldCore.configureExpectedSigningCertificate(realFingerprint)
        val result = RaspShieldCore.checkRepackagingBlocking(context)
        assertEquals(RaspCheckStatus.SECURE, result.status)
    }

    @Test
    fun repackaging_reportsDetected_whenConfiguredWithAWrongFingerprint() {
        RaspShieldCore.configureExpectedSigningCertificate(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        val result = RaspShieldCore.checkRepackagingBlocking(context)
        assertEquals(RaspCheckStatus.DETECTED, result.status)
    }

    @Test
    fun repackaging_normalizesFingerprintFormatting() {
        // configureExpectedSigningCertificate must strip ':'/spaces/dashes
        // and uppercase, matching how a fingerprint is commonly copied
        // from `keytool`/Play Console output.
        val realFingerprint = RaspSigningProbes.signingCertSha256(context)
        val withSeparators = realFingerprint.chunked(2).joinToString(":").lowercase()

        RaspShieldCore.configureExpectedSigningCertificate(withSeparators)
        val result = RaspShieldCore.checkRepackagingBlocking(context)
        assertEquals(
            "a colon-separated, lowercase fingerprint must still match after normalization",
            RaspCheckStatus.SECURE, result.status,
        )
    }

    @Test
    fun tamper_completesWithoutThrowing_regardlessOfConfiguration() {
        val result = RaspShieldCore.checkTamperBlocking(context)
        assertEquals("tamper", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun tamper_isMeaningfulEvenWithNoExpectedCertificateConfigured() {
        // Unlike repackaging, tamper must not report UNAVAILABLE just
        // because no fingerprint is configured — the install-directory
        // check alone still means something.
        val result = RaspShieldCore.checkTamperBlocking(context)
        assert(result.status == RaspCheckStatus.SECURE || result.status == RaspCheckStatus.DETECTED) {
            "expected a conclusive tamper verdict with no configuration, got ${result.status}"
        }
    }

    @Test
    fun untrustedInstallSource_completesWithoutThrowing() {
        val result = RaspShieldCore.checkUntrustedInstallSourceBlocking(context)
        assertEquals("untrusted_install_source", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun scanAppIntegrityBlocking_returnsAllThreeDetectors() {
        val results = RaspShieldCore.scanAppIntegrityBlocking(context)
        assertEquals(3, results.size)
        assertEquals(
            setOf("tamper", "repackage", "untrusted_install_source"),
            results.map { it.detectorId }.toSet(),
        )
    }
}
