package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Test

class RaspCertificatePinProbesTest {
    @Test fun `blank host is invalid not a clean result`() {
        assertEquals(CertificatePinCheckResult.INVALID_CONFIGURATION,
            RaspCertificatePinProbes.checkCertificatePin("", RaspCertificatePinProbes.PinSet(setOf("sha256/AA=="))))
    }

    @Test fun `malformed current pin is invalid`() {
        assertEquals(CertificatePinCheckResult.INVALID_CONFIGURATION,
            RaspCertificatePinProbes.checkCertificatePin("example.com", RaspCertificatePinProbes.PinSet(setOf("not-a-pin"))))
    }

    @Test fun `pin set accepts backup and revoked sets as configured`() {
        val pins = RaspCertificatePinProbes.PinSet(setOf("sha256/AA=="), setOf("sha256/AQ=="), setOf("sha256/Ag=="))
        assert(pins.isConfigured())
    }
}
