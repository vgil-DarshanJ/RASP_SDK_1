package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `mitm` verdict (Task 4.8 item 4): each signal on its own, no pin, pin
 * match / mismatch / revoked / not completed / invalid, and probes that
 * could not run.
 *
 * Real: [RaspMitmAnalysis.evaluate], [RaspNetworkProbes.proxySignals] and
 * (for the invalid-pin case) [RaspCertificatePinProbes.checkCertificatePinDetailed].
 * Doubles: the probe results and the pin check's outcome are passed in.
 * Not exercised (need a device / network): the proxy setting, the
 * AndroidCAStore read and a real TLS handshake.
 */
class RaspMitmAnalysisTest {

    private val pin = RaspMitmAnalysis.PinConfig("api.example.com", RaspCertificatePinProbes.PinSet(setOf("sha256/AAAA")))
    private val pinMustNotRun: (RaspMitmAnalysis.PinConfig) -> RaspCertificatePinProbes.PinCheck =
        { throw AssertionError("the pin check must not run") }

    private fun probe(vararg signals: String, failed: Set<String> = emptySet()) =
        RaspNetworkProbes.MitmProbe(signals.toSet(), failed)

    private fun pinCheck(result: CertificatePinCheckResult, observed: List<String> = emptyList()):
        (RaspMitmAnalysis.PinConfig) -> RaspCertificatePinProbes.PinCheck = { RaspCertificatePinProbes.PinCheck(result, observed) }

    private fun RaspCheckResult.values(key: String) = evidence.filter { it.key == key }.map { it.value }

    @Test fun `http proxy alone is DETECTED`() {
        val r = RaspMitmAnalysis.evaluate(probe("http_proxy"), null, pinMustNotRun)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("http_proxy"), r.values("network_signal"))
    }

    @Test fun `https proxy alone is DETECTED`() {
        assertEquals(RaspCheckStatus.DETECTED, RaspMitmAnalysis.evaluate(probe("https_proxy"), null, pinMustNotRun).status)
    }

    @Test fun `user-installed CA alone is DETECTED`() {
        val r = RaspMitmAnalysis.evaluate(probe("user_installed_ca"), null, pinMustNotRun)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("user_installed_ca"), r.values("network_signal"))
    }

    @Test fun `a signal is DETECTED with a pin configured too, without running the pin check`() {
        assertEquals(RaspCheckStatus.DETECTED, RaspMitmAnalysis.evaluate(probe("platform_proxy"), pin, pinMustNotRun).status)
    }

    @Test fun `proxy properties give the http and https proxy signals on their own`() {
        assertEquals(setOf("https_proxy"), RaspNetworkProbes.proxySignals(mapOf("http.proxyHost" to null, "https.proxyHost" to "p.local", "http.proxySet" to null)))
        assertEquals(setOf("http_proxy"), RaspNetworkProbes.proxySignals(mapOf("http.proxyHost" to "p.local", "https.proxyHost" to null, "http.proxySet" to null)))
    }

    @Test fun `no signal and no pin is SECURE with pin_not_configured evidence`() {
        val r = RaspMitmAnalysis.evaluate(probe(), null, pinMustNotRun)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf(true), r.values("pin_not_configured"))
        assertTrue(r.evidence.first { it.key == "pin_not_configured" }.note!!.contains("proxy and user-CA checks only"))
    }

    @Test fun `no signal and no pin but a probe could not run is UNKNOWN, not SECURE`() {
        val r = RaspMitmAnalysis.evaluate(probe(failed = setOf("user_ca_store")), null, pinMustNotRun)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals(listOf("user_ca_store"), r.values("probe_unavailable"))
    }

    @Test fun `pin match is SECURE`() {
        val r = RaspMitmAnalysis.evaluate(probe(), pin, pinCheck(CertificatePinCheckResult.MATCH, listOf("sha256/AAAA")))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf("match"), r.values("tls_pin"))
        assertEquals(emptyList<Any?>(), r.values("pin_not_configured"))
    }

    @Test fun `pin mismatch is DETECTED and names the pins the server presented`() {
        val r = RaspMitmAnalysis.evaluate(probe(), pin, pinCheck(CertificatePinCheckResult.MISMATCH, listOf("sha256/LEAF", "sha256/CA")))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("tls_pinning_probe"), r.values("source"))
        assertEquals(listOf("sha256/LEAF", "sha256/CA"), r.values("observed_pin"))
        assertEquals(listOf("api.example.com"), r.values("pinned_host"))
    }

    @Test fun `revoked pin is DETECTED`() {
        val r = RaspMitmAnalysis.evaluate(probe(), pin, pinCheck(CertificatePinCheckResult.REVOKED))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("tls_spki_revoked"), r.values("source"))
    }

    @Test fun `pin check that did not complete is UNKNOWN`() {
        val r = RaspMitmAnalysis.evaluate(probe(), pin, pinCheck(CertificatePinCheckResult.NOT_ATTEMPTED))
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("TLS pin check did not complete", r.reason)
    }

    @Test fun `pin match but a probe could not run is UNKNOWN`() {
        val r = RaspMitmAnalysis.evaluate(probe(failed = setOf("platform_proxy")), pin, pinCheck(CertificatePinCheckResult.MATCH))
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
    }

    @Test fun `malformed pin in the config is ERROR (real pin check, no network needed)`() {
        val badPin = RaspMitmAnalysis.PinConfig("api.example.com", RaspCertificatePinProbes.PinSet(setOf("not-a-pin")))
        val r = RaspMitmAnalysis.evaluate(probe(), badPin) {
            RaspCertificatePinProbes.checkCertificatePinDetailed(it.host, it.pins)
        }
        assertEquals(RaspCheckStatus.ERROR, r.status)
    }
}
