package com.shieldsdk.rasp

/**
 * `mitm` verdict. Pure: the probes and the TLS pin check are passed in.
 *
 * 1. Any proxy or user-CA signal (`http_proxy`, `https_proxy`,
 *    `http_proxy_set`, `platform_proxy`, `user_installed_ca`) → DETECTED on
 *    its own. The pin check is skipped.
 * 2. No pin configured → SECURE with evidence `pin_not_configured`: the
 *    verdict covers the proxy and user-CA checks only. If one of those probes
 *    could not run → UNKNOWN instead.
 * 3. Pin configured → the SPKI check runs:
 *    - mismatch or revoked pin → DETECTED (observed pins in evidence);
 *    - match → SECURE (UNKNOWN if a proxy/CA probe could not run);
 *    - check did not complete (network, TLS or hostname failure) → UNKNOWN;
 *    - a pin that is not `sha256/` + Base64 of exactly 32 bytes → ERROR
 *      "invalid pin".
 */
object RaspMitmAnalysis {

    const val DETECTOR_ID = "mitm"

    /** Host and pins for the SPKI check. */
    data class PinConfig(val host: String, val pins: RaspCertificatePinProbes.PinSet)

    /** The probes [RaspNetworkProbes.mitmProbe] runs; listed in SECURE evidence. */
    private const val CHECKED = "http_proxy,https_proxy,platform_proxy,user_installed_ca"

    fun evaluate(
        probe: RaspNetworkProbes.MitmProbe,
        pin: PinConfig?,
        pinCheck: (PinConfig) -> RaspCertificatePinProbes.PinCheck,
    ): RaspCheckResult {
        val failed = probe.failedProbes.sorted().map { RaspEvidence("probe_unavailable", it) }

        if (probe.signals.isNotEmpty()) {
            return RaspCheckResult.detected(
                DETECTOR_ID, probe.signals.sorted().map { RaspEvidence("network_signal", it) } + failed,
            )
        }

        if (pin == null) {
            if (failed.isNotEmpty()) return unknown("Proxy or user-CA check could not run", failed)
            return RaspCheckResult.secure(
                DETECTOR_ID,
                listOf(
                    RaspEvidence("pin_not_configured", true, "SECURE covers the proxy and user-CA checks only"),
                    RaspEvidence("checked", CHECKED),
                ),
            )
        }

        val check = pinCheck(pin)
        val pinEvidence = listOf(RaspEvidence("pinned_host", pin.host)) +
            check.observedPins.map { RaspEvidence("observed_pin", it) }
        return when (check.result) {
            CertificatePinCheckResult.MISMATCH -> RaspCheckResult.detected(
                DETECTOR_ID, listOf(RaspEvidence("source", "tls_pinning_probe")) + pinEvidence + failed,
            )
            CertificatePinCheckResult.REVOKED -> RaspCheckResult.detected(
                DETECTOR_ID, listOf(RaspEvidence("source", "tls_spki_revoked")) + pinEvidence + failed,
            )
            CertificatePinCheckResult.NOT_ATTEMPTED ->
                unknown("TLS pin check did not complete", pinEvidence + failed)
            CertificatePinCheckResult.INVALID_CONFIGURATION -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.ERROR,
                listOf(RaspEvidence("pin_format", "sha256/<Base64 of 32 bytes>")),
                reason = "invalid pin",
            )
            CertificatePinCheckResult.MATCH ->
                if (failed.isNotEmpty()) unknown("Proxy or user-CA check could not run", pinEvidence + failed)
                else RaspCheckResult.secure(
                    DETECTOR_ID,
                    listOf(RaspEvidence("tls_pin", "match"), RaspEvidence("checked", CHECKED)) + pinEvidence,
                )
        }
    }

    private fun unknown(reason: String, evidence: List<RaspEvidence>) =
        RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = reason)
}
