package com.shieldsdk.rasp

import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

public enum class CertificatePinCheckResult { MATCH, MISMATCH, NOT_ATTEMPTED }

/**
 * TLS certificate-pinning probe — the deferred half of MITM detection
 * (Phase 8). Verbatim-equivalent port of the Dart layer's
 * `SslPinningService.checkCertificatePin`/`isMitmDetected`'s pinning half,
 * using a permissive `TrustManager` that captures the presented
 * certificate without validating it (mirroring
 * `SecurityContext(withTrustedRoots: false)` +
 * `badCertificateCallback => false` there) — a certificate can be validly
 * issued by a trusted CA and still not be the pinned one (a compromised or
 * coerced CA, an enterprise MITM proxy with a real installed root); only
 * inspecting already-invalid certificates would miss exactly that case.
 *
 * ## Explicit configuration, no backend dependency
 *
 * Unlike the Dart side (which reads a pin baked in at compile time via
 * `String.fromEnvironment`), this native probe takes the pin and host as
 * plain parameters — matching the same "explicit configuration, never
 * magic" pattern [RaspShieldCore.configureExpectedSigningCertificate]
 * already established for repackaging detection. No pin configured means
 * [CertificatePinCheckResult.NOT_ATTEMPTED], never a silent pass.
 */
public object RaspCertificatePinProbes {

    /**
     * `pinnedSha256Hex` must be 64 lowercase hex characters (a raw SHA-256
     * digest of the DER-encoded certificate) — malformed/blank input is
     * treated identically to "not configured."
     */
    fun checkCertificatePin(
        host: String?,
        pinnedSha256Hex: String?,
        port: Int = 443,
        timeoutMs: Int = 5000,
    ): CertificatePinCheckResult {
        val pin = normalizePin(pinnedSha256Hex) ?: return CertificatePinCheckResult.NOT_ATTEMPTED
        if (host.isNullOrBlank()) return CertificatePinCheckResult.NOT_ATTEMPTED

        var presented: X509Certificate? = null
        val capturingTrustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                presented = chain?.firstOrNull()
                // Never trust at this layer — the pin comparison below
                // decides. Intentionally does not throw, so the handshake
                // completes far enough to capture the certificate.
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        var connection: HttpsURLConnection? = null
        return try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(capturingTrustManager), java.security.SecureRandom())

            val url = java.net.URL("https://$host:$port/")
            connection = (url.openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = sslContext.socketFactory
                hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
            }
            try {
                connection.connect()
            } catch (e: Exception) {
                // Connection/handshake failure before a certificate could
                // be captured is reported the same as "not attempted" —
                // never a false mismatch for an offline/unreachable host.
                return CertificatePinCheckResult.NOT_ATTEMPTED
            }

            val cert = presented ?: return CertificatePinCheckResult.NOT_ATTEMPTED
            val observed = MessageDigest.getInstance("SHA-256")
                .digest(cert.encoded)
                .joinToString("") { "%02x".format(it) }

            if (observed == pin) CertificatePinCheckResult.MATCH else CertificatePinCheckResult.MISMATCH
        } catch (e: Exception) {
            CertificatePinCheckResult.NOT_ATTEMPTED
        } finally {
            connection?.disconnect()
        }
    }

    private fun normalizePin(raw: String?): String? {
        val normalized = raw?.replace(":", "")?.replace(" ", "")?.lowercase()
        if (normalized.isNullOrEmpty()) return null
        return normalized.takeIf { Regex("^[0-9a-f]{64}$").matches(it) }
    }
}
