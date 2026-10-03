package com.shieldsdk.rasp

import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection

/** Result of a pin check. A transport failure is deliberately not a pass. */
public enum class CertificatePinCheckResult { MATCH, MISMATCH, REVOKED, NOT_ATTEMPTED, INVALID_CONFIGURATION }

/**
 * SPKI (SubjectPublicKeyInfo) certificate pinning.
 *
 * This probe keeps Android's normal trust-manager and hostname verification in
 * place. It only inspects the peer certificate after a successful, ordinary
 * TLS handshake; it never installs a permissive trust manager or an accepting
 * hostname verifier. Pins use the standard `sha256/<base64>` representation.
 */
public object RaspCertificatePinProbes {
    public data class PinSet(
        val current: Set<String>,
        val backup: Set<String> = emptySet(),
        val revoked: Set<String> = emptySet(),
    ) {
        fun isConfigured(): Boolean = current.isNotEmpty() || backup.isNotEmpty()
    }

    @JvmStatic
    fun checkCertificatePin(
        host: String?,
        pins: PinSet?,
        port: Int = 443,
        timeoutMs: Int = 5_000,
    ): CertificatePinCheckResult {
        if (host.isNullOrBlank() || pins == null || !pins.isConfigured() || timeoutMs <= 0) {
            return CertificatePinCheckResult.INVALID_CONFIGURATION
        }
        val accepted = pins.current + pins.backup
        if (accepted.any { !isPin(it) } || pins.revoked.any { !isPin(it) }) {
            return CertificatePinCheckResult.INVALID_CONFIGURATION
        }

        var connection: HttpsURLConnection? = null
        return try {
            connection = (java.net.URL("https://$host:$port/").openConnection() as HttpsURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "HEAD"
                instanceFollowRedirects = false
            }
            connection.connect()
            val chain = connection.serverCertificates.filterIsInstance<X509Certificate>()
            val observed = chain.map(::spkiPin).toSet()
            when {
                observed.any { it in pins.revoked } -> CertificatePinCheckResult.REVOKED
                observed.any { it in accepted } -> CertificatePinCheckResult.MATCH
                else -> CertificatePinCheckResult.MISMATCH
            }
        } catch (_: Exception) {
            // Includes hostname, platform trust and network failures. None is
            // proof of a clean transport, so callers map this to UNAVAILABLE.
            CertificatePinCheckResult.NOT_ATTEMPTED
        } finally {
            connection?.disconnect()
        }
    }

    /** Backward-compatible convenience for a single SPKI pin. */
    @JvmStatic
    fun checkCertificatePin(host: String?, pin: String?, port: Int = 443, timeoutMs: Int = 5_000): CertificatePinCheckResult =
        checkCertificatePin(host, pin?.let { PinSet(setOf(it)) }, port, timeoutMs)

    // RaspBase64, not java.util.Base64 (API 26; minSdk is 23) and not
    // android.util.Base64 (a stub in JVM unit tests, which would make every
    // pin look malformed there).
    @JvmStatic
    fun spkiPin(certificate: X509Certificate): String =
        "sha256/" + RaspBase64.encode(
            MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded)
        )

    internal fun isPin(value: String): Boolean =
        value.startsWith("sha256/") && value.length > "sha256/".length &&
            RaspBase64.decode(value.removePrefix("sha256/")) != null
}
