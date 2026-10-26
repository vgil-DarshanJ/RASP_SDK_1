package com.shieldsdk.rasp

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Play Integrity end to end, with the backend deciding:
 * `POST /v1/integrity/challenge` (one-time nonce) → Play Integrity token on
 * the phone, bound to that nonce → `POST /v1/integrity/verify`, where the
 * backend decodes the token with Google and returns PASS / FAIL with reasons.
 *
 * Both calls are signed like device registration (`X-Api-Key`,
 * `X-Timestamp`, `X-Signature` = HMAC-SHA256 of `"<timestamp>." + body`).
 * The token goes only to the backend and is never logged or stored.
 *
 * Blocking: call it off the main thread.
 */
public class RaspPlayIntegrityVerifier(
    private val packageName: String,
    /** Asks Play Integrity for a token bound to the nonce (production: [RaspPlayIntegrityBridge.requestToken]). */
    private val tokenSource: (nonce: String, onResult: (Result<String>) -> Unit) -> Unit,
    private val exchange: RaspHttpExchange = RaspHttpExchange.URL_CONNECTION,
    private val clock: () -> Long = System::currentTimeMillis,
    private val tokenTimeoutMillis: Long = 30_000,
) {
    public enum class Verdict {
        /** Google and the backend accept this app and device. */
        PASS,
        /** The backend checked the token and refused it; see [Outcome.reasons]. */
        FAIL,
        /** Could not be checked now (no Play Store, network, backend not configured); see [Outcome.error]. */
        UNAVAILABLE,
    }

    public data class Outcome(
        val verdict: Verdict,
        val reasons: List<String> = emptyList(),
        /** Why the check could not run, for [Verdict.UNAVAILABLE]: a backend error code or a Play Integrity error code. */
        val error: String? = null,
        val appRecognition: String? = null,
        val deviceRecognition: List<String> = emptyList(),
    )

    public fun verifyBlocking(credential: RaspEventCredential): Outcome {
        val challengeUrl = RaspBackendUrls.endpoint(credential.ingestionUrl, "integrity/challenge")
        val verifyUrl = RaspBackendUrls.endpoint(credential.ingestionUrl, "integrity/verify")
        if (challengeUrl == null || verifyUrl == null) return unavailable("BAD_INGESTION_URL")

        val challenge = post(credential, challengeUrl, "{}")
        if (challenge.status != 200) return unavailable(errorOf(challenge) ?: "CHALLENGE_HTTP_${challenge.status}")
        val nonce = (parse(challenge.body)?.get("nonce") as? String) ?: return unavailable("CHALLENGE_UNREADABLE")

        val token = requestToken(nonce)
        token.exceptionOrNull()?.let { e ->
            return unavailable((e as? IntegrityRequestException)?.code ?: "TOKEN_REQUEST_FAILED")
        }

        val body = RaspCanonicalJson.encode(mapOf("packageName" to packageName, "nonce" to nonce, "token" to token.getOrThrow()))
        val verified = post(credential, verifyUrl, body)
        if (verified.status != 200) return unavailable(errorOf(verified) ?: "VERIFY_HTTP_${verified.status}")
        val answer = parse(verified.body) ?: return unavailable("VERIFY_UNREADABLE")
        val verdict = when (answer["verdict"]) {
            "PASS" -> Verdict.PASS
            "FAIL" -> Verdict.FAIL
            else -> return unavailable("VERIFY_UNREADABLE")
        }
        return Outcome(
            verdict = verdict,
            reasons = (answer["reasons"] as? List<*>)?.filterIsInstance<String>().orEmpty(),
            appRecognition = answer["appRecognition"] as? String,
            deviceRecognition = (answer["deviceRecognition"] as? List<*>)?.filterIsInstance<String>().orEmpty(),
        )
    }

    private fun requestToken(nonce: String): Result<String> {
        val latch = CountDownLatch(1)
        val result = AtomicReference<Result<String>>()
        try {
            tokenSource(nonce) { r -> result.compareAndSet(null, r); latch.countDown() }
        } catch (e: Exception) {
            return Result.failure(IntegrityRequestException("INTEGRITY_REQUEST_FAILED", e))
        }
        if (!latch.await(tokenTimeoutMillis, TimeUnit.MILLISECONDS)) {
            return Result.failure(IntegrityRequestException("TOKEN_TIMEOUT"))
        }
        return result.get()
    }

    private fun post(credential: RaspEventCredential, url: String, json: String): RaspHttpResponse {
        val bytes = json.toByteArray(Charsets.UTF_8)
        val timestamp = clock().toString()
        return try {
            exchange.post(
                url,
                mapOf(
                    "Content-Type" to "application/json",
                    "X-Api-Key" to credential.apiKey,
                    "X-Timestamp" to timestamp,
                    "X-Signature" to RaspHmacSigner.sign(credential.apiSecret, timestamp, bytes),
                ),
                bytes,
            )
        } catch (e: Exception) {
            RaspHttpResponse(-1, null)
        }
    }

    private fun parse(body: String?): Map<*, *>? = try {
        RaspJson.parse(body ?: "") as? Map<*, *>
    } catch (e: Exception) {
        null
    }

    private fun errorOf(response: RaspHttpResponse): String? =
        if (response.status == -1) "NETWORK_ERROR" else parse(response.body)?.get("error") as? String

    private fun unavailable(error: String) = Outcome(Verdict.UNAVAILABLE, error = error)
}
