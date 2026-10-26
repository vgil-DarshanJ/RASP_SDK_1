package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** RaspPlayIntegrityVerifier against a scripted backend and token source (no Play Services, no network). */
class RaspPlayIntegrityVerifierTest {

    private val credential = RaspEventCredential(
        organizationId = "org", applicationId = "app", apiKey = "rasp_live_k", apiSecret = "secret",
        ingestionUrl = "https://rasp.example/v1/events",
    )

    private class Backend(val challenge: RaspHttpResponse, val verify: RaspHttpResponse) : RaspHttpExchange {
        val calls = mutableListOf<Triple<String, Map<String, String>, String>>()
        override fun post(url: String, headers: Map<String, String>, body: ByteArray): RaspHttpResponse {
            calls += Triple(url, headers, String(body, Charsets.UTF_8))
            return if (url.endsWith("/challenge")) challenge else verify
        }
    }

    private val okChallenge = RaspHttpResponse(200, """{"nonce":"NONCE-123456789012345","expiresInSeconds":300}""")

    private fun verifier(backend: Backend, token: Result<String>? = Result.success("TOKEN"), timeout: Long = 1_000) =
        RaspPlayIntegrityVerifier("com.example.bank", { _, onResult -> token?.let(onResult) }, backend, { 1_700_000_000_000 }, timeout)

    @Test fun `PASS - nonce from the backend goes to Play, token goes back signed`() {
        val seenNonce = mutableListOf<String>()
        val backend = Backend(okChallenge, RaspHttpResponse(200, """{"verdict":"PASS","reasons":[],"appRecognition":"PLAY_RECOGNIZED","deviceRecognition":["MEETS_DEVICE_INTEGRITY"]}"""))
        val outcome = RaspPlayIntegrityVerifier("com.example.bank", { nonce, cb -> seenNonce += nonce; cb(Result.success("TOKEN")) }, backend, { 1_700_000_000_000 })
            .verifyBlocking(credential)
        assertEquals(RaspPlayIntegrityVerifier.Verdict.PASS, outcome.verdict)
        assertEquals(listOf("MEETS_DEVICE_INTEGRITY"), outcome.deviceRecognition)
        assertEquals(listOf("NONCE-123456789012345"), seenNonce)

        val (verifyUrl, headers, body) = backend.calls[1]
        assertEquals("https://rasp.example/v1/integrity/verify", verifyUrl)
        assertEquals(RaspHmacSigner.sign("secret", "1700000000000", body.toByteArray()), headers["X-Signature"])
        assertEquals(mapOf("nonce" to "NONCE-123456789012345", "packageName" to "com.example.bank", "token" to "TOKEN"), RaspJson.parse(body))
        assertEquals("https://rasp.example/v1/integrity/challenge", backend.calls[0].first)
    }

    @Test fun `FAIL carries the backend's reasons`() {
        val backend = Backend(okChallenge, RaspHttpResponse(200, """{"verdict":"FAIL","reasons":["DEVICE_INTEGRITY_FAILED"]}"""))
        val outcome = verifier(backend).verifyBlocking(credential)
        assertEquals(RaspPlayIntegrityVerifier.Verdict.FAIL, outcome.verdict)
        assertEquals(listOf("DEVICE_INTEGRITY_FAILED"), outcome.reasons)
    }

    @Test fun `UNAVAILABLE - backend not configured, network down, no Play Store, timeout, garbage`() {
        val notConfigured = Backend(RaspHttpResponse(503, """{"error":"PLAY_INTEGRITY_NOT_CONFIGURED"}"""), okChallenge)
        assertEquals("PLAY_INTEGRITY_NOT_CONFIGURED", verifier(notConfigured).verifyBlocking(credential).error)
        assertEquals(1, notConfigured.calls.size)

        assertEquals("NETWORK_ERROR", verifier(Backend(RaspHttpResponse(-1, null), okChallenge)).verifyBlocking(credential).error)

        val noPlay = verifier(Backend(okChallenge, okChallenge), Result.failure(IntegrityRequestException("PLAY_STORE_NOT_FOUND")))
        assertEquals("PLAY_STORE_NOT_FOUND", noPlay.verifyBlocking(credential).error)

        assertEquals("TOKEN_TIMEOUT", verifier(Backend(okChallenge, okChallenge), token = null, timeout = 50).verifyBlocking(credential).error)

        val garbage = verifier(Backend(okChallenge, RaspHttpResponse(200, "<html>"))).verifyBlocking(credential)
        assertEquals(RaspPlayIntegrityVerifier.Verdict.UNAVAILABLE, garbage.verdict)
        assertTrue(garbage.reasons.isEmpty())
    }
}
