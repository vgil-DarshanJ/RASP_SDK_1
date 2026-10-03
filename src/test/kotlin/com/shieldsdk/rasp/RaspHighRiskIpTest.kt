package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `high_risk_ip` against the backend's `GET /v1/ip-risk` (Task 4.8 item 5).
 *
 * Real: [RaspGeoIpProbes.check] / [RaspGeoIpProbes.evaluate], the URL
 * derivation, [RaspHmacSigner], and the `HttpURLConnection` transport against
 * a local socket server ([FakeHttpServer]) that plays the backend.
 * Not exercised: the real backend (see the backend's own tests), and the
 * per-network cache key (ConnectivityManager needs a device).
 */
class RaspHighRiskIpTest {

    private val now = 1_790_000_000_000L
    private fun credential(ingestionUrl: String) = RaspEventCredential("org-1", "app-1", "key-1", "secret-1", ingestionUrl)

    private fun answer(country: String?, blocked: Boolean?, proxy: Boolean? = false, reason: String? = null, source: String = "lookup") =
        """{"country":${country?.let { "\"$it\"" } ?: "null"},"flags":{"blocked_country":$blocked,"proxy":$proxy,"hosting":null,"private_address":false},"source":"$source","reason":${reason?.let { "\"$it\"" } ?: "null"},"cached":false}"""

    private fun RaspCheckResult.values(key: String) = evidence.filter { it.key == key }.map { it.value }

    @Test fun `endpoint URL is derived from the ingestion URL in the credential`() {
        assertEquals("https://api.example.com/v1/ip-risk", RaspGeoIpProbes.ipRiskUrl("https://api.example.com/v1/events"))
        assertEquals("http://10.0.2.2:4000/v1/ip-risk", RaspGeoIpProbes.ipRiskUrl("http://10.0.2.2:4000/v1/events/"))
    }

    @Test fun `no backend credential is UNAVAILABLE and nothing is sent`() {
        var called = false
        val r = RaspGeoIpProbes.check(null, { _, _ -> called = true; null }, now)
        assertEquals(RaspCheckStatus.UNAVAILABLE, r.status)
        assertEquals(false, called)
    }

    @Test fun `request is a GET to v1 ip-risk, HMAC-signed over the timestamp and an empty body`() {
        FakeHttpServer(bodyFor = { answer("IN", blocked = false) }) { 200 }.use { server ->
            val r = RaspGeoIpProbes.check(credential("${server.baseUrl}/v1/events"), RaspGeoIpProbes.HttpTransport, now)
            assertEquals(RaspCheckStatus.SECURE, r.status)
            val request = server.requests.single()
            assertEquals("GET", request.method)
            assertEquals("/v1/ip-risk", request.path)
            assertEquals("key-1", request.headers["x-api-key"])
            assertEquals(now.toString(), request.headers["x-timestamp"])
            assertEquals(RaspHmacSigner.sign("secret-1", now.toString(), ByteArray(0)), request.headers["x-signature"])
            assertEquals("", request.body)
        }
    }

    @Test fun `empty-body signature matches the vector the backend computes (computeSignature in BE src crypto hmac)`() {
        // Same vector as the backend's test/ipRisk.test.ts: computeSignature("test-secret", "1700000000000", Buffer.alloc(0)).
        assertEquals(
            "27ae51cd1754dbdae532ea92ca49b7a352d4a2d8258c5e1105a6ef52a0c1e7a9",
            RaspHmacSigner.sign("test-secret", "1700000000000", ByteArray(0)),
        )
    }

    @Test fun `dev override answer (private address placed by the backend) is decided by country and flags`() {
        val body = """{"country":"IN","flags":{"blocked_country":true,"proxy":null,"hosting":null,"private_address":true},"source":"dev_override","reason":null,"cached":false}"""
        val r = RaspGeoIpProbes.evaluate(RaspGeoIpProbes.Response(200, body))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("dev_override"), r.values("country_source"))
    }

    @Test fun `blocked country is DETECTED`() {
        val r = RaspGeoIpProbes.evaluate(RaspGeoIpProbes.Response(200, answer("KP", blocked = true)))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("blocked_country"), r.values("high_risk_ip_signal"))
        assertEquals(listOf("KP"), r.values("country"))
    }

    @Test fun `proxy flag from the backend is DETECTED`() {
        val r = RaspGeoIpProbes.evaluate(RaspGeoIpProbes.Response(200, answer("DE", blocked = false, proxy = true)))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("proxy_flag"), r.values("high_risk_ip_signal"))
    }

    @Test fun `allowed country without flags is SECURE with country and source evidence`() {
        val r = RaspGeoIpProbes.evaluate(RaspGeoIpProbes.Response(200, answer("IN", blocked = false, proxy = null, source = "header")))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf("IN"), r.values("country"))
        assertEquals(listOf("header"), r.values("country_source"))
        assertEquals(listOf(false), r.values("proxy_flag_available"))
    }

    @Test fun `country the backend could not determine is UNKNOWN with its reason`() {
        for ((reason, words) in listOf("private_address" to "private address", "no_geo_source" to "no IP geo source", "lookup_failed" to "lookup failed")) {
            val r = RaspGeoIpProbes.evaluate(RaspGeoIpProbes.Response(200, answer(null, blocked = null, proxy = null, reason = reason, source = "none")))
            assertEquals(reason, RaspCheckStatus.UNKNOWN, r.status)
            assertTrue("$reason → ${r.reason}", r.reason!!.contains(words))
        }
    }

    @Test fun `no answer, HTTP errors and unreadable answers are UNKNOWN, never SECURE`() {
        assertEquals(RaspCheckStatus.UNKNOWN, RaspGeoIpProbes.evaluate(null).status)
        for (response in listOf(
            RaspGeoIpProbes.Response(401, """{"error":"SIGNATURE_MISMATCH"}"""),
            RaspGeoIpProbes.Response(429, ""),
            RaspGeoIpProbes.Response(503, ""),
            RaspGeoIpProbes.Response(200, "not json"),
            RaspGeoIpProbes.Response(200, "{}"),
        )) {
            assertEquals("$response", RaspCheckStatus.UNKNOWN, RaspGeoIpProbes.evaluate(response).status)
        }
    }

    @Test fun `backend that refuses the connection is UNKNOWN`() {
        val closedPort = FakeHttpServer { 200 }.let { it.close(); it.port }
        val r = RaspGeoIpProbes.check(credential("http://127.0.0.1:$closedPort/v1/events"), RaspGeoIpProbes.HttpTransport, now)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
    }
}
