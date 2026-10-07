package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The credential's secret never goes on the network.
 *
 * Every request the engine makes to the backend is sent for real
 * (HttpURLConnection) to a local socket server that records the raw request:
 * device registration, an evidence envelope, and GET /v1/ip-risk. None may
 * contain the api_secret, the words api_secret / apiSecret, or the credential
 * JSON. What is sent instead: X-Api-Key (an identifier), X-Timestamp and
 * X-Signature (HMAC-SHA256 computed WITH the secret on the device).
 *
 * Real: RaspDeviceRegistrar, RaspEnvelopeDelivery, RaspGeoIpProbes and their
 * HTTP transports. Fixed inputs: the device key (no Keystore in JVM tests).
 * Not covered here: the legacy HMAC batch (RaspEventShipper.postBatch, private,
 * needs a device); it sets the same three headers (RaspEventShipper.kt).
 */
class RaspCredentialLeakTest {

    private val secret = "s3cr3t-DO-NOT-SEND-7f1c9a"

    private val key = object : RaspRegistrationKeySource {
        override fun deviceKeyId() = "kid-1"
        override fun publicKeyBase64() = "cHVibGljLWtleQ=="
        override fun attestationChainBase64() = listOf("Y2VydA==")
    }

    private class MemoryStore : RaspRegistrationStore {
        var id: String? = null
        override fun registeredKeyId() = id
        override fun setRegisteredKeyId(keyId: String?): Boolean { id = keyId; return true }
    }

    @Test fun `no request to the backend carries the secret or the credential JSON`() {
        FakeHttpServer(bodyFor = { """{"country":"IN","flags":{"blocked_country":false,"proxy":false},"risk_level":"low","reasons":[],"source":"lookup","reason":null,"cached":false}""" }) { req ->
            when {
                req.path.endsWith("/devices/register") -> 201
                req.path.endsWith("/events") -> 202
                else -> 200
            }
        }.use { server ->
            // Built directly: RaspEventCredentialParser uses org.json, a stub in JVM tests.
            val credential = RaspEventCredential("org-1", "app-1", "key-1", secret, "${server.baseUrl}/v1/events")

            val now = System.currentTimeMillis()
            val registrar = RaspDeviceRegistrar(key, MemoryStore(), "com.example.bank", "test",
                signingCertSha256 = { "AB".repeat(32) })
            val delivery = RaspEnvelopeDelivery({ credential }, registrar, clock = { now })
            assertEquals(RaspDeliveryOutcome.DELIVERED,
                delivery.deliver("""{"envelopeVersion":1,"eventTimeMillis":$now,"detectorResults":[]}"""))
            RaspGeoIpProbes.check(credential, RaspGeoIpProbes.HttpTransport, now, "kid-1")

            val paths = server.requests.map { "${it.method} ${it.path}" }
            assertEquals(listOf("POST /v1/devices/register", "POST /v1/events", "GET /v1/ip-risk"), paths)
            for (r in server.requests) {
                val raw = (r.headers.entries.joinToString("\n") { "${it.key}: ${it.value}" } + "\n\n" + r.body)
                assertFalse("${r.path} leaks the secret", raw.contains(secret))
                assertFalse("${r.path} names api_secret", raw.contains("api_secret", ignoreCase = true) || raw.contains("apiSecret"))
                assertFalse("${r.path} carries the credential JSON", raw.contains("\"organization_id\""))
                assertEquals("key-1", r.headers["x-api-key"])
            }
            // The two HMAC-signed requests carry a signature, never the secret itself.
            for (r in server.requests.filter { it.method == "GET" || it.path.endsWith("/register") }) {
                assertTrue(r.headers["x-signature"]!!.matches(Regex("[0-9a-f]{64}")))
                assertEquals(RaspHmacSigner.sign(secret, r.headers["x-timestamp"]!!, r.body.toByteArray()), r.headers["x-signature"])
            }
        }
    }
}
