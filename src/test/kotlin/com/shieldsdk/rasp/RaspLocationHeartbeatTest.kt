package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicLong

/**
 * Location heartbeat (Task 9.3).
 * Real: RaspLocationHeartbeat (policy and the event it builds), the status
 * mapping, RaspEvidenceEnvelope + RaspEnvelopeDelivery + RaspDeviceRegistrar
 * over real HTTP to a local server (FakeHttpServer).
 * Doubles: a software EC key instead of the Keystore key, an in-memory counter.
 */
class RaspLocationHeartbeatTest {

    private val t0 = 1_790_000_000_000L
    private fun fix(capturedAt: Long = t0, share: Boolean = true, isMock: Boolean? = false) = RaspLocationSnapshot(
        latitude = 21.04538, longitude = 79.03812, accuracyMeters = 12.0,
        capturedAtMillis = capturedAt, isMock = isMock, shareWithBackend = share,
    )
    private fun RaspCheckResult.value(key: String) = evidence.firstOrNull { it.key == key }?.value
    private fun RaspCheckResult.has(key: String) = evidence.any { it.key == key }

    @Test fun `first fix is sent at once, with coarse coordinates, accuracy, fix age and mock flag`() {
        val hb = RaspLocationHeartbeat()
        val action = hb.next(fix(capturedAt = t0 - 5_000), t0) as RaspLocationHeartbeat.Action.Send
        val r = action.result
        assertEquals("location_heartbeat", r.detectorId)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertTrue(r.reason!!.contains("not a security verdict"))
        assertEquals(true, r.value("location_opt_in"))
        assertEquals(21.045, r.value("latitude"))
        assertEquals(79.038, r.value("longitude"))
        assertEquals(12.0, r.value("location_accuracy_m"))
        assertEquals(5L, r.value("location_fix_age_seconds"))
        assertEquals(false, r.value("location_is_mock"))
    }

    @Test fun `then every interval (default 60 s), not on every tick`() {
        val hb = RaspLocationHeartbeat()
        assertTrue(hb.next(fix(), t0) is RaspLocationHeartbeat.Action.Send)
        assertNull(hb.next(fix(capturedAt = t0 + 30_000), t0 + 30_000))
        assertNull(hb.next(fix(capturedAt = t0 + 59_000), t0 + 59_999))
        assertTrue(hb.next(fix(capturedAt = t0 + 60_000), t0 + 60_000) is RaspLocationHeartbeat.Action.Send)
    }

    @Test fun `interval is configurable with a 30 s minimum`() {
        assertEquals(30_000L, RaspLocationHeartbeat(5_000).intervalMillis)
        assertEquals(90_000L, RaspLocationHeartbeat(90_000).intervalMillis)
        val hb = RaspLocationHeartbeat(1_000)
        hb.next(fix(), t0)
        assertNull(hb.next(fix(capturedAt = t0 + 10_000), t0 + 10_000))
        assertTrue(hb.next(fix(capturedAt = t0 + 30_000), t0 + 30_000) is RaspLocationHeartbeat.Action.Send)
    }

    @Test fun `no heartbeat without sharing, and a fix older than 2 minutes is not sent`() {
        val hb = RaspLocationHeartbeat()
        assertNull(hb.next(null, t0))
        assertNull(hb.next(fix(share = false), t0))
        assertNull("stale", hb.next(fix(capturedAt = t0 - 120_001), t0))
        assertTrue(hb.next(fix(capturedAt = t0 - 120_000), t0) is RaspLocationHeartbeat.Action.Send)
        val fresh = RaspLocationHeartbeat()
        assertNull("from the future", fresh.next(fix(capturedAt = t0 + 3_600_000), t0))
    }

    @Test fun `turning sharing off sends one cleared message without coordinates, then nothing`() {
        val hb = RaspLocationHeartbeat()
        hb.next(fix(), t0)
        val clear = hb.next(null, t0 + 1_000) as RaspLocationHeartbeat.Action.Clear
        assertEquals(false, clear.result.value("location_opt_in"))
        assertFalse(clear.result.has("latitude") || clear.result.has("longitude"))
        assertNull(hb.next(null, t0 + 2_000))
        assertNull(hb.next(fix(share = false), t0 + 3_000))
        // Sharing again: the next fix counts as a first fix.
        assertTrue(hb.next(fix(capturedAt = t0 + 4_000), t0 + 4_000) is RaspLocationHeartbeat.Action.Send)
    }

    @Test fun `delivery outcomes become a short status for the screen`() {
        assertEquals(RaspLocationHeartbeatStatus.Outcome.DELIVERED, RaspLocationHeartbeatStatus.fromDelivery(RaspDeliveryOutcome.DELIVERED, t0, false).outcome)
        assertEquals("rejected by the backend", RaspLocationHeartbeatStatus.fromDelivery(RaspDeliveryOutcome.DROPPED, t0, false).detail)
        assertEquals(RaspLocationHeartbeatStatus.Outcome.NOT_DELIVERED, RaspLocationHeartbeatStatus.fromDelivery(RaspDeliveryOutcome.RETRY_LATER, t0, false).outcome)
        assertEquals("HTTP 400", RaspLocationHeartbeatStatus.fromHttpStatus(400, t0, false).detail)
        assertEquals(RaspLocationHeartbeatStatus.Outcome.NOT_DELIVERED, RaspLocationHeartbeatStatus.fromHttpStatus(-1, t0, true).outcome)
        assertTrue(RaspLocationHeartbeatStatus.fromHttpStatus(202, t0, true).cleared)
    }

    @Test fun `a heartbeat envelope is signed and delivered on its own over real HTTP`() {
        val keys = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
        val signer = object : RaspEnvelopeSigner {
            override fun publicKeySpki() = keys.public.encoded
            override fun signDer(payload: ByteArray): ByteArray? = Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(payload); sign() }
        }
        val counter = AtomicLong()
        val counterStore = object : RaspEnvelopeCounterStore {
            override fun next(): Long = counter.incrementAndGet()
        }
        val envelope = RaspEvidenceEnvelope(signer, counterStore, "com.example.bank", "test", clock = { System.currentTimeMillis() })
        val result = (RaspLocationHeartbeat().next(fix(capturedAt = System.currentTimeMillis()), System.currentTimeMillis()) as RaspLocationHeartbeat.Action.Send).result
        val json = envelope.build(listOf(result))!!
        FakeHttpServer { if (it.path == "/v1/devices/register") 201 else 201 }.use { server ->
            val keySource = object : RaspRegistrationKeySource {
                override fun deviceKeyId() = RaspEvidenceEnvelope.deviceKeyId(keys.public.encoded)
                override fun publicKeyBase64() = RaspBase64.encode(keys.public.encoded)
                override fun attestationChainBase64() = listOf("LEAF")
            }
            val store = object : RaspRegistrationStore {
                var id: String? = null
                override fun registeredKeyId() = id
                override fun setRegisteredKeyId(keyId: String?): Boolean { id = keyId; return true }
            }
            val credential = RaspEventCredential("org", "app", "api-key-1", "secret-1", "${server.baseUrl}/v1/events")
            val delivery = RaspEnvelopeDelivery({ credential }, RaspDeviceRegistrar(keySource, store, "com.example.bank", "test"))
            val status = RaspLocationHeartbeatStatus.fromDelivery(delivery.deliver(json), t0, cleared = false)
            assertEquals(RaspLocationHeartbeatStatus.Outcome.DELIVERED, status.outcome)
            val posted = server.requests.last()
            assertEquals("/v1/events", posted.path)
            assertTrue(posted.body.contains("\"detectorId\":\"location_heartbeat\""))
            assertTrue(posted.body.contains("\"value\":21.045"))
            assertFalse("only coarse coordinates leave the device", posted.body.contains("21.04538"))
            assertFalse(posted.body.contains("secret-1"))
        }
    }
}
