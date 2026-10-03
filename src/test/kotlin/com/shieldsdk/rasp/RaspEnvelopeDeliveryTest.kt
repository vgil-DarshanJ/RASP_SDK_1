package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

/**
 * What each backend response does to a queued envelope, and device
 * registration, over real HTTP to a fake server on 127.0.0.1.
 *
 * Real: [RaspEnvelopeDelivery], [RaspDeviceRegistrar] (request body, HMAC
 * headers, URL), [RaspHttpPost.URL_CONNECTION] (HttpURLConnection),
 * [RaspOfflineQueue], RaspHmacSigner.
 * Doubles: [FakeHttpServer] (scripted backend), [FixedKey] (device key —
 * Android Keystore is not on the JVM), [MemoryRegistrationStore] (instead of
 * EncryptedSharedPreferences).
 */
class RaspEnvelopeDeliveryTest {

    private class FixedKey(var keyId: String = "key-1") : RaspRegistrationKeySource {
        override fun deviceKeyId() = keyId
        override fun publicKeyBase64() = "PUBLIC-$keyId"
        override fun attestationChainBase64() = listOf("LEAF", "ROOT")
    }

    private class MemoryRegistrationStore : RaspRegistrationStore {
        @Volatile var keyId: String? = null
        override fun registeredKeyId() = keyId
        override fun setRegisteredKeyId(keyId: String?): Boolean { this.keyId = keyId; return true }
    }

    private val now = 1_790_000_000_000L
    private val freshEnvelope = """{"envelopeVersion":1,"eventTimeMillis":${now - 60_000}}"""

    /** Scripted backend: each path answers with the next status of its list (last one repeats). */
    private class Script(vararg routes: Pair<String, List<Int>>) {
        private val queues = ConcurrentHashMap(routes.toMap().mapValues { ArrayDeque(it.value) })
        fun answer(path: String): Int {
            val q = queues[path] ?: return 404
            return if (q.size > 1) q.removeFirst() else q.first()
        }
    }

    private inner class Setup(script: Script) : AutoCloseable {
        val server = FakeHttpServer { script.answer(it.path) }
        val store = MemoryRegistrationStore()
        val key = FixedKey()
        val credential = RaspEventCredential("org", "app", "api-key-1", "secret-1", "${server.baseUrl}/v1/events")
        val registrar = RaspDeviceRegistrar(key, store, appId = "com.example.bank", sdkVersion = "test", clock = { now })
        val delivery = RaspEnvelopeDelivery({ credential }, registrar, clock = { now })
        fun paths() = server.requests.map { it.path }
        override fun close() = server.close()
    }

    // ── registration ─────────────────────────────────────────────────────

    @Test fun `first delivery registers the device key, then sends - later deliveries do not register again`() {
        Setup(Script("/v1/devices/register" to listOf(201), "/v1/events" to listOf(201))).use { s ->
            assertEquals(RaspDeliveryOutcome.DELIVERED, s.delivery.deliver(freshEnvelope))
            assertEquals(RaspDeliveryOutcome.DELIVERED, s.delivery.deliver(freshEnvelope))
            assertEquals(listOf("/v1/devices/register", "/v1/events", "/v1/events"), s.paths())
            assertEquals("key-1", s.store.keyId)

            val register = s.server.requests[0]
            assertEquals("""{"appId":"com.example.bank","attestationChain":["LEAF","ROOT"],"publicKey":"PUBLIC-key-1","sdkVersion":"test"}""", register.body)
            assertEquals("api-key-1", register.headers["x-api-key"])
            assertEquals(now.toString(), register.headers["x-timestamp"])
            assertEquals(RaspHmacSigner.sign("secret-1", now.toString(), register.body.toByteArray()), register.headers["x-signature"])

            val events = s.server.requests[1]
            assertEquals("api-key-1", events.headers["x-api-key"])
            assertNull("envelopes carry no HMAC", events.headers["x-signature"])
        }
    }

    @Test fun `already registered key is not registered again after a restart`() {
        Setup(Script("/v1/events" to listOf(201))).use { s ->
            s.store.keyId = "key-1" // stored by an earlier run
            assertEquals(RaspDeliveryOutcome.DELIVERED, s.delivery.deliver(freshEnvelope))
            assertEquals(listOf("/v1/events"), s.paths())
        }
    }

    @Test fun `a new device key is registered even if an old one was stored`() {
        Setup(Script("/v1/devices/register" to listOf(201), "/v1/events" to listOf(201))).use { s ->
            s.store.keyId = "old-key"
            s.delivery.deliver(freshEnvelope)
            assertEquals(listOf("/v1/devices/register", "/v1/events"), s.paths())
            assertEquals("key-1", s.store.keyId)
        }
    }

    @Test fun `registration failing with 5xx or no network keeps the envelope and sends nothing`() {
        Setup(Script("/v1/devices/register" to listOf(503))).use { s ->
            assertEquals(RaspDeliveryOutcome.RETRY_LATER, s.delivery.deliver(freshEnvelope))
            assertEquals(listOf("/v1/devices/register"), s.paths())
            assertNull(s.store.keyId)
        }
        val closedPort = java.net.ServerSocket(0).use { it.localPort }
        val registrar = RaspDeviceRegistrar(FixedKey(), MemoryRegistrationStore(), "com.example.bank", clock = { now })
        val credential = RaspEventCredential("o", "a", "k", "s", "http://127.0.0.1:$closedPort/v1/events")
        assertEquals(RaspDeliveryOutcome.RETRY_LATER, RaspEnvelopeDelivery({ credential }, registrar, clock = { now }).deliver(freshEnvelope))
    }

    @Test fun `registration URL is derived from the ingestion URL`() {
        assertEquals("https://api.bank.test/v1/devices/register", RaspDeviceRegistrar.registrationUrl("https://api.bank.test/v1/events"))
        assertEquals("https://api.bank.test/v1/devices/register", RaspDeviceRegistrar.registrationUrl("https://api.bank.test/v1/events/"))
    }

    // ── 401: re-register, retry once ─────────────────────────────────────

    @Test fun `401 re-registers the device and retries once, then delivers`() {
        Setup(Script("/v1/devices/register" to listOf(201), "/v1/events" to listOf(401, 201))).use { s ->
            s.store.keyId = "key-1"
            assertEquals(RaspDeliveryOutcome.DELIVERED, s.delivery.deliver(freshEnvelope))
            assertEquals(listOf("/v1/events", "/v1/devices/register", "/v1/events"), s.paths())
            assertEquals(1L, s.delivery.stats.snapshot()["re_registrations"])
        }
    }

    @Test fun `a second 401 after re-registration drops and counts the envelope`() {
        Setup(Script("/v1/devices/register" to listOf(201), "/v1/events" to listOf(401, 401))).use { s ->
            s.store.keyId = "key-1"
            assertEquals(RaspDeliveryOutcome.DROPPED, s.delivery.deliver(freshEnvelope))
            assertEquals(listOf("/v1/events", "/v1/devices/register", "/v1/events"), s.paths())
            assertEquals(1L, s.delivery.stats.snapshot()["dropped_unauthorized"])
        }
    }

    @Test fun `401 with re-registration unreachable keeps the envelope`() {
        Setup(Script("/v1/devices/register" to listOf(503), "/v1/events" to listOf(401))).use { s ->
            s.store.keyId = "key-1"
            assertEquals(RaspDeliveryOutcome.RETRY_LATER, s.delivery.deliver(freshEnvelope))
            assertNull("registration was forgotten, so the next attempt registers first", s.store.keyId)
        }
    }

    // ── drop cases ───────────────────────────────────────────────────────

    @Test fun `400 and 422 drop the envelope and count it as invalid`() {
        for (status in listOf(400, 422)) {
            Setup(Script("/v1/events" to listOf(status))).use { s ->
                s.store.keyId = "key-1"
                assertEquals("$status", RaspDeliveryOutcome.DROPPED, s.delivery.deliver(freshEnvelope))
                assertEquals(1L, s.delivery.stats.snapshot()["dropped_invalid"])
                assertEquals(1, s.server.requests.size)
            }
        }
    }

    @Test fun `an event older than 7 days is dropped without being sent`() {
        Setup(Script("/v1/events" to listOf(201))).use { s ->
            s.store.keyId = "key-1"
            val old = """{"envelopeVersion":1,"eventTimeMillis":${now - RaspEnvelopeDelivery.MAX_EVENT_AGE_MS - 1}}"""
            assertEquals(RaspDeliveryOutcome.DROPPED, s.delivery.deliver(old))
            assertTrue(s.server.requests.isEmpty())
            assertEquals(1L, s.delivery.stats.snapshot()["dropped_expired"])
            // Just inside the limit is still sent.
            val edge = """{"envelopeVersion":1,"eventTimeMillis":${now - RaspEnvelopeDelivery.MAX_EVENT_AGE_MS + 1000}}"""
            assertEquals(RaspDeliveryOutcome.DELIVERED, s.delivery.deliver(edge))
        }
    }

    @Test fun `other 4xx responses drop the envelope as rejected`() {
        for (status in listOf(403, 404, 409, 413)) {
            Setup(Script("/v1/events" to listOf(status))).use { s ->
                s.store.keyId = "key-1"
                assertEquals("$status", RaspDeliveryOutcome.DROPPED, s.delivery.deliver(freshEnvelope))
                assertEquals(1L, s.delivery.stats.snapshot()["dropped_rejected"])
            }
        }
    }

    @Test fun `an unreadable stored envelope is dropped as invalid without being sent`() {
        Setup(Script("/v1/events" to listOf(201))).use { s ->
            s.store.keyId = "key-1"
            assertEquals(RaspDeliveryOutcome.DROPPED, s.delivery.deliver("not json"))
            assertTrue(s.server.requests.isEmpty())
            assertEquals(1L, s.delivery.stats.snapshot()["dropped_invalid"])
        }
    }

    // ── retry cases ──────────────────────────────────────────────────────

    @Test fun `5xx and 429 keep the envelope for a retry`() {
        for (status in listOf(500, 502, 503, 429)) {
            Setup(Script("/v1/events" to listOf(status))).use { s ->
                s.store.keyId = "key-1"
                assertEquals("$status", RaspDeliveryOutcome.RETRY_LATER, s.delivery.deliver(freshEnvelope))
                assertEquals(0L, s.delivery.stats.snapshot().values.sum())
            }
        }
    }

    @Test fun `network error keeps the envelope for a retry`() {
        val closedPort = java.net.ServerSocket(0).use { it.localPort }
        val store = MemoryRegistrationStore().apply { keyId = "key-1" }
        val registrar = RaspDeviceRegistrar(FixedKey(), store, "com.example.bank", clock = { now })
        val credential = RaspEventCredential("o", "a", "k", "s", "http://127.0.0.1:$closedPort/v1/events")
        assertEquals(RaspDeliveryOutcome.RETRY_LATER, RaspEnvelopeDelivery({ credential }, registrar, clock = { now }).deliver(freshEnvelope))
    }

    @Test fun `no credential configured keeps the envelope`() {
        val registrar = RaspDeviceRegistrar(FixedKey(), MemoryRegistrationStore(), "com.example.bank")
        assertEquals(RaspDeliveryOutcome.RETRY_LATER, RaspEnvelopeDelivery({ null }, registrar).deliver(freshEnvelope))
    }

    // ── through the queue ────────────────────────────────────────────────

    @Test fun `queue with delivery - dropped and delivered leave, 5xx stays`() {
        Setup(Script("/v1/devices/register" to listOf(201), "/v1/events" to listOf(422, 201, 503))).use { s ->
            val store = object : RaspQueueStore {
                val data = ConcurrentHashMap<Long, String>()
                override fun loadAll(): Map<Long, String> = HashMap(data)
                override fun put(id: Long, envelopeJson: String): Boolean { data[id] = envelopeJson; return true }
                override fun remove(id: Long) { data.remove(id) }
                override fun clear() = data.clear()
            }
            val q = RaspOfflineQueue(store)
            repeat(3) { q.enqueue(freshEnvelope.replace("}", ""","n":$it}""")) }

            val r = q.drain(s.delivery::deliver)

            assertTrue(r.failed)
            assertEquals(1, r.dropped)
            assertEquals(1, r.sent)
            assertEquals(1, store.data.size)
            assertTrue(store.data.values.single().contains("\"n\":2"))
            assertEquals(mapOf(
                "delivered" to 1L, "dropped_invalid" to 1L, "dropped_expired" to 0L,
                "dropped_unauthorized" to 0L, "dropped_rejected" to 0L, "re_registrations" to 0L,
            ), s.delivery.stats.snapshot())
        }
    }
}
