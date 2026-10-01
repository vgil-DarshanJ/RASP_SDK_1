package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Offline queue delivery rule: persisted before sending, removed only after a
 * 2xx, order kept across failures and restarts.
 *
 * Real components: [RaspOfflineQueue] (ordering, removal rule, eviction,
 * reload, background retry), [RaspEventShipper.postEnvelope] and
 * [RaspEventShipper.isDelivered] over real HTTP (HttpURLConnection) to a
 * minimal HTTP responder on a 127.0.0.1 socket.
 *
 * Test double: [MemoryStore] instead of the EncryptedSharedPreferences store
 * (`RaspEncryptedQueueStore`, not exercised on the JVM).
 */
class RaspOfflineQueueTest {

    private class MemoryStore : RaspQueueStore {
        val data = ConcurrentHashMap<Long, String>()
        var failPuts = false
        override fun loadAll(): Map<Long, String> = HashMap(data)
        override fun put(id: Long, envelopeJson: String): Boolean {
            if (failPuts) return false
            data[id] = envelopeJson
            return true
        }
        override fun remove(id: Long) { data.remove(id) }
        override fun clear() = data.clear()
        fun storedInOrder(): List<String> = data.toSortedMap().values.toList()
    }

    @Test
    fun `failed send stays queued in memory and in storage`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        assertTrue(q.enqueue("e1"))

        val r = q.drain { false }

        assertTrue(r.failed)
        assertEquals(0, r.sent)
        assertEquals(listOf("e1"), q.peekAll())
        assertEquals(listOf("e1"), store.storedInOrder())
    }

    @Test
    fun `exception during send keeps the envelope`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        q.enqueue("e1")
        val r = q.drain { throw java.io.IOException("network down") }
        assertTrue(r.failed)
        assertEquals(listOf("e1"), store.storedInOrder())
    }

    @Test
    fun `envelope is removed from memory and storage only after a successful send`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        q.enqueue("e1")
        val seen = mutableListOf<String>()

        val r = q.drain { seen.add(it); true }

        assertFalse(r.failed)
        assertEquals(1, r.sent)
        assertEquals(listOf("e1"), seen)
        assertEquals(0, q.size())
        assertTrue(store.data.isEmpty())
    }

    @Test
    fun `drain stops at the first failure and keeps order for the retry`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        listOf("e1", "e2", "e3").forEach { q.enqueue(it) }

        val r = q.drain { it == "e1" }

        assertTrue(r.failed)
        assertEquals(1, r.sent)
        assertEquals(listOf("e2", "e3"), q.peekAll())
        assertEquals(listOf("e2", "e3"), store.storedInOrder())

        val attempts = mutableListOf<String>()
        q.drain { attempts.add(it); true }
        assertEquals(listOf("e2", "e3"), attempts)
    }

    @Test
    fun `queued envelopes survive a restart in order without id reuse`() {
        val store = MemoryStore()
        RaspOfflineQueue(store).apply { enqueue("e1"); enqueue("e2") }

        val afterRestart = RaspOfflineQueue(store)
        assertEquals(listOf("e1", "e2"), afterRestart.peekAll())
        afterRestart.enqueue("e3")
        assertEquals(3, store.data.size)
        assertEquals(listOf("e1", "e2", "e3"), store.storedInOrder())
    }

    @Test
    fun `full queue evicts the oldest from storage too`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store, maxSize = 3)
        listOf("e1", "e2", "e3", "e4").forEach { q.enqueue(it) }
        assertEquals(listOf("e2", "e3", "e4"), q.peekAll())
        assertEquals(listOf("e2", "e3", "e4"), store.storedInOrder())
    }

    @Test
    fun `enqueue reports a storage write failure but keeps the envelope in memory`() {
        val store = MemoryStore().apply { failPuts = true }
        val q = RaspOfflineQueue(store)
        assertFalse(q.enqueue("e1"))
        assertEquals(listOf("e1"), q.peekAll())
    }

    @Test
    fun `backoff doubles with jitter and stays within bounds`() {
        assertEquals(2000L, RaspOfflineQueue.nextBackoffMs(1000L, 0.5))   // no jitter
        assertEquals(1600L, RaspOfflineQueue.nextBackoffMs(1000L, 0.0))   // -20 %
        assertEquals(2399L, RaspOfflineQueue.nextBackoffMs(1000L, 0.9999)) // ~+20 %
        assertEquals(RaspOfflineQueue.MAX_BACKOFF_MS, RaspOfflineQueue.nextBackoffMs(RaspOfflineQueue.MAX_BACKOFF_MS, 0.5))
        assertEquals(RaspOfflineQueue.MAX_BACKOFF_MS, RaspOfflineQueue.nextBackoffMs(RaspOfflineQueue.MAX_BACKOFF_MS, 0.9999))
    }

    @Test
    fun `only HTTP 2xx counts as delivered`() {
        listOf(200, 201, 202, 204, 299).forEach { assertTrue("$it", RaspEventShipper.isDelivered(it)) }
        listOf(-1, 0, 199, 300, 304, 400, 401, 403, 409, 429, 500, 503).forEach {
            assertFalse("$it", RaspEventShipper.isDelivered(it))
        }
    }

    /**
     * Minimal HTTP/1.1 responder on a real localhost socket: records each
     * request's body and `X-Api-Key`, answers with the next status from
     * [statuses]. (`com.sun.net.httpserver` is not on the Android unit-test
     * compile classpath.)
     */
    private class MiniHttpServer(statuses: List<Int>) : AutoCloseable {
        private val statuses = ArrayDeque(statuses)
        private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = socket.localPort
        val bodies: MutableList<String> = Collections.synchronizedList(mutableListOf())
        val apiKeys: MutableList<String?> = Collections.synchronizedList(mutableListOf())

        init {
            Thread {
                while (!socket.isClosed) {
                    val client = try { socket.accept() } catch (e: IOException) { break }
                    client.use { handle(it) }
                }
            }.apply { isDaemon = true; start() }
        }

        private fun handle(client: Socket) {
            val input = BufferedInputStream(client.getInputStream())
            val headers = mutableMapOf<String, String>()
            readLine(input) // request line
            while (true) {
                val line = readLine(input)
                if (line.isEmpty()) break
                val idx = line.indexOf(':')
                if (idx > 0) headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
            }
            val length = headers["content-length"]?.toInt() ?: 0
            val body = ByteArray(length)
            var read = 0
            while (read < length) {
                val n = input.read(body, read, length - read)
                if (n < 0) break
                read += n
            }
            bodies.add(String(body, Charsets.UTF_8))
            apiKeys.add(headers["x-api-key"])
            val code = synchronized(statuses) { statuses.removeFirst() }
            client.getOutputStream().apply {
                write("HTTP/1.1 $code Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                flush()
            }
        }

        private fun readLine(input: InputStream): String {
            val sb = StringBuilder()
            while (true) {
                val c = input.read()
                if (c < 0 || c == '\n'.code) break
                if (c != '\r'.code) sb.append(c.toChar())
            }
            return sb.toString()
        }

        override fun close() = socket.close()
    }

    @Test
    fun `real HTTP - non-2xx responses keep the envelope, 201 removes it`() {
        MiniHttpServer(listOf(503, 401, 201)).use { server ->
            val credential = RaspEventCredential(
                "org", "app", "key-1", "secret", "http://127.0.0.1:${server.port}/v1/events",
            )
            val store = MemoryStore()
            val q = RaspOfflineQueue(store)
            val envelope = "{\"envelopeVersion\":1}"
            q.enqueue(envelope)
            val send: (String) -> Boolean = { RaspEventShipper.postEnvelope(credential, it) }

            assertTrue("503 must fail", q.drain(send).failed)
            assertEquals(listOf(envelope), store.storedInOrder())

            assertTrue("401 must fail", q.drain(send).failed)
            assertEquals(listOf(envelope), store.storedInOrder())

            val ok = q.drain(send)
            assertFalse(ok.failed)
            assertEquals(1, ok.sent)
            assertTrue(store.data.isEmpty())

            assertEquals(listOf(envelope, envelope, envelope), server.bodies.toList())
            assertEquals(listOf("key-1", "key-1", "key-1"), server.apiKeys.toList())
        }
    }

    @Test
    fun `real HTTP - connection refused keeps the envelope`() {
        val port = java.net.ServerSocket(0).use { it.localPort } // closed again: nothing listens
        val credential = RaspEventCredential("org", "app", "key-1", "secret", "http://127.0.0.1:$port/v1/events")
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        q.enqueue("e1")
        assertTrue(q.drain { RaspEventShipper.postEnvelope(credential, it) }.failed)
        assertEquals(listOf("e1"), store.storedInOrder())
    }

    @Test
    fun `background flusher retries after the backoff and then delivers`() {
        val attemptTimes = Collections.synchronizedList(mutableListOf<Long>())
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        q.enqueue("e1")

        q.startFlusher {
            attemptTimes.add(System.nanoTime())
            attemptTimes.size >= 2 // first attempt fails, second succeeds
        }
        val deadline = System.currentTimeMillis() + 10_000
        while (store.data.isNotEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(50)
        q.stopFlusher()

        assertTrue("delivered within 10 s", store.data.isEmpty())
        assertEquals(2, attemptTimes.size)
        val gapMs = (attemptTimes[1] - attemptTimes[0]) / 1_000_000
        assertTrue("retry waited for the initial backoff (was ${gapMs}ms)", gapMs >= 900)
    }
}
