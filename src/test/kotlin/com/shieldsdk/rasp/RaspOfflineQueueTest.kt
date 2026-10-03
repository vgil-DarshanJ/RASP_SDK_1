package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

/**
 * Offline queue mechanics: persisted before sending, DELIVERED/DROPPED remove,
 * RETRY_LATER keeps (order preserved), restarts, eviction, backoff.
 * (Which HTTP response maps to which outcome is RaspEnvelopeDeliveryTest.)
 *
 * Real: [RaspOfflineQueue] (ordering, removal rule, eviction, reload,
 * background retry).
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

    private val delivered: (String) -> RaspDeliveryOutcome = { RaspDeliveryOutcome.DELIVERED }
    private val retry: (String) -> RaspDeliveryOutcome = { RaspDeliveryOutcome.RETRY_LATER }

    @Test
    fun `retry-later keeps the envelope in memory and in storage`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        assertTrue(q.enqueue("e1"))

        val r = q.drain(retry)

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
    fun `delivered envelope is removed from memory and storage`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        q.enqueue("e1")
        val r = q.drain(delivered)
        assertFalse(r.failed)
        assertEquals(1, r.sent)
        assertEquals(0, q.size())
        assertTrue(store.data.isEmpty())
    }

    @Test
    fun `dropped envelope is removed, counted, and the drain continues`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        listOf("bad", "good").forEach { q.enqueue(it) }
        val r = q.drain { if (it == "bad") RaspDeliveryOutcome.DROPPED else RaspDeliveryOutcome.DELIVERED }
        assertFalse(r.failed)
        assertEquals(1, r.dropped)
        assertEquals(1, r.sent)
        assertTrue(store.data.isEmpty())
    }

    @Test
    fun `drain stops at the first retry and keeps order for the next attempt`() {
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        listOf("e1", "e2", "e3").forEach { q.enqueue(it) }

        val r = q.drain { if (it == "e1") RaspDeliveryOutcome.DELIVERED else RaspDeliveryOutcome.RETRY_LATER }

        assertTrue(r.failed)
        assertEquals(1, r.sent)
        assertEquals(listOf("e2", "e3"), q.peekAll())
        assertEquals(listOf("e2", "e3"), store.storedInOrder())

        val attempts = mutableListOf<String>()
        q.drain { attempts.add(it); RaspDeliveryOutcome.DELIVERED }
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
    fun `background flusher retries after the backoff and then delivers`() {
        val attemptTimes = Collections.synchronizedList(mutableListOf<Long>())
        val store = MemoryStore()
        val q = RaspOfflineQueue(store)
        q.enqueue("e1")

        q.startFlusher {
            attemptTimes.add(System.nanoTime())
            if (attemptTimes.size >= 2) RaspDeliveryOutcome.DELIVERED else RaspDeliveryOutcome.RETRY_LATER
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
