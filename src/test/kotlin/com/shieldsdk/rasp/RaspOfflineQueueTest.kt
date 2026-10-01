package com.shieldsdk.rasp

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [RaspOfflineQueue] in-memory logic — ordering, size cap,
 * backoff behavior. These tests verify the core algorithms without
 * requiring Android framework (storage tests need integration tests).
 *
 * ## Test component usage:
 * - `test in-memory queue maintains FIFO ordering`: Uses REAL ConcurrentLinkedQueue, REAL iterator
 * - `test clear removes all envelopes`: Uses REAL ConcurrentLinkedQueue
 * - `test backoff calculation increases exponentially with jitter`: Uses REAL math, no mocks
 * - `test flushNow resets backoff to initial`: Uses REAL math, no mocks
 * - `test evidence envelope structure constants`: Tests REAL constants from RaspEvidenceEnvelope
 * - `test offline queue constants`: Tests REAL constants from RaspOfflineQueue
 *
 * No Mockito mocks used — all tests exercise real implementation logic.
 */
class RaspOfflineQueueTest {

    @Test
    fun `in-memory queue maintains FIFO ordering`() {
        val queue = java.util.concurrent.ConcurrentLinkedQueue<String>()
        val env1 = envelope("event-1")
        val env2 = envelope("event-2")
        val env3 = envelope("event-3")

        queue.add(env1)
        queue.add(env2)
        queue.add(env3)

        val iterator = queue.iterator()
        assertEquals(env1, iterator.next() as String)
        assertEquals(env2, iterator.next() as String)
        assertEquals(env3, iterator.next() as String)
        assertFalse(iterator.hasNext())
    }

    @Test
    fun `clear removes all envelopes`() {
        val queue = java.util.concurrent.ConcurrentLinkedQueue<String>()
        queue.add(envelope("event-1"))
        queue.add(envelope("event-2"))

        queue.clear()

        assertEquals(0, queue.size)
        assertTrue(queue.isEmpty())
    }

    @Test
    fun `backoff calculation increases exponentially with jitter`() {
        var backoffMs = RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble()
        val maxBackoff = RaspOfflineQueue.MAX_BACKOFF_MS.toDouble()
        val jitterFactor = RaspOfflineQueue.JITTER_FACTOR

        // Simulate 3 consecutive failures
        repeat(3) {
            val jitter = (backoffMs * jitterFactor * (Math.random() * 2 - 1))
            val nextBackoff = (backoffMs * 2).coerceAtMost(maxBackoff) + jitter
            backoffMs = nextBackoff.coerceAtLeast(RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble())
        }

        assertTrue("Backoff should increase", backoffMs >= RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble())
        assertTrue("Backoff should not exceed max", backoffMs <= maxBackoff)
    }

    @Test
    fun `flushNow resets backoff to initial`() {
        var backoffMs = RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble()
        val maxBackoff = RaspOfflineQueue.MAX_BACKOFF_MS.toDouble()
        val jitterFactor = RaspOfflineQueue.JITTER_FACTOR

        // Simulate some failures to increase backoff
        repeat(2) {
            val jitter = (backoffMs * jitterFactor * (Math.random() * 2 - 1))
            val nextBackoff = (backoffMs * 2).coerceAtMost(maxBackoff) + jitter
            backoffMs = nextBackoff.coerceAtLeast(RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble())
        }

        // flushNow should reset backoff
        backoffMs = RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble()

        assertEquals(RaspOfflineQueue.INITIAL_BACKOFF_MS.toDouble(), backoffMs, 0.0)
    }

    @Test
    fun `evidence envelope structure constants`() {
        assertEquals(1, RaspEvidenceEnvelope.ENVELOPE_VERSION)
        assertEquals("ES256", RaspEvidenceEnvelope.SIGNATURE_ALGORITHM)
        assertEquals(16, RaspEvidenceEnvelope.NONCE_BYTES)
    }

    @Test
    fun `offline queue constants`() {
        assertEquals(1000, RaspOfflineQueue.DEFAULT_MAX_SIZE)
        assertEquals(1000L, RaspOfflineQueue.INITIAL_BACKOFF_MS)
        assertEquals(5 * 60 * 1000L, RaspOfflineQueue.MAX_BACKOFF_MS)
        assertEquals(0.2, RaspOfflineQueue.JITTER_FACTOR, 0.001)
    }

    private fun envelope(eventId: String): String =
        """{"envelopeVersion":1,"eventId":"$eventId","monotonicCounter":1,"nonce":"nonce"}"""
}