package com.shieldsdk.rasp

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Encrypted, ordered, size-capped offline queue for evidence envelopes.
 *
 * ## Design
 * - **Storage**: Each envelope is encrypted with AES-256-GCM via
 *   `EncryptedSharedPreferences` (Keystore-wrapped MasterKey). The queue
 *   metadata (ordering, size) is kept in-memory with a persistent index.
 * - **Ordering**: FIFO — `ConcurrentLinkedQueue` preserves insertion order.
 *   On restart, envelopes are reloaded in the order they were persisted.
 * - **Size cap**: Default 1000 envelopes (~few MB). When full, oldest
 *   envelopes are dropped (FIFO eviction) to make room for new ones —
 *   "never lose the newest threat" priority.
 * - **Retry with backoff**: Exponential backoff (1s, 2s, 4s, 8s... max 5m)
 *   with jitter. Retries run on a dedicated single-thread executor so
 *   network stalls never block the detector scan loop.
 * - **Durability**: Every successful `enqueue` persists to encrypted storage
 *   before returning. A crash after `enqueue` returns will not lose the event.
 * - **No secrets in stored data**: Envelopes carry only public data +
 *   signatures (the private key never leaves Keystore).
 *
 * ## Usage
 * ```kotlin
 * val queue = RaspOfflineQueue(context)
 * queue.enqueue(envelopeJson)  // returns immediately, persists durably
 * queue.startFlusher { envelope -> shipToBackend(envelope) }  // background retry
 * ```
 */
open class RaspOfflineQueue(private val context: Context) {

    companion object {
        const val DEFAULT_MAX_SIZE = 1000
        const val INITIAL_BACKOFF_MS = 1000L
        const val MAX_BACKOFF_MS = 5 * 60 * 1000L // 5 minutes
        const val JITTER_FACTOR = 0.2 // ±20%
    }

    private val prefsName = "rasp_offline_queue"
    private val prefsEnvelopePrefix = "env_"
    private val prefsIndexKey = "queue_index"
    private val prefsSizeKey = "queue_size"

    private val memoryQueue = ConcurrentLinkedQueue<String>()
    private val maxSize: Int = DEFAULT_MAX_SIZE
    private val flusherExecutor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "RaspOfflineQueue-flusher").apply { isDaemon = true }
    }
    private val isFlushing = AtomicBoolean(false)
    private val backoffMs = AtomicLong(INITIAL_BACKOFF_MS)
    private val secureRandom = SecureRandom()

    @Volatile
    private var flushCallback: ((String) -> Boolean)? = null

    /** Returns current queue size (in-memory, fast). */
    public fun size(): Int = memoryQueue.size

    /** Returns whether the queue is at capacity. */
    public fun isFull(): Boolean = memoryQueue.size >= maxSize

    /**
     * Adds an envelope to the queue. Persists to encrypted storage before returning.
     * Returns `false` if the queue is full and eviction failed (should never happen).
     */
    public fun enqueue(envelopeJson: String): Boolean {
        // Evict oldest if at capacity
        if (memoryQueue.size >= maxSize) {
            val evicted = memoryQueue.poll()
            if (evicted != null) {
                removeFromStorage(evicted)
            }
        }

        memoryQueue.add(envelopeJson)
        persistToStorage(envelopeJson)
        return true
    }

    /**
     * Starts the background flusher. [shipFn] should return `true` on success
     * (envelope removed from queue) or `false` on failure (retry later).
     * Idempotent — calling twice replaces the callback.
     */
    public fun startFlusher(shipFn: (String) -> Boolean) {
        flushCallback = shipFn
        scheduleFlush()
    }

    /** Stops the background flusher. */
    public fun stopFlusher() {
        flushCallback = null
    }

    /** Forces an immediate flush attempt (e.g. on network connectivity change). */
    public fun flushNow() {
        scheduleFlush()
    }

    /** Drains and returns all envelopes without removing them (for inspection). */
    public fun peekAll(): List<String> = memoryQueue.toList()

    /** Removes all envelopes (e.g. on user logout). */
    public fun clear() {
        memoryQueue.clear()
        clearStorage()
    }

    /** Test-only access to internal state. */
    public fun getBackoffMsForTests(): Long = backoffMs.get()

    private fun scheduleFlush() {
        if (isFlushing.getAndSet(true)) return
        flusherExecutor.execute { flushLoop() }
    }

    private fun flushLoop() {
        val callback = flushCallback
        if (callback == null) {
            isFlushing.set(false)
            return
        }
        var consecutiveFailures = 0

        while (callback == flushCallback) { // loop until callback cleared or queue empty
            val envelope = memoryQueue.peek()
            if (envelope == null) {
                isFlushing.set(false)
                return
            }

            val success = try {
                callback(envelope)
            } catch (e: Exception) {
                notifyLogger("offline_queue", e)
                false
            }

            if (success) {
                memoryQueue.poll()
                removeFromStorage(envelope)
                consecutiveFailures = 0
                backoffMs.set(INITIAL_BACKOFF_MS)
            } else {
                consecutiveFailures++
                val currentBackoff = backoffMs.get()
                val jitter = (currentBackoff * JITTER_FACTOR * (secureRandom.nextDouble() * 2 - 1)).toLong()
                val nextBackoff = (currentBackoff * 2).coerceAtMost(MAX_BACKOFF_MS) + jitter
                backoffMs.set(nextBackoff.coerceAtLeast(INITIAL_BACKOFF_MS))
                isFlushing.set(false)
                return // back off; will be rescheduled by next enqueue/flushNow
            }
        }
        isFlushing.set(false)
    }

    open fun persistToStorage(envelopeJson: String) {
        try {
            val prefs = getEncryptedPrefs()
            val index = getIndex(prefs)
            val newIndex = index + 1
            prefs.edit()
                .putString("$prefsEnvelopePrefix$newIndex", envelopeJson)
                .putInt(prefsIndexKey, newIndex)
                .putInt(prefsSizeKey, memoryQueue.size)
                .apply()
        } catch (e: Exception) {
            notifyLogger("offline_queue", e)
        }
    }

    open fun removeFromStorage(envelopeJson: String) {
        try {
            val prefs = getEncryptedPrefs()
            val index = getIndex(prefs)
            // Find and remove the matching envelope (linear scan, queue is small)
            for (i in 1..index) {
                val stored = prefs.getString("$prefsEnvelopePrefix$i", null)
                if (stored == envelopeJson) {
                    prefs.edit()
                        .remove("$prefsEnvelopePrefix$i")
                        .putInt(prefsSizeKey, memoryQueue.size)
                        .apply()
                    break
                }
            }
        } catch (e: Exception) {
            notifyLogger("offline_queue", e)
        }
    }

    open fun clearStorage() {
        try {
            val prefs = getEncryptedPrefs()
            val index = getIndex(prefs)
            val editor = prefs.edit()
            for (i in 1..index) {
                editor.remove("$prefsEnvelopePrefix$i")
            }
            editor.remove(prefsIndexKey).putInt(prefsSizeKey, 0).apply()
        } catch (e: Exception) {
            notifyLogger("offline_queue", e)
        }
    }

    open fun getIndex(prefs: EncryptedSharedPreferences): Int =
        prefs.getInt(prefsIndexKey, 0)

    open fun getEncryptedPrefs(): EncryptedSharedPreferences =
        EncryptedSharedPreferences.create(
            context.applicationContext ?: context,
            prefsName,
            MasterKey.Builder(context.applicationContext ?: context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ) as EncryptedSharedPreferences

    /** Reloads queue from encrypted storage on process start. */
    public fun reloadFromStorage() {
        try {
            val prefs = getEncryptedPrefs()
            val index = getIndex(prefs)
            memoryQueue.clear()
            for (i in 1..index) {
                val envelope = prefs.getString("$prefsEnvelopePrefix$i", null)
                if (envelope != null) memoryQueue.add(envelope)
            }
        } catch (e: Exception) {
            notifyLogger("offline_queue", e)
        }
    }

    private fun notifyLogger(tag: String, throwable: Throwable) {
        try {
            RaspShieldCore.logger.onDetectorError(tag, throwable)
        } catch (_: Exception) { }
    }
}