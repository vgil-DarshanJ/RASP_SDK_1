package com.shieldsdk.rasp

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Durable storage behind [RaspOfflineQueue]. Production: [RaspEncryptedQueueStore]. */
public interface RaspQueueStore {
    /** Every stored envelope, keyed by its sequence id. */
    public fun loadAll(): Map<Long, String>

    /** Stores one envelope; `true` once it is on disk. */
    public fun put(id: Long, envelopeJson: String): Boolean

    public fun remove(id: Long)

    public fun clear()
}

/**
 * Encrypted, ordered, size-capped offline queue for evidence envelopes.
 *
 * ## Delivery rule
 * Every envelope is enqueued (persisted) **before** any send is attempted.
 * [drain] sends oldest-first and removes an envelope — from memory and from
 * storage — only when the sender returns `true`, which
 * [RaspEventShipper.postEnvelope] does only for an HTTP 2xx. Any other status,
 * a timeout, or an exception leaves it at the head of the queue and stops the
 * drain, so order is preserved for the retry.
 *
 * ## Retry
 * After a failed drain the next attempt is scheduled after a backoff
 * (1 s doubling to 5 min, ±20 % jitter); a successful drain resets it.
 * [flushNow] does not cut a pending backoff short.
 *
 * ## Capacity
 * [DEFAULT_MAX_SIZE] envelopes; when full the oldest is evicted (from storage
 * too) so the newest evidence is kept.
 */
open class RaspOfflineQueue(
    private val store: RaspQueueStore,
    private val maxSize: Int = DEFAULT_MAX_SIZE,
) {

    public constructor(context: Context) : this(RaspEncryptedQueueStore(context.applicationContext ?: context))

    companion object {
        const val DEFAULT_MAX_SIZE = 1000
        const val INITIAL_BACKOFF_MS = 1000L
        const val MAX_BACKOFF_MS = 5 * 60 * 1000L // 5 minutes
        const val JITTER_FACTOR = 0.2 // ±20%

        /** Backoff after a failure that followed a wait of [currentMs]; [unitRandom] in [0, 1). */
        @JvmStatic
        fun nextBackoffMs(currentMs: Long, unitRandom: Double): Long {
            val doubled = (currentMs * 2).coerceAtMost(MAX_BACKOFF_MS)
            val jitter = (doubled * JITTER_FACTOR * (unitRandom * 2 - 1)).toLong()
            return (doubled + jitter).coerceIn(INITIAL_BACKOFF_MS, MAX_BACKOFF_MS)
        }
    }

    /** Outcome of one [drain]. */
    data class DrainResult(val sent: Int, val remaining: Int, val failed: Boolean)

    private data class Entry(val id: Long, val json: String)

    private val lock = Any()
    private val entries = ArrayDeque<Entry>()
    private var nextId = 1L
    private var loaded = false

    private val draining = AtomicBoolean(false)
    private val backoffMs = AtomicLong(INITIAL_BACKOFF_MS)
    private val secureRandom = SecureRandom()
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "RaspOfflineQueue-flusher").apply { isDaemon = true }
    }
    private var pendingRun: ScheduledFuture<*>? = null // guarded by lock

    @Volatile
    private var sender: ((String) -> Boolean)? = null

    /** Returns current queue size. */
    public fun size(): Int = synchronized(lock) { ensureLoadedLocked(); entries.size }

    /** Returns whether the queue is at capacity. */
    public fun isFull(): Boolean = size() >= maxSize

    /** The queued envelopes, oldest first, without removing them. */
    public fun peekAll(): List<String> = synchronized(lock) { ensureLoadedLocked(); entries.map { it.json } }

    /**
     * Adds an envelope. Returns `true` if it was written to storage; `false`
     * means it is held in memory only (lost if the process dies before it is
     * delivered).
     */
    public fun enqueue(envelopeJson: String): Boolean = synchronized(lock) {
        ensureLoadedLocked()
        while (entries.size >= maxSize) {
            val evicted = entries.removeFirst()
            store.remove(evicted.id)
        }
        val entry = Entry(nextId++, envelopeJson)
        entries.addLast(entry)
        store.put(entry.id, entry.json)
    }

    /**
     * Sends queued envelopes oldest-first until one fails or the queue is
     * empty. An envelope is removed only after [send] returns `true`.
     * Synchronous; returns immediately with `failed = false` and `sent = 0`
     * if another drain is already running.
     */
    public fun drain(send: (String) -> Boolean): DrainResult {
        if (!draining.compareAndSet(false, true)) return DrainResult(0, size(), failed = false)
        try {
            var sent = 0
            while (true) {
                val head = synchronized(lock) { ensureLoadedLocked(); entries.firstOrNull() }
                    ?: return DrainResult(sent, 0, failed = false)
                val delivered = try {
                    send(head.json)
                } catch (e: Exception) {
                    notifyLogger(e)
                    false
                }
                if (!delivered) return DrainResult(sent, size(), failed = true)
                synchronized(lock) {
                    entries.remove(head) // no-op if it was evicted while in flight
                    store.remove(head.id)
                }
                sent++
            }
        } finally {
            draining.set(false)
        }
    }

    /**
     * Sets the sender used by the background flusher and starts a flush.
     * Calling again replaces the sender.
     */
    public fun startFlusher(shipFn: (String) -> Boolean) {
        sender = shipFn
        flushNow()
    }

    /** Stops background flushing; queued envelopes stay stored. */
    public fun stopFlusher() {
        sender = null
        synchronized(lock) {
            pendingRun?.cancel(false)
            pendingRun = null
        }
    }

    /** Starts a background flush now, unless one is already scheduled (including a backoff retry). */
    public fun flushNow() {
        schedule(0)
    }

    /** Removes all envelopes (e.g. on user logout). */
    public fun clear() {
        synchronized(lock) {
            entries.clear()
            store.clear()
        }
    }

    /** Current backoff delay, for tests and diagnostics. */
    public fun getBackoffMsForTests(): Long = backoffMs.get()

    private fun schedule(delayMs: Long) {
        synchronized(lock) {
            if (sender == null) return
            if (pendingRun?.isDone == false) return
            pendingRun = scheduler.schedule(::runFlush, delayMs, TimeUnit.MILLISECONDS)
        }
    }

    private fun runFlush() {
        synchronized(lock) { pendingRun = null }
        val send = sender ?: return
        val result = drain(send)
        if (result.failed) {
            val wait = backoffMs.get() // only the flusher thread writes it here
            backoffMs.set(nextBackoffMs(wait, secureRandom.nextDouble()))
            schedule(wait)
        } else if (result.remaining == 0) {
            backoffMs.set(INITIAL_BACKOFF_MS)
        }
    }

    private fun ensureLoadedLocked() {
        if (loaded) return
        loaded = true
        try {
            store.loadAll().toSortedMap().forEach { (id, json) ->
                entries.addLast(Entry(id, json))
                if (id >= nextId) nextId = id + 1
            }
        } catch (e: Exception) {
            notifyLogger(e)
        }
    }

    private fun notifyLogger(throwable: Throwable) {
        try {
            RaspShieldCore.logger.onDetectorError("offline_queue", throwable)
        } catch (_: Exception) { }
    }
}

/**
 * [RaspQueueStore] in EncryptedSharedPreferences (AES-256-GCM values,
 * Keystore-wrapped key). Writes use `commit()` so "stored" means on disk.
 * Keys `env_<id>` — the same file and key prefix as the earlier
 * implementation, so envelopes queued by it are picked up.
 */
internal class RaspEncryptedQueueStore(private val context: Context) : RaspQueueStore {

    private val prefs: SharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    override fun loadAll(): Map<Long, String> =
        prefs.all.mapNotNull { (key, value) ->
            val id = key.removePrefix(PREFIX).takeIf { key.startsWith(PREFIX) }?.toLongOrNull()
            if (id != null && value is String) id to value else null
        }.toMap()

    override fun put(id: Long, envelopeJson: String): Boolean = try {
        prefs.edit().putString("$PREFIX$id", envelopeJson).commit()
    } catch (e: Exception) {
        false
    }

    override fun remove(id: Long) {
        try {
            prefs.edit().remove("$PREFIX$id").commit()
        } catch (_: Exception) { }
    }

    override fun clear() {
        try {
            prefs.edit().clear().commit()
        } catch (_: Exception) { }
    }

    private companion object {
        const val PREFS_NAME = "rasp_offline_queue"
        const val PREFIX = "env_"
    }
}
