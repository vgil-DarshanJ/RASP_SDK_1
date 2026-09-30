package com.shieldsdk.rasp

import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Shared non-reentrancy guard for scheduled and manual scan requests. */
public class RaspTickGate {
    private val running = AtomicBoolean(false)
    fun run(block: () -> Unit): Boolean {
        if (!running.compareAndSet(false, true)) return false
        try { block() } finally { running.set(false) }
        return true
    }
}

/** Bounded execution used by the shared lean session for every detector. */
public class RaspTimedDetector(
    private val executor: ExecutorService = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "RaspShield-detector").apply { isDaemon = true }
    },
) {
    fun run(detectorId: String, timeoutMillis: Long, block: () -> RaspCheckResult): RaspCheckResult {
        // UNAVAILABLE = "cannot run on this device/API level" (expected, no fault).
        // ERROR = "ran but timed out, threw, or received a malformed reply" (fault, investigate).
        if (timeoutMillis <= 0) return RaspCheckResult.unavailable(detectorId, "Detector timeout must be positive")
        val future = executor.submit(Callable { block() })
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: java.util.concurrent.TimeoutException) {
            future.cancel(true)
            // Timeout is a fault — the detector started but did not finish. Distinct from UNAVAILABLE
            // (which means the detector was never applicable on this device/API level).
            RaspCheckResult.error(detectorId, "Detector timed out after ${timeoutMillis}ms")
        } catch (e: Exception) {
            RaspCheckResult.error(detectorId, e.cause?.message ?: e.message ?: e.javaClass.simpleName)
        }
    }

    fun shutdown() = executor.shutdownNow()
}
