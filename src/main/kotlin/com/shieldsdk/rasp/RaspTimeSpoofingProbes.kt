package com.shieldsdk.rasp

import android.content.Context
import android.os.SystemClock
import android.provider.Settings

/**
 * `time_spoofing` — has the device's wall clock been moved away from real time?
 *
 * Three soft signals; DETECTED needs two. One alone is never DETECTED.
 *
 * | Signal | How |
 * |---|---|
 * | `clock_jump` | between two readings, wall-clock time advanced differently from `SystemClock.elapsedRealtime()` (monotonic, not user-settable) by more than [DEFAULT_MAX_JUMP_MS] |
 * | `server_time_offset` | wall clock differs from a server time the host supplied by more than [DEFAULT_MAX_SERVER_OFFSET_MS]; the server time is anchored to elapsed realtime when received, so it stays correct as the app keeps running |
 * | `auto_time_disabled` | `Settings.Global.AUTO_TIME` = 0 |
 *
 * Without a server time that signal simply does not exist. A signal that
 * could not be measured yet (no previous reading, setting unreadable) counts
 * as "might fire": when the fired plus not-yet-measured signals could still
 * reach two, the result is UNKNOWN rather than SECURE.
 */
object RaspTimeSpoofingProbes {

    const val DETECTOR_ID = "time_spoofing"
    const val DEFAULT_MAX_JUMP_MS = 5_000L
    const val DEFAULT_MAX_SERVER_OFFSET_MS = 60_000L

    data class ClockReading(val wallMillis: Long, val elapsedMillis: Long) {
        companion object {
            fun now() = ClockReading(System.currentTimeMillis(), SystemClock.elapsedRealtime())
        }
    }

    data class Observation(
        /** |wall delta − elapsed delta| since the previous reading; `null` on the first reading. */
        val clockJumpMs: Long?,
        /** wall clock − anchored server time; `null` when no server time was supplied. */
        val serverOffsetMs: Long?,
        /** `null` when the setting could not be read. */
        val autoTimeEnabled: Boolean?,
    )

    /** Keeps the previous reading and the anchored server time between checks. Thread-safe. */
    class Monitor {
        private var previous: ClockReading? = null
        private var serverAnchor: ClockReading? = null // wallMillis = server time, elapsedMillis = when received

        @Synchronized
        fun setServerTime(serverTimeMillis: Long, receivedAtElapsedMillis: Long = SystemClock.elapsedRealtime()) {
            serverAnchor = ClockReading(serverTimeMillis, receivedAtElapsedMillis)
        }

        @Synchronized
        fun observe(now: ClockReading, autoTimeEnabled: Boolean?): Observation {
            val jump = previous?.let { prev ->
                Math.abs((now.wallMillis - prev.wallMillis) - (now.elapsedMillis - prev.elapsedMillis))
            }
            previous = now
            val offset = serverAnchor?.let { anchor ->
                now.wallMillis - (anchor.wallMillis + (now.elapsedMillis - anchor.elapsedMillis))
            }
            return Observation(jump, offset, autoTimeEnabled)
        }
    }

    /** Used by [RaspShieldCore.checkTimeSpoofingBlocking]; sessions keep their own [Monitor]. */
    val processMonitor = Monitor()

    fun evaluate(
        o: Observation,
        maxJumpMs: Long = DEFAULT_MAX_JUMP_MS,
        maxServerOffsetMs: Long = DEFAULT_MAX_SERVER_OFFSET_MS,
    ): RaspCheckResult {
        val fired = mutableListOf<String>()
        var unmeasured = 0
        when (val jump = o.clockJumpMs) {
            null -> unmeasured++
            else -> if (jump > maxJumpMs) fired.add("clock_jump")
        }
        o.serverOffsetMs?.let { if (Math.abs(it) > maxServerOffsetMs) fired.add("server_time_offset") }
        when (o.autoTimeEnabled) {
            null -> unmeasured++
            false -> fired.add("auto_time_disabled")
            true -> Unit
        }

        val evidence = fired.map { RaspEvidence("time_signal", it, "soft") } + listOf(
            RaspEvidence("clock_jump_ms", o.clockJumpMs),
            RaspEvidence("server_offset_ms", o.serverOffsetMs),
            RaspEvidence("auto_time_enabled", o.autoTimeEnabled),
        )
        return when {
            fired.size >= 2 -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            fired.size + unmeasured >= 2 -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Not every signal could be measured yet (first reading, or setting unreadable)",
            )
            else -> RaspCheckResult.secure(DETECTOR_ID, evidence)
        }
    }

    fun readAutoTimeEnabled(context: Context): Boolean? = try {
        Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME) == 1
    } catch (e: Exception) {
        null
    }
}
