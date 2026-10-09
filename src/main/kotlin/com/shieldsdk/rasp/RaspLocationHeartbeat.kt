package com.shieldsdk.rasp

import kotlin.math.roundToLong

/**
 * Location heartbeat (Task 9.3): while the user shares location, one small
 * signed event (`location_heartbeat`) every [intervalMillis] (default 60 s,
 * at least 30 s) and on the first fix — independent of detector results,
 * which only ship when they change. No heartbeat while sharing is off; a
 * fix older than [MAX_FIX_AGE_MILLIS] is not sent. When sharing is turned
 * off, one `cleared` heartbeat (no coordinates, `location_opt_in = false`)
 * tells the backend to delete the device's stored point and trail.
 *
 * The event is not a security verdict: status UNKNOWN with that reason, so
 * it never counts as clean or as a threat anywhere.
 */
internal class RaspLocationHeartbeat(intervalMillis: Long = DEFAULT_INTERVAL_MILLIS) {

    val intervalMillis: Long = intervalMillis.coerceAtLeast(MIN_INTERVAL_MILLIS)

    sealed class Action {
        data class Send(val result: RaspCheckResult) : Action()
        /** Sharing was just turned off: tell the backend to forget the stored point. */
        data class Clear(val result: RaspCheckResult) : Action()
    }

    private var lastSentAtMillis: Long? = null
    private var sharing = false

    /** What to send now for [location] (the session's current one), or `null`. */
    @Synchronized
    fun next(location: RaspLocationSnapshot?, nowMillis: Long): Action? {
        if (location == null || !location.shareWithBackend) {
            if (!sharing) return null
            sharing = false
            lastSentAtMillis = null
            return Action.Clear(clearedResult(nowMillis))
        }
        sharing = true
        val age = nowMillis - location.capturedAtMillis
        if (age > MAX_FIX_AGE_MILLIS || age < -MAX_CLOCK_SKEW_MILLIS) return null
        val last = lastSentAtMillis
        if (last != null && nowMillis - last < intervalMillis) return null
        lastSentAtMillis = nowMillis
        return Action.Send(heartbeatResult(location, nowMillis))
    }

    companion object {
        const val DETECTOR_ID = "location_heartbeat"
        const val DEFAULT_INTERVAL_MILLIS = 60_000L
        const val MIN_INTERVAL_MILLIS = 30_000L
        const val MAX_FIX_AGE_MILLIS = 120_000L
        private const val MAX_CLOCK_SKEW_MILLIS = 60_000L
        const val REASON = "Location heartbeat (not a security verdict)"

        /** Coarse: 3 decimals (about 110 m). */
        fun coarse(value: Double): Double = (value * 1000).roundToLong() / 1000.0

        fun heartbeatResult(location: RaspLocationSnapshot, nowMillis: Long): RaspCheckResult = RaspCheckResult(
            DETECTOR_ID,
            RaspCheckStatus.UNKNOWN,
            listOf(
                RaspEvidence("location_opt_in", true),
                RaspEvidence("latitude", coarse(location.latitude)),
                RaspEvidence("longitude", coarse(location.longitude)),
                RaspEvidence("location_accuracy_m", location.accuracyMeters),
                RaspEvidence("location_captured_at_millis", location.capturedAtMillis),
                RaspEvidence("location_fix_age_seconds", ((nowMillis - location.capturedAtMillis) / 1000).coerceAtLeast(0)),
                RaspEvidence("location_is_mock", location.isMock),
            ),
            reason = REASON,
            observedAtMillis = nowMillis,
        )

        fun clearedResult(nowMillis: Long): RaspCheckResult = RaspCheckResult(
            DETECTOR_ID,
            RaspCheckStatus.UNKNOWN,
            listOf(RaspEvidence("location_opt_in", false), RaspEvidence("location_sharing", "off")),
            reason = REASON,
            observedAtMillis = nowMillis,
        )
    }
}

/** Delivery result of the last location heartbeat, for the host app's screen. */
public data class RaspLocationHeartbeatStatus(
    val atMillis: Long,
    val outcome: Outcome,
    /** Short text, no URLs or keys: "delivered", "HTTP 400", "no answer from the backend", … */
    val detail: String,
    /** `true` for the "sharing turned off" message. */
    val cleared: Boolean = false,
) {
    public enum class Outcome { DELIVERED, NOT_DELIVERED, REJECTED, NOT_CONFIGURED }

    public companion object {
        /** From an evidence-envelope delivery outcome. */
        @JvmStatic
        public fun fromDelivery(outcome: RaspDeliveryOutcome, atMillis: Long, cleared: Boolean): RaspLocationHeartbeatStatus =
            when (outcome) {
                RaspDeliveryOutcome.DELIVERED -> RaspLocationHeartbeatStatus(atMillis, Outcome.DELIVERED, "delivered", cleared)
                RaspDeliveryOutcome.DROPPED -> RaspLocationHeartbeatStatus(atMillis, Outcome.REJECTED, "rejected by the backend", cleared)
                RaspDeliveryOutcome.RETRY_LATER ->
                    RaspLocationHeartbeatStatus(atMillis, Outcome.NOT_DELIVERED, "no answer from the backend (network or registration)", cleared)
            }

        /** From a legacy HMAC post: HTTP status, -1 when no answer. */
        @JvmStatic
        public fun fromHttpStatus(code: Int, atMillis: Long, cleared: Boolean): RaspLocationHeartbeatStatus = when {
            code in 200..299 -> RaspLocationHeartbeatStatus(atMillis, Outcome.DELIVERED, "delivered", cleared)
            code < 0 -> RaspLocationHeartbeatStatus(atMillis, Outcome.NOT_DELIVERED, "no answer from the backend", cleared)
            else -> RaspLocationHeartbeatStatus(atMillis, Outcome.REJECTED, "HTTP $code", cleared)
        }
    }
}

/** Latitude / longitude rounded to 3 decimals (about 110 m): the most precise location that leaves the phone (F-16). */
internal fun coarseCoordinate(value: Double): Double = (value * 1000).roundToLong() / 1000.0
