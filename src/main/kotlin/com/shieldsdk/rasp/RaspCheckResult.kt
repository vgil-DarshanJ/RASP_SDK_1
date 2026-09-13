package com.shieldsdk.rasp

/**
 * Every detector in this SDK reports one of these — never a bare boolean.
 * Mirrors the Flutter/Dart side's `DetectionStatus` exactly (see
 * `lib/sdk/core/detection_status.dart` in the Flutter plugin) so the same
 * mental model applies whichever consumption path a host app uses.
 *
 * **The single most important invariant in this entire SDK**: a check that
 * could not run is never reported as [SECURE]. Collapsing "could not
 * determine" into "safe" is exactly how a RASP control fails open instead
 * of closed — every detector in `android_core` is written, reviewed, and
 * tested against this rule with no exceptions.
 */
enum class RaspCheckStatus {
    /** The check ran and found nothing — the only "safe" status. */
    SECURE,

    /** The check ran and found a threat. */
    DETECTED,

    /** The check never ran — wrong platform/API level, nothing configured,
     *  or a signed policy disabled it. Expected, not a fault. */
    UNAVAILABLE,

    /** The check ran but could not reach a conclusive answer — e.g. a
     *  system path this app is not permitted to list, so "absent" cannot
     *  be told apart from "hidden." Distinct from [UNAVAILABLE]: the check
     *  *did* run, it just could not conclude. */
    UNKNOWN,

    /** The check ran and threw/timed out/received a malformed reply — a
     *  fault worth investigating, distinct from the two states above that
     *  are expected outcomes. */
    ERROR;

    /** `true` only for [DETECTED] — the sole "this is a threat" state. */
    val isThreat: Boolean get() = this == DETECTED

    /** `true` for [SECURE] or [DETECTED] — the check reached a real answer. */
    val isConclusive: Boolean get() = this == SECURE || this == DETECTED
}

/**
 * One piece of supporting evidence behind a [RaspCheckResult] — never the
 * full raw signal a caller didn't ask for (e.g. clipboard evidence carries
 * a change *count*, never clipboard *content*). Mirrors the Dart side's
 * `DetectionEvidence`.
 */
data class RaspEvidence(
    val key: String,
    val value: Any?,
    val note: String? = null,
)

/**
 * The result of running one detector. Deliberately carries **no**
 * confidence/severity score — this native SDK reports raw per-detector
 * results only; scoring and policy decisions are the host app's or
 * backend's job (see the Android Native/Flutter Feature Parity plan's
 * scope decision). A host that wants a single risk number should combine
 * these results with its own weighting, or use the full licensed
 * `RaspShield` Flutter pipeline, which already does this.
 */
data class RaspCheckResult(
    val detectorId: String,
    val status: RaspCheckStatus,
    val evidence: List<RaspEvidence> = emptyList(),
    /** Set for [RaspCheckStatus.UNAVAILABLE]/[RaspCheckStatus.UNKNOWN]/
     *  [RaspCheckStatus.ERROR] only — `null` for [RaspCheckStatus.SECURE]/
     *  [RaspCheckStatus.DETECTED], which are self-explanatory. */
    val reason: String? = null,
    val observedAtMillis: Long = System.currentTimeMillis(),
) {
    companion object {
        fun secure(detectorId: String, evidence: List<RaspEvidence> = emptyList()) =
            RaspCheckResult(detectorId, RaspCheckStatus.SECURE, evidence)

        fun detected(detectorId: String, evidence: List<RaspEvidence> = emptyList()) =
            RaspCheckResult(detectorId, RaspCheckStatus.DETECTED, evidence)

        fun unavailable(detectorId: String, reason: String) =
            RaspCheckResult(detectorId, RaspCheckStatus.UNAVAILABLE, reason = reason)

        fun unknown(detectorId: String, reason: String) =
            RaspCheckResult(detectorId, RaspCheckStatus.UNKNOWN, reason = reason)

        fun error(detectorId: String, reason: String) =
            RaspCheckResult(detectorId, RaspCheckStatus.ERROR, reason = reason)
    }
}

/**
 * Pluggable error observability — set once via [RaspShieldCore.logger] to
 * wire detector-level exceptions into a host app's own crash-reporting
 * pipeline, without this SDK forcing a specific logging library on anyone.
 *
 * Default is a silent no-op. [RaspShieldCore] guarantees this interface's
 * own implementation is never allowed to throw back into a detector — see
 * `RaspShieldCore.notifyLogger`.
 */
interface RaspShieldLogger {
    fun onDetectorError(detectorId: String, throwable: Throwable)

    companion object {
        val NONE: RaspShieldLogger = object : RaspShieldLogger {
            override fun onDetectorError(detectorId: String, throwable: Throwable) {
                // Intentional no-op default.
            }
        }
    }
}
