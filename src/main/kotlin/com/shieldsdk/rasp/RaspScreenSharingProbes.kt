package com.shieldsdk.rasp

import android.content.Context

/**
 * `screen_sharing_risk` — while this app is in the foreground, its screen is
 * being captured (Android 15+ screen-recording callback) or a cast/external
 * display is attached. Background → SECURE (nothing of this app is shown).
 * When capture cannot be observed (below Android 15, or the host did not
 * declare DETECT_SCREEN_RECORDING) and no external display is attached →
 * UNKNOWN, never SECURE.
 */
public object RaspScreenSharingProbes {
    const val DETECTOR_ID = "screen_sharing_risk"

    public data class Observation(
        val foreground: Boolean?,
        val recording: RaspScreenRecordingProbes.State?,
        val recordingObservable: Boolean,
        val externalDisplay: RaspPrivacyScreenProbes.ExternalDisplayState,
    )

    public fun evaluate(o: Observation): RaspCheckResult {
        val evidence = listOf(
            RaspEvidence("app_in_foreground", o.foreground),
            RaspEvidence("screen_recording_state", if (o.recordingObservable) o.recording?.name else "not_observable"),
            RaspEvidence("external_display_count", if (o.externalDisplay.supported) o.externalDisplay.externalDisplayCount else null),
        )
        val foreground = o.foreground ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Foreground state could not be read",
        )
        if (!foreground) return RaspCheckResult.secure(DETECTOR_ID, evidence)
        val recorded = o.recording == RaspScreenRecordingProbes.State.RECORDED
        val cast = o.externalDisplay.supported && o.externalDisplay.externalDisplayDetected
        if (recorded || cast) return RaspCheckResult.detected(DETECTOR_ID, evidence)
        if (!o.externalDisplay.supported) {
            return RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Displays could not be read")
        }
        if (!o.recordingObservable || o.recording == null) {
            return RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Screen capture is not observable (needs Android 15 and ${RaspScreenRecordingProbes.PERMISSION})",
            )
        }
        return RaspCheckResult.secure(DETECTOR_ID, evidence)
    }

    public fun observe(context: Context): Observation {
        val recording = RaspScreenRecordingProbes.observe(context)
        return Observation(
            foreground = RaspFraudEnvironment.isAppInForeground(),
            recording = recording.state,
            recordingObservable = recording.apiLevel >= RaspScreenRecordingProbes.MIN_API && recording.permissionGranted &&
                recording.registrationError == null,
            externalDisplay = RaspPrivacyScreenProbes.externalDisplayState(context),
        )
    }
}
