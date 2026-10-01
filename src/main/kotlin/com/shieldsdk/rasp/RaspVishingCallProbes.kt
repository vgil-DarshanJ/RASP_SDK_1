package com.shieldsdk.rasp

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.telephony.TelephonyManager

/**
 * `vishing_call` — is a phone call ringing or in progress while the app is
 * in the foreground? (The common voice-phishing pattern: a caller talks the
 * victim through a transfer in the banking app.)
 *
 * Needs `READ_PHONE_STATE` (the host requests it at runtime); without it →
 * UNAVAILABLE. Call state from `TelephonyManager.getCallState()`; foreground
 * from `ActivityManager.getMyMemoryState()` (no permission).
 *
 * Call RINGING/OFFHOOK + app in foreground → DETECTED; otherwise SECURE;
 * call state or foreground state unreadable → UNKNOWN.
 *
 * Limitation: VoIP calls (messaging apps) do not change the telephony call
 * state and are not seen by this detector.
 *
 * For payment screens, [isCallActive] gives the host the raw flag directly.
 */
object RaspVishingCallProbes {

    const val DETECTOR_ID = "vishing_call"
    const val PERMISSION = "android.permission.READ_PHONE_STATE"

    enum class CallState { IDLE, RINGING, OFFHOOK }

    data class Observation(
        val permissionGranted: Boolean,
        /** `null` when it could not be read. */
        val callState: CallState?,
        /** `null` when it could not be read. */
        val appInForeground: Boolean?,
    )

    fun evaluate(o: Observation): RaspCheckResult {
        if (!o.permissionGranted) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "$PERMISSION not granted to the host app")
        }
        val evidence = listOf(
            RaspEvidence("call_state", o.callState?.name),
            RaspEvidence("app_in_foreground", o.appInForeground),
        )
        if (o.callState == null || o.appInForeground == null) {
            return RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Call state or foreground state could not be read",
            )
        }
        val callActive = o.callState != CallState.IDLE
        return if (callActive && o.appInForeground) RaspCheckResult.detected(DETECTOR_ID, evidence)
        else RaspCheckResult.secure(DETECTOR_ID, evidence)
    }

    fun observe(context: Context): Observation {
        val granted = context.checkSelfPermission(PERMISSION) == PackageManager.PERMISSION_GRANTED
        if (!granted) return Observation(false, null, null)
        return Observation(true, readCallState(context), isAppInForeground(context))
    }

    /**
     * For the host app's payment/transfer screens: `true` while a phone call is
     * ringing or in progress, `false` when there is none, `null` when it cannot
     * be told (no READ_PHONE_STATE, or the state is unreadable).
     */
    fun isCallActive(context: Context): Boolean? {
        if (context.checkSelfPermission(PERMISSION) != PackageManager.PERMISSION_GRANTED) return null
        return readCallState(context)?.let { it != CallState.IDLE }
    }

    @Suppress("DEPRECATION")
    private fun readCallState(context: Context): CallState? = try {
        val telephony = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        when (telephony.callState) {
            TelephonyManager.CALL_STATE_IDLE -> CallState.IDLE
            TelephonyManager.CALL_STATE_RINGING -> CallState.RINGING
            TelephonyManager.CALL_STATE_OFFHOOK -> CallState.OFFHOOK
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    private fun isAppInForeground(context: Context): Boolean? = try {
        val info = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(info)
        info.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
    } catch (e: Exception) {
        null
    }
}
