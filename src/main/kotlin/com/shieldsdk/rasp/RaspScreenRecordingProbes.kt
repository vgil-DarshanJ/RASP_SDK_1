package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.view.WindowManager
import androidx.annotation.RequiresApi
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/**
 * `screen_recording` — are this app's windows currently being screen-recorded?
 *
 * Android 15 (API 35)+: `WindowManager.addScreenRecordingCallback`, which
 * reports whether this app's windows are visible in an active recording.
 * Needs `android.permission.DETECT_SCREEN_RECORDING` (a normal permission the
 * host declares). Registered once per process on first use; the initial
 * state comes back from the registration call.
 *
 * Below API 35 → UNAVAILABLE. Android has no public API that lets an app see
 * another app's MediaProjection session; mirroring to a display is covered
 * separately by `external_display`.
 */
object RaspScreenRecordingProbes {

    const val DETECTOR_ID = "screen_recording"
    const val PERMISSION = "android.permission.DETECT_SCREEN_RECORDING"
    const val MIN_API = 35

    enum class State { RECORDED, NOT_RECORDED }

    data class Observation(
        val apiLevel: Int,
        val permissionGranted: Boolean,
        /** `null` until the callback has reported a state. */
        val state: State?,
        val registrationError: String?,
    )

    private val state = AtomicReference<State?>(null)
    private val registrationError = AtomicReference<String?>(null)
    @Volatile private var registered = false
    private val callbackExecutor by lazy {
        Executors.newSingleThreadExecutor { Thread(it, "RaspScreenRecording").apply { isDaemon = true } }
    }

    /** Maps `WindowManager.SCREEN_RECORDING_STATE_*` to [State]. */
    fun stateFromPlatform(value: Int): State =
        if (value == 1 /* SCREEN_RECORDING_STATE_VISIBLE */) State.RECORDED else State.NOT_RECORDED

    fun evaluate(o: Observation): RaspCheckResult {
        if (o.apiLevel < MIN_API) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "Screen-recording callback needs Android 15 (API 35)")
        }
        if (!o.permissionGranted) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "$PERMISSION not granted to the host app")
        }
        o.registrationError?.let { return RaspCheckResult.error(DETECTOR_ID, "Callback registration failed: $it") }
        val evidence = listOf(RaspEvidence("recording_state", o.state?.name))
        return when (o.state) {
            State.RECORDED -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            State.NOT_RECORDED -> RaspCheckResult.secure(DETECTOR_ID, evidence)
            null -> RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "No recording state reported yet")
        }
    }

    fun observe(context: Context): Observation {
        val api = Build.VERSION.SDK_INT
        if (api < MIN_API) return Observation(api, false, null, null)
        val granted = context.checkSelfPermission(PERMISSION) == PackageManager.PERMISSION_GRANTED
        if (!granted) return Observation(api, false, null, null)
        if (!registered) register(context.applicationContext ?: context)
        return Observation(api, true, state.get(), registrationError.get())
    }

    @Synchronized
    private fun register(context: Context) {
        if (registered || Build.VERSION.SDK_INT < MIN_API) return
        try {
            registerApi35(context)
            registered = true
        } catch (e: Exception) {
            registrationError.set(e.message ?: e.javaClass.simpleName)
        }
    }

    @RequiresApi(35)
    private fun registerApi35(context: Context) {
        val windowManager = context.getSystemService(WindowManager::class.java)
        val initial = windowManager.addScreenRecordingCallback(callbackExecutor) { value ->
            state.set(stateFromPlatform(value))
        }
        state.set(stateFromPlatform(initial))
    }
}
