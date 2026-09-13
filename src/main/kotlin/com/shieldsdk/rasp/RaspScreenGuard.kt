package com.shieldsdk.rasp

import android.app.Activity
import android.os.Build
import android.view.MotionEvent
import android.view.Window

/**
 * The Activity-lifecycle-bound half of screen protection: touch-obscured
 * tracking (overlay/tapjacking corroboration) and screenshot-event capture
 * (API 34+). [ScreenshotGuard] already covers the stateless FLAG_SECURE
 * toggle and is reused here rather than duplicated — this class adds
 * exactly what genuinely needs to live across an Activity's attach/detach
 * lifecycle.
 *
 * ## Why this exists as its own class, separate from [RaspShieldCore]
 *
 * Every [RaspShieldCore] check takes a `Context` and is stateless per call.
 * Touch-obscured tracking and screenshot-event capture are fundamentally
 * different: they require wrapping the *live* `Window.Callback` for as
 * long as an Activity is on screen, and unwrapping it again on detach — a
 * one-shot `Context`-based call cannot express that. A native host
 * constructs one `RaspScreenGuard` per Activity (or reuses one across
 * Activities, calling [attach]/[detach] on each transition) — the exact
 * same lifecycle [RaspShieldPlugin] already manages for the Flutter path,
 * ported here with no Flutter dependency.
 *
 * ## Usage
 *
 * ```kotlin
 * class TransferActivity : AppCompatActivity() {
 *     private val screenGuard = RaspScreenGuard()
 *
 *     override fun onCreate(savedInstanceState: Bundle?) {
 *         screenGuard.attach(this)   // apply BEFORE super.onCreate() — see class doc
 *         super.onCreate(savedInstanceState)
 *     }
 *
 *     override fun onDestroy() {
 *         screenGuard.detach()
 *         super.onDestroy()
 *     }
 * }
 * ```
 *
 * ## FLAG_SECURE timing — same disclosed risk as [ScreenshotGuard]
 *
 * [attach] applies `FLAG_SECURE` immediately, and a native host calling it
 * before `super.onCreate()` gets the same early-as-possible timing the
 * pre-extraction `MainActivity.onCreate()` had — this is the one genuine
 * advantage the native path has over the Flutter plugin path, which has no
 * hook that runs that early (`onAttachedToActivity` necessarily fires
 * after `super.onCreate()`). Still test on your real OEM device matrix —
 * see `docs/LEAN_SECURITY_INTEGRATION_GUIDE.md` Part C for the specific
 * OnePlus compositor finding this disclosure is based on.
 */
class RaspScreenGuard {

    private var activity: Activity? = null
    private var originalWindowCallback: Window.Callback? = null
    private var screenCaptureCallback: Activity.ScreenCaptureCallback? = null

    @Volatile
    private var lastTouchObscured: Boolean? = null

    @Volatile
    private var screenshotEventCount = 0

    @Volatile
    private var lastScreenshotEventAtMillis: Long? = null

    /**
     * Applies `FLAG_SECURE`, installs touch-obscured tracking, and
     * registers the screenshot-event callback (API 34+ only). Safe to call
     * again on the same or a different Activity — [detach] is called
     * internally first if something is already attached.
     */
    fun attach(target: Activity) {
        if (activity != null) detach()
        activity = target

        ScreenshotGuard.enable(target)
        installTouchObscuredTracking(target)
        registerScreenCaptureCallback(target)
    }

    /** Idempotent — safe to call when never attached or already detached. */
    fun detach() {
        unregisterScreenCaptureCallback()
        restoreWindowCallback()
        activity = null
    }

    // ── FLAG_SECURE passthrough — see ScreenshotGuard for the real logic ──

    fun isScreenshotProtectionActive(): Boolean? = ScreenshotGuard.isActive(activity)
    fun enableScreenshotProtection() = ScreenshotGuard.enable(activity)
    fun disableScreenshotProtection() = ScreenshotGuard.disable(activity)

    // ── Touch-obscured tracking ───────────────────────────────────────

    private fun installTouchObscuredTracking(target: Activity) {
        val window = target.window
        val current = window.callback ?: return
        originalWindowCallback = current
        window.callback = TouchObscuredWindowCallback(current) { obscured ->
            lastTouchObscured = obscured
        }
    }

    private fun restoreWindowCallback() {
        val current = activity ?: return
        val original = originalWindowCallback ?: return
        try {
            if (current.window.callback is TouchObscuredWindowCallback) {
                current.window.callback = original
            }
        } catch (e: Exception) {
            // Activity/window may already be torn down; nothing to restore.
        }
        originalWindowCallback = null
    }

    private class TouchObscuredWindowCallback(
        private val delegate: Window.Callback,
        private val onTouch: (Boolean) -> Unit,
    ) : Window.Callback by delegate {
        override fun dispatchTouchEvent(event: MotionEvent): Boolean {
            onTouch(
                (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0 ||
                    (event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
            )
            return delegate.dispatchTouchEvent(event)
        }
    }

    /**
     * `null` before any touch has been observed this attach — never
     * silently treated as "not obscured." See [RaspOverlayEvidence].
     */
    fun currentTouchObscuredState(): Boolean? = lastTouchObscured

    // ── Screenshot-event capture (API 34+) ────────────────────────────

    private fun registerScreenCaptureCallback(target: Activity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        try {
            val callback = Activity.ScreenCaptureCallback {
                screenshotEventCount += 1
                lastScreenshotEventAtMillis = System.currentTimeMillis()
            }
            target.registerScreenCaptureCallback(target.mainExecutor, callback)
            screenCaptureCallback = callback
        } catch (e: Exception) {
            screenCaptureCallback = null
        }
    }

    private fun unregisterScreenCaptureCallback() {
        val current = activity
        val callback = screenCaptureCallback ?: return
        if (current != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                current.unregisterScreenCaptureCallback(callback)
            } catch (e: Exception) {
                // Activity may already be torn down; nothing to unregister.
            }
        }
        screenCaptureCallback = null
    }

    /**
     * Read-and-clear: call once per scan cycle. The count reported is
     * exactly how many screenshot events fired since the last read, then
     * resets — never double-reports the same capture.
     */
    fun drainScreenshotEventEvidence(): RaspScreenshotEventEvidence {
        val count = screenshotEventCount
        val lastAt = lastScreenshotEventAtMillis
        screenshotEventCount = 0
        return RaspScreenshotEventEvidence(
            supported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
            detected = count > 0,
            count = count,
            lastAtMillis = lastAt,
        )
    }

    /**
     * What this build/OS combination can actually do. See this class's
     * doc for why screen-recording/casting has no complementary
     * *detection* capability on any Android API level — `FLAG_SECURE` is
     * the platform's actual defense there, not a paired detector.
     */
    fun screenCaptureCapabilities(): RaspScreenCaptureCapabilities = RaspScreenCaptureCapabilities(
        screenshotPreventionSupported = true,
        screenshotDetectionSupported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
        screenshotDetectionMinSdkInt = Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
        screenRecordingDetectionSupported = false,
        screenShareDetectionSupported = false,
        externalDisplayDetectionSupported = true,
    )
}

data class RaspScreenshotEventEvidence(
    val supported: Boolean,
    val detected: Boolean,
    val count: Int,
    val lastAtMillis: Long?,
)

data class RaspScreenCaptureCapabilities(
    val screenshotPreventionSupported: Boolean,
    val screenshotDetectionSupported: Boolean,
    val screenshotDetectionMinSdkInt: Int,
    val screenRecordingDetectionSupported: Boolean,
    val screenShareDetectionSupported: Boolean,
    val externalDisplayDetectionSupported: Boolean,
)
