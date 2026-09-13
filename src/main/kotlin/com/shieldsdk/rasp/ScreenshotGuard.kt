package com.shieldsdk.rasp

import android.app.Activity
import android.view.WindowManager

/**
 * Standalone screenshot **and** screen-recording block, for a consumer that
 * wants only this one control with zero Flutter dependency — a pure
 * Kotlin/Java Android app, or any `Activity` that wants to manage the flag
 * itself outside the [RaspShieldPlugin]/[RaspSecurityChannelHandler]
 * MethodChannel path. See `docs/LEAN_SECURITY_INTEGRATION_GUIDE.md`.
 *
 * ## Screenshots AND video — same flag, same guarantee
 *
 * `WindowManager.LayoutParams.FLAG_SECURE` is a single Android primitive
 * that covers **both** attack surfaces at once:
 *
 * * A screenshot taken via the system screenshot action, a launcher
 *   shortcut, or a third-party "screenshot" app — the OS refuses to
 *   rasterize the window; the resulting image is black.
 * * **Screen recording / screen casting** — `MediaProjection` (the API every
 *   screen-recorder and casting app, including Google's own, is built on)
 *   and wireless display mirroring are blocked by the identical flag: a
 *   secure window is omitted from the captured/mirrored output, not merely
 *   the still-image path. This is not a separate control to configure —
 *   [enable] below already stops both the instant it is applied, and there
 *   is no "video-only" or "screenshot-only" variant of this flag to choose
 *   between.
 *
 * ## What this cannot do
 *
 * `FLAG_SECURE` blocks the OS-level capture path. It cannot, and no app-side
 * control ever can, prevent a second physical camera pointed at the screen,
 * or a video cable/HDMI-out capture device the OS is unaware of on some
 * heavily modified/rooted devices. Stated honestly here rather than implied
 * as an absolute guarantee — the same framing this SDK already applies to
 * clipboard protection's limits.
 *
 * ## FLAG_SECURE timing — read before shipping
 *
 * Applying this flag **before** `super.onCreate()` was empirically proven on
 * a physical OnePlus device (Android 16 / API 36) to avoid a black-screen
 * regression some OEM compositors otherwise cause when the flag is applied
 * to an already-rendering surface. A plain `Activity` (this class's use
 * case) *can* apply it that early — unlike a Flutter plugin, which has no
 * hook that runs before `Activity.onCreate()` at all. Test on your actual
 * OEM device matrix regardless (Samsung, Xiaomi/Oppo/Vivo, OnePlus) — this
 * is a disclosed, not fully eliminated, compatibility risk.
 */
object ScreenshotGuard {

    /**
     * `true`/`false` = the real, read-back window state. `null` = could not
     * be determined (no Activity/window yet, or the platform threw) — never
     * collapse this into `false`. A `null` you treat as "safe" is exactly
     * how this control fails open instead of closed.
     */
    fun isActive(activity: Activity?): Boolean? {
        val window = activity?.window ?: return null
        return try {
            (window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Blocks screenshots and screen recording/casting for [activity]'s
     * window. Never throws — a platform failure here is silently absorbed
     * so it can never crash the host `Activity`; call [isActive] immediately
     * after if you need to confirm it actually took effect (it always
     * should on real Android, but this SDK never assumes that without
     * reading it back — see the class doc's honesty policy).
     */
    fun enable(activity: Activity?) {
        val window = activity?.window ?: return
        try {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        } catch (e: Exception) {
            // Never let this crash the Activity. isActive() reads the real
            // attribute, so a failure here surfaces honestly at the next
            // check instead of being silently assumed to have worked.
        }
    }

    /** Clears the flag — e.g. for a screen the user is meant to capture. */
    fun disable(activity: Activity?) {
        val window = activity?.window ?: return
        try {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } catch (e: Exception) {
        }
    }
}
