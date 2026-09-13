package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.view.Display
import android.view.accessibility.AccessibilityManager

/**
 * Overlay/tapjacking, third-party accessibility abuse, and external-display
 * presence — verbatim port of `RaspSecurityChannelHandler.isOverlayAttackDetected()`/
 * `isAccessibilityAbused()`/`externalDisplayState()`.
 */
public object RaspPrivacyScreenProbes {

    /**
     * `true` when a third-party app holds `SYSTEM_ALERT_WINDOW`.
     *
     * ## A real, disclosed limitation — not fixed in this port
     *
     * This walks `PackageManager.getInstalledPackages()` — a **bulk**
     * installed-apps enumeration. On API 30+ package-visibility rules,
     * that call is filtered to only the packages this app can already see
     * (itself, anything declared in `<queries>`, and a small system
     * allowlist) **unless** the app holds the `QUERY_ALL_PACKAGES`
     * permission — a sensitive permission Google Play requires explicit,
     * narrow justification to declare, and this SDK does not request it on
     * a consuming app's behalf (that decision belongs to the app team, not
     * a library). The practical consequence: on a real API 30+ device
     * without that permission, this check is **structurally blind** to
     * most third-party overlay-permission holders — it will typically
     * report `false` regardless of what is actually installed, not
     * because nothing was found but because nothing outside this app's
     * visibility scope could be enumerated at all.
     *
     * Ported unchanged from the pre-extraction implementation, which had
     * the identical limitation — not a regression introduced here. If your
     * threat model requires this signal to actually work on API 30+, the
     * two real options are: request `QUERY_ALL_PACKAGES` (Play Store
     * policy review required) or corroborate with [RaspScreenGuard]'s
     * `touch_obscured` runtime signal instead, which needs no package
     * visibility at all and is unaffected by this limitation — see
     * [overlayEvidence]'s two-signal design.
     */
    fun isOverlayAttackDetected(context: Context): Boolean = try {
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        packages.any { pkg ->
            val permissions = pkg.requestedPermissions
            permissions != null && permissions.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW) &&
                !pkg.packageName.startsWith("com.android.") &&
                !pkg.packageName.startsWith("com.google.android.") &&
                pkg.packageName != context.packageName
        }
    } catch (e: Exception) {
        false
    }

    /**
     * Two independent signals, matching the Dart side's `OverlayDetector`
     * exactly: the static permission-holder scan above, plus
     * [RaspScreenGuard]'s runtime touch-obscured signal when a guard
     * instance is supplied (`null` if the caller has none attached — the
     * touch signal is simply reported as not-yet-observed rather than
     * omitted).
     */
    fun overlayEvidence(context: Context, screenGuard: RaspScreenGuard?): List<RaspOverlaySignal> {
        val permissionHolderDetected = try {
            isOverlayAttackDetected(context)
        } catch (e: Exception) {
            null
        }
        val touchObscured = screenGuard?.currentTouchObscuredState()

        return listOf(
            RaspOverlaySignal(
                signal = "system_alert_window_holder",
                detected = permissionHolderDetected == true,
                conclusive = permissionHolderDetected != null,
            ),
            RaspOverlaySignal(
                signal = "touch_obscured",
                detected = touchObscured == true,
                conclusive = touchObscured != null,
            ),
        )
    }

    /**
     * `null` when it could not be determined. Filters out this app's own
     * accessibility usage and known first-party/screen-reader services
     * (`com.android.*`, `com.google.android.*`, TalkBack).
     */
    fun isAccessibilityAbused(context: Context): Boolean? = try {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )
        enabledServices.any { service ->
            val pkgName = service.resolveInfo.serviceInfo.packageName
            !pkgName.startsWith("com.android.") &&
                !pkgName.startsWith("com.google.android.") &&
                !pkgName.contains("talkback")
        }
    } catch (e: Exception) {
        null
    }

    data class ExternalDisplayState(
        val supported: Boolean,
        val externalDisplayCount: Int = 0,
        val externalDisplayDetected: Boolean = false,
        val displayNames: List<String> = emptyList(),
    )

    /**
     * Reports PRESENCE of a non-default display (external/wireless/cast) —
     * not proof this app's content is actually being shown there (Android
     * exposes no such distinction to an app that has not itself created a
     * `Presentation`).
     */
    fun externalDisplayState(context: Context): ExternalDisplayState = try {
        val displayManager = context.getSystemService(Context.DISPLAY_SERVICE)
            as? DisplayManager ?: return ExternalDisplayState(supported = false)
        val nonDefault = displayManager.displays.filter { it.displayId != Display.DEFAULT_DISPLAY }
        ExternalDisplayState(
            supported = true,
            externalDisplayCount = nonDefault.size,
            externalDisplayDetected = nonDefault.isNotEmpty(),
            displayNames = nonDefault.map { it.name },
        )
    } catch (e: Exception) {
        ExternalDisplayState(supported = false)
    }
}

data class RaspOverlaySignal(
    val signal: String,
    val detected: Boolean,
    /** `false` means this individual signal could not reach a verdict —
     *  mirrors the shared two-signal aggregation rule: DETECTED wins if
     *  either signal fired; otherwise SECURE only if at least one signal
     *  was conclusively clean; otherwise UNKNOWN. */
    val conclusive: Boolean,
)
