package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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
    fun isOverlayAttackDetected(context: Context): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        return try {
            val pm = context.packageManager
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
                ?: return null
            val holders = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                .filter { pkg ->
                    pkg.packageName != context.packageName &&
                        pkg.packageName !in accessibilityAllowlist &&
                        pkg.requestedPermissions?.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW) == true
                }
            if (holders.any { pkg ->
                    val uid = pkg.applicationInfo?.uid ?: return@any false
                    appOps.checkOpNoThrow(
                        AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                        uid,
                        pkg.packageName,
                    ) == AppOpsManager.MODE_ALLOWED
                }) true
            // Package visibility means an ordinary app cannot prove there are
            // no overlay windows. A negative scan is UNKNOWN, never SECURE.
            else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Evidence from the static permission-holder scan and the runtime
     * [RaspScreenGuard] touch-obscured signal. A permission holder is audit
     * context only: it does not prove an overlay is currently obscuring this
     * window. The Android framework's touch flag is the sole verdict signal.
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
                signal = "overlay_permission_holder_present",
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
     * `null` when it could not be determined. Known password managers and
     * assistive services are allowlisted. Unknown services are DETECTED only
     * when they can retrieve window content or perform gestures.
     */
    fun isAccessibilityAbused(context: Context): Boolean? = try {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_ALL_MASK
        )
        enabledServices.any { service -> classifyAccessibilityService(
            packageName = service.resolveInfo?.serviceInfo?.packageName,
            capabilities = service.capabilities,
        ).detected }
    } catch (e: Exception) {
        null
    }

    /** Package allowlist is intentionally explicit and may be extended by a release. */
    @JvmField
    val accessibilityAllowlist: Set<String> = setOf(
        "com.google.android.marvin.talkback", "com.android.talkback",
        "com.samsung.android.accessibility.talkback", "com.bjbyhd.screenreader_huawei",
        "com.bitwarden", "com.agilebits.onepassword", "com.lastpass.lpandroid",
        "com.dashlane", "com.keepersecurity.keeper", "com.enpass.app",
        "com.truekey", "com.zoho.vault",
    )

    data class AccessibilityAssessment(val detected: Boolean, val allowlisted: Boolean)

    /** Pure policy seam for false-positive and threat-path unit tests. */
    @JvmStatic
    fun classifyAccessibilityService(packageName: String?, capabilities: Int): AccessibilityAssessment {
        val allowlisted = packageName in accessibilityAllowlist ||
            packageName?.startsWith("com.android.") == true ||
            packageName?.startsWith("com.google.android.") == true
        val canObserve = capabilities and
            AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0
        val canPerformGestures = capabilities and
            AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES != 0
        return AccessibilityAssessment(
            detected = !allowlisted && (canObserve || canPerformGestures),
            allowlisted = allowlisted,
        )
    }

    /** The runtime `FLAG_WINDOW_IS_OBSCURED`/partial-obscured signal decides. */
    @JvmStatic
    fun classifyOverlaySignals(signals: List<RaspOverlaySignal>): RaspCheckStatus {
        val touch = signals.firstOrNull { it.signal == "touch_obscured" }
        return when {
            touch?.detected == true -> RaspCheckStatus.DETECTED
            touch?.conclusive == true -> RaspCheckStatus.SECURE
            else -> RaspCheckStatus.UNKNOWN
        }
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
