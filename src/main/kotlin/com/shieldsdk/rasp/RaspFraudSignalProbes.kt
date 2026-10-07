package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.ActivityManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager

/*
 * Shared parts of the Task 8.1 fraud signals (otp_interception_risk,
 * sms_reader_abuse, otp_forwarding_risk, remote_control_app,
 * screen_sharing_risk; one probe object per file).
 *
 * Privacy: none of these reads SMS content, contacts, phone numbers, IMEI or
 * account names, and none needs a new permission. Apps are seen only through
 * package visibility the engine already declares (`<queries>` packages and
 * the launcher intent); READ_SMS, RECEIVE_SMS and QUERY_ALL_PACKAGES are not
 * requested. Every observation is split from a pure `evaluate`, so all three
 * outcomes are unit-tested without a device.
 */

/** Present / absent / could not be decided — one input of a combined verdict. */
public enum class RaspSignalState { PRESENT, ABSENT, UNDECIDED }

/**
 * One input of a combined verdict. [hard]: one hard signal is enough;
 * soft signals need a second one.
 */
public data class RaspContributingSignal(
    val name: String,
    val hard: Boolean,
    val state: RaspSignalState,
    val detail: String? = null,
)

/**
 * Combines signals without ever turning "could not decide" into SECURE:
 * DETECTED when the present signals alone are enough (1 hard or 2 soft);
 * SECURE only when the verdict would stay clean even if every undecided
 * signal were present; otherwise UNKNOWN naming the undecided signals.
 */
internal object RaspSignalCombiner {
    fun combine(
        detectorId: String,
        signals: List<RaspContributingSignal>,
        extraEvidence: List<RaspEvidence> = emptyList(),
        softNeeded: Int = 2,
    ): RaspCheckResult {
        val present = signals.filter { it.state == RaspSignalState.PRESENT }
        val undecided = signals.filter { it.state == RaspSignalState.UNDECIDED }
        val evidence = present.map { RaspEvidence("contributing_signal", it.name, if (it.hard) "hard" else "soft") } +
            present.mapNotNull { s -> s.detail?.let { RaspEvidence("${s.name}_detail", it) } } +
            undecided.map { RaspEvidence("undecided_signal", it.name, it.detail) } +
            extraEvidence
        fun reaches(list: List<RaspContributingSignal>) = list.any { it.hard } || list.count { !it.hard } >= softNeeded
        return when {
            reaches(present) -> RaspCheckResult.detected(detectorId, evidence)
            reaches(present + undecided) -> RaspCheckResult(
                detectorId, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Could not decide: " + undecided.joinToString { it.name },
            )
            else -> RaspCheckResult.secure(detectorId, evidence)
        }
    }
}

/** Facts about one package, as far as package visibility allows. */
public data class RaspAppFacts(val packageName: String, val visible: Boolean, val system: Boolean)

/** Shared device reads used by several fraud detectors. Each returns `null` when it could not be read. */
internal object RaspFraudEnvironment {

    /** Package names holding notification-listener access (`enabled_notification_listeners`). */
    fun notificationListenerPackages(context: Context): List<String>? = try {
        parseListenerSetting(Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners"))
    } catch (e: Exception) {
        null
    }

    /** `"pkg/cls:pkg2/cls2"` → `["pkg", "pkg2"]`. Pure. */
    fun parseListenerSetting(value: String?): List<String> =
        value.orEmpty().split(':').mapNotNull { it.substringBefore('/').trim().takeIf(String::isNotEmpty) }.distinct()

    fun appFacts(context: Context, packageName: String): RaspAppFacts = try {
        val info = context.packageManager.getApplicationInfo(packageName, 0)
        val system = info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        RaspAppFacts(packageName, visible = true, system = system)
    } catch (e: PackageManager.NameNotFoundException) {
        RaspAppFacts(packageName, visible = false, system = false)
    }

    /** Enabled accessibility services as (package, capabilities). */
    fun accessibilityServices(context: Context): List<Pair<String?, Int>>? = try {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .map { it.resolveInfo?.serviceInfo?.packageName to it.capabilities }
    } catch (e: Exception) {
        null
    }

    /** Which of [packages] are installed and visible; `null` if PackageManager failed. */
    fun installed(context: Context, packages: Collection<String>): List<String>? = try {
        val pm = context.packageManager
        packages.distinct().filter { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    } catch (e: Exception) {
        null
    }

    fun isAppInForeground(): Boolean? = try {
        val info = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(info)
        info.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
    } catch (e: Exception) {
        null
    }

    /** `"all"` before Android 11 or with QUERY_ALL_PACKAGES (granted by the host); otherwise limited. */
    fun visibilityComplete(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
            context.checkSelfPermission("android.permission.QUERY_ALL_PACKAGES") == PackageManager.PERMISSION_GRANTED

    fun visibilityLabel(complete: Boolean): String = if (complete) "all" else "declared_queries_and_launcher_apps"

    /** TRUSTED: host, allowlisted, platform prefix or a visible system app. */
    enum class ListenerClass { TRUSTED, UNKNOWN_APP, UNVERIFIED }

    fun classifyListener(facts: RaspAppFacts, hostPackage: String, allowlist: Collection<String>): ListenerClass = when {
        facts.packageName == hostPackage || facts.packageName in allowlist ||
            facts.packageName.startsWith("com.android.") || facts.packageName.startsWith("com.google.android.") ||
            facts.packageName == "android" -> ListenerClass.TRUSTED
        !facts.visible -> ListenerClass.UNVERIFIED
        facts.system -> ListenerClass.TRUSTED
        else -> ListenerClass.UNKNOWN_APP
    }

    /** Non-allowlisted accessibility services that can perform gestures. */
    fun gestureServices(services: List<Pair<String?, Int>>): List<String> = services.filter { (pkg, caps) ->
        val assessment = RaspPrivacyScreenProbes.classifyAccessibilityService(pkg, caps)
        !assessment.allowlisted && caps and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES != 0
    }.map { it.first ?: "unknown" }.distinct()
}
