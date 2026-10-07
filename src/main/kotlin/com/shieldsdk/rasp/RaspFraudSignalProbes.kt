package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.ActivityManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager

/*
 * Task 8.1 fraud signals: otp_interception_risk, sms_reader_abuse,
 * otp_forwarding_risk, remote_control_app, screen_sharing_risk.
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

// ── remote_control_app ──────────────────────────────────────────────────

/**
 * `remote_control_app` — a known remote-control or screen-sharing app is
 * installed, or a cast display / screen recording is active now.
 *
 * Packages: [builtInPackages] (declared in the engine `<queries>`) plus an
 * optional signed list in the same format as `malware_reputation`
 * (`{payload, signature}`, Ed25519, see [RaspMalwareReputationProbes]).
 * Packages from the signed list are only seen if the host declares them in
 * its own `<queries>` (or they have a launcher icon).
 *
 * Screen recording is read only on Android 15+ with DETECT_SCREEN_RECORDING;
 * below that it is reported as evidence (`screen_recording_state =
 * not_observable`) and the verdict rests on installed apps and cast displays.
 * `screen_sharing_risk` reports that case as UNKNOWN.
 */
public object RaspRemoteControlProbes {
    public const val DETECTOR_ID: String = "remote_control_app"

    /** Starting list; extend with a signed list. Each package is in the engine `<queries>`. */
    @JvmField
    public val builtInPackages: List<String> = listOf(
        "com.teamviewer.quicksupport.market",
        "com.teamviewer.host.market",
        "com.anydesk.anydeskandroid",
        "com.rsupport.mobizen.remote",
        "com.remotepc.rpcmobile",
        "com.sand.airdroid",
        "com.carriez.flutter_hbb",
    )

    public data class Observation(
        /** Built-in packages installed; `null` when the package check failed. */
        val builtInInstalled: List<String>?,
        /** `null` = no signed list configured. */
        val listLoad: RaspMalwareReputationProbes.Load?,
        /** Signed-list packages installed; `null` when not checked or failed. */
        val listInstalled: List<String>?,
        val recording: RaspScreenRecordingProbes.State?,
        val recordingObservable: Boolean,
        val externalDisplay: RaspPrivacyScreenProbes.ExternalDisplayState,
        val visibility: String,
    )

    /** Installed remote-control packages from [o], `null` when a configured source could not be checked. */
    internal fun installedPackages(o: Observation): List<String>? {
        val builtIn = o.builtInInstalled ?: return null
        val fromList = when (o.listLoad) {
            null -> emptyList()
            is RaspMalwareReputationProbes.Load.Invalid -> emptyList()
            is RaspMalwareReputationProbes.Load.Ok -> o.listInstalled ?: return null
        }
        return (builtIn + fromList).distinct()
    }

    public fun evaluate(o: Observation): RaspCheckResult {
        val installed = installedPackages(o)
        val recorded = o.recording == RaspScreenRecordingProbes.State.RECORDED
        val cast = o.externalDisplay.supported && o.externalDisplay.externalDisplayDetected
        val evidence = buildList {
            installed?.forEach { add(RaspEvidence("remote_control_package", it, "installed")) }
            if (recorded) add(RaspEvidence("active_screen_session", "screen_recording"))
            if (cast) add(RaspEvidence("active_screen_session", "cast_or_external_display", o.externalDisplay.displayNames.joinToString()))
            add(RaspEvidence("screen_recording_state", if (o.recordingObservable) o.recording?.name else "not_observable"))
            add(RaspEvidence("visibility", o.visibility))
            (o.listLoad as? RaspMalwareReputationProbes.Load.Ok)?.let { add(RaspEvidence("list_version", it.list.version)) }
        }
        if (!installed.isNullOrEmpty() || recorded || cast) return RaspCheckResult.detected(DETECTOR_ID, evidence)
        if (installed == null) {
            return RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Installed packages could not be checked")
        }
        (o.listLoad as? RaspMalwareReputationProbes.Load.Invalid)?.let {
            return RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Remote-control list rejected (${it.reason}); only the built-in list was checked",
            )
        }
        if (!o.externalDisplay.supported) {
            return RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Displays could not be read")
        }
        return RaspCheckResult.secure(DETECTOR_ID, evidence)
    }

    private val listCache = java.util.concurrent.atomic.AtomicReference<Triple<String, String, RaspMalwareReputationProbes.Load>?>(null)

    internal fun loadList(listJson: String?, publicKey: String?): RaspMalwareReputationProbes.Load? {
        if (listJson.isNullOrBlank() && publicKey.isNullOrBlank()) return null
        listCache.get()?.takeIf { it.first == listJson && it.second == publicKey }?.let { return it.third }
        return RaspMalwareReputationProbes.loadList(listJson, publicKey).also { load ->
            if (listJson != null && publicKey != null) listCache.set(Triple(listJson, publicKey, load))
        }
    }

    public fun observe(context: Context, listJson: String?, publicKey: String?): Observation {
        val load = loadList(listJson, publicKey)
        val listInstalled = (load as? RaspMalwareReputationProbes.Load.Ok)
            ?.let { ok -> RaspFraudEnvironment.installed(context, ok.list.entries.map { it.packageName }) }
        val recording = RaspScreenRecordingProbes.observe(context)
        val observable = recording.apiLevel >= RaspScreenRecordingProbes.MIN_API && recording.permissionGranted &&
            recording.registrationError == null
        return Observation(
            builtInInstalled = RaspFraudEnvironment.installed(context, builtInPackages),
            listLoad = load,
            listInstalled = listInstalled,
            recording = recording.state,
            recordingObservable = observable,
            externalDisplay = RaspPrivacyScreenProbes.externalDisplayState(context),
            visibility = RaspFraudEnvironment.visibilityLabel(RaspFraudEnvironment.visibilityComplete(context)),
        )
    }
}

// ── screen_sharing_risk ─────────────────────────────────────────────────

/**
 * `screen_sharing_risk` — while this app is in the foreground, its screen is
 * being captured (Android 15+ screen-recording callback) or a cast/external
 * display is attached. Background → SECURE (nothing of this app is shown).
 * When capture cannot be observed (below Android 15, or the host did not
 * declare DETECT_SCREEN_RECORDING) and no external display is attached →
 * UNKNOWN, never SECURE.
 */
public object RaspScreenSharingProbes {
    public const val DETECTOR_ID: String = "screen_sharing_risk"

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

// ── otp_interception_risk ───────────────────────────────────────────────

/**
 * `otp_interception_risk` — one verdict from signals that let another app
 * read or relay what is on screen or in notifications:
 *
 * | Signal | Weight |
 * |---|---|
 * | `accessibility_abuse` — a non-allowlisted accessibility service that can read windows or perform gestures | hard |
 * | `unknown_notification_listener` — a visible, non-system, non-allowlisted app holds notification-listener access (it can read OTP notifications) | hard |
 * | `overlay` — the window was touched through an overlay (needs the screen guard), or an app holding the overlay permission was seen | soft |
 * | `remote_control_app` — see [RaspRemoteControlProbes] | soft |
 *
 * 1 hard or 2 soft → DETECTED. A listener whose package is not visible is
 * undecided. Evidence names every contributing signal. A risk signal, not
 * proof that an OTP was read.
 */
public object RaspOtpInterceptionProbes {
    public const val DETECTOR_ID: String = "otp_interception_risk"

    public data class Observation(
        val hostPackage: String,
        /** Enabled accessibility services (package, capabilities); `null` = unreadable. */
        val accessibilityServices: List<Pair<String?, Int>>?,
        /** Listener packages with their facts; `null` = unreadable. */
        val notificationListeners: List<RaspAppFacts>?,
        val listenerAllowlist: List<String>,
        /** Touch through an overlay seen by the screen guard; `null` = no guard attached. */
        val touchObscured: Boolean?,
        /** An overlay-permission holder was seen (`true`), else `null` (a scan cannot prove absence). */
        val overlayPermissionHolder: Boolean?,
        /** Installed remote-control packages; `null` = could not be checked. */
        val remoteControlPackages: List<String>?,
    )

    public fun signals(o: Observation): List<RaspContributingSignal> {
        val abused = o.accessibilityServices?.filter { (pkg, caps) ->
            RaspPrivacyScreenProbes.classifyAccessibilityService(pkg, caps).detected
        }?.map { it.first ?: "unknown" }
        val listenerClasses = o.notificationListeners?.map {
            it.packageName to RaspFraudEnvironment.classifyListener(it, o.hostPackage, o.listenerAllowlist)
        }
        val unknownListeners = listenerClasses?.filter { it.second == RaspFraudEnvironment.ListenerClass.UNKNOWN_APP }?.map { it.first }
        val unverified = listenerClasses?.filter { it.second == RaspFraudEnvironment.ListenerClass.UNVERIFIED }?.map { it.first }
        val overlayState = when {
            o.touchObscured == true || o.overlayPermissionHolder == true -> RaspSignalState.PRESENT
            o.touchObscured == false -> RaspSignalState.ABSENT
            else -> RaspSignalState.UNDECIDED
        }
        return listOf(
            RaspContributingSignal(
                "accessibility_abuse", hard = true,
                state = when { abused == null -> RaspSignalState.UNDECIDED; abused.isEmpty() -> RaspSignalState.ABSENT; else -> RaspSignalState.PRESENT },
                detail = abused?.takeIf { it.isNotEmpty() }?.joinToString(),
            ),
            RaspContributingSignal(
                "unknown_notification_listener", hard = true,
                state = when {
                    unknownListeners == null -> RaspSignalState.UNDECIDED
                    unknownListeners.isNotEmpty() -> RaspSignalState.PRESENT
                    !unverified.isNullOrEmpty() -> RaspSignalState.UNDECIDED
                    else -> RaspSignalState.ABSENT
                },
                detail = when {
                    unknownListeners == null -> "notification listeners could not be read"
                    unknownListeners.isNotEmpty() -> unknownListeners.joinToString()
                    !unverified.isNullOrEmpty() -> "not visible to this app: " + unverified.joinToString()
                    else -> null
                },
            ),
            RaspContributingSignal(
                "overlay", hard = false, state = overlayState,
                detail = if (overlayState == RaspSignalState.UNDECIDED) "no screen guard attached" else null,
            ),
            RaspContributingSignal(
                "remote_control_app", hard = false,
                state = when {
                    o.remoteControlPackages == null -> RaspSignalState.UNDECIDED
                    o.remoteControlPackages.isEmpty() -> RaspSignalState.ABSENT
                    else -> RaspSignalState.PRESENT
                },
                detail = o.remoteControlPackages?.takeIf { it.isNotEmpty() }?.joinToString(),
            ),
        )
    }

    public fun evaluate(o: Observation): RaspCheckResult = RaspSignalCombiner.combine(DETECTOR_ID, signals(o))

    public fun observe(
        context: Context,
        screenGuard: RaspScreenGuard?,
        listenerAllowlist: List<String>,
        remoteListJson: String?,
        remoteListKey: String?,
    ): Observation {
        val remote = RaspRemoteControlProbes.observe(context, remoteListJson, remoteListKey)
        return Observation(
            hostPackage = context.packageName,
            accessibilityServices = RaspFraudEnvironment.accessibilityServices(context),
            notificationListeners = RaspFraudEnvironment.notificationListenerPackages(context)
                ?.map { RaspFraudEnvironment.appFacts(context, it) },
            listenerAllowlist = listenerAllowlist,
            touchObscured = screenGuard?.currentTouchObscuredState(),
            overlayPermissionHolder = try { RaspPrivacyScreenProbes.isOverlayAttackDetected(context) } catch (e: Exception) { null },
            remoteControlPackages = RaspRemoteControlProbes.installedPackages(remote),
        )
    }
}

// ── sms_reader_abuse ────────────────────────────────────────────────────

/**
 * `sms_reader_abuse` — visible apps that hold a granted SMS permission
 * (READ_SMS, RECEIVE_SMS, RECEIVE_MMS, RECEIVE_WAP_PUSH) or notification-
 * listener access, excluding this app, system apps, the default SMS app and
 * the configured allowlist. Reads only package metadata; never message
 * content. Clean but with limited package visibility (Android 11+ without
 * QUERY_ALL_PACKAGES, which this SDK does not request) → UNKNOWN with the
 * reason, never SECURE.
 */
public object RaspSmsReaderProbes {
    public const val DETECTOR_ID: String = "sms_reader_abuse"

    @JvmField
    public val SMS_PERMISSIONS: List<String> = listOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
    )

    public data class AppSms(val packageName: String, val system: Boolean, val grantedSmsPermissions: List<String>)

    public data class Observation(
        val hostPackage: String,
        /** Visible packages; `null` when they could not be listed. */
        val packages: List<AppSms>?,
        val notificationListeners: List<RaspAppFacts>?,
        val defaultSmsPackage: String?,
        val allowlist: List<String>,
        val visibilityComplete: Boolean,
    )

    public fun evaluate(o: Observation): RaspCheckResult {
        val packages = o.packages ?: return RaspCheckResult.unknown(DETECTOR_ID, "Installed packages could not be listed")
        fun excluded(pkg: String) = pkg == o.hostPackage || pkg == o.defaultSmsPackage || pkg in o.allowlist
        val smsApps = packages.filter { !it.system && !excluded(it.packageName) && it.grantedSmsPermissions.isNotEmpty() }
        val listenerClasses = o.notificationListeners?.filterNot { excluded(it.packageName) }?.map {
            it.packageName to RaspFraudEnvironment.classifyListener(it, o.hostPackage, o.allowlist)
        }
        val listenerApps = listenerClasses?.filter { it.second == RaspFraudEnvironment.ListenerClass.UNKNOWN_APP }?.map { it.first }
        val unverified = listenerClasses?.filter { it.second == RaspFraudEnvironment.ListenerClass.UNVERIFIED }?.map { it.first }
        val evidence = smsApps.map { RaspEvidence("sms_permission_app", it.packageName, it.grantedSmsPermissions.joinToString()) } +
            listenerApps.orEmpty().map { RaspEvidence("notification_listener_app", it) } +
            unverified.orEmpty().map { RaspEvidence("unverified_notification_listener", it, "package not visible") } +
            listOf(
                RaspEvidence("packages_checked", packages.size),
                RaspEvidence("visibility", RaspFraudEnvironment.visibilityLabel(o.visibilityComplete)),
                RaspEvidence("message_content_read", false),
            )
        return when {
            smsApps.isNotEmpty() || !listenerApps.isNullOrEmpty() -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            listenerApps == null -> RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Notification listeners could not be read")
            !unverified.isNullOrEmpty() -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "A notification listener is not visible to this app",
            )
            !o.visibilityComplete -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Package visibility is limited: only launcher apps and declared packages were checked",
            )
            else -> RaspCheckResult.secure(DETECTOR_ID, evidence)
        }
    }

    /** Granted SMS permissions of one package, from its requested-permission flags. Pure. */
    public fun grantedSms(requested: Array<String>?, flags: IntArray?): List<String> {
        if (requested == null || flags == null) return emptyList()
        return requested.indices.filter { i ->
            requested[i] in SMS_PERMISSIONS && i < flags.size && flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }.map { requested[it] }
    }

    public fun observe(context: Context, allowlist: List<String>): Observation {
        val packages = try {
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS).map { info ->
                val flags = info.applicationInfo?.flags ?: 0
                AppSms(
                    info.packageName,
                    system = flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                    grantedSmsPermissions = grantedSms(info.requestedPermissions, info.requestedPermissionsFlags),
                )
            }
        } catch (e: Exception) {
            null
        }
        val defaultSms = try { Telephony.Sms.getDefaultSmsPackage(context) } catch (e: Exception) { null }
        return Observation(
            hostPackage = context.packageName,
            packages = packages,
            notificationListeners = RaspFraudEnvironment.notificationListenerPackages(context)
                ?.map { RaspFraudEnvironment.appFacts(context, it) },
            defaultSmsPackage = defaultSms,
            allowlist = allowlist,
            visibilityComplete = RaspFraudEnvironment.visibilityComplete(context),
        )
    }
}

// ── otp_forwarding_risk ─────────────────────────────────────────────────

/**
 * `otp_forwarding_risk` — a RISK HINT from the environment, never proof that
 * an OTP was forwarded. DETECTED when any of these is present:
 * a known SMS auto-forward app ([builtInAutoForwardPackages] plus config), a
 * non-allowlisted accessibility service that can perform gestures, or a
 * remote-control app. Call forwarding is not read (no public API without
 * extra permissions); it is reported as `call_forwarding = not_checked`.
 * Every result carries `risk_hint = true`.
 */
public object RaspOtpForwardingProbes {
    public const val DETECTOR_ID: String = "otp_forwarding_risk"

    /** Starting list of SMS auto-forward apps (each in the engine `<queries>`); extend via config. */
    @JvmField
    public val builtInAutoForwardPackages: List<String> = listOf(
        "com.frzinapps.smsforward",
        "tech.bogomolov.incomingsmsgateway",
    )

    public data class Observation(
        val autoForwardApps: List<String>?,
        val accessibilityServices: List<Pair<String?, Int>>?,
        val remoteControlPackages: List<String>?,
    )

    public fun evaluate(o: Observation): RaspCheckResult {
        val gesture = o.accessibilityServices?.let(RaspFraudEnvironment::gestureServices)
        fun state(list: List<String>?) = when {
            list == null -> RaspSignalState.UNDECIDED
            list.isEmpty() -> RaspSignalState.ABSENT
            else -> RaspSignalState.PRESENT
        }
        val signals = listOf(
            RaspContributingSignal("auto_forward_app", true, state(o.autoForwardApps), o.autoForwardApps?.takeIf { it.isNotEmpty() }?.joinToString()),
            RaspContributingSignal("gesture_accessibility_service", true, state(gesture), gesture?.takeIf { it.isNotEmpty() }?.joinToString()),
            RaspContributingSignal("remote_control_app", true, state(o.remoteControlPackages), o.remoteControlPackages?.takeIf { it.isNotEmpty() }?.joinToString()),
        )
        return RaspSignalCombiner.combine(
            DETECTOR_ID, signals,
            extraEvidence = listOf(
                RaspEvidence("risk_hint", true, "environment hint, not proof that an OTP was forwarded"),
                RaspEvidence("call_forwarding", "not_checked"),
            ),
        )
    }

    public fun observe(context: Context, extraAutoForwardPackages: List<String>, remoteListJson: String?, remoteListKey: String?): Observation {
        val remote = RaspRemoteControlProbes.observe(context, remoteListJson, remoteListKey)
        return Observation(
            autoForwardApps = RaspFraudEnvironment.installed(context, builtInAutoForwardPackages + extraAutoForwardPackages),
            accessibilityServices = RaspFraudEnvironment.accessibilityServices(context),
            remoteControlPackages = RaspRemoteControlProbes.installedPackages(remote),
        )
    }
}
