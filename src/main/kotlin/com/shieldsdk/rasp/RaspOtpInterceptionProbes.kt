package com.shieldsdk.rasp

import android.content.Context

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
    const val DETECTOR_ID = "otp_interception_risk"

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
