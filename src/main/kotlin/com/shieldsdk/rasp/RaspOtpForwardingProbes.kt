package com.shieldsdk.rasp

import android.content.Context

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
    const val DETECTOR_ID = "otp_forwarding_risk"

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
