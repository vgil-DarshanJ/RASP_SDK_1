package com.shieldsdk.rasp

import android.content.Context

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
    const val DETECTOR_ID = "remote_control_app"

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
