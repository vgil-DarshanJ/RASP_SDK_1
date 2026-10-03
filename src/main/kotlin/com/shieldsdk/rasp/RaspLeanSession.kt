package com.shieldsdk.rasp

import android.app.Activity
import android.content.Context
import android.location.Location
import android.os.Build
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Host-supplied optional location; the engine never requests location itself.
 * [isMock] is the fix's own mock flag when the host has it (`Location.isMock()`,
 * Flutter geolocator `Position.isMocked`); `null` when unknown.
 */
public data class RaspLocationSnapshot(
    val latitude: Double, val longitude: Double, val accuracyMeters: Double? = null,
    val capturedAtMillis: Long = System.currentTimeMillis(),
    val isMock: Boolean? = null,
) {
    public companion object {
        /** Builds a snapshot from an Android [Location], including its mock flag. */
        @JvmStatic
        @Suppress("DEPRECATION")
        public fun fromLocation(location: Location): RaspLocationSnapshot = RaspLocationSnapshot(
            latitude = location.latitude,
            longitude = location.longitude,
            accuracyMeters = if (location.hasAccuracy()) location.accuracy.toDouble() else null,
            capturedAtMillis = location.time,
            isMock = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) location.isMock else location.isFromMockProvider,
        )
    }
}

/** The one configuration contract used by native and Flutter wrappers. */
public data class RaspLeanConfig(
    val screenshotProtection: Boolean = false, val usbDetection: Boolean = false,
    val adbDetection: Boolean = false, val clipboardProtection: Boolean = false,
    val clipboardAutoClear: Boolean = true, val rootDetection: Boolean = false,
    val emulatorDetection: Boolean = false, val deviceBindingCheck: Boolean = false,
    val cloneDetection: Boolean = false, val developerModeDetection: Boolean = false,
    val deviceLockCheck: Boolean = false, val secureHardwareCheck: Boolean = false,
    val deviceFingerprintCheck: Boolean = false, val fridaDetection: Boolean = false,
    val debuggerDetection: Boolean = false, val reverseEngineeringToolsDetection: Boolean = false,
    val hookDetection: Boolean = false, val riskyAppDetection: Boolean = false,
    val tamperDetection: Boolean = false, val untrustedInstallSourceDetection: Boolean = false,
    val repackagingDetection: Boolean = false, val expectedSigningCertSha256: String? = null,
    val vpnDetection: Boolean = false, val mitmDetection: Boolean = false,
    /** Host for the `mitm` SPKI pin check (e.g. your API host); `null` = no pin check. */
    val certificatePinHost: String? = null,
    /** Accepted SPKI pins for [certificatePinHost], `sha256/<Base64>`; empty = no pin check. */
    val certificatePins: List<String> = emptyList(),
    val highRiskIpDetection: Boolean = false, val overlayDetection: Boolean = false,
    val accessibilityDetection: Boolean = false, val externalDisplayDetection: Boolean = false,
    val screenshotEventDetection: Boolean = false,
    // Task 3a detectors — all off by default
    val mockLocationDetection: Boolean = false, val timeSpoofingDetection: Boolean = false,
    val unsafeWifiDetection: Boolean = false, val screenRecordingDetection: Boolean = false,
    /** Optional server time (ms since epoch) for `time_spoofing`, anchored when the session starts. */
    val serverTimeMillis: Long? = null,
    // Task 3b detectors — all off by default
    val vishingCallDetection: Boolean = false, val simChangeDetection: Boolean = false,
    val thirdPartyKeyboardDetection: Boolean = false, val taskHijackDetection: Boolean = false,
    /** Extra keyboard packages to trust when installed from Google Play (Gboard is built in). */
    val trustedKeyboardPackages: List<String> = emptyList(),
    // Task 3c detectors — all off by default
    val deviceStateAttestationDetection: Boolean = false,
    /** Report `patch_too_old` when the attested OS patch is older than this many days; `null` = off. */
    val maxSecurityPatchAgeDays: Int? = null,
    val malwareReputationDetection: Boolean = false,
    /** Signed reputation list (see RaspMalwareReputationProbes); e.g. read from an app asset. */
    val malwareReputationListJson: String? = null,
    /** Ed25519 public key that signs the list: Base64 of 32 raw bytes or of an X.509 SPKI. */
    val malwareReputationPublicKey: String? = null,
    /** Enable Evidence Envelope path (device-key signed, replay-resistant) instead of legacy HMAC. Default off. */
    val useEvidenceEnvelope: Boolean = false,
    val pollIntervalMillis: Long = 4_000,
    val heartbeatIntervalMillis: Long = 20_000, val detectorTimeoutMillis: Long = 6_000,
)

public data class RaspLeanState(
    val screenshotActive: Boolean? = null, val usbConnected: Boolean? = null,
    val usbDeviceCount: Int = 0, val usbDebuggingEnabled: Boolean? = null,
    val developerModeEnabled: Boolean? = null, val clipboardActive: Boolean? = null,
    val clipboardChangeCount: Int = 0, val extendedDetectors: Map<String, RaspCheckResult> = emptyMap(),
) { public companion object { @JvmField val INITIAL = RaspLeanState() } }

public fun interface RaspLeanStateListener { fun onStateChanged(state: RaspLeanState) }

/**
 * The sole polling/session implementation. It serializes ticks, runs every
 * detector with an individual deadline, and schedules its first scan on a
 * worker rather than the caller/UI thread.
 */
public class RaspLeanSession private constructor(
    private val appContext: Context, private val config: RaspLeanConfig,
    private val activityProvider: (() -> Activity?)?, private val screenGuard: RaspScreenGuard?,
) {
    @Volatile public var currentLocation: RaspLocationSnapshot? = null
    @Volatile public var current: RaspLeanState = RaspLeanState.INITIAL; private set
    @Volatile private var listener: RaspLeanStateListener? = null
    private val disposed = AtomicBoolean(false)
    private val tickGate = RaspTickGate()
    private val scheduler = Executors.newSingleThreadScheduledExecutor { Thread(it, "RaspLeanSession").apply { isDaemon = true } }
    private val timedDetector = RaspTimedDetector()
    private var scheduled: ScheduledFuture<*>? = null
    private val usb by lazy { RaspUsbAnalysis(appContext) }
    private val clipboard by lazy { RaspClipboardGuard(appContext) }
    private val shippingPolicy = RaspLeanShippingPolicy(config.heartbeatIntervalMillis)
    private val timeMonitor = RaspTimeSpoofingProbes.Monitor().also { monitor ->
        config.serverTimeMillis?.let { monitor.setServerTime(it) }
    }

    public fun setListener(value: RaspLeanStateListener?) { listener = value }

    /** Supplies a trusted server time for `time_spoofing` (e.g. from an HTTP `Date` header). */
    public fun setServerTime(serverTimeMillis: Long) { timeMonitor.setServerTime(serverTimeMillis) }
    public fun refreshNow() { if (!disposed.get()) scheduler.execute(::tick) }

    private fun applyConfig() {
        if (config.screenshotProtection) ScreenshotGuard.enable(activityProvider?.invoke())
        else ScreenshotGuard.disable(activityProvider?.invoke())
        if (config.clipboardProtection) clipboard.enable(config.clipboardAutoClear) else clipboard.disable()
        if (config.repackagingDetection) RaspShieldCore.configureExpectedSigningCertificate(config.expectedSigningCertSha256)
    }

    private fun tick() {
        if (disposed.get()) return
        tickGate.run {
            val active = if (config.screenshotProtection) ScreenshotGuard.isActive(activityProvider?.invoke()) else null
            val usbConnected = if (config.usbDetection) usb.isUsbConnected() else null
            val usbCount = if (config.usbDetection) (usb.usbConnectionEvidence()["device_count"] as? Int ?: 0) else 0
            val adb = if (config.adbDetection) AdbGuard.isAdbEnabled(appContext) else null
            val clipActive = if (config.clipboardProtection) clipboard.isActive() else null
            val clipCount = if (config.clipboardProtection) (clipboard.drainEvidence()["change_count"] as? Int ?: 0) else 0
            val extended = runExtended()
            current = RaspLeanState(active, usbConnected, usbCount, adb,
                if (config.usbDetection || config.adbDetection) AdbGuard.isDeveloperModeEnabled(appContext) else null,
                clipActive, clipCount, extended)
            runCatching { listener?.onStateChanged(current) }
            ship(controlResults(active, usbConnected, usbCount, adb, clipActive, clipCount) + extended.values)
        }
    }

    private fun runExtended(): Map<String, RaspCheckResult> {
        val work = linkedMapOf<String, () -> RaspCheckResult>()
        fun add(enabled: Boolean, id: String, call: () -> RaspCheckResult) { if (enabled) work[id] = call }
        add(config.rootDetection, "root_jailbreak") { RaspShieldCore.checkRootBlocking(appContext) }
        add(config.emulatorDetection, "emulator") { RaspShieldCore.checkEmulatorBlocking(appContext) }
        add(config.deviceBindingCheck, "device_binding") { RaspShieldCore.checkDeviceBindingBlocking(appContext) }
        add(config.cloneDetection, "clone") { RaspShieldCore.checkCloneBlocking(appContext) }
        add(config.developerModeDetection, "developer_mode") { RaspShieldCore.checkDeveloperModeBlocking(appContext) }
        add(config.deviceLockCheck, "device_lock_missing") { RaspShieldCore.checkDeviceLockMissingBlocking(appContext) }
        add(config.secureHardwareCheck, "secure_hardware_unavailable") { RaspShieldCore.checkSecureHardwareUnavailableBlocking(appContext) }
        add(config.deviceFingerprintCheck, "device_fingerprint") { RaspShieldCore.checkDeviceFingerprintBlocking(appContext) }
        add(config.fridaDetection, "frida") { RaspShieldCore.checkFridaBlocking(appContext) }
        add(config.debuggerDetection, "debugger") { RaspShieldCore.checkDebuggerBlocking(appContext) }
        add(config.reverseEngineeringToolsDetection, "re_tools") { RaspShieldCore.checkReverseEngineeringToolsBlocking(appContext) }
        add(config.hookDetection, "hook_detection") { RaspShieldCore.checkHookingBlocking(appContext) }
        add(config.riskyAppDetection, "risky_app") { RaspShieldCore.checkRiskyAppBlocking(appContext) }
        add(config.tamperDetection, "tamper") { RaspShieldCore.checkTamperBlocking(appContext) }
        add(config.untrustedInstallSourceDetection, "untrusted_install_source") { RaspShieldCore.checkUntrustedInstallSourceBlocking(appContext) }
        add(config.repackagingDetection, "repackage") { RaspShieldCore.checkRepackagingBlocking(appContext) }
        add(config.vpnDetection, "vpn") { RaspShieldCore.checkVpnBlocking(appContext) }
        add(config.mitmDetection, "mitm") {
            RaspShieldCore.checkMitmBlocking(appContext, config.certificatePinHost, config.certificatePins)
        }
        add(config.highRiskIpDetection, "high_risk_ip") { RaspShieldCore.checkHighRiskIpBlocking(appContext) }
        add(config.overlayDetection, "overlay") { RaspShieldCore.checkOverlayBlocking(appContext, screenGuard) }
        add(config.accessibilityDetection, "accessibility") { RaspShieldCore.checkAccessibilityBlocking(appContext) }
        add(config.externalDisplayDetection, "external_display") { RaspShieldCore.checkExternalDisplayBlocking(appContext) }
        add(config.screenshotEventDetection, "screenshot_event") { screenshotEventResult() }
        add(config.mockLocationDetection, RaspMockLocationProbes.DETECTOR_ID) {
            RaspShieldCore.checkMockLocationBlocking(appContext, currentLocation)
        }
        add(config.timeSpoofingDetection, RaspTimeSpoofingProbes.DETECTOR_ID) {
            RaspShieldCore.checkTimeSpoofingBlocking(appContext, timeMonitor)
        }
        add(config.unsafeWifiDetection, RaspUnsafeWifiProbes.DETECTOR_ID) { RaspShieldCore.checkUnsafeWifiBlocking(appContext) }
        add(config.screenRecordingDetection, RaspScreenRecordingProbes.DETECTOR_ID) {
            RaspShieldCore.checkScreenRecordingBlocking(appContext)
        }
        add(config.vishingCallDetection, RaspVishingCallProbes.DETECTOR_ID) { RaspShieldCore.checkVishingCallBlocking(appContext) }
        add(config.simChangeDetection, RaspSimChangeProbes.DETECTOR_ID) { RaspShieldCore.checkSimChangeBlocking(appContext) }
        add(config.thirdPartyKeyboardDetection, RaspThirdPartyKeyboardProbes.DETECTOR_ID) {
            RaspShieldCore.checkThirdPartyKeyboardBlocking(appContext, config.trustedKeyboardPackages)
        }
        add(config.taskHijackDetection, RaspTaskHijackProbes.DETECTOR_ID) { RaspShieldCore.checkTaskHijackBlocking(appContext) }
        add(config.deviceStateAttestationDetection, RaspDeviceStateAttestationProbes.DETECTOR_ID) {
            RaspShieldCore.checkDeviceStateAttestationBlocking(appContext, config.maxSecurityPatchAgeDays)
        }
        add(config.malwareReputationDetection, RaspMalwareReputationProbes.DETECTOR_ID) {
            RaspShieldCore.checkMalwareReputationBlocking(appContext, config.malwareReputationListJson, config.malwareReputationPublicKey)
        }
        return work.mapValues { (id, call) -> timedDetector.run(id, config.detectorTimeoutMillis, call) }
    }

    private fun screenshotEventResult(): RaspCheckResult {
        val guard = screenGuard ?: return RaspCheckResult.unavailable(
            "screenshot_event", "Screenshot-event detection requires an attached screen guard"
        )
        val event = guard.drainScreenshotEventEvidence()
        if (!event.supported) return RaspCheckResult.unavailable(
            "screenshot_event", "Screenshot-event detection requires Android 14+"
        )
        val evidence = listOf(
            RaspEvidence("count", event.count),
            RaspEvidence("last_at_millis", event.lastAtMillis),
        )
        return if (event.detected) RaspCheckResult.detected("screenshot_event", evidence)
        else RaspCheckResult.secure("screenshot_event", evidence)
    }

    private fun controlResults(active: Boolean?, usbConnected: Boolean?, count: Int, adb: Boolean?, clip: Boolean?, clipCount: Int): List<RaspCheckResult> = buildList {
        if (config.screenshotProtection) add(RaspCheckResult("screenshot_protection", if (active == true) RaspCheckStatus.SECURE else RaspCheckStatus.UNAVAILABLE))
        if (config.usbDetection) add(RaspCheckResult("usb_connection", if (usbConnected == true) RaspCheckStatus.DETECTED else RaspCheckStatus.SECURE, listOf(RaspEvidence("device_count", count))))
        if (config.adbDetection) add(RaspCheckResult("adb_enabled", if (adb == true) RaspCheckStatus.DETECTED else RaspCheckStatus.SECURE))
        if (config.clipboardProtection) add(RaspCheckResult("clipboard_protection", if (clip == true) RaspCheckStatus.SECURE else RaspCheckStatus.UNAVAILABLE, listOf(RaspEvidence("change_count", clipCount))))
    }

    private fun ship(results: Collection<RaspCheckResult>) {
        if (!RaspEventShipper.isConfigured()) return
        val now = System.currentTimeMillis()
        results.filter { shippingPolicy.shouldShip(it, now) }
            .forEach { result -> RaspEventShipper.shipAsync(appContext, listOf(withLocation(result))) }
    }

    private fun withLocation(result: RaspCheckResult): RaspCheckResult {
        val location = currentLocation ?: return result
        if (!result.status.isThreat) return result
        return result.copy(evidence = result.evidence + listOf(
            RaspEvidence("latitude", location.latitude),
            RaspEvidence("longitude", location.longitude),
            RaspEvidence("location_accuracy_m", location.accuracyMeters),
            RaspEvidence("location_captured_at_millis", location.capturedAtMillis),
        ))
    }

    public fun dispose() { if (disposed.compareAndSet(false, true)) { scheduled?.cancel(false); scheduler.shutdownNow(); timedDetector.shutdown(); if (config.clipboardProtection) clipboard.disable() } }

    public companion object {
        @JvmStatic @JvmOverloads public fun start(context: Context, config: RaspLeanConfig, activityProvider: (() -> Activity?)? = null, screenGuardForOverlay: RaspScreenGuard? = null): RaspLeanSession {
            require(config.pollIntervalMillis > 0) { "pollIntervalMillis must be positive" }
            val session = RaspLeanSession(context.applicationContext ?: context, config, activityProvider, screenGuardForOverlay)
            session.applyConfig()
            // Always enqueue the initial scan; never perform network/disk work on the caller thread.
            session.scheduler.execute(session::tick)
            session.scheduled = session.scheduler.scheduleWithFixedDelay(session::tick, config.pollIntervalMillis, config.pollIntervalMillis, TimeUnit.MILLISECONDS)
            return session
        }
    }
}

/**
 * Stateful shipping policy kept separate from Android scheduling so its
 * baseline, change-detection, and detected-heartbeat contract can be unit
 * tested without a device, network, or Flutter channel.
 */
internal class RaspLeanShippingPolicy(private val heartbeatIntervalMillis: Long) {
    private val lastSignature = java.util.concurrent.ConcurrentHashMap<String, String>()
    private val lastShippedAt = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun shouldShip(result: RaspCheckResult, nowMillis: Long): Boolean {
        val signature = result.status.name + result.evidence.joinToString { "${it.key}=${it.value}" }
        val baseline = lastShippedAt[result.detectorId] == null
        val changed = lastSignature[result.detectorId] != signature
        val heartbeat = result.status.isThreat && !baseline &&
            nowMillis - (lastShippedAt[result.detectorId] ?: nowMillis) >= heartbeatIntervalMillis
        if (!baseline && !changed && !heartbeat) return false
        lastSignature[result.detectorId] = signature
        lastShippedAt[result.detectorId] = nowMillis
        return true
    }
}
