package com.shieldsdk.rasp

import android.app.Activity
import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Host-supplied optional location; the engine never requests location itself. */
public data class RaspLocationSnapshot(
    val latitude: Double, val longitude: Double, val accuracyMeters: Double? = null,
    val capturedAtMillis: Long = System.currentTimeMillis(),
)

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
    val highRiskIpDetection: Boolean = false, val overlayDetection: Boolean = false,
    val accessibilityDetection: Boolean = false, val externalDisplayDetection: Boolean = false,
    val screenshotEventDetection: Boolean = false, val pollIntervalMillis: Long = 4_000,
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
    private val lastSignature = ConcurrentHashMap<String, String>()
    private val lastShippedAt = ConcurrentHashMap<String, Long>()

    public fun setListener(value: RaspLeanStateListener?) { listener = value }
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
        add(config.mitmDetection, "mitm") { RaspShieldCore.checkMitmBlocking(appContext) }
        add(config.highRiskIpDetection, "high_risk_ip") { RaspShieldCore.checkHighRiskIpBlocking(appContext) }
        add(config.overlayDetection, "overlay") { RaspShieldCore.checkOverlayBlocking(appContext, screenGuard) }
        add(config.accessibilityDetection, "accessibility") { RaspShieldCore.checkAccessibilityBlocking(appContext) }
        add(config.externalDisplayDetection, "external_display") { RaspShieldCore.checkExternalDisplayBlocking(appContext) }
        add(config.screenshotEventDetection, "screenshot_event") { screenshotEventResult() }
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
        results.filter { result ->
            val signature = result.status.name + result.evidence.joinToString { "${it.key}=${it.value}" }
            val baseline = lastShippedAt[result.detectorId] == null
            val changed = lastSignature[result.detectorId] != signature
            val heartbeat = result.status.isThreat && !baseline && now - (lastShippedAt[result.detectorId] ?: now) >= config.heartbeatIntervalMillis
            if (baseline || changed || heartbeat) { lastSignature[result.detectorId] = signature; lastShippedAt[result.detectorId] = now; true } else false
        }.forEach { result -> RaspEventShipper.shipAsync(appContext, listOf(withLocation(result))) }
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
