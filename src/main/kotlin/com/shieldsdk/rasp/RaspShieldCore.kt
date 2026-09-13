package com.shieldsdk.rasp

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The single public entry point for the pure Kotlin/Java native SDK —
 * consumed directly by [RaspShieldNative] (the Flutter-free facade module)
 * and indirectly by the Flutter plugin's `RaspSecurityChannelHandler`,
 * which now delegates here instead of holding its own copy of any
 * detection logic. See the Android Native/Flutter Feature Parity plan for
 * the full rationale.
 *
 * ## Every detector, two ways
 *
 * Several checks do real I/O (Keystore key generation, `Runtime.exec`,
 * filesystem reads) and must never run on the main thread. Every detector
 * therefore ships as a matched pair:
 * - `checkXBlocking(context): RaspCheckResult` — synchronous. Call it off
 *   the main thread yourself if you already manage background execution.
 * - `checkXAsync(context, callback)` — runs on an internal background
 *   executor and delivers [callback] on the main thread via [Handler], so
 *   UI code can react safely with no threading of its own. Callable from
 *   Java as `checkXAsync(context, result -> { ... })`.
 *
 * No `kotlinx-coroutines` dependency is required either way — a deliberate
 * choice so this module never forces a coroutines dependency on a
 * consuming app that doesn't already use one.
 *
 * ## Failure model
 *
 * Every detector is wrapped by [runGuarded]: an uncaught exception inside
 * detector logic can never escape to the caller — it becomes a
 * [RaspCheckStatus.ERROR] result with a `reason`, and is reported to
 * [logger] if one is set. See [RaspCheckResult]/[RaspCheckStatus] for the
 * full 5-state contract this never relaxes.
 */
object RaspShieldCore {

    /**
     * Pluggable error observability — see [RaspShieldLogger]. Default is a
     * silent no-op; set this once at app startup to wire detector-level
     * exceptions into your own crash-reporting pipeline.
     */
    @Volatile
    var logger: RaspShieldLogger = RaspShieldLogger.NONE

    /**
     * The fingerprint a running build's signing certificate must match for
     * [checkRepackagingBlocking]/[checkRepackagingAsync] (Phase 3) to run
     * at all. Deliberately explicit — **not** read via reflection from a
     * host app's generated `BuildConfig` (see the Flutter plugin's
     * `readHostSigningBuildConfig()`, a convention specific to that
     * reference app and not portable to an arbitrary native host). Pass
     * `null`/blank to clear it.
     */
    @Volatile
    var expectedSigningCertificateSha256: String? = null
        private set

    fun configureExpectedSigningCertificate(fingerprint: String?) {
        val normalized = (fingerprint ?: "")
            .replace(Regex("[:\\s-]"), "")
            .uppercase()
        expectedSigningCertificateSha256 = normalized.ifEmpty { null }
    }

    /** Host + expected certificate SHA-256 for [checkMitmBlocking]'s TLS-pin
     *  half (Phase 8). `null` means "not configured" — see
     *  [configureCertificatePin]. */
    @Volatile
    private var pinnedHost: String? = null

    @Volatile
    private var pinnedCertificateSha256: String? = null

    /**
     * Configures the backend host + expected certificate fingerprint for
     * the TLS-pinning half of MITM detection. Pass `null` for either to
     * clear — the pin check then reports [CertificatePinCheckResult.NOT_ATTEMPTED]
     * rather than a silent pass. No backend/license dependency: this is a
     * plain, explicit parameter your app supplies, exactly like
     * [configureExpectedSigningCertificate].
     */
    fun configureCertificatePin(host: String?, pinnedSha256Hex: String?) {
        pinnedHost = host?.takeIf { it.isNotBlank() }
        pinnedCertificateSha256 = pinnedSha256Hex?.takeIf { it.isNotBlank() }
    }

    private val backgroundExecutor: ExecutorService =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "RaspShieldCore-worker").apply { isDaemon = true }
        }

    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

    /**
     * Runs [block], mapping any thrown exception to
     * [RaspCheckStatus.ERROR] and notifying [logger] — the one place every
     * detector's failure handling funnels through. `block` itself should
     * still handle its own expected failure paths (see each probe class);
     * this is the last-resort net, not the primary error-handling
     * mechanism.
     */
    private inline fun runGuarded(detectorId: String, block: () -> RaspCheckResult): RaspCheckResult {
        return try {
            block()
        } catch (e: Exception) {
            notifyLogger(detectorId, e)
            RaspCheckResult.error(detectorId, e.message ?: e.javaClass.simpleName)
        }
    }

    /** [logger] itself must never be allowed to crash a detector. */
    private fun notifyLogger(detectorId: String, throwable: Throwable) {
        try {
            logger.onDetectorError(detectorId, throwable)
        } catch (e: Exception) {
            // A failing logger must never take down the detector that
            // triggered it — dropped intentionally.
        }
    }

    private fun runAsync(
        context: Context,
        callback: (RaspCheckResult) -> Unit,
        blocking: (Context) -> RaspCheckResult,
    ) {
        val appContext = context.applicationContext ?: context
        backgroundExecutor.execute {
            val result = blocking(appContext)
            mainHandler.post { callback(result) }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Device integrity (Phase 1)
    // ═══════════════════════════════════════════════════════════════════

    // ── Root ───────────────────────────────────────────────────────────

    fun checkRootBlocking(context: Context): RaspCheckResult = runGuarded("root_jailbreak") {
        val probes = RaspDeviceIntegrityProbes(context)
        val signals = probes.rootSignals()
        val rooted = RaspRootAnalysis.isRooted(signals)
        val evidence = signals.map { RaspEvidence("root_signal", it) } +
            listOf(RaspEvidence("signal_count", signals.size))
        if (rooted) RaspCheckResult.detected("root_jailbreak", evidence)
        else RaspCheckResult.secure("root_jailbreak", evidence)
    }

    fun checkRootAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkRootBlocking)

    // ── Emulator ───────────────────────────────────────────────────────

    fun checkEmulatorBlocking(context: Context): RaspCheckResult = runGuarded("emulator") {
        val probes = RaspDeviceIntegrityProbes(context)
        val signals = probes.emulatorSignals()
        val emulated = RaspEmulatorAnalysis.isEmulator(signals)
        val evidence = signals.map { RaspEvidence("emulator_signal", it) } +
            listOf(RaspEvidence("signal_count", signals.size))
        if (emulated) RaspCheckResult.detected("emulator", evidence)
        else RaspCheckResult.secure("emulator", evidence)
    }

    fun checkEmulatorAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkEmulatorBlocking)

    // ── Device binding ────────────────────────────────────────────────

    fun checkDeviceBindingBlocking(context: Context): RaspCheckResult =
        runGuarded("device_binding") {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                return@runGuarded RaspCheckResult.unavailable(
                    "device_binding", "AndroidKeyStore hardware binding requires API 23+"
                )
            }
            val intact = RaspKeystoreProbes.isDeviceBindingIntact()
            if (intact) RaspCheckResult.secure("device_binding")
            else RaspCheckResult.detected(
                "device_binding",
                listOf(RaspEvidence("reason", "keystore_binding_key_missing_or_unreadable"))
            )
        }

    fun checkDeviceBindingAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkDeviceBindingBlocking)

    // ── Device fingerprint ────────────────────────────────────────────

    fun checkDeviceFingerprintBlocking(context: Context): RaspCheckResult =
        runGuarded("device_fingerprint") {
            val fp = RaspDeviceFingerprintProbes.readFingerprint(context)
                ?: return@runGuarded RaspCheckResult.error(
                    "device_fingerprint", "Fingerprint read failed catastrophically"
                )

            val failedChecks = buildList {
                if (!fp.screenLockEnabled) add("no_screen_lock")
                if (fp.adbEnabled) add("adb_enabled")
                if (!fp.selinuxEnforcing) add("selinux_permissive")
                if (fp.installSource == "unknown") add("unknown_install_source")
            }

            val evidence = failedChecks.map { RaspEvidence("device_fingerprint_signal", it) } +
                listOf(
                    RaspEvidence("model", fp.model),
                    RaspEvidence("manufacturer", fp.manufacturer),
                    RaspEvidence("install_source", fp.installSource),
                )

            if (failedChecks.isNotEmpty()) RaspCheckResult.detected("device_fingerprint", evidence)
            else RaspCheckResult.secure("device_fingerprint", evidence)
        }

    fun checkDeviceFingerprintAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkDeviceFingerprintBlocking)

    // ── Clone / Parallel Space ────────────────────────────────────────

    fun checkCloneBlocking(context: Context): RaspCheckResult = runGuarded("clone") {
        val signals = RaspCloneProbes.evidence(context)
        val evidence = signals.map {
            RaspEvidence("clone_${it.signal}", it.detected, it.reason)
        }
        val anyDetected = signals.any { it.detected }
        val anyConclusiveClean = signals.any { it.conclusive && !it.detected }

        when {
            anyDetected -> RaspCheckResult.detected("clone", evidence)
            anyConclusiveClean -> RaspCheckResult.secure("clone", evidence)
            else -> RaspCheckResult(
                "clone", RaspCheckStatus.UNKNOWN, evidence,
                reason = "No clone signal reached a conclusive verdict"
            )
        }
    }

    fun checkCloneAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkCloneBlocking)

    // ── Developer mode ────────────────────────────────────────────────

    fun checkDeveloperModeBlocking(context: Context): RaspCheckResult =
        runGuarded("developer_mode") {
            val enabled = AdbGuard.isDeveloperModeEnabled(context)
            when (enabled) {
                null -> RaspCheckResult.unavailable(
                    "developer_mode", "Settings.Global read failed"
                )
                true -> RaspCheckResult.detected("developer_mode")
                false -> RaspCheckResult.secure("developer_mode")
            }
        }

    fun checkDeveloperModeAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkDeveloperModeBlocking)

    // ── USB debugging (ADB) ───────────────────────────────────────────

    fun checkAdbEnabledBlocking(context: Context): RaspCheckResult =
        runGuarded("adb_enabled") {
            val enabled = AdbGuard.isAdbEnabled(context)
            when (enabled) {
                null -> RaspCheckResult.unavailable("adb_enabled", "Settings.Global read failed")
                true -> RaspCheckResult.detected("adb_enabled")
                false -> RaspCheckResult.secure("adb_enabled")
            }
        }

    fun checkAdbEnabledAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkAdbEnabledBlocking)

    // ── USB physical connection ───────────────────────────────────────

    fun checkUsbConnectionBlocking(context: Context): RaspCheckResult =
        runGuarded("usb_connection") {
            val analysis = RaspUsbAnalysis(context)
            val evidenceMap = analysis.usbConnectionEvidence()
            if (evidenceMap["supported"] != true) {
                return@runGuarded RaspCheckResult.unavailable(
                    "usb_connection", "UsbManager unavailable on this device/build"
                )
            }
            val connected = evidenceMap["connected"] == true
            val evidence = listOf(
                RaspEvidence("usb_device_count", evidenceMap["device_count"]),
            )
            if (connected) RaspCheckResult.detected("usb_connection", evidence)
            else RaspCheckResult.secure("usb_connection", evidence)
        }

    fun checkUsbConnectionAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkUsbConnectionBlocking)

    // ── Device lock (PIN/pattern/password/biometric) ─────────────────

    fun checkDeviceLockMissingBlocking(context: Context): RaspCheckResult =
        runGuarded("device_lock_missing") {
            val missing = RaspDeviceFingerprintProbes.isDeviceLockMissing(context)
            if (missing) RaspCheckResult.detected("device_lock_missing")
            else RaspCheckResult.secure("device_lock_missing")
        }

    fun checkDeviceLockMissingAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkDeviceLockMissingBlocking)

    // ── Secure hardware (TEE/StrongBox) ───────────────────────────────

    fun checkSecureHardwareUnavailableBlocking(context: Context): RaspCheckResult =
        runGuarded("secure_hardware_unavailable") {
            val unavailable = RaspKeystoreProbes.isSecureHardwareUnavailable(context)
            when (unavailable) {
                null -> RaspCheckResult.unavailable(
                    "secure_hardware_unavailable", "Keystore query failed"
                )
                true -> RaspCheckResult.detected("secure_hardware_unavailable")
                false -> RaspCheckResult.secure("secure_hardware_unavailable")
            }
        }

    fun checkSecureHardwareUnavailableAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkSecureHardwareUnavailableBlocking)

    // ═══════════════════════════════════════════════════════════════════
    // Runtime protection (Phase 2)
    // ═══════════════════════════════════════════════════════════════════

    // ── Frida / instrumentation ────────────────────────────────────────

    fun checkFridaBlocking(context: Context): RaspCheckResult = runGuarded("frida") {
        val probes = RaspDeviceProbes(context)
        val signals = probes.fridaSignals()
        val detected = RaspSignalAnalysis.fridaVerdict(signals)
        val evidence = signals.map { RaspEvidence("frida_signal", it) } +
            listOf(RaspEvidence("signal_count", signals.size))
        if (detected) RaspCheckResult.detected("frida", evidence)
        else RaspCheckResult.secure("frida", evidence)
    }

    fun checkFridaAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkFridaBlocking)

    // ── Debugger ───────────────────────────────────────────────────────

    /**
     * `true` when the currently running build is compiled with
     * `android:debuggable="true"` — the native equivalent of the Dart
     * layer's `kDebugMode`, and, like it, always `false` in a proper
     * release build. Combined with the runtime attach verdict below,
     * matching the Dart `DebuggerDetector`'s exact OR-combination: either
     * source firing is a threat.
     */
    private fun isDebuggableBuild(context: Context): Boolean = try {
        (context.applicationInfo.flags and
            android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
    } catch (e: Exception) {
        false
    }

    fun checkDebuggerBlocking(context: Context): RaspCheckResult = runGuarded("debugger") {
        val probes = RaspDeviceProbes(context)
        val runtimeSignals = probes.debuggerSignals().filter { it != RaspSignalAnalysis.DEBUGGABLE_FLAG }
        val runtimeAttached = RaspSignalAnalysis.debuggerVerdict(runtimeSignals)
        val debuggableBuild = isDebuggableBuild(context)

        val evidence = buildList {
            if (debuggableBuild) add(RaspEvidence("build_mode", "debug", "Running a debug build"))
            runtimeSignals.forEach { add(RaspEvidence("debugger_signal", it, "Runtime debugger indicator")) }
        }

        if (debuggableBuild || runtimeAttached) RaspCheckResult.detected("debugger", evidence)
        else RaspCheckResult.secure("debugger", evidence)
    }

    fun checkDebuggerAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkDebuggerBlocking)

    // ── Reverse-engineering tools ──────────────────────────────────────

    fun checkReverseEngineeringToolsBlocking(context: Context): RaspCheckResult =
        runGuarded("re_tools") {
            val found = RaspReverseEngineeringToolsProbe.detectedPackages(context)
            val evidence = found.map { RaspEvidence("re_tool_package", it) }
            if (found.isNotEmpty()) RaspCheckResult.detected("re_tools", evidence)
            else RaspCheckResult.secure("re_tools", evidence)
        }

    fun checkReverseEngineeringToolsAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkReverseEngineeringToolsBlocking)

    // ── Hooking / method interception ─────────────────────────────────

    fun checkHookingBlocking(context: Context): RaspCheckResult = runGuarded("hook_detection") {
        val probes = RaspHookProbes(context)
        val signals = probes.hookSignals()
        val detected = RaspHookAnalysis.hookVerdict(signals)
        val evidence = signals.map { RaspEvidence("hook_signal", it) } +
            listOf(RaspEvidence("signal_count", signals.size))
        if (detected) RaspCheckResult.detected("hook_detection", evidence)
        else RaspCheckResult.secure("hook_detection", evidence)
    }

    fun checkHookingAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkHookingBlocking)

    // ═══════════════════════════════════════════════════════════════════
    // Category batch — runtime protection
    // ═══════════════════════════════════════════════════════════════════

    fun scanRuntimeProtectionBlocking(context: Context): List<RaspCheckResult> = listOf(
        checkFridaBlocking(context),
        checkDebuggerBlocking(context),
        checkReverseEngineeringToolsBlocking(context),
        checkHookingBlocking(context),
    )

    // ═══════════════════════════════════════════════════════════════════
    // App integrity (Phase 3)
    // ═══════════════════════════════════════════════════════════════════

    // ── Tamper ─────────────────────────────────────────────────────────

    /**
     * `true` when this build's own binary looks modified since signing —
     * either a configured expected certificate no longer matches, or the
     * install directory itself is missing/corrupt. Unlike
     * [checkRepackagingBlocking], this check is meaningful even with no
     * expected fingerprint configured (the install-directory check alone
     * still catches a corrupted install), matching the original
     * `isAppTampered()`'s exact two-signal shape.
     */
    fun checkTamperBlocking(context: Context): RaspCheckResult = runGuarded("tamper") {
        val expected = expectedSigningCertificateSha256
        val mismatch = expected?.let { RaspSigningProbes.signatureMismatches(context, it) }
        val installMissing = RaspSigningProbes.installDirectoryMissing(context)

        val tampered = mismatch == true || installMissing
        val evidence = listOfNotNull(
            mismatch?.let { RaspEvidence("signing_certificate_mismatch", it) },
            RaspEvidence("install_directory_missing", installMissing),
        )
        if (tampered) RaspCheckResult.detected("tamper", evidence)
        else RaspCheckResult.secure("tamper", evidence)
    }

    fun checkTamperAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkTamperBlocking)

    // ── Repackaging / signature ───────────────────────────────────────

    /**
     * `UNAVAILABLE` — never a silent `SECURE` — when no expected signing
     * certificate has been configured via
     * [configureExpectedSigningCertificate]. A pinning check that never
     * actually compared anything must never present as a passing control.
     * Matches the Dart side's `RepackagingDetector` exactly.
     */
    fun checkRepackagingBlocking(context: Context): RaspCheckResult =
        runGuarded("repackage") {
            val expected = expectedSigningCertificateSha256
                ?: return@runGuarded RaspCheckResult.unavailable(
                    "repackage",
                    "NOT_CONFIGURED — no expected signing certificate supplied. " +
                        "Call RaspShieldCore.configureExpectedSigningCertificate() first."
                )
            val mismatch = RaspSigningProbes.signatureMismatches(context, expected)
                ?: return@runGuarded RaspCheckResult.error(
                    "repackage", "Could not read this build's own signing certificate"
                )
            if (mismatch) RaspCheckResult.detected("repackage")
            else RaspCheckResult.secure("repackage")
        }

    fun checkRepackagingAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkRepackagingBlocking)

    // ── Untrusted install source ──────────────────────────────────────

    fun checkUntrustedInstallSourceBlocking(context: Context): RaspCheckResult =
        runGuarded("untrusted_install_source") {
            when (RaspSigningProbes.isUntrustedInstallSource(context)) {
                null -> RaspCheckResult.unavailable(
                    "untrusted_install_source", "PackageManager query failed"
                )
                true -> RaspCheckResult.detected("untrusted_install_source")
                false -> RaspCheckResult.secure("untrusted_install_source")
            }
        }

    fun checkUntrustedInstallSourceAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkUntrustedInstallSourceBlocking)

    // ═══════════════════════════════════════════════════════════════════
    // Category batch — app integrity
    // ═══════════════════════════════════════════════════════════════════

    fun scanAppIntegrityBlocking(context: Context): List<RaspCheckResult> = listOf(
        checkTamperBlocking(context),
        checkRepackagingBlocking(context),
        checkUntrustedInstallSourceBlocking(context),
    )

    // ═══════════════════════════════════════════════════════════════════
    // Network security — native-only half (Phase 4)
    // ═══════════════════════════════════════════════════════════════════

    fun checkVpnBlocking(context: Context): RaspCheckResult = runGuarded("vpn") {
        if (RaspNetworkProbes.isVpnActive(context)) RaspCheckResult.detected("vpn")
        else RaspCheckResult.secure("vpn")
    }

    fun checkVpnAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkVpnBlocking)

    /**
     * `true` when the native system-proxy check found nothing, so the
     * (network-blocking) TLS-pin corroboration should run at all — same
     * short-circuit shape as the Dart `MitmDetector`: the cheap check
     * first, the expensive one only when it's still inconclusive.
     * Requires [configureCertificatePin] to have been called; otherwise
     * this check reports on the native-only signal alone, same as before
     * Phase 8.
     */
    fun checkMitmBlocking(context: Context): RaspCheckResult = runGuarded("mitm") {
        if (RaspNetworkProbes.isSystemProxyConfigured()) {
            return@runGuarded RaspCheckResult.detected(
                "mitm", listOf(RaspEvidence("source", "native_proxy_check"))
            )
        }

        val host = pinnedHost
        val pin = pinnedCertificateSha256
        if (host == null || pin == null) {
            return@runGuarded RaspCheckResult.secure("mitm")
        }

        // Real network I/O — this branch only runs when the cheap native
        // check found nothing AND a pin is configured. Call off the main
        // thread; use checkMitmAsync from UI code.
        when (RaspCertificatePinProbes.checkCertificatePin(host, pin)) {
            CertificatePinCheckResult.MISMATCH -> RaspCheckResult.detected(
                "mitm", listOf(RaspEvidence("source", "tls_pinning_probe"))
            )
            CertificatePinCheckResult.MATCH -> RaspCheckResult.secure("mitm")
            CertificatePinCheckResult.NOT_ATTEMPTED -> RaspCheckResult.secure("mitm")
        }
    }

    fun checkMitmAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkMitmBlocking)

    // ── High-risk IP / geo reputation ─────────────────────────────────

    /**
     * Real network I/O (a lookup to a public IP-reputation endpoint, 5s
     * timeout) — always call off the main thread, or use
     * [checkHighRiskIpAsync]. A failed/timed-out lookup reports
     * `UNAVAILABLE`, never a threat — an unreliable network must not
     * itself block a legitimate user.
     */
    fun checkHighRiskIpBlocking(context: Context): RaspCheckResult =
        runGuarded("high_risk_ip") {
            val result = RaspGeoIpProbes.checkHighRiskIp()
            if (result.checkFailed) {
                return@runGuarded RaspCheckResult.unavailable(
                    "high_risk_ip", "IP reputation lookup did not complete"
                )
            }
            val evidence = buildList {
                if (result.matchedBlockedCountry) add(RaspEvidence("high_risk_ip_signal", "blocked_country"))
                if (result.isProxy) add(RaspEvidence("high_risk_ip_signal", "proxy_flag"))
            }
            if (result.isRisk) RaspCheckResult.detected("high_risk_ip", evidence)
            else RaspCheckResult.secure("high_risk_ip", evidence)
        }

    fun checkHighRiskIpAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkHighRiskIpBlocking)

    // ═══════════════════════════════════════════════════════════════════
    // Category batch — network security
    // ═══════════════════════════════════════════════════════════════════
    //
    // NOTE: checkMitmBlocking (when a pin is configured) and
    // checkHighRiskIpBlocking both perform real network I/O — this whole
    // batch is heavier and slower than every other category's. Call it
    // off the main thread; do not run it on every frame/tight loop.

    fun scanNetworkSecurityBlocking(context: Context): List<RaspCheckResult> = listOf(
        checkVpnBlocking(context),
        checkMitmBlocking(context),
        checkHighRiskIpBlocking(context),
    )

    // ═══════════════════════════════════════════════════════════════════
    // Privacy & screen (Phase 5)
    // ═══════════════════════════════════════════════════════════════════

    // ── Overlay / tapjacking ───────────────────────────────────────────

    /**
     * `screenGuard` is optional — pass the [RaspScreenGuard] instance your
     * Activity has attached (if any) to include its runtime
     * touch-obscured corroboration. Without one, only the static
     * permission-holder signal is evaluated — see
     * [RaspPrivacyScreenProbes.isOverlayAttackDetected]'s doc for that
     * signal's own disclosed API 30+ limitation.
     */
    fun checkOverlayBlocking(context: Context, screenGuard: RaspScreenGuard? = null): RaspCheckResult =
        runGuarded("overlay") {
            val signals = RaspPrivacyScreenProbes.overlayEvidence(context, screenGuard)
            val evidence = signals.map { RaspEvidence("overlay_${it.signal}", it.detected) }
            val anyDetected = signals.any { it.detected }
            val anyConclusiveClean = signals.any { it.conclusive && !it.detected }
            when {
                anyDetected -> RaspCheckResult.detected("overlay", evidence)
                anyConclusiveClean -> RaspCheckResult.secure("overlay", evidence)
                else -> RaspCheckResult(
                    "overlay", RaspCheckStatus.UNKNOWN, evidence,
                    reason = "No overlay signal reached a conclusive verdict"
                )
            }
        }

    fun checkOverlayAsync(
        context: Context,
        screenGuard: RaspScreenGuard? = null,
        callback: (RaspCheckResult) -> Unit,
    ) = runAsync(context, callback) { checkOverlayBlocking(it, screenGuard) }

    // ── Accessibility abuse ────────────────────────────────────────────

    fun checkAccessibilityBlocking(context: Context): RaspCheckResult =
        runGuarded("accessibility") {
            when (RaspPrivacyScreenProbes.isAccessibilityAbused(context)) {
                null -> RaspCheckResult.unavailable("accessibility", "AccessibilityManager query failed")
                true -> RaspCheckResult.detected("accessibility")
                false -> RaspCheckResult.secure("accessibility")
            }
        }

    fun checkAccessibilityAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkAccessibilityBlocking)

    // ── External display ──────────────────────────────────────────────

    fun checkExternalDisplayBlocking(context: Context): RaspCheckResult =
        runGuarded("external_display") {
            val state = RaspPrivacyScreenProbes.externalDisplayState(context)
            if (!state.supported) {
                return@runGuarded RaspCheckResult.unavailable(
                    "external_display", "DisplayManager unavailable on this device/build"
                )
            }
            val evidence = listOf(
                RaspEvidence("external_display_count", state.externalDisplayCount),
                RaspEvidence("display_names", state.displayNames),
            )
            if (state.externalDisplayDetected) RaspCheckResult.detected("external_display", evidence)
            else RaspCheckResult.secure("external_display", evidence)
        }

    fun checkExternalDisplayAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkExternalDisplayBlocking)

    // ── Screenshot / video protection ─────────────────────────────────
    //
    // Deliberately NOT here: this needs a live Activity, not just a
    // Context, so it lives on RaspScreenGuard/ScreenshotGuard directly —
    // see RaspScreenGuard's class doc for why a one-shot Context-based
    // call cannot express this correctly.

    // ═══════════════════════════════════════════════════════════════════
    // Category batch — privacy & screen
    // ═══════════════════════════════════════════════════════════════════

    /**
     * `screenGuard` optional, same as [checkOverlayBlocking] — supply it
     * to include the touch-obscured corroboration and, via
     * [RaspScreenGuard.drainScreenshotEventEvidence]/
     * [RaspScreenGuard.isScreenshotProtectionActive], call those
     * separately since they are not part of this Context-only batch.
     */
    fun scanPrivacyScreenBlocking(
        context: Context,
        screenGuard: RaspScreenGuard? = null,
    ): List<RaspCheckResult> = listOf(
        checkOverlayBlocking(context, screenGuard),
        checkAccessibilityBlocking(context),
        checkExternalDisplayBlocking(context),
    )

    // ═══════════════════════════════════════════════════════════════════
    // Risky app / app intelligence (Phase 6)
    // ═══════════════════════════════════════════════════════════════════

    fun checkRiskyAppBlocking(context: Context): RaspCheckResult = runGuarded("risky_app") {
        val signals = RaspRiskyAppProbes.evidence(context)
        val known = signals.filter { it.category == RiskyAppCategory.KNOWN_RISKY_PACKAGE }
        val suspicious = signals.filter { it.category == RiskyAppCategory.SUSPICIOUS_BEHAVIOR }

        val evidence = signals.map {
            val key = if (it.category == RiskyAppCategory.KNOWN_RISKY_PACKAGE)
                "known_risky_package" else "suspicious_accessibility_service"
            RaspEvidence(key, it.pkg, it.reason)
        }

        if (known.isNotEmpty() || suspicious.isNotEmpty()) {
            RaspCheckResult.detected("risky_app", evidence)
        } else {
            RaspCheckResult.secure("risky_app", evidence)
        }
    }

    fun checkRiskyAppAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkRiskyAppBlocking)

    fun checkAppIntelligenceBlocking(context: Context): RaspCheckResult =
        runGuarded("app_intelligence") {
            val profiles = RaspAppIntelligenceProbes.profileInstalledPackages(context)
            val threats = profiles.filter {
                it.classification == AppRiskClassification.KNOWN_MALICIOUS ||
                    it.classification == AppRiskClassification.HIGH_RISK ||
                    it.classification == AppRiskClassification.SUSPICIOUS
            }
            val evidence = threats.flatMap { p ->
                p.evidence.map { reason -> RaspEvidence(reason, p.pkg) }
            }
            if (threats.isNotEmpty()) RaspCheckResult.detected("app_intelligence", evidence)
            else RaspCheckResult.secure("app_intelligence", evidence)
        }

    fun checkAppIntelligenceAsync(context: Context, callback: (RaspCheckResult) -> Unit) =
        runAsync(context, callback, ::checkAppIntelligenceBlocking)

    // ═══════════════════════════════════════════════════════════════════
    // Category batch — risky app / app intelligence
    // ═══════════════════════════════════════════════════════════════════

    fun scanRiskyAppBlocking(context: Context): List<RaspCheckResult> = listOf(
        checkRiskyAppBlocking(context),
        checkAppIntelligenceBlocking(context),
    )

    // ═══════════════════════════════════════════════════════════════════
    // Play Integrity attestation (Phase 7)
    // ═══════════════════════════════════════════════════════════════════
    //
    // Not a RaspCheckResult-shaped detector — it returns an attestation
    // TOKEN (opaque, server-verified), not a local secure/detected verdict,
    // so forcing it into the 5-state model would misrepresent what it is.
    // A thin passthrough is provided here purely for API discoverability;
    // RaspPlayIntegrityBridge itself remains the primary, directly
    // constructible entry point — see its own class doc.

    /** Heuristic-only reachability probe — see [RaspPlayIntegrityBridge.isAvailable]. */
    fun isPlayIntegrityAvailable(context: Context): Boolean =
        RaspPlayIntegrityBridge(context).isAvailable()

    /**
     * Requests a real Play Integrity token bound to [nonce] (the SERVER-
     * issued challenge — never a locally-minted one). See
     * [RaspPlayIntegrityBridge.requestToken] for the full contract.
     */
    fun requestPlayIntegrityToken(
        context: Context,
        nonce: String,
        onResult: (Result<String>) -> Unit,
    ) = RaspPlayIntegrityBridge(context).requestToken(nonce, onResult)

    // ═══════════════════════════════════════════════════════════════════
    // Whole-catalog orchestration (Phase 9)
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Every Context-only detector across every category — 25 of this
     * SDK's 27 detectors. Not included:
     * - Screenshot/video protection — needs a live `Activity`, not just a
     *   `Context`; call [RaspScreenGuard.isScreenshotProtectionActive]
     *   separately (see that class's doc for why).
     * - Offline-compliance — requires the licensed backend pipeline this
     *   native SDK deliberately does not include (see the Android
     *   Native/Flutter Feature Parity plan's scope decision). There is no
     *   native equivalent to call at all.
     *
     * Includes Phase 8's network detectors, so — like
     * [scanNetworkSecurityBlocking] — this performs real network I/O and
     * is heavier/slower than a pure on-device scan. Always call off the
     * main thread, or use [scanAllAsync].
     */
    fun scanAllBlocking(context: Context): List<RaspCheckResult> =
        scanDeviceIntegrityBlocking(context) +
            scanRuntimeProtectionBlocking(context) +
            scanAppIntegrityBlocking(context) +
            scanNetworkSecurityBlocking(context) +
            scanPrivacyScreenBlocking(context) +
            scanRiskyAppBlocking(context)

    fun scanAllAsync(context: Context, callback: (List<RaspCheckResult>) -> Unit) {
        val appContext = context.applicationContext ?: context
        backgroundExecutor.execute {
            val results = scanAllBlocking(appContext)
            mainHandler.post { callback(results) }
        }
    }

    /**
     * The result of [selfTest] — a QA/CI-callable diagnostic distinct from
     * a real security scan. Run this against your **release** (R8-
     * minified) build before shipping, not just once in debug at setup —
     * the specific failure mode it exists to catch (a stripped/renamed
     * class silently going dark) is invisible in an unminified debug
     * build by construction.
     */
    data class RaspSelfTestReport(
        /** Every detector's real result from one full [scanAllBlocking] pass. */
        val results: List<RaspCheckResult>,
        /**
         * `false` means [RaspHookProbes]' six critical-method reflection
         * targets did not all resolve — the one concrete, self-diagnosable
         * symptom of a missing/misconfigured R8 keep rule (see
         * `consumer-rules.pro`'s keep rules for exactly which methods).
         * When `false`, `hook_native_method` can never fire on this build,
         * silently. This is THE thing this method exists to catch.
         */
        val criticalReflectionIntact: Boolean,
    ) {
        /** Detector ids that faulted (status ERROR) — always worth investigating,
         *  never an expected outcome on a healthy build. */
        val erroredDetectorIds: List<String>
            get() = results.filter { it.status == RaspCheckStatus.ERROR }.map { it.detectorId }

        /** Detector ids reporting UNAVAILABLE — inspect each one's `reason`:
         *  some are expected (repackaging with no fingerprint configured,
         *  screenshot-event detection below API 34), others may indicate a
         *  packaging problem worth investigating on THIS specific build. */
        val unavailableDetectorIds: List<String>
            get() = results.filter { it.status == RaspCheckStatus.UNAVAILABLE }.map { it.detectorId }
    }

    /**
     * Exercises every detector once via [scanAllBlocking] and additionally
     * verifies [RaspHookProbes]' reflection-based integrity checks
     * actually resolve on this build — the native SDK's equivalent of the
     * lean SDK's `verifyIntegration()`, extended to the full catalog. Call
     * this from your release-build CI pipeline before every production
     * release, not just once at integration time.
     *
     * Blocking — call off the main thread, same as [scanAllBlocking].
     */
    fun selfTest(context: Context): RaspSelfTestReport {
        val results = scanAllBlocking(context)
        val hookProbes = RaspHookProbes(context)
        val reflectionIntact = hookProbes.criticalMethodIntegrity().values.none {
            it == RaspHookProbes.MethodIntegrity.UNAVAILABLE
        }
        return RaspSelfTestReport(results, reflectionIntact)
    }

    // ═══════════════════════════════════════════════════════════════════
    // Category batch — device integrity
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Runs every device-integrity detector (Phase 1) and returns all 10
     * results. Each detector already isolates its own exceptions via
     * [runGuarded] — one failing detector can never prevent the others
     * from running or being reported. This method itself adds no further
     * exception risk since it just sequences already-guarded calls.
     *
     * Blocking — call off the main thread. See [scanAllBlocking] for the
     * whole-catalog version.
     */
    fun scanDeviceIntegrityBlocking(context: Context): List<RaspCheckResult> = listOf(
        checkRootBlocking(context),
        checkEmulatorBlocking(context),
        checkDeviceBindingBlocking(context),
        checkDeviceFingerprintBlocking(context),
        checkCloneBlocking(context),
        checkDeveloperModeBlocking(context),
        checkAdbEnabledBlocking(context),
        checkUsbConnectionBlocking(context),
        checkDeviceLockMissingBlocking(context),
        checkSecureHardwareUnavailableBlocking(context),
    )
}
