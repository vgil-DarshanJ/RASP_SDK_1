package com.shieldsdk.rasp

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

/**
 * Device-fingerprint evidence: screen lock, ADB, SELinux enforcement,
 * install source, and hardware identity — verbatim port of
 * `RaspSecurityChannelHandler.getDeviceFingerprint()`/`isSELinuxEnforcing()`,
 * plus `isDeviceLockMissing()`. Grouped in one file since they share the
 * same handful of `Context`-scoped accessors.
 */
public object RaspDeviceFingerprintProbes {

    data class Fingerprint(
        val androidId: String?,
        val model: String,
        val manufacturer: String,
        val board: String,
        val hardware: String,
        val buildFingerprint: String,
        val screenLockEnabled: Boolean?,
        /** `null` when the ADB setting could not be read (never read as "off"). */
        val adbEnabled: Boolean?,
        /** Installer package, `"unknown"` when none is recorded, `null` when it could not be read. */
        val installSource: String?,
        val selinuxEnforcing: Boolean?,
    )

    /**
     * `device_fingerprint` verdict. Pure. Any failed check → DETECTED; else
     * any check that could not be read → UNKNOWN; else SECURE. `null`
     * (fingerprint not read at all) → UNKNOWN.
     */
    fun evaluate(fp: Fingerprint?): RaspCheckResult {
        if (fp == null) {
            return RaspCheckResult.unknown("device_fingerprint", "Device fingerprint security state could not be read")
        }
        val failedChecks = buildList {
            if (fp.screenLockEnabled == false) add("no_screen_lock")
            if (fp.adbEnabled == true) add("adb_enabled")
            if (fp.selinuxEnforcing == false) add("selinux_permissive")
            if (fp.installSource == "unknown") add("unknown_install_source")
        }
        val unknownChecks = buildList {
            if (fp.screenLockEnabled == null) add("screen_lock_unknown")
            if (fp.adbEnabled == null) add("adb_unknown")
            if (fp.selinuxEnforcing == null) add("selinux_unknown")
            if (fp.installSource == null) add("install_source_unknown")
        }
        val evidence = failedChecks.map { RaspEvidence("device_fingerprint_signal", it) } +
            unknownChecks.map { RaspEvidence("device_fingerprint_unknown", it) } +
            listOf(
                RaspEvidence("model", fp.model),
                RaspEvidence("manufacturer", fp.manufacturer),
                RaspEvidence("install_source", fp.installSource ?: "unreadable"),
            )
        return when {
            failedChecks.isNotEmpty() -> RaspCheckResult.detected("device_fingerprint", evidence)
            unknownChecks.isNotEmpty() -> RaspCheckResult(
                "device_fingerprint", RaspCheckStatus.UNKNOWN, evidence,
                "Device fingerprint contains unreadable security state",
            )
            else -> RaspCheckResult.secure("device_fingerprint", evidence)
        }
    }

    /**
     * `null` only if the whole read failed catastrophically (should not
     * normally happen — every individual field already has its own
     * fallback). Never a signal for "safe."
     */
    fun readFingerprint(context: Context): Fingerprint? = try {
        val androidId = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        } catch (e: Exception) {
            null
        }

        val screenLockEnabled = try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            km.isDeviceSecure
        } catch (e: Exception) {
            null
        }

        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        } catch (e: Exception) {
            null
        }

        val installSource = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager
                    .getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            } ?: "unknown"
        } catch (e: Exception) {
            null
        }

        Fingerprint(
            androidId = androidId,
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            board = Build.BOARD,
            hardware = Build.HARDWARE,
            buildFingerprint = Build.FINGERPRINT,
            screenLockEnabled = screenLockEnabled,
            adbEnabled = adbEnabled,
            installSource = installSource,
            selinuxEnforcing = isSELinuxEnforcing(),
        )
    } catch (e: Exception) {
        null
    }

    /**
     * `getenforce` (bounded via [RaspProcessUtils]), then
     * `/sys/fs/selinux/enforce`. `null` when neither answers — the state is
     * then unknown; it is never assumed to be enforcing.
     */
    fun isSELinuxEnforcing(): Boolean? {
        val execLine = RaspProcessUtils.firstLineOf(arrayOf("getenforce"))
        parseSelinuxValue(execLine)?.let { return it }
        val fileValue = try {
            val file = java.io.File("/sys/fs/selinux/enforce")
            if (file.isFile) file.readText() else null
        } catch (_: Exception) {
            null
        }
        return parseSelinuxValue(fileValue)
    }

    /** A denied or malformed SELinux read is UNKNOWN, never "enforcing". */
    @JvmStatic
    fun parseSelinuxValue(value: String?): Boolean? = when (value?.trim()?.lowercase()) {
        "enforcing", "1" -> true
        "permissive", "0" -> false
        else -> null
    }

    /** `null` means the keyguard service could not be queried; never treat that as clean. */
    fun isDeviceLockMissing(context: Context): Boolean? = try {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        km.isDeviceSecure.not()
    } catch (e: Exception) {
        null
    }

    /** Whether the person has a fingerprint (or face) enrolled in system settings. */
    enum class BiometricState { ENROLLED, NONE_ENROLLED, NO_HARDWARE, UNKNOWN }

    /**
     * Biometric enrolment from `android.hardware.biometrics.BiometricManager`
     * (Android 10+; needs the normal permission USE_BIOMETRIC, declared by
     * this module). [BiometricState.UNKNOWN] before Android 10, when the
     * service or permission is missing, or when the platform cannot say
     * (hardware busy, security update required, unsupported) — never read as
     * enrolled.
     */
    fun biometricState(context: Context): BiometricState = try {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            BiometricState.UNKNOWN
        } else {
            val bm = context.getSystemService(android.hardware.biometrics.BiometricManager::class.java)
            val code = when {
                bm == null -> null
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
                    bm.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_WEAK)
                else -> @Suppress("DEPRECATION") bm.canAuthenticate()
            }
            biometricStateOf(code)
        }
    } catch (e: Exception) {
        BiometricState.UNKNOWN
    }

    /** `BiometricManager.BIOMETRIC_*` code → state. Pure; `null` and unlisted codes are UNKNOWN. */
    @JvmStatic
    fun biometricStateOf(code: Int?): BiometricState = when (code) {
        0 -> BiometricState.ENROLLED          // BIOMETRIC_SUCCESS
        11 -> BiometricState.NONE_ENROLLED    // BIOMETRIC_ERROR_NONE_ENROLLED
        12 -> BiometricState.NO_HARDWARE      // BIOMETRIC_ERROR_NO_HARDWARE
        else -> BiometricState.UNKNOWN        // HW_UNAVAILABLE, UNSUPPORTED, STATUS_UNKNOWN, ...
    }

    /**
     * `device_lock_missing` verdict. Pure.
     *
     * - no screen lock at all → DETECTED (a fingerprint cannot exist without one);
     * - lock set and a fingerprint/face enrolled → SECURE (a strong safety feature);
     * - lock set but nothing enrolled → DETECTED (the severity is low: the
     *   phone still needs a PIN, pattern or password);
     * - lock set and the phone has no biometric hardware → SECURE (nothing to enrol);
     * - anything unreadable → UNKNOWN, never SECURE.
     */
    fun evaluateDeviceLock(deviceSecure: Boolean?, biometric: BiometricState): RaspCheckResult {
        val id = "device_lock_missing"
        fun evidence(lock: String, bio: String) =
            listOf(RaspEvidence("screen_lock", lock), RaspEvidence("biometric", bio))
        if (deviceSecure == null) return RaspCheckResult.unknown(id, "Keyguard state could not be read")
        if (!deviceSecure) return RaspCheckResult.detected(id, evidence("none", "not_enrolled"))
        return when (biometric) {
            BiometricState.ENROLLED -> RaspCheckResult.secure(id, evidence("set", "enrolled"))
            BiometricState.NONE_ENROLLED -> RaspCheckResult.detected(id, evidence("set", "not_enrolled"))
            BiometricState.NO_HARDWARE -> RaspCheckResult.secure(id, evidence("set", "no_hardware"))
            BiometricState.UNKNOWN -> RaspCheckResult.unknown(id, "Fingerprint enrolment could not be read")
        }
    }
}
