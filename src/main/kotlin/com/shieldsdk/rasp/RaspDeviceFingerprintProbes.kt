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
        val screenLockEnabled: Boolean,
        val adbEnabled: Boolean,
        val installSource: String,
        val selinuxEnforcing: Boolean,
    )

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
            false
        }

        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        } catch (e: Exception) {
            false
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
            "unknown"
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
     * Bounded via [RaspProcessUtils] (was an unbounded `Runtime.exec` in
     * the original — see that object's doc for why this matters). Falls
     * back to `/sys/fs/selinux/enforce`, then to `true` (fail toward
     * "assume enforcing," the conservative/secure default) if neither
     * source answers — unchanged from the original's fallback chain.
     */
    private fun isSELinuxEnforcing(): Boolean {
        val execLine = RaspProcessUtils.firstLineOf(arrayOf("getenforce"))
        if (execLine != null) {
            return execLine.trim().lowercase() == "enforcing"
        }
        return try {
            val file = java.io.File("/sys/fs/selinux/enforce")
            if (file.exists()) file.readText().trim() == "1" else true
        } catch (e: Exception) {
            true
        }
    }

    fun isDeviceLockMissing(context: Context): Boolean = try {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        km.isDeviceSecure.not()
    } catch (e: Exception) {
        false
    }
}
