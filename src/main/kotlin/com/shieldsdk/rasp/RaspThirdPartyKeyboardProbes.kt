package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.provider.Settings

/**
 * `third_party_keyboard` — is the active keyboard something other than a
 * system keyboard or an allowlisted one? (A keyboard sees every key typed,
 * including passwords and OTPs.)
 *
 * Active keyboard: `Settings.Secure.DEFAULT_INPUT_METHOD` (no permission).
 *
 * Trusted when either:
 * - it is a system app (`FLAG_SYSTEM` / `FLAG_UPDATED_SYSTEM_APP`) — this
 *   covers OEM default keyboards and preinstalled Gboard; or
 * - its package is allowlisted (Gboard by default, plus the host's
 *   `trustedKeyboardPackages`) **and** it was installed from Google Play.
 *   A package name alone is not trusted: a sideloaded app can reuse it.
 *
 * Untrusted → DETECTED; trusted → SECURE; active keyboard or its package
 * details unreadable → UNKNOWN.
 */
object RaspThirdPartyKeyboardProbes {

    const val DETECTOR_ID = "third_party_keyboard"
    const val GBOARD = "com.google.android.inputmethod.latin"
    val DEFAULT_ALLOWLIST: Set<String> = setOf(GBOARD)
    val PLAY_INSTALLERS: Set<String> = setOf("com.android.vending")

    data class KeyboardInfo(val packageName: String, val isSystemApp: Boolean, val installerPackage: String?)

    data class Observation(
        /** `null` when the active keyboard or its package details could not be read. */
        val active: KeyboardInfo?,
        val readError: String? = null,
    )

    /** Package part of a `DEFAULT_INPUT_METHOD` value such as `com.pkg/.Service`. */
    fun packageOf(defaultInputMethod: String?): String? =
        defaultInputMethod?.substringBefore('/')?.trim()?.takeIf { it.isNotEmpty() }

    fun evaluate(o: Observation, extraAllowlist: Collection<String> = emptyList()): RaspCheckResult {
        val ime = o.active ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN,
            reason = o.readError ?: "Active keyboard could not be read",
        )
        val allowlisted = ime.packageName in DEFAULT_ALLOWLIST || ime.packageName in extraAllowlist
        val fromPlay = ime.installerPackage in PLAY_INSTALLERS
        val trusted = ime.isSystemApp || (allowlisted && fromPlay)
        val evidence = listOf(
            RaspEvidence("keyboard_package", ime.packageName),
            RaspEvidence("system_app", ime.isSystemApp),
            RaspEvidence("allowlisted", allowlisted),
            RaspEvidence("installer", ime.installerPackage),
        )
        return if (trusted) RaspCheckResult.secure(DETECTOR_ID, evidence)
        else RaspCheckResult.detected(DETECTOR_ID, evidence)
    }

    fun observe(context: Context): Observation {
        val pkg = try {
            packageOf(Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD))
        } catch (e: Exception) {
            return Observation(null, "DEFAULT_INPUT_METHOD unreadable: ${e.javaClass.simpleName}")
        } ?: return Observation(null, "No active keyboard reported")

        return try {
            val pm = context.packageManager
            val app = pm.getApplicationInfo(pkg, 0)
            val system = app.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkg).installingPackageName
            } else {
                @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
            }
            Observation(KeyboardInfo(pkg, system, installer))
        } catch (e: Exception) {
            Observation(null, "Keyboard package details unreadable: ${e.javaClass.simpleName}")
        }
    }
}
