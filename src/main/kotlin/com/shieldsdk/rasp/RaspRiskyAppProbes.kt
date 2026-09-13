package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.view.accessibility.AccessibilityManager

/** One risky-app evidence entry — package presence or accessibility abuse. */
public data class RiskyAppSignal(
    val pkg: String?,
    val category: RiskyAppCategory,
    val reason: String,
)

public enum class RiskyAppCategory { KNOWN_RISKY_PACKAGE, SUSPICIOUS_BEHAVIOR }

/**
 * Curated remote-access/instrumentation-framework package presence, plus
 * active third-party accessibility services — verbatim port of
 * `RaspSecurityChannelHandler.knownRiskyPackages`/`riskyAppEvidence()`.
 * **Not a malware scanner** — see [RaspAppIntelligenceProbes]'s class doc
 * for the full `<queries>`-visibility constraint this shares.
 */
public object RaspRiskyAppProbes {

    /** The exact 7 packages declared in this module's `<queries>` block for
     *  this purpose — see [RaspAppIntelligenceProbes.defaultDatabase], which
     *  must never drift from this list (a test asserts the two agree). */
    val knownRiskyPackages: Map<String, String> = mapOf(
        "com.teamviewer.quicksupport.market" to "remote_access",
        "com.teamviewer.host.market" to "remote_access",
        "com.anydesk.anydeskandroid" to "remote_access",
        "com.rsupport.mobizen.remote" to "screen_share",
        "com.remotepc.rpcmobile" to "remote_access",
        "de.robv.android.xposed" to "instrumentation_framework",
        "com.saurik.substrate" to "instrumentation_framework",
    )

    fun evidence(context: Context): List<RiskyAppSignal> {
        val results = mutableListOf<RiskyAppSignal>()
        val pm = context.packageManager

        for ((pkg, category) in knownRiskyPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                results.add(RiskyAppSignal(pkg, RiskyAppCategory.KNOWN_RISKY_PACKAGE, category))
            } catch (e: PackageManager.NameNotFoundException) {
                // Not installed — genuinely not detected, no evidence entry.
            } catch (e: Exception) {
                // Query failed for a reason other than "not installed" —
                // silently omitted here, same as the original; the facade
                // layer reports ERROR only when NOTHING could be evaluated
                // (see RaspShieldCore.checkRiskyAppBlocking).
            }
        }

        try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val enabledServices = am.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
            for (service in enabledServices) {
                val pkgName = service.resolveInfo.serviceInfo.packageName
                if (pkgName.startsWith("com.android.") ||
                    pkgName.startsWith("com.google.android.") ||
                    pkgName.contains("talkback") ||
                    knownRiskyPackages.containsKey(pkgName)
                ) continue
                results.add(
                    RiskyAppSignal(
                        pkgName, RiskyAppCategory.SUSPICIOUS_BEHAVIOR,
                        "active_third_party_accessibility_service",
                    )
                )
            }
        } catch (e: Exception) {
            // Accessibility query failed — omitted, same reasoning as above.
        }

        return results
    }
}
