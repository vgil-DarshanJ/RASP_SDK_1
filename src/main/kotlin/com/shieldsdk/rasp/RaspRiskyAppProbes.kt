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

    /** The package scan: matching [signals], and [failedPackages] whose query failed for a reason other than "not installed". */
    data class Observation(val signals: List<RiskyAppSignal>, val failedPackages: List<String>)

    /** Signals only (failed queries dropped); see [observe]. */
    fun evidence(context: Context): List<RiskyAppSignal> = observe(context).signals

    /**
     * Queries every listed package. A query that fails for a reason other
     * than "not installed" is recorded in [Observation.failedPackages]; if
     * the PackageManager itself cannot be reached this throws (→ ERROR).
     */
    fun observe(context: Context): Observation {
        val results = mutableListOf<RiskyAppSignal>()
        val failed = mutableListOf<String>()
        val pm = context.packageManager

        for ((pkg, category) in knownRiskyPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                results.add(RiskyAppSignal(pkg, RiskyAppCategory.KNOWN_RISKY_PACKAGE, category))
            } catch (e: PackageManager.NameNotFoundException) {
                // Not installed — genuinely not detected, no evidence entry.
            } catch (e: Exception) {
                failed.add(pkg)
            }
        }

        try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
            val enabledServices = am.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
            // Accessibility is an assistive technology. Presence alone is
            // neither malicious nor sufficient to label an app risky.
        } catch (e: Exception) {
            // Accessibility query failed — omitted: it never decides the verdict.
        }

        return Observation(results, failed)
    }

    /**
     * `risky_app` verdict. Pure. A listed package found → DETECTED (also when
     * other queries failed); no match but a query failed → UNKNOWN, never
     * SECURE; otherwise SECURE.
     */
    fun evaluate(o: Observation): RaspCheckResult {
        val evidence = o.signals.map {
            val key = if (it.category == RiskyAppCategory.KNOWN_RISKY_PACKAGE)
                "known_risky_package" else "suspicious_accessibility_service"
            RaspEvidence(key, it.pkg, it.reason)
        } + o.failedPackages.map { RaspEvidence("query_failed", it) }
        return when {
            o.signals.isNotEmpty() -> RaspCheckResult.detected("risky_app", evidence)
            o.failedPackages.isNotEmpty() -> RaspCheckResult(
                "risky_app", RaspCheckStatus.UNKNOWN, evidence,
                reason = "${o.failedPackages.size} package check(s) failed",
            )
            else -> RaspCheckResult.secure("risky_app", evidence)
        }
    }
}
