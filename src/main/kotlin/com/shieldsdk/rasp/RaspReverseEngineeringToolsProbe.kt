package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager

/**
 * Xposed/LSPosed, Magisk manager, Lucky Patcher, GameGuardian, and similar
 * tampering-framework/installer packages — verbatim port of
 * `RaspSecurityChannelHandler.hasReverseEngineeringTools()`.
 *
 * ## A real bug fixed during this port
 *
 * The pre-extraction manifest declared `<queries>` for only 2 of these 9
 * packages, and one of those 2 was the wrong exact name (the Xposed
 * *framework* package, not the Xposed *Installer app* package this check
 * actually targets). On API 30+ package-visibility rules, a package
 * `PackageManager` is not told about via `<queries>` is invisible — not
 * "reported as absent," genuinely unqueryable — regardless of whether it
 * is installed. The check was silently blind to 7 of its 9 targets on
 * every device running a modern Android version. Fixed at the manifest
 * (`android_core/src/main/AndroidManifest.xml`), which is the actual
 * mechanism Android provides for this — not worked around in code.
 */
public object RaspReverseEngineeringToolsProbe {

    val reTools = listOf(
        "de.robv.android.xposed.installer",
        "io.va.exposed",
        "com.chelpus.lackypatch",
        "com.eltechs.axm",
        "com.saurik.substrate",
        "com.topjohnwu.magisk",
        "com.noshufou.android.su",
    )

    /** The package scan: [found] packages, and [failedPackages] whose query failed for a reason other than "not installed". */
    data class Observation(val found: List<String>, val failedPackages: List<String>)

    /**
     * Queries every targeted package. If the PackageManager itself cannot be
     * reached this throws (→ ERROR in `checkReverseEngineeringToolsBlocking`).
     */
    fun observe(context: Context): Observation {
        val pm = context.packageManager
        val found = mutableListOf<String>()
        val failed = mutableListOf<String>()
        for (pkg in reTools) {
            try {
                pm.getApplicationInfo(pkg, 0)
                found.add(pkg)
            } catch (e: PackageManager.NameNotFoundException) {
                // Not installed (or not visible): not detected.
            } catch (e: Exception) {
                failed.add(pkg)
            }
        }
        return Observation(found, failed)
    }

    /**
     * `re_tools` verdict. Pure. A targeted package found → DETECTED; none
     * found but a query failed → UNKNOWN, never SECURE; otherwise SECURE.
     */
    fun evaluate(o: Observation): RaspCheckResult {
        val evidence = o.found.map { RaspEvidence("re_tool_package", it) } +
            o.failedPackages.map { RaspEvidence("query_failed", it) }
        return when {
            o.found.isNotEmpty() -> RaspCheckResult.detected("re_tools", evidence)
            o.failedPackages.isNotEmpty() -> RaspCheckResult(
                "re_tools", RaspCheckStatus.UNKNOWN, evidence,
                reason = "${o.failedPackages.size} package check(s) failed",
            )
            else -> RaspCheckResult.secure("re_tools", evidence)
        }
    }

    /**
     * Every targeted package that is present. Legacy boolean-style helper:
     * a failed scan gives an empty list here; the `re_tools` detector uses
     * [observe] + [evaluate] instead, which report it as UNKNOWN / ERROR.
     */
    fun detectedPackages(context: Context): List<String> = try {
        observe(context).found
    } catch (e: Exception) {
        emptyList()
    }

    fun hasReverseEngineeringTools(context: Context): Boolean =
        detectedPackages(context).isNotEmpty()
}
