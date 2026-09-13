package com.shieldsdk.rasp

import android.content.Context

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
        "com.sygic.aura",
        "de.robv.android.xposed.installer",
        "io.va.exposed",
        "com.chelpus.lackypatch",
        "com.eltechs.axm",
        "com.saurik.substrate",
        "com.topjohnwu.magisk",
        "org.adaway",
        "com.noshufou.android.su",
    )

    /**
     * Every targeted package that is actually present, as evidence — not
     * just a bare boolean, matching every other detector's evidence-first
     * convention in this SDK.
     */
    fun detectedPackages(context: Context): List<String> = try {
        val pm = context.packageManager
        reTools.filter { pkg ->
            try {
                pm.getApplicationInfo(pkg, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    } catch (e: Exception) {
        emptyList()
    }

    fun hasReverseEngineeringTools(context: Context): Boolean =
        detectedPackages(context).isNotEmpty()
}
