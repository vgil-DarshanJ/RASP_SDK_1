package com.shieldsdk.rasp

import android.content.Context
import android.provider.Settings

/**
 * USB debugging (ADB) and Developer Options detection.
 *
 * Distinct from [RaspUsbAnalysis], which answers "is a cable physically
 * plugged in right now" — this answers "is ADB *permitted*", a completely
 * independent fact (ADB can be enabled with no cable attached, and a cable
 * can be attached with ADB off).
 *
 * Plain `Settings.Global` reads, zero Flutter dependency, zero permissions
 * required.
 */
object AdbGuard {

    /**
     * `true`/`false` when the setting could be read, `null` when it could
     * not (should not normally happen on a real Android device — never
     * collapse this into `false`; a control that could not read the real
     * state must never be reported as "safe").
     */
    fun isAdbEnabled(context: Context): Boolean? = try {
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    } catch (e: Exception) {
        null
    }

    /**
     * A weaker signal than [isAdbEnabled] — Developer Options can be
     * unlocked with ADB itself still off.
     */
    fun isDeveloperModeEnabled(context: Context): Boolean? = try {
        Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) == 1
    } catch (e: Exception) {
        null
    }
}
