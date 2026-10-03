package com.shieldsdk.rasp

import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import java.util.concurrent.atomic.AtomicReference

/**
 * `mock_location` — is the location the host app supplied a mock (fake GPS) fix?
 *
 * Evaluated only on a location the host passed in ([RaspLocationSnapshot]);
 * the engine never requests location itself. No location → UNAVAILABLE.
 *
 * | Input | Source | Role |
 * |---|---|---|
 * | `isMock` on the snapshot | `Location.isMock()` (API 31+) / `isFromMockProvider()` (API 18–30) via [RaspLocationSnapshot.fromLocation], or the host's own flag (e.g. Flutter geolocator `Position.isMocked`) | decides |
 * | mock location apps | API 23+: installed apps requesting `ACCESS_MOCK_LOCATION` whose AppOps `mock_location` mode is ALLOWED (the app picked in Developer options); API ≤ 22: `Settings.Secure.ALLOW_MOCK_LOCATION` = 1 | evidence only |
 *
 * Verdict: no location supplied by the host → UNAVAILABLE; a location whose
 * `isMock` is true → DETECTED; false → SECURE; a location without its mock
 * flag → UNKNOWN (where the fix came from cannot be decided). A selected mock-location app
 * is reported but does not decide on its own: it shows a mock provider is
 * allowed, not that this particular fix came from it.
 */
object RaspMockLocationProbes {

    const val DETECTOR_ID = "mock_location"
    private const val ACCESS_MOCK_LOCATION = "android.permission.ACCESS_MOCK_LOCATION"
    private const val APPS_CACHE_MILLIS = 60_000L

    data class Observation(
        val locationSupplied: Boolean,
        /** The supplied fix's mock flag; `null` when the host did not provide it. */
        val isMock: Boolean?,
        /** Apps currently allowed to provide mock locations; `null` when this could not be read. */
        val mockLocationApps: List<String>?,
    )

    private val appsCache = AtomicReference<Pair<Long, List<String>?>?>(null)

    fun observe(context: Context, location: RaspLocationSnapshot?): Observation =
        Observation(
            locationSupplied = location != null,
            isMock = location?.isMock,
            mockLocationApps = if (location == null) null else cachedMockLocationApps(context),
        )

    fun evaluate(o: Observation): RaspCheckResult {
        if (!o.locationSupplied) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "No location supplied by the host app")
        }
        val evidence = listOf(
            RaspEvidence("is_mock", o.isMock),
            RaspEvidence("mock_location_apps", o.mockLocationApps ?: "unreadable"),
        )
        return when (o.isMock) {
            true -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            false -> RaspCheckResult.secure(DETECTOR_ID, evidence)
            null -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Location supplied without its mock flag",
            )
        }
    }

    private fun cachedMockLocationApps(context: Context): List<String>? {
        val now = SystemClock.elapsedRealtime()
        appsCache.get()?.let { (at, apps) -> if (now - at < APPS_CACHE_MILLIS) return apps }
        val apps = readMockLocationApps(context)
        appsCache.set(now to apps)
        return apps
    }

    @Suppress("DEPRECATION")
    private fun readMockLocationApps(context: Context): List<String>? = try {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            val allowed = Settings.Secure.getString(context.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION)
            if (allowed == "1") listOf("(any — developer setting enabled)") else emptyList()
        } else {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                .filter { it.requestedPermissions?.contains(ACCESS_MOCK_LOCATION) == true }
                .filter { pkg ->
                    val uid = pkg.applicationInfo?.uid ?: return@filter false
                    appOps.checkOpNoThrow(AppOpsManager.OPSTR_MOCK_LOCATION, uid, pkg.packageName) ==
                        AppOpsManager.MODE_ALLOWED
                }
                .map { it.packageName }
        }
    } catch (e: Exception) {
        null
    }
}
