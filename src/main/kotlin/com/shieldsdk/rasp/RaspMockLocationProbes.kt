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
 * Verdict:
 * - no location supplied by the host → UNAVAILABLE;
 * - a fix older than [MAX_AGE_SECONDS] → UNKNOWN "stale location" (not used);
 * - the fix's own mock flag true → DETECTED (hard);
 * - soft signals: `mock_app_selected` (an installed app holds the
 *   mock-location AppOp — it shows a mock provider is allowed, not that this
 *   fix came from it) and `location_jump` (the last two fixes imply more than
 *   [MAX_SPEED_MPS] m/s). Two soft signals → DETECTED;
 * - mock flag false → SECURE (one soft signal is reported in evidence);
 * - mock flag missing → UNKNOWN.
 *
 * The last two fixes are kept in memory only ([Movement]), never stored.
 */
object RaspMockLocationProbes {

    const val DETECTOR_ID = "mock_location"
    private const val ACCESS_MOCK_LOCATION = "android.permission.ACCESS_MOCK_LOCATION"
    private const val APPS_CACHE_MILLIS = 60_000L

    /** A fix older than this is not used ("stale location"). */
    const val MAX_AGE_SECONDS: Long = 120

    /** Implied speed between the last two fixes above which `location_jump` fires (≈ 1080 km/h). */
    const val MAX_SPEED_MPS: Double = 300.0

    data class Jump(val distanceM: Double, val seconds: Double, val speedMps: Double)

    data class Observation(
        val locationSupplied: Boolean,
        /** The supplied fix's mock flag; `null` when the host did not provide it. */
        val isMock: Boolean?,
        /** Apps currently allowed to provide mock locations; `null` when this could not be read. */
        val mockLocationApps: List<String>?,
        /** Age of the fix when checked; `null` when unknown. */
        val ageSeconds: Long? = null,
        val accuracyM: Double? = null,
        val provider: String? = null,
        /** Impossible movement between the last two fixes, when it happened. */
        val jump: Jump? = null,
    )

    private val appsCache = AtomicReference<Pair<Long, List<String>?>?>(null)

    /**
     * The last two fixes the host supplied (memory only). [record] adds a fix
     * once (by capture time); [jump] reports impossible movement between them.
     */
    class Movement {
        private var previous: RaspLocationSnapshot? = null
        private var latest: RaspLocationSnapshot? = null

        @Synchronized
        fun record(fix: RaspLocationSnapshot) {
            val last = latest
            if (last != null && last.capturedAtMillis == fix.capturedAtMillis &&
                last.latitude == fix.latitude && last.longitude == fix.longitude) return
            previous = last
            latest = fix
        }

        @Synchronized
        fun jump(): Jump? {
            val a = previous ?: return null
            val b = latest ?: return null
            return impliedJump(a, b)
        }

        @Synchronized
        fun clear() { previous = null; latest = null }
    }

    /** Per process: the fixes of the current session. */
    val movement = Movement()

    /** Great-circle distance in metres (haversine, mean Earth radius). */
    fun distanceMeters(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val r = 6_371_000.0
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val h = Math.sin(dLat / 2).let { it * it } +
            Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) * Math.sin(dLon / 2).let { it * it }
        return 2 * r * Math.asin(Math.min(1.0, Math.sqrt(h)))
    }

    /** The movement from [a] to [b] when it implies more than [MAX_SPEED_MPS]; time under 1 s counts as 1 s. */
    fun impliedJump(a: RaspLocationSnapshot, b: RaspLocationSnapshot): Jump? {
        val distance = distanceMeters(a.latitude, a.longitude, b.latitude, b.longitude)
        val seconds = Math.max(1.0, Math.abs(b.capturedAtMillis - a.capturedAtMillis) / 1000.0)
        val speed = distance / seconds
        return if (speed > MAX_SPEED_MPS) Jump(distance, seconds, speed) else null
    }

    fun observe(context: Context, location: RaspLocationSnapshot?, nowMillis: Long = System.currentTimeMillis()): Observation {
        if (location == null) return Observation(false, null, null)
        movement.record(location)
        return Observation(
            locationSupplied = true,
            isMock = location.isMock,
            mockLocationApps = cachedMockLocationApps(context),
            ageSeconds = ((nowMillis - location.capturedAtMillis) / 1000).coerceAtLeast(0),
            accuracyM = location.accuracyMeters,
            provider = location.provider,
            jump = movement.jump(),
        )
    }

    fun evaluate(o: Observation): RaspCheckResult {
        if (!o.locationSupplied) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "No location supplied by the host app")
        }
        val mockAppSelected = o.mockLocationApps?.isNotEmpty()
        val evidence = buildList {
            add(RaspEvidence("is_mock", o.isMock))
            add(RaspEvidence("location_age_seconds", o.ageSeconds))
            add(RaspEvidence("accuracy_m", o.accuracyM))
            add(RaspEvidence("provider", o.provider ?: "unknown"))
            add(RaspEvidence("mock_app_selected", mockAppSelected ?: "unreadable", if (mockAppSelected == true) "soft" else null))
            add(RaspEvidence("mock_location_apps", o.mockLocationApps ?: "unreadable"))
            o.jump?.let {
                add(RaspEvidence("location_jump", Math.round(it.speedMps), "soft; m/s over %.0f m in %.0f s".format(it.distanceM, it.seconds)))
            }
        }
        if (o.ageSeconds != null && o.ageSeconds > MAX_AGE_SECONDS) {
            return RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "stale location")
        }
        val softSignals = listOfNotNull(
            "mock_app_selected".takeIf { mockAppSelected == true },
            "location_jump".takeIf { o.jump != null },
        )
        return when {
            o.isMock == true -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            softSignals.size >= 2 -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            o.isMock == false -> RaspCheckResult.secure(DETECTOR_ID, evidence)
            else -> RaspCheckResult(
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
