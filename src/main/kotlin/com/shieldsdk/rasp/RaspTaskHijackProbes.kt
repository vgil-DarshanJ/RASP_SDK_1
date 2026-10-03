package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicReference

/**
 * `task_hijack` — does another installed app declare an activity with this
 * app's task affinity? (Task hijacking: a malicious activity joins the
 * banking app's task and is shown in its place — fake login screens.)
 *
 * | Signal | Role |
 * |---|---|
 * | another package's activity whose `taskAffinity` equals one of the host's affinities | decides → DETECTED |
 * | host's own activities: non-empty affinity with `singleTask`/`singleInstance`, `allowTaskReparenting`, an affinity that is not the host's own package | evidence only — the same on every device, so it is a build finding, not a runtime detection |
 *
 * Package visibility (API 30+): only packages visible to the host are
 * scanned. The engine manifest declares a `<queries>` intent for launcher
 * activities, which makes apps with a launcher icon visible; apps without
 * one are not (see docs/PACKAGE_VISIBILITY.md). The scope is reported as
 * evidence (`visibility`). Scan results are cached for 5 minutes.
 *
 * Host activities unreadable or foreign scan failed → UNKNOWN.
 */
object RaspTaskHijackProbes {

    const val DETECTOR_ID = "task_hijack"
    private const val SCAN_CACHE_MILLIS = 5 * 60_000L

    data class ActivityConfig(
        val name: String,
        /** `null` = no affinity (`android:taskAffinity=""`). */
        val taskAffinity: String?,
        val launchMode: Int,
        val allowTaskReparenting: Boolean,
    )

    data class ForeignActivity(val packageName: String, val activityName: String, val taskAffinity: String?)

    data class Observation(
        val hostPackage: String,
        /** `null` when the host's own activities could not be read. */
        val hostActivities: List<ActivityConfig>?,
        /** Activities of other visible packages; `null` when the scan failed. */
        val foreignActivities: List<ForeignActivity>?,
        /** `"all"` (API < 30) or `"launcher_apps"` (API 30+). */
        val visibility: String,
        val visiblePackageCount: Int,
    )

    /** Host configuration findings, for evidence. */
    fun hostConfigFindings(hostPackage: String, activities: List<ActivityConfig>): List<String> = buildList {
        for (a in activities) {
            val singleTaskLike = a.launchMode == ActivityInfo.LAUNCH_SINGLE_TASK ||
                a.launchMode == ActivityInfo.LAUNCH_SINGLE_INSTANCE
            if (a.taskAffinity != null && singleTaskLike) add("${a.name}: singleTask/singleInstance with affinity ${a.taskAffinity}")
            if (a.allowTaskReparenting) add("${a.name}: allowTaskReparenting")
            if (a.taskAffinity != null && a.taskAffinity != hostPackage) add("${a.name}: custom affinity ${a.taskAffinity}")
        }
    }

    fun evaluate(o: Observation): RaspCheckResult {
        val host = o.hostActivities ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN, reason = "Host activities could not be read",
        )
        val foreign = o.foreignActivities ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN, reason = "Installed packages could not be scanned",
        )
        val hostAffinities = host.mapNotNull { it.taskAffinity }.toSet()
        val hijackers = foreign
            .filter { it.packageName != o.hostPackage && it.taskAffinity != null && it.taskAffinity in hostAffinities }
            .map { it.packageName }
            .distinct()
        val evidence = hijackers.map { RaspEvidence("hijacking_package", it, "hard") } +
            hostConfigFindings(o.hostPackage, host).map { RaspEvidence("host_config_finding", it) } +
            listOf(
                RaspEvidence("visibility", o.visibility),
                RaspEvidence("visible_packages", o.visiblePackageCount),
            )
        return if (hijackers.isNotEmpty()) RaspCheckResult.detected(DETECTOR_ID, evidence)
        else RaspCheckResult.secure(DETECTOR_ID, evidence)
    }

    private val foreignCache = AtomicReference<Pair<Long, Pair<List<ForeignActivity>, Int>>?>(null)

    fun observe(context: Context): Observation {
        val pm = context.packageManager
        val hostPackage = context.packageName
        val host = try {
            pm.getPackageInfo(hostPackage, PackageManager.GET_ACTIVITIES).activities.orEmpty().map { it.toConfig() }
        } catch (e: Exception) {
            null
        }
        val visibility = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) "all" else "launcher_apps"
        val scan = cachedForeignScan(pm, hostPackage)
        return Observation(hostPackage, host, scan?.first, visibility, scan?.second ?: 0)
    }

    private fun cachedForeignScan(pm: PackageManager, hostPackage: String): Pair<List<ForeignActivity>, Int>? {
        val now = SystemClock.elapsedRealtime()
        foreignCache.get()?.let { (at, result) -> if (now - at < SCAN_CACHE_MILLIS) return result }
        val result = try {
            // One package per call: GET_ACTIVITIES for every package in one call
            // can exceed the binder transaction limit.
            val packages = pm.getInstalledPackages(0).map { it.packageName }.filter { it != hostPackage }
            val activities = packages.flatMap { pkg ->
                try {
                    pm.getPackageInfo(pkg, PackageManager.GET_ACTIVITIES).activities.orEmpty()
                        .map { ForeignActivity(pkg, it.name, it.taskAffinity) }
                } catch (e: Exception) {
                    emptyList()
                }
            }
            activities to packages.size
        } catch (e: Exception) {
            return null
        }
        foreignCache.set(now to result)
        return result
    }

    private fun ActivityInfo.toConfig() = ActivityConfig(
        name = name,
        taskAffinity = taskAffinity,
        launchMode = launchMode,
        allowTaskReparenting = flags and ActivityInfo.FLAG_ALLOW_TASK_REPARENTING != 0,
    )
}
