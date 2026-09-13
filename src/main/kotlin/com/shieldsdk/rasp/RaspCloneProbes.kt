package com.shieldsdk.rasp

import android.content.Context
import android.os.UserManager

/** One signal's outcome inside the 2-signal clone check — see [RaspCloneProbes.evidence]. */
public data class CloneSignal(
    val signal: String,
    val detected: Boolean,
    val conclusive: Boolean,
    val reason: String? = null,
)

/**
 * Parallel Space / Dual App clone-container detection — verbatim port of
 * `RaspSecurityChannelHandler.isCloneDetected()`/`cloneEvidence()`.
 *
 * Two independent signals, matching the Flutter/Dart side's
 * `CloneDetector` exactly:
 * 1. `known_clone_container_path` — path-substring match against known
 *    clone-app data-directory naming.
 * 2. `unexplained_secondary_user` — cross-checked against
 *    `UserManager.isManagedProfile()` so a legitimate work/enterprise
 *    profile is not misclassified as a clone.
 */
public object RaspCloneProbes {

    private val commonClonePaths =
        listOf("parallel", "dual", "clone", "multiple", "app_clone", "bit_64")

    fun evidence(context: Context): List<CloneSignal> {
        val path = try {
            context.filesDir.path
        } catch (e: Exception) {
            null
        }

        if (path == null) {
            return listOf(
                CloneSignal("known_clone_container_path", detected = false, conclusive = false),
                CloneSignal("unexplained_secondary_user", detected = false, conclusive = false),
            )
        }

        val results = mutableListOf<CloneSignal>()

        val containerMatch = commonClonePaths.any { path.contains(it, ignoreCase = true) }
        results.add(
            CloneSignal("known_clone_container_path", detected = containerMatch, conclusive = true)
        )

        val isPrimaryUserPath = path.contains("/user/0/") || path.contains("/data/data/")
        if (isPrimaryUserPath) {
            results.add(
                CloneSignal("unexplained_secondary_user", detected = false, conclusive = true)
            )
        } else {
            try {
                val userManager =
                    context.getSystemService(Context.USER_SERVICE) as UserManager
                val managedProfile = userManager.isManagedProfile
                results.add(
                    CloneSignal(
                        signal = "unexplained_secondary_user",
                        detected = !managedProfile,
                        conclusive = true,
                        reason = if (managedProfile) "legitimate_work_profile"
                        else "unrecognized_secondary_user",
                    )
                )
            } catch (e: Exception) {
                results.add(
                    CloneSignal("unexplained_secondary_user", detected = false, conclusive = false)
                )
            }
        }

        return results
    }
}
