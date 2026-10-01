package com.shieldsdk.rasp

/**
 * Classification logic for the hook-detection engine.
 *
 * ## Why this is not a signature list
 *
 * The cheap version of hook detection is "does package `de.robv.android.xposed`
 * exist?" — one name, one lookup, defeated by renaming or by any of the
 * hiding modules that ship with modern LSPosed. That is the same single-point
 * failure the Frida detector was rebuilt to escape, so this engine follows the
 * same rule: **several independent signal families, correlated, none of them
 * individually sufficient unless it is genuinely hard to forge.**
 *
 * The families here are deliberately different in kind, so that defeating one
 * says nothing about the others:
 *
 * | Family | What it observes | Forgery cost |
 * |---|---|---|
 * | `hook_framework_lib` | a framework's own library mapped into this process | moderate — the SONAME is not the filename |
 * | `hook_native_method` | a Java method that should be interpreted is now `native` | **high** — it is the hook's own mechanism |
 * | `hook_suspicious_lib_path` | code mapped from a writable/temp location | moderate |
 * | `hook_rwx_mapping` | writable **and** executable memory | low on its own — JIT does this legitimately |
 *
 * `hook_native_method` is the load-bearing one. Java-level hooking frameworks
 * in the Xposed/YAHFA/Epic family work by replacing a method's entry point,
 * which the runtime then reports as `native`. Observing that is observing the
 * hook itself rather than an artefact it happened to leave behind, so renaming
 * the framework does not help an attacker.
 *
 * ## Pure by construction
 *
 * No Android imports, no I/O — same split as [RaspSignalAnalysis]. The reading
 * lives in [RaspDeviceProbes]; this decides what the readings mean, and is
 * therefore testable on any JVM.
 */
object RaspHookAnalysis {

    /**
     * Library/SONAME fragments belonging to Java-hooking and native-hooking
     * frameworks.
     *
     * These are matched against **mapped regions**, not installed package
     * names, because a mapped library reveals what is actually resident in the
     * process rather than what is merely installed on the device.
     */
    val hookFrameworkMarkers: List<String> = listOf(
        // Xposed family and its reimplementations
        "xposed", "lsposed", "edxposed", "riru", "zygisk", "yahfa", "sandhook",
        // Cydia Substrate / its Android port
        "substrate", "libsubstrate",
        // Native inline-hooking engines commonly embedded in tampered apps
        "dobby", "libdobby", "whale", "libwhale", "epic", "shadowhook",
        // Generic injection helpers
        "libinject", "injector",
    )

    /**
     * Directories that should never be the origin of code mapped into a
     * production process. All are world-writable or app-writable, which is what
     * makes them the natural staging ground for an injected payload.
     */
    val suspiciousCodeDirectories: List<String> = listOf(
        "/data/local/tmp/", "/sdcard/", "/storage/emulated/", "/data/misc/",
        "/tmp/", "/cache/",
    )

    /** Hard signal: known hooking library found in maps (individually conclusive). */
    val hardHookSignals: Set<String> = setOf("hook_framework_lib")

    /** Soft signals: need corroboration (two required for verdict). */
    val softHookSignals: Set<String> = setOf("hook_rwx_mapping", "hook_suspicious_lib_path", "hook_native_method")

    /** `true` when a mapped region names a known hooking framework. */
    fun mapsIndicateHookFramework(mapsContent: String): Boolean {
        val maps = mapsContent.lowercase()
        return hookFrameworkMarkers.any { maps.contains(it) }
    }

    /**
     * Extracts the framework markers actually present, for evidence.
     *
     * Reporting *which* framework was seen is what lets an analyst distinguish
     * a Zygisk module on a developer's own phone from Substrate inside a
     * repackaged banking app.
     */
    fun hookFrameworksIn(mapsContent: String): List<String> {
        val maps = mapsContent.lowercase()
        return hookFrameworkMarkers.filter { maps.contains(it) }
    }

    /**
     * `true` when an executable mapping originates from a writable location.
     *
     * Only `x` mappings count: an app legitimately reads data files from
     * `/sdcard`, and flagging those would fire on almost every device.
     */
    fun isSuspiciousExecutableMapping(mapsLine: String): Boolean {
        val line = mapsLine.lowercase()
        val perms = line.split(Regex("\\s+")).getOrNull(1) ?: return false
        if (!perms.contains("x")) return false
        return suspiciousCodeDirectories.any { line.contains(it) }
    }

    /** Suspicious executable mappings in a whole `/proc/self/maps` dump. */
    fun suspiciousExecutableMappings(mapsContent: String): List<String> =
        mapsContent.lineSequence()
            .filter { isSuspiciousExecutableMapping(it) }
            .map { it.substringAfterLast(" ").trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .toList()

    /**
     * `true` for a mapping that is writable **and** executable.
     *
     * Deliberately a *soft* signal: ART's JIT and several legitimate runtimes
     * create RWX regions, so this is evidence of "code could be patched here",
     * never proof that it was.
     */
    fun isRwxMapping(mapsLine: String): Boolean {
        val perms = mapsLine.trim().split(Regex("\\s+")).getOrNull(1) ?: return false
        return perms.length >= 3 && perms[1] == 'w' && perms[2] == 'x'
    }

    /** Count of RWX regions in a maps dump. */
    fun countRwxMappings(mapsContent: String): Int =
        mapsContent.lineSequence().count { isRwxMapping(it) }

    /**
     * How many RWX regions are unremarkable on a healthy ART process.
     *
     * Chosen well above what the runtime itself creates, because this signal's
     * job is to notice *unusual* patching surface, not to report that the JIT
     * exists. Below the threshold the signal does not fire at all.
     */
    const val RWX_MAPPING_THRESHOLD: Int = 12

    /**
     * The hook verdict: one HARD signal OR two SOFT signals.
     *
     * Hard signal (individually conclusive): hook_framework_lib (known hooking library in maps)
     * Soft signals (need corroboration): hook_rwx_mapping, hook_suspicious_lib_path, hook_native_method
     *
     * This prevents false positives from:
     * - RWX mapping threshold (12) firing on JIT-heavy processes (soft, needs corroboration)
     * - Reflection check on SDK's own methods firing on obfuscated/ART-optimized builds (soft, needs corroboration)
     * - Single soft signals having innocent explanations
     *
     * Families are independent by construction — see class doc table.
     * Counts DISTINCT signal types, not total occurrences.
     */
    fun hookVerdict(signals: List<String>): Boolean {
        val distinctSignals = signals.distinct()
        val hardSignals = distinctSignals.count { it in hardHookSignals }
        val softSignals = distinctSignals.count { it in softHookSignals }
        return hardSignals >= 1 || softSignals >= 2
    }

    /**
     * Severity for a set of hook signals, as the SDK's shared vocabulary.
     *
     * With the 1-hard-or-2-soft verdict rule, severity reflects corroboration level:
     * - critical: hook_framework_lib + corroboration (another signal)
     * - high: hook_framework_lib alone (single hard)
     * - medium: two soft signals corroborating each other
     * - none: fewer than required signals
     */
    fun severityFor(signals: List<String>): String {
        val distinctSignals = signals.distinct()
        val hardSignals = distinctSignals.count { it in hardHookSignals }
        val softSignals = distinctSignals.count { it in softHookSignals }
        val hasFrameworkLib = signals.contains("hook_framework_lib")
        val total = distinctSignals.size

        return when {
            // Critical: framework lib + corroboration (any other signal)
            hasFrameworkLib && total >= 2 -> "critical"
            // High: framework lib alone (single hard)
            hasFrameworkLib && total == 1 -> "high"
            // Medium: two soft signals corroborating
            hookVerdict(signals) -> "medium"
            else -> "none"
        }
    }

    /**
     * Confidence, 0–100, from how many independent signal families fired.
     *
     * Reported alongside the verdict so a policy can require corroboration
     * before taking a destructive action such as locking the app.
     * Each distinct signal family contributes ~25 confidence (max 4 families = 100).
     */
    fun confidenceFor(signals: List<String>): Int {
        if (signals.isEmpty()) return 0
        val uniqueFamilies = signals.distinct().size
        return (uniqueFamilies * 25).coerceAtMost(100)
    }
}
