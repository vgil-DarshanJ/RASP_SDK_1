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
        "xposed", "lsposed", "lspd", "edxposed", "riru", "zygisk", "yahfa", "sandhook",
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

    /**
     * Markers short or common enough to appear inside unrelated names
     * (`epic` in `epicenter`, `whale` in `whalesong`). They match only a whole
     * path token, never a prefix. Every other marker matches a token prefix,
     * so `xposed` also catches `XposedBridge.jar`.
     */
    private val exactTokenMarkers: Set<String> =
        setOf("epic", "libepic", "whale", "libwhale", "riru", "lspd", "libinject", "injector")

    /** Hard signal: known hooking library found in maps (individually conclusive). */
    val hardHookSignals: Set<String> = setOf("hook_framework_lib")

    /** Soft signals: need corroboration (two required for verdict). */
    val softHookSignals: Set<String> = setOf("hook_rwx_mapping", "hook_suspicious_lib_path", "hook_native_method")

    /** `true` when a mapped region names a known hooking framework. */
    fun mapsIndicateHookFramework(mapsContent: String): Boolean =
        hookFrameworksIn(mapsContent).isNotEmpty()

    /**
     * Extracts the framework markers actually present, for evidence.
     *
     * Reporting *which* framework was seen is what lets an analyst distinguish
     * a Zygisk module on a developer's own phone from Substrate inside a
     * repackaged banking app.
     *
     * Only the pathname part of each mapping is inspected, split into tokens
     * on anything that is not a letter or digit (`/data/adb/lspd/libriru_x.so`
     * → `data adb lspd libriru x so`, plus `riru` with the `lib` prefix
     * removed). Matching a raw substring of the whole dump was the hard
     * signal's false-positive source: a hard signal convicts on its own, so it
     * must name a library, not happen to contain four letters of one.
     */
    fun hookFrameworksIn(mapsContent: String): List<String> {
        val tokens = HashSet<String>()
        mapsContent.lineSequence().forEach { line -> tokens.addAll(pathTokens(line)) }
        return hookFrameworkMarkers.filter { marker ->
            if (marker in exactTokenMarkers) marker in tokens
            else tokens.any { it.startsWith(marker) }
        }
    }

    /** Lower-cased name tokens of one maps line's pathname (empty for anonymous memory). */
    internal fun pathTokens(mapsLine: String): List<String> {
        val slash = mapsLine.indexOf('/')
        val bracket = mapsLine.indexOf('[')
        val start = when {
            slash >= 0 && (bracket < 0 || slash < bracket) -> slash
            bracket >= 0 -> bracket
            else -> return emptyList()
        }
        val raw = mapsLine.substring(start).lowercase().split(Regex("[^a-z0-9]+")).filter { it.isNotEmpty() }
        return raw + raw.filter { it.length > 3 && it.startsWith("lib") }.map { it.removePrefix("lib") }
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
        if (isTrustedCodePath(mappedPath(mapsLine))) return false
        return suspiciousCodeDirectories.any { line.contains(it) }
    }

    /**
     * System-owned folders inside a [suspiciousCodeDirectories] entry that
     * hold normal code. Since Android 12 an updated ART module keeps its
     * compiled boot image in `/data/misc/apexdata/com.android.art/dalvik-cache/`
     * (written only by the system, never by apps), so every updated phone maps
     * `boot.oat` and framework `.odex` files from there.
     */
    val trustedCodeDirectories: List<String> = listOf(
        "/data/misc/apexdata/com.android.art/dalvik-cache/",
    )

    /** The mapped path of a maps line (6th field onwards), or `""` for an anonymous region. */
    fun mappedPath(mapsLine: String): String =
        mapsLine.trim().split(Regex("\\s+"), limit = 6).getOrNull(5)?.trim().orEmpty()

    /**
     * `true` when [path] itself starts with a [trustedCodeDirectories] entry.
     * A path that only *contains* one further in (for example
     * `/data/local/tmp/data/misc/apexdata/...`) is not trusted.
     */
    fun isTrustedCodePath(path: String): Boolean =
        trustedCodeDirectories.any { path.startsWith(it) && !path.contains("/../") }

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

    /**
     * The Dart VM's own code pages (`[anon:dart-code]`). A Flutter debug build
     * JIT-compiles into these RWX regions — the host app's own code, not a
     * patch — so they are not counted towards [RWX_MAPPING_THRESHOLD].
     * (Release builds are AOT-compiled and do not create them.)
     */
    fun isDartCodeRegion(mapsLine: String): Boolean = mappedPath(mapsLine) == "[anon:dart-code]"

    /** An RWX region that counts towards [RWX_MAPPING_THRESHOLD]: every one except [isDartCodeRegion]. */
    fun isCountedRwxMapping(mapsLine: String): Boolean = isRwxMapping(mapsLine) && !isDartCodeRegion(mapsLine)

    /** Count of RWX regions in a maps dump, not counting the Dart VM's own code pages. */
    fun countRwxMappings(mapsContent: String): Int =
        mapsContent.lineSequence().count { isCountedRwxMapping(it) }

    /** RWX `[anon:dart-code]` regions left out of [countRwxMappings]. */
    fun countDartCodeRwxRegions(mapsContent: String): Int =
        mapsContent.lineSequence().count { isRwxMapping(it) && isDartCodeRegion(it) }

    /** How close to [RWX_MAPPING_THRESHOLD] the count must be for `hook_near_threshold`. */
    const val NEAR_THRESHOLD_MARGIN: Int = 2

    /** `true` when [rwxCount] is within [NEAR_THRESHOLD_MARGIN] of the threshold without exceeding it. */
    fun isNearRwxThreshold(rwxCount: Int): Boolean =
        rwxCount in (RWX_MAPPING_THRESHOLD - NEAR_THRESHOLD_MARGIN)..RWX_MAPPING_THRESHOLD

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

    /** `"hard"` or `"soft"` for a signal id, for evidence. */
    fun signalClass(signal: String): String = if (signal in hardHookSignals) "hard" else "soft"

    /**
     * Everything one hook scan observed. [mapsContent] is `null` when
     * `/proc/self/maps` could not be read.
     */
    data class Observation(
        val signals: List<String>,
        val frameworks: List<String>,
        val rwxMappingCount: Int?,
        val suspiciousExecMappingCount: Int?,
        val mapsReadable: Boolean,
        /** `null` when no critical method could be resolved by reflection. */
        val nativeMethodHooked: Boolean?,
        /**
         * Per fired signal, the lines that made it fire (at most
         * [LINES_PER_SIGNAL], each shortened by [evidenceLine]): maps lines
         * for the maps-based signals, `native method: <name>` for
         * `hook_native_method`.
         */
        val signalLines: Map<String, List<String>> = emptyMap(),
        /** `[anon:dart-code]` RWX regions not counted in [rwxMappingCount]; `null` when maps were unreadable. */
        val dartCodeRwxCount: Int? = null,
    )

    /** Longest maps line written to evidence. */
    const val EVIDENCE_LINE_MAX: Int = 80

    /** Matching lines kept per signal (`hook_rwx_mapping` alone can match dozens). */
    const val LINES_PER_SIGNAL: Int = 3

    /**
     * A maps line for evidence, at most [EVIDENCE_LINE_MAX] characters.
     * Column-alignment whitespace is collapsed first. A line still too long
     * keeps its start (address range, permissions) and its end (the file
     * path) with `…` in place of the middle — cutting only the end would
     * usually remove the library name, which is the part that identifies
     * what matched.
     */
    fun evidenceLine(mapsLine: String): String {
        val collapsed = mapsLine.trim().replace(Regex("\\s+"), " ")
        if (collapsed.length <= EVIDENCE_LINE_MAX) return collapsed
        val head = 30
        val tail = EVIDENCE_LINE_MAX - head - 1
        return collapsed.take(head) + "…" + collapsed.takeLast(tail)
    }

    /**
     * Everything the hook scan takes from one maps dump — the part the native
     * core (`native/src/maps.rs`) computes too. Lines are evidence lines
     * ([evidenceLine]), at most [LINES_PER_SIGNAL] each, collected whether or
     * not the signal fires.
     */
    data class MapsSummary(
        val frameworks: List<String>,
        val frameworkLines: List<String>,
        val suspiciousExecMappingCount: Int,
        val suspiciousLines: List<String>,
        val rwxMappingCount: Int,
        val rwxLines: List<String>,
        val dartCodeRwxCount: Int,
    ) {
        /** The JSON fields, for the parity fixtures. */
        fun toMap(): Map<String, Any?> = linkedMapOf(
            "frameworks" to frameworks,
            "frameworkLines" to frameworkLines,
            "suspiciousExecMappingCount" to suspiciousExecMappingCount.toLong(),
            "suspiciousLines" to suspiciousLines,
            "rwxMappingCount" to rwxMappingCount.toLong(),
            "rwxLines" to rwxLines,
            "dartCodeRwxCount" to dartCodeRwxCount.toLong(),
        )

        companion object {
            /** Parses the native core's JSON; `null` when malformed. */
            fun fromJson(json: String): MapsSummary? = try {
                val o = RaspJson.parse(json) as Map<*, *>
                fun strings(key: String) = (o[key] as List<*>).map { it as String }
                fun count(key: String) = (o[key] as Long).toInt()
                MapsSummary(
                    strings("frameworks"), strings("frameworkLines"),
                    count("suspiciousExecMappingCount"), strings("suspiciousLines"),
                    count("rwxMappingCount"), strings("rwxLines"), count("dartCodeRwxCount"),
                )
            } catch (e: Exception) {
                null
            }
        }
    }

    /** The Kotlin [MapsSummary] of [mapsContent] (reference for the native one). */
    fun summarizeMaps(mapsContent: String): MapsSummary {
        fun keep(matched: Sequence<String>) = matched.take(LINES_PER_SIGNAL).map(::evidenceLine).toList()
        val frameworks = hookFrameworksIn(mapsContent)
        return MapsSummary(
            frameworks = frameworks,
            frameworkLines = if (frameworks.isEmpty()) emptyList()
            else keep(mapsContent.lineSequence().filter { hookFrameworksIn(it).isNotEmpty() }),
            suspiciousExecMappingCount = suspiciousExecutableMappings(mapsContent).size,
            suspiciousLines = keep(mapsContent.lineSequence().filter(::isSuspiciousExecutableMapping)),
            rwxMappingCount = countRwxMappings(mapsContent),
            rwxLines = keep(mapsContent.lineSequence().filter(::isCountedRwxMapping)),
            dartCodeRwxCount = countDartCodeRwxRegions(mapsContent),
        )
    }

    /**
     * Turns raw readings into signals. Pure: the probe class supplies the
     * maps text and the method-integrity reading ([hookedMethods]: names of
     * critical methods that report `native`).
     */
    fun observe(
        mapsContent: String?,
        nativeMethodHooked: Boolean?,
        hookedMethods: List<String> = emptyList(),
    ): Observation = observeSummary(mapsContent?.let(::summarizeMaps), nativeMethodHooked, hookedMethods)

    /** [observe] from a [MapsSummary] (Kotlin or native); `null` = maps unreadable. */
    fun observeSummary(
        summary: MapsSummary?,
        nativeMethodHooked: Boolean?,
        hookedMethods: List<String> = emptyList(),
    ): Observation {
        val signals = mutableListOf<String>()
        val lines = linkedMapOf<String, List<String>>()
        fun keep(signal: String, matched: Sequence<String>) {
            lines[signal] = matched.take(LINES_PER_SIGNAL).map(::evidenceLine).toList()
        }
        var frameworks = emptyList<String>()
        var rwx: Int? = null
        var dartCode: Int? = null
        var suspicious: Int? = null
        if (summary != null) {
            frameworks = summary.frameworks
            if (frameworks.isNotEmpty()) {
                signals.add("hook_framework_lib")
                lines["hook_framework_lib"] = summary.frameworkLines
            }
            suspicious = summary.suspiciousExecMappingCount
            if (suspicious > 0) {
                signals.add("hook_suspicious_lib_path")
                lines["hook_suspicious_lib_path"] = summary.suspiciousLines
            }
            rwx = summary.rwxMappingCount
            dartCode = summary.dartCodeRwxCount
            if (rwx > RWX_MAPPING_THRESHOLD) {
                signals.add("hook_rwx_mapping")
                lines["hook_rwx_mapping"] = summary.rwxLines
            }
        }
        if (nativeMethodHooked == true) {
            signals.add("hook_native_method")
            keep("hook_native_method", hookedMethods.asSequence().map { "native method: $it" })
        }
        return Observation(signals, frameworks, rwx, suspicious, summary != null, nativeMethodHooked, lines, dartCode)
    }

    /**
     * The signals that produced a DETECTED verdict: the hard signal(s) when
     * present (one is enough), otherwise the soft signals (two or more).
     * Empty when the verdict is not DETECTED.
     */
    fun decisiveSignals(signals: List<String>): List<String> {
        val distinct = signals.distinct()
        if (!hookVerdict(distinct)) return emptyList()
        val hard = distinct.filter { it in hardHookSignals }
        return hard.ifEmpty { distinct.filter { it in softHookSignals } }
    }

    /**
     * The reported result: DETECTED on one hard or two soft signals; UNKNOWN
     * when `/proc/self/maps` was unreadable, because the hard signal and two
     * of the three soft signals come from it, so "nothing found" would only
     * mean "nothing looked at"; SECURE otherwise.
     *
     * Evidence names every signal that fired (with its hard/soft class), the
     * framework markers matched, and the counts behind the soft signals, so a
     * DETECTED on a real device shows which rule convicted it:
     * - `detected_by` (only on DETECTED): the signals that decided it;
     * - `hook_signal_line` (note = signal name): for each fired signal, up to
     *   [LINES_PER_SIGNAL] lines that matched, shortened by [evidenceLine].
     */
    fun toCheckResult(observation: Observation, detectorId: String = "hook_detection"): RaspCheckResult {
        val distinct = observation.signals.distinct()
        val decisive = decisiveSignals(distinct)
        val evidence = buildList {
            if (decisive.isNotEmpty()) add(RaspEvidence("detected_by", decisive))
            distinct.forEach { add(RaspEvidence("hook_signal", it, signalClass(it))) }
            distinct.forEach { signal ->
                observation.signalLines[signal].orEmpty().forEach { add(RaspEvidence("hook_signal_line", it, signal)) }
            }
            observation.frameworks.forEach { add(RaspEvidence("hook_framework", it)) }
            observation.rwxMappingCount?.let {
                val dart = observation.dartCodeRwxCount ?: 0
                val note = "threshold $RWX_MAPPING_THRESHOLD" +
                    if (dart > 0) "; $dart [anon:dart-code] regions not counted" else ""
                add(RaspEvidence("rwx_mapping_count", it, note))
                if (isNearRwxThreshold(it)) {
                    add(RaspEvidence("hook_near_threshold", true,
                        "rwx_mapping_count $it is within $NEAR_THRESHOLD_MARGIN of the threshold $RWX_MAPPING_THRESHOLD"))
                }
            }
            observation.suspiciousExecMappingCount?.let { add(RaspEvidence("suspicious_exec_mapping_count", it)) }
            add(RaspEvidence("method_integrity", when (observation.nativeMethodHooked) {
                true -> "hooked"
                false -> "intact"
                null -> "unavailable"
            }))
            add(RaspEvidence("maps_readable", observation.mapsReadable))
            add(RaspEvidence("signal_count", distinct.size))
        }
        return when {
            hookVerdict(distinct) -> RaspCheckResult.detected(detectorId, evidence)
            !observation.mapsReadable -> RaspCheckResult(
                detectorId, RaspCheckStatus.UNKNOWN, evidence,
                reason = "/proc/self/maps unreadable; hard and most soft hook signals could not be evaluated",
            )
            else -> RaspCheckResult.secure(detectorId, evidence)
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
