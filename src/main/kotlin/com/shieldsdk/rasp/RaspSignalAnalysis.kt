package com.shieldsdk.rasp

/**
 * The classification logic behind the Frida and debugger detectors.
 *
 * ## Why this is a separate object
 *
 * The detectors in [MainActivity] mix two very different kinds of work:
 * **reading** a source of evidence (`/proc/self/maps`, `/proc/self/task`,
 * `LD_PRELOAD`, a socket) and **deciding** what that evidence means. Only the
 * reading needs Android — the deciding is pure logic over strings.
 *
 * While the two were fused inside `private fun`s on a `FlutterActivity`, the
 * deciding could not be tested at all without a device or an emulator: the
 * Dart-side tests mock the platform channel, so they prove the *Dart* wiring
 * and never execute a single line of this Kotlin. That is a real gap for the
 * two highest-value detectors in the SDK.
 *
 * Splitting the decision out makes it a plain JVM object with **no Android
 * imports**, so the actual production classification code runs under ordinary
 * local unit tests (`src/test/kotlin`) on any machine — including a Windows
 * dev box with no emulator attached.
 *
 * ## What is deliberately NOT here
 *
 * The I/O itself. `MainActivity` still opens `/proc`, enumerates threads and
 * probes sockets, and those paths remain untestable without a device — see
 * `SECURITY_LIMITATIONS.md`. This object never touches the filesystem, the
 * network, or the Android framework, which is exactly what makes it testable.
 *
 * Behaviour is intentionally identical to the inline implementation it
 * replaced; this is an extraction, not a redesign.
 */
object RaspSignalAnalysis {

    // ── Frida / instrumentation ───────────────────────────────────────────

    /** Frida artefacts on disk. Renaming defeats these — hence the other signals. */
    val fridaFiles: List<String> = listOf(
        "/system/lib/libfrida.so", "/system/lib64/libfrida.so",
        "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so",
        "/data/local/tmp/frida-server", "/data/local/tmp/frida-server-arm64",
        "/data/local/tmp/frida-server-arm", "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-gadget.so", "/data/local/tmp/linjector",
    )

    /**
     * Substrings that only appear in a mapped region when an instrumentation
     * engine is resident. `libgum` is Frida's instrumentation core and shows up
     * even when the server binary was renamed, because the library's internal
     * SONAME is not what the attacker renamed.
     */
    val instrumentationMapMarkers: List<String> = listOf(
        "frida", "gadget", "libgum", "gum-js", "linjector", "re.frida",
    )

    /** Thread names Frida creates that no ordinary app produces. */
    val hardFridaThreads: List<String> = listOf("gum-js-loop", "pool-frida", "gmainrunner")

    /**
     * Thread names Frida creates that a GLib-based library could *also*
     * legitimately create. Soft on their own — see [fridaVerdict].
     */
    val softFridaThreads: List<String> = listOf("gmain", "gdbus")

    /** Frida's default control ports. */
    val fridaPorts: List<Int> = listOf(27042, 27043)

    /**
     * Signals that are individually explainable on a clean device, and so are
     * never allowed to convict alone.
     */
    val softFridaSignals: Set<String> = setOf("frida_thread_glib", "frida_port_open")

    /** How a single thread name classifies. */
    enum class ThreadClass { HARD, SOFT, NONE }

    /** `true` when a `/proc/self/maps` dump names an instrumentation engine. */
    fun mapsIndicateInstrumentation(mapsContent: String): Boolean {
        val maps = mapsContent.lowercase()
        return instrumentationMapMarkers.any { maps.contains(it) }
    }

    /**
     * Classifies one `/proc/self/task/<tid>/comm` value.
     *
     * Hard names match by prefix because the kernel truncates `comm` to 15
     * characters, so a longer Frida thread name arrives clipped.
     */
    fun classifyThreadName(comm: String): ThreadClass {
        val name = comm.trim().lowercase()
        if (name.isEmpty()) return ThreadClass.NONE
        if (hardFridaThreads.any { name == it || name.startsWith(it) }) return ThreadClass.HARD
        if (softFridaThreads.any { name == it }) return ThreadClass.SOFT
        return ThreadClass.NONE
    }

    /** `true` when `LD_PRELOAD` names an instrumentation library. */
    fun ldPreloadIndicatesInstrumentation(preload: String?): Boolean {
        if (preload.isNullOrBlank()) return false
        val value = preload.lowercase()
        return instrumentationMapMarkers.any { value.contains(it) }
    }

    /**
     * The instrumentation verdict: **one hard signal, or two soft ones**.
     *
     * Mirrors `isEmulator()`'s confidence model rather than `isDeviceRooted()`'s
     * `isNotEmpty()`. A `gmain` thread or a merely-open port 27042 each have
     * innocent explanations, and a false positive here blocks a paying
     * customer's phone (see the false-positive requirement in the security
     * brief), so neither is sufficient by itself.
     */
    fun fridaVerdict(signals: List<String>): Boolean {
        val hard = signals.count { it !in softFridaSignals }
        val soft = signals.count { it in softFridaSignals }
        return hard >= 1 || soft >= 2
    }

    // ── Debugger ──────────────────────────────────────────────────────────

    /**
     * Reads `TracerPid` out of a `/proc/self/status` dump.
     *
     * Returns `0` when the field is absent or unparseable — "no tracer known",
     * which is the same answer a clean process gives. That is deliberate: this
     * parser must never invent a tracer from a malformed file, because a false
     * `tracer_pid` is a hard signal and would convict on its own.
     */
    fun parseTracerPid(statusContent: String): Int =
        statusContent.lineSequence()
            .firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(":")
            ?.trim()
            ?.toIntOrNull()
            ?: 0

    /** `true` when some process is ptrace-attached, per a `/proc/self/status` dump. */
    fun tracerPidIndicatesDebugger(statusContent: String): Boolean =
        parseTracerPid(statusContent) != 0

    /**
     * Signal that describes how the APK was *built* rather than whether anyone
     * is debugging it. Reported as evidence, excluded from the verdict.
     */
    const val DEBUGGABLE_FLAG = "debuggable_flag"

    /**
     * The debugger verdict: any signal **other than** [DEBUGGABLE_FLAG].
     *
     * Including the build flag would make every developer build look like a
     * live attack, which is why it is filtered here rather than at the call
     * site — a future caller cannot forget to exclude it.
     */
    fun debuggerVerdict(signals: List<String>): Boolean =
        signals.any { it != DEBUGGABLE_FLAG }
}
