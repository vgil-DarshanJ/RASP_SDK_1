package com.shieldsdk.rasp

import android.content.Context

/**
 * The **I/O half** of the Frida and debugger detectors.
 *
 * ## Why this exists
 *
 * These checks were `private fun`s on `MainActivity : FlutterActivity`. That
 * made the production implementation unreachable from any test: an
 * instrumentation test cannot call a private method, and reaching it through
 * the platform channel means booting a Flutter engine and asserting on a
 * `MethodChannel` round-trip rather than on the signals themselves.
 *
 * The consequence was a real coverage hole. [RaspSignalAnalysis] made the
 * *classification* testable on any JVM, but the part that actually opens
 * `/proc`, walks the thread table and probes a socket — the part that can only
 * be validated on a real Android runtime — had no test at all.
 *
 * Taking a [Context] rather than an `Activity` is what makes this testable:
 * an instrumentation test can construct it from
 * `InstrumentationRegistry.getInstrumentation().targetContext` and call the
 * real production code directly, with no Activity, no Flutter engine, and
 * nothing mocked.
 *
 * ## Split of responsibilities
 *
 * ```
 *   RaspDeviceProbes   — reads evidence   (this class; needs a device)
 *   RaspSignalAnalysis — decides meaning  (pure JVM; needs nothing)
 * ```
 *
 * `MainActivity` keeps the platform-channel plumbing and delegates here. The
 * logic below is a verbatim move — behaviour is unchanged.
 */
class RaspDeviceProbes(private val context: Context) {

    private fun fileExistsQuietly(path: String): Boolean = try {
        java.io.File(path).exists()
    } catch (e: Exception) {
        false
    }

    // ── Frida / instrumentation ───────────────────────────────────────────

    /**
     * Every instrumentation signal currently firing, as stable ids.
     *
     * Signals are grouped by forgery cost: a filename is trivial to change, a
     * mapped library's internal name much less so, and a live D-Bus handshake
     * on Frida's control port hardest of all. All are reported so the backend
     * scorer can weigh the combination rather than trusting one flag.
     */
    fun fridaSignals(): List<String> {
        val hits = mutableListOf<String>()

        // 1. Known artefacts on disk.
        try {
            if (RaspSignalAnalysis.fridaFiles.any { fileExistsQuietly(it) }) {
                hits.add("frida_file")
            }
        } catch (e: Exception) { /* absent is the normal case */ }

        // 2. Mapped memory regions. Survives renaming the server binary.
        try {
            java.io.File("/proc/self/maps").bufferedReader().use { r ->
                if (RaspSignalAnalysis.mapsIndicateInstrumentation(r.readText())) {
                    hits.add("frida_maps")
                }
            }
        } catch (e: Exception) { /* unreadable on some hardened builds */ }

        // 3. Thread table. Frida's worker threads are named distinctively.
        try {
            val tasks = java.io.File("/proc/self/task").listFiles()
            var hardThread = false
            var softThread = false
            tasks?.forEach { task ->
                try {
                    when (RaspSignalAnalysis.classifyThreadName(
                        java.io.File(task, "comm").readText()
                    )) {
                        RaspSignalAnalysis.ThreadClass.HARD -> hardThread = true
                        RaspSignalAnalysis.ThreadClass.SOFT -> softThread = true
                        RaspSignalAnalysis.ThreadClass.NONE -> { /* ordinary thread */ }
                    }
                } catch (e: Exception) { /* thread exited mid-read */ }
            }
            if (hardThread) hits.add("frida_thread")
            if (softThread) hits.add("frida_thread_glib")
        } catch (e: Exception) { /* /proc/self/task unreadable */ }

        // 4. Loader environment — a gadget injected via LD_PRELOAD.
        try {
            if (RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(
                    System.getenv("LD_PRELOAD")
                )
            ) hits.add("frida_ld_preload")
        } catch (e: Exception) { /* env unreadable */ }

        // 5. Default control ports, validated by handshake.
        try {
            when (probeFridaPorts()) {
                PortProbe.HANDSHAKE -> hits.add("frida_port")
                PortProbe.OPEN -> hits.add("frida_port_open")
                PortProbe.NONE -> { /* nothing listening — the normal case */ }
            }
        } catch (e: Exception) { /* probe failed — no signal, not an error */ }

        return hits
    }

    enum class PortProbe { NONE, OPEN, HANDSHAKE }

    /**
     * Probes Frida's default ports on loopback.
     *
     * Runs on a worker thread with a hard join deadline: this is invoked from
     * the platform-channel handler, which is on the main thread, where any
     * socket call — loopback included — raises `NetworkOnMainThreadException`.
     * The deadline also bounds the cost of the whole check on a device where
     * loopback is filtered and connects hang.
     *
     * Returns [PortProbe.HANDSHAKE] only when the peer answers Frida's D-Bus
     * AUTH greeting, so an unrelated service on 27042 is reported as the
     * weaker [PortProbe.OPEN] instead of a false Frida verdict.
     */
    fun probeFridaPorts(): PortProbe {
        var result = PortProbe.NONE
        val worker = Thread {
            for (port in RaspSignalAnalysis.fridaPorts) {
                try {
                    java.net.Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 120)
                        if (result == PortProbe.NONE) result = PortProbe.OPEN
                        socket.soTimeout = 120
                        // Frida speaks D-Bus: an unauthenticated AUTH line gets
                        // a REJECT/OK back. Anything else is not Frida.
                        socket.getOutputStream().write("\u0000AUTH\r\n".toByteArray())
                        socket.getOutputStream().flush()
                        val buf = ByteArray(64)
                        val read = socket.getInputStream().read(buf)
                        if (read > 0) {
                            val reply = String(buf, 0, read).uppercase()
                            if (reply.contains("REJECT") || reply.contains("OK ")) {
                                result = PortProbe.HANDSHAKE
                            }
                        }
                    }
                } catch (e: Exception) { /* closed port is the normal case */ }
                if (result == PortProbe.HANDSHAKE) break
            }
        }
        worker.isDaemon = true
        worker.start()
        worker.join(500)
        return result
    }

    /**
     * True when instrumentation is judged present: one **hard** signal, or two
     * independent **soft** ones. See [RaspSignalAnalysis.fridaVerdict].
     */
    fun isFridaDetected(): Boolean =
        RaspSignalAnalysis.fridaVerdict(fridaSignals())

    // ── Debugger ──────────────────────────────────────────────────────────

    /**
     * Every debugger signal currently firing, as stable ids.
     *
     * `tracer_pid` is the load-bearing one: `ptrace` attach is how native
     * debuggers and several injection frameworks operate, and it is visible
     * even when the Java-level debugger flags read clean.
     */
    fun debuggerSignals(): List<String> {
        val hits = mutableListOf<String>()

        try {
            if (android.os.Debug.isDebuggerConnected()) hits.add("jdwp_connected")
        } catch (e: Exception) { /* unreadable — absence is not proof of safety */ }

        try {
            if (android.os.Debug.waitingForDebugger()) hits.add("waiting_for_debugger")
        } catch (e: Exception) { /* as above */ }

        // A non-zero TracerPid means some process is ptrace-attached to us.
        try {
            java.io.File("/proc/self/status").bufferedReader().use { r ->
                if (RaspSignalAnalysis.tracerPidIndicatesDebugger(r.readText())) {
                    hits.add("tracer_pid")
                }
            }
        } catch (e: Exception) { /* /proc unreadable on some hardened builds */ }

        // Build property rather than a live debugger: reported as evidence, but
        // deliberately not sufficient on its own — see [isDebuggerAttached].
        try {
            val debuggable =
                (context.applicationInfo.flags and
                    android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
            if (debuggable) hits.add(RaspSignalAnalysis.DEBUGGABLE_FLAG)
        } catch (e: Exception) { /* applicationInfo unavailable */ }

        return hits
    }

    /**
     * True when a debugger is actually attached *right now*.
     *
     * `debuggable_flag` is excluded from the verdict on purpose: it describes
     * how the APK was built, not whether anyone is debugging it.
     */
    fun isDebuggerAttached(): Boolean =
        RaspSignalAnalysis.debuggerVerdict(debuggerSignals())
}
