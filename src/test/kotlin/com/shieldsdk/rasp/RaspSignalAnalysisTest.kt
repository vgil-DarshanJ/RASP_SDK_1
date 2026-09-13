package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Local unit tests for the native Android security layer.
 *
 * ## What these prove, and what they do not
 *
 * These execute the **real production Kotlin** in [RaspSignalAnalysis] — the
 * code that decides whether a `/proc` dump, a thread name or a set of signals
 * means "instrumented" or "debugged". The Dart-side tests cannot do this: they
 * mock the platform channel, so they verify the Dart wiring while never running
 * a line of Kotlin.
 *
 * They do **not** prove that reading `/proc/self/maps` on a real handset finds a
 * real Frida server. The I/O layer stays in [MainActivity] and needs a device;
 * see `SECURITY_LIMITATIONS.md`. Detection efficacy against a live attack is
 * unverified until an instrumented on-device test exists.
 *
 * Fixtures are **realistic captured shapes**, not live payloads. Nothing here
 * launches, installs, or contacts anything.
 */
class RaspSignalAnalysisTest {

    // ── Fixtures ──────────────────────────────────────────────────────────

    /** A `/proc/self/maps` excerpt from an ordinary, clean app process. */
    private val cleanMaps = """
        12c00000-12e00000 rw-p 00000000 00:00 0                  [anon:dalvik-main space]
        7f8a2c1000-7f8a2c3000 r--p 00000000 fd:00 1234           /system/lib64/libc.so
        7f8a2c3000-7f8a2c9000 r-xp 00002000 fd:00 1234           /system/lib64/libc.so
        7f8a2d0000-7f8a2d4000 r--p 00000000 fd:00 5678           /system/lib64/libutils.so
        7fff1a2000-7fff1c3000 rw-p 00000000 00:00 0              [stack]
    """.trimIndent()

    /** The same process with a frida-gadget mapped in. */
    private val fridaGadgetMaps = """
        12c00000-12e00000 rw-p 00000000 00:00 0                  [anon:dalvik-main space]
        7f8a2c1000-7f8a2c3000 r--p 00000000 fd:00 1234           /system/lib64/libc.so
        7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999           /data/local/tmp/frida-gadget.so
        7fff1a2000-7fff1c3000 rw-p 00000000 00:00 0              [stack]
    """.trimIndent()

    /**
     * A renamed Frida server. The filename gives nothing away — but the
     * instrumentation core's own SONAME still appears, which is the whole point
     * of scanning maps rather than trusting filenames.
     */
    private val renamedFridaMaps = """
        12c00000-12e00000 rw-p 00000000 00:00 0                  [anon:dalvik-main space]
        7f9b001000-7f9b400000 r-xp 00000000 fd:00 9999           /data/local/tmp/totally-legit-helper
        7f9c001000-7f9c200000 r-xp 00000000 fd:00 8888           /data/local/tmp/libgum.so
    """.trimIndent()

    private fun statusWithTracer(pid: Int) = """
        Name:	rasp_app
        State:	S (sleeping)
        Tgid:	4242
        Pid:	4242
        PPid:	1000
        TracerPid:	$pid
        Uid:	10234	10234	10234	10234
    """.trimIndent()

    // ══════════════════════════════════════════════════════════════════════
    // FRIDA
    // ══════════════════════════════════════════════════════════════════════

    // ── 1. Clean environment ──────────────────────────────────────────────

    @Test
    fun `clean maps produce no instrumentation signal`() {
        assertFalse(RaspSignalAnalysis.mapsIndicateInstrumentation(cleanMaps))
    }

    @Test
    fun `clean environment yields no frida verdict`() {
        assertFalse(RaspSignalAnalysis.fridaVerdict(emptyList()))
    }

    // ── 2. Known Frida file signal ────────────────────────────────────────

    @Test
    fun `the known-artefact list covers server, gadget and linjector`() {
        val files = RaspSignalAnalysis.fridaFiles
        assertTrue(files.any { it.endsWith("frida-server") })
        assertTrue(files.any { it.contains("frida-gadget") })
        assertTrue(files.any { it.contains("linjector") })
        assertTrue("64-bit server path must be covered",
            files.any { it.contains("frida-server-arm64") })
    }

    @Test
    fun `a file signal alone is hard enough to convict`() {
        assertTrue(RaspSignalAnalysis.fridaVerdict(listOf("frida_file")))
    }

    // ── 3. /proc/maps signal ──────────────────────────────────────────────

    @Test
    fun `a mapped frida-gadget is detected`() {
        assertTrue(RaspSignalAnalysis.mapsIndicateInstrumentation(fridaGadgetMaps))
    }

    @Test
    fun `a RENAMED frida server is still detected via its instrumentation core`() {
        // The regression that motivated this whole engine: the previous
        // implementation checked four filenames, so renaming the binary
        // defeated detection outright.
        assertTrue(
            "renaming the server must not defeat maps scanning",
            RaspSignalAnalysis.mapsIndicateInstrumentation(renamedFridaMaps),
        )
    }

    @Test
    fun `maps matching is case-insensitive`() {
        assertTrue(RaspSignalAnalysis.mapsIndicateInstrumentation("/data/local/tmp/FRIDA-server"))
    }

    // ── 4. Thread-name signal ─────────────────────────────────────────────

    @Test
    fun `frida worker threads classify as HARD`() {
        assertEquals(RaspSignalAnalysis.ThreadClass.HARD,
            RaspSignalAnalysis.classifyThreadName("gum-js-loop"))
        assertEquals(RaspSignalAnalysis.ThreadClass.HARD,
            RaspSignalAnalysis.classifyThreadName("pool-frida"))
    }

    @Test
    fun `a comm value truncated by the kernel still classifies as HARD`() {
        // The kernel clips comm to 15 chars, so a longer name arrives cut short.
        assertEquals(RaspSignalAnalysis.ThreadClass.HARD,
            RaspSignalAnalysis.classifyThreadName("gum-js-loop-123"))
    }

    @Test
    fun `glib thread names classify as SOFT, not HARD`() {
        // gmain/gdbus are legitimate GLib names. Treating them as hard would
        // block ordinary apps that link a GLib-based library.
        assertEquals(RaspSignalAnalysis.ThreadClass.SOFT,
            RaspSignalAnalysis.classifyThreadName("gmain"))
        assertEquals(RaspSignalAnalysis.ThreadClass.SOFT,
            RaspSignalAnalysis.classifyThreadName("gdbus"))
    }

    @Test
    fun `ordinary thread names classify as NONE`() {
        listOf("main", "Binder:4242_1", "RenderThread", "FinalizerDaemon", "")
            .forEach {
                assertEquals("'$it' must not look like instrumentation",
                    RaspSignalAnalysis.ThreadClass.NONE,
                    RaspSignalAnalysis.classifyThreadName(it))
            }
    }

    @Test
    fun `thread classification tolerates whitespace and case`() {
        assertEquals(RaspSignalAnalysis.ThreadClass.HARD,
            RaspSignalAnalysis.classifyThreadName("  GUM-JS-LOOP\n"))
    }

    // ── 5. LD_PRELOAD signal ──────────────────────────────────────────────

    @Test
    fun `an injected gadget in LD_PRELOAD is detected`() {
        assertTrue(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(
            "/data/local/tmp/frida-gadget.so"))
        assertTrue(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(
            "/system/lib64/libgum.so:/system/lib64/libc.so"))
    }

    @Test
    fun `an absent or innocuous LD_PRELOAD is not a signal`() {
        assertFalse(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(null))
        assertFalse(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(""))
        assertFalse(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation("   "))
        assertFalse(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(
            "/vendor/lib64/libperfmon.so"))
    }

    // ── 6. Port / probe signal ────────────────────────────────────────────

    @Test
    fun `frida default control ports are covered`() {
        assertTrue(RaspSignalAnalysis.fridaPorts.contains(27042))
        assertTrue(RaspSignalAnalysis.fridaPorts.contains(27043))
    }

    @Test
    fun `a handshake-confirmed port convicts but a merely-open port does not`() {
        // frida_port means a D-Bus AUTH handshake succeeded — that is Frida.
        assertTrue(RaspSignalAnalysis.fridaVerdict(listOf("frida_port")))
        // frida_port_open means something is listening but did not speak D-Bus.
        // An unrelated service squatting on 27042 must not be called Frida.
        assertFalse(RaspSignalAnalysis.fridaVerdict(listOf("frida_port_open")))
    }

    // ── 7. Multiple weak signals ──────────────────────────────────────────

    @Test
    fun `two soft signals together do convict`() {
        assertTrue(RaspSignalAnalysis.fridaVerdict(
            listOf("frida_thread_glib", "frida_port_open")))
    }

    @Test
    fun `one soft signal alone never convicts`() {
        assertFalse(RaspSignalAnalysis.fridaVerdict(listOf("frida_thread_glib")))
        assertFalse(RaspSignalAnalysis.fridaVerdict(listOf("frida_port_open")))
    }

    // ── 8. Confidence-threshold behaviour ─────────────────────────────────

    @Test
    fun `every hard signal convicts on its own`() {
        listOf("frida_file", "frida_maps", "frida_thread", "frida_ld_preload", "frida_port")
            .forEach {
                assertTrue("'$it' is a hard signal and must convict alone",
                    RaspSignalAnalysis.fridaVerdict(listOf(it)))
            }
    }

    @Test
    fun `a hard signal convicts even when mixed with soft ones`() {
        assertTrue(RaspSignalAnalysis.fridaVerdict(
            listOf("frida_port_open", "frida_maps")))
    }

    @Test
    fun `exactly the two documented signals are soft`() {
        // Guards the threshold model: promoting a signal to soft silently
        // weakens detection, demoting one to hard invites false positives.
        assertEquals(setOf("frida_thread_glib", "frida_port_open"),
            RaspSignalAnalysis.softFridaSignals)
    }

    // ══════════════════════════════════════════════════════════════════════
    // ANTI-DEBUG
    // ══════════════════════════════════════════════════════════════════════

    // ── 9. Clean process ──────────────────────────────────────────────────

    @Test
    fun `a clean process reports TracerPid zero and no debugger`() {
        assertEquals(0, RaspSignalAnalysis.parseTracerPid(statusWithTracer(0)))
        assertFalse(RaspSignalAnalysis.tracerPidIndicatesDebugger(statusWithTracer(0)))
    }

    @Test
    fun `no signals means no debugger verdict`() {
        assertFalse(RaspSignalAnalysis.debuggerVerdict(emptyList()))
    }

    // ── 10. JDWP signal ───────────────────────────────────────────────────

    @Test
    fun `a JDWP debugger convicts on its own`() {
        assertTrue(RaspSignalAnalysis.debuggerVerdict(listOf("jdwp_connected")))
        assertTrue(RaspSignalAnalysis.debuggerVerdict(listOf("waiting_for_debugger")))
    }

    // ── 11. TracerPid signal ──────────────────────────────────────────────

    @Test
    fun `a non-zero TracerPid is detected as a ptrace attach`() {
        assertEquals(4711, RaspSignalAnalysis.parseTracerPid(statusWithTracer(4711)))
        assertTrue(RaspSignalAnalysis.tracerPidIndicatesDebugger(statusWithTracer(4711)))
        assertTrue(RaspSignalAnalysis.debuggerVerdict(listOf("tracer_pid")))
    }

    @Test
    fun `a malformed or absent TracerPid never invents a tracer`() {
        // A false tracer_pid is a hard signal and would convict alone, so a
        // parse failure must fail toward "no tracer known", not toward a threat.
        assertEquals(0, RaspSignalAnalysis.parseTracerPid(""))
        assertEquals(0, RaspSignalAnalysis.parseTracerPid("Name:\trasp_app\nState:\tS"))
        assertEquals(0, RaspSignalAnalysis.parseTracerPid("TracerPid:\tnot-a-number"))
        assertEquals(0, RaspSignalAnalysis.parseTracerPid("TracerPid:"))
    }

    @Test
    fun `TracerPid is not confused with other Pid fields`() {
        // Tgid/Pid/PPid all end in 'id' and all precede TracerPid in the file.
        assertEquals(0, RaspSignalAnalysis.parseTracerPid(statusWithTracer(0)))
        assertEquals(99, RaspSignalAnalysis.parseTracerPid(statusWithTracer(99)))
    }

    // ── 12. Multiple signals ──────────────────────────────────────────────

    @Test
    fun `multiple debugger signals still convict`() {
        assertTrue(RaspSignalAnalysis.debuggerVerdict(
            listOf("jdwp_connected", "tracer_pid")))
        assertTrue(RaspSignalAnalysis.debuggerVerdict(
            listOf("debuggable_flag", "tracer_pid")))
    }

    // ── 13. Confidence-threshold behaviour ────────────────────────────────

    @Test
    fun `the debuggable build flag alone is NOT a debugger`() {
        // It describes how the APK was built, not whether anyone is attached.
        // Convicting on it would flag every developer build as a live attack.
        assertFalse(
            "a debug build with no debugger attached is not under attack",
            RaspSignalAnalysis.debuggerVerdict(listOf(RaspSignalAnalysis.DEBUGGABLE_FLAG)),
        )
    }

    @Test
    fun `the excluded flag constant matches the signal the native layer emits`() {
        assertEquals("debuggable_flag", RaspSignalAnalysis.DEBUGGABLE_FLAG)
    }

    // ══════════════════════════════════════════════════════════════════════
    // FALSE POSITIVES — ordinary developer / user environments
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `an ordinary developer machine profile raises no frida verdict`() {
        // Debug build, debugger available, GLib threads present: a normal day
        // at a desk. None of it is instrumentation.
        assertFalse(RaspSignalAnalysis.fridaVerdict(listOf("frida_thread_glib")))
        assertFalse(RaspSignalAnalysis.mapsIndicateInstrumentation(cleanMaps))
        assertFalse(RaspSignalAnalysis.ldPreloadIndicatesInstrumentation(null))
    }

    @Test
    fun `common library names are not mistaken for instrumentation`() {
        // Guards the marker list against over-broad substrings.
        listOf(
            "/system/lib64/libgcc.so",
            "/system/lib64/libgui.so",
            "/vendor/lib64/libgatekeeper.so",
            "/system/lib64/libglib-ish.so",
        ).forEach {
            assertFalse("'$it' must not look like instrumentation",
                RaspSignalAnalysis.mapsIndicateInstrumentation(it))
        }
    }
}
