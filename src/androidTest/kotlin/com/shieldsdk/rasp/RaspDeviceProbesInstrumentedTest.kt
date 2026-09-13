package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — real Android device I/O
 *
 * These run **on a device or emulator** and call [RaspDeviceProbes] — the
 * actual production implementation — with a real [android.content.Context].
 * Nothing is mocked. `/proc` is the real `/proc` of this very process, the
 * thread table is this process's real thread table, and the socket probe opens
 * real loopback connections.
 *
 * ## How this differs from the unit tests
 *
 * `src/test/kotlin/RaspSignalAnalysisTest` covers **classification**: given a
 * `/proc` dump, what does it mean? It runs on any JVM and proves the decision
 * logic, including that a renamed Frida server is still caught via its
 * instrumentation core.
 *
 * This file covers **acquisition**: can the detector actually read those
 * sources on a real Android runtime, and does it stay quiet on a clean one?
 * A regression where `/proc/self/maps` becomes unreadable under a new SELinux
 * policy would pass every unit test and fail here — which is the entire reason
 * this layer exists.
 *
 * ## Safety
 *
 * These tests are safe on an authorized development device. They **only read**:
 * no system partition, bootloader, kernel, other application, or device
 * security setting is modified, and no attack tooling is installed or
 * launched. The loopback probe makes outbound TCP connections to 127.0.0.1 on
 * Frida's default ports and writes a D-Bus AUTH greeting — on a clean device
 * nothing is listening and the connection simply fails.
 *
 * ## What these tests deliberately do NOT assert
 *
 * That a **live Frida server is detected**. Doing so requires pushing and
 * running `frida-server` on the device, which is attack tooling this harness
 * will not install automatically. That condition is recorded as **NOT TESTED**
 * in `docs/ANDROID_RUNTIME_SECURITY_VALIDATION.md` rather than being
 * manufactured into a PASS.
 */
@RunWith(AndroidJUnit4::class)
class RaspDeviceProbesInstrumentedTest {

    private lateinit var probes: RaspDeviceProbes

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        probes = RaspDeviceProbes(context)
    }

    // ══════════════════════════════════════════════════════════════════════
    // I/O REACHABILITY — the sources must actually be readable here
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun procSelfMaps_isReadable_onThisDevice() {
        // If SELinux or a future OS release makes this unreadable, frida_maps
        // silently stops firing forever. The detector swallows the exception by
        // design (a probe must never crash the host app), so only a test that
        // reads the file directly can catch the regression.
        val maps = java.io.File("/proc/self/maps")
        assertTrue("/proc/self/maps must exist", maps.exists())
        val text = maps.readText()
        assertTrue("/proc/self/maps must be non-empty", text.isNotEmpty())
        assertTrue(
            "a real maps dump should reference libc",
            text.contains("libc", ignoreCase = true),
        )
    }

    @Test
    fun procSelfTask_isEnumerable_onThisDevice() {
        val tasks = java.io.File("/proc/self/task").listFiles()
        assertNotNull("/proc/self/task must be listable", tasks)
        assertTrue("a live process has at least one thread", tasks!!.isNotEmpty())

        // comm must be readable for the thread-name signal to work at all.
        val readable = tasks.count { java.io.File(it, "comm").canRead() }
        assertTrue("at least one thread's comm must be readable", readable > 0)
    }

    @Test
    fun procSelfStatus_exposesTracerPid_onThisDevice() {
        val status = java.io.File("/proc/self/status").readText()
        assertTrue(
            "TracerPid must be present for ptrace detection to function",
            status.contains("TracerPid:"),
        )
        // Parsed by the same production code the detector uses.
        val pid = RaspSignalAnalysis.parseTracerPid(status)
        assertTrue("TracerPid must parse to a non-negative value", pid >= 0)
    }

    // ══════════════════════════════════════════════════════════════════════
    // FRIDA — real detector, real I/O
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun fridaSignals_completeWithoutThrowing() {
        // A probe must never crash the host app, whatever /proc looks like.
        val signals = probes.fridaSignals()
        assertNotNull(signals)
    }

    @Test
    fun fridaSignals_returnOnlyKnownSignalIds() {
        // Guards the contract the Dart layer and backend scorer depend on: an
        // unrecognised id would be shipped as evidence and scored as nothing.
        val known = setOf(
            "frida_file", "frida_maps", "frida_thread",
            "frida_thread_glib", "frida_ld_preload",
            "frida_port", "frida_port_open",
        )
        probes.fridaSignals().forEach {
            assertTrue("unexpected signal id '$it'", it in known)
        }
    }

    @Test
    fun cleanDevice_reportsNoInstrumentation() {
        // The false-positive test that matters commercially: an ordinary device
        // with no instrumentation must not be called compromised.
        //
        // If this fails on YOUR device, check whether frida-server is actually
        // running before treating it as a bug — the failure message prints the
        // signals so the cause is visible rather than guessed.
        val signals = probes.fridaSignals()
        val detected = probes.isFridaDetected()
        assertFalse(
            "clean device reported instrumentation; signals=$signals",
            detected,
        )
    }

    @Test
    fun fridaVerdict_isConsistentWithItsOwnSignals() {
        // The verdict must be derivable from the reported evidence. If these
        // ever disagree, the SOC console would show evidence that does not
        // justify the verdict an analyst is acting on.
        val signals = probes.fridaSignals()
        assertEquals(
            RaspSignalAnalysis.fridaVerdict(signals),
            probes.isFridaDetected(),
        )
    }

    @Test
    fun portProbe_returnsCleanlyOnLoopback() {
        // Exercises the real socket path, including the main-thread guard: the
        // probe runs on a worker thread because a loopback connect on the main
        // thread raises NetworkOnMainThreadException.
        val result = probes.probeFridaPorts()
        assertNotNull(result)
        assertTrue(
            "nothing should be answering Frida's D-Bus handshake on a clean device",
            result != RaspDeviceProbes.PortProbe.HANDSHAKE,
        )
    }

    @Test
    fun portProbe_staysWithinItsDeadline() {
        // The probe is on the scan path; an unbounded socket wait would stall
        // every security scan on a device where loopback is filtered.
        val started = System.currentTimeMillis()
        probes.probeFridaPorts()
        val elapsed = System.currentTimeMillis() - started
        assertTrue("port probe took ${elapsed}ms, expected < 2000ms", elapsed < 2000)
    }

    @Test
    fun fridaScan_isFastEnoughForTheScanPath() {
        val started = System.currentTimeMillis()
        probes.fridaSignals()
        val elapsed = System.currentTimeMillis() - started
        assertTrue("fridaSignals took ${elapsed}ms, expected < 3000ms", elapsed < 3000)
    }

    // ══════════════════════════════════════════════════════════════════════
    // DEBUGGER — real detector, real I/O
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun debuggerSignals_completeWithoutThrowing() {
        assertNotNull(probes.debuggerSignals())
    }

    @Test
    fun debuggerSignals_returnOnlyKnownSignalIds() {
        val known = setOf(
            "jdwp_connected", "waiting_for_debugger",
            "tracer_pid", RaspSignalAnalysis.DEBUGGABLE_FLAG,
        )
        probes.debuggerSignals().forEach {
            assertTrue("unexpected signal id '$it'", it in known)
        }
    }

    @Test
    fun debuggableFlag_reflectsThisTestBuild() {
        // The instrumentation APK is debuggable, so this signal must be present.
        // It proves the ApplicationInfo read works — and the next test proves it
        // does not, on its own, produce a "debugger attached" verdict.
        assertTrue(
            "a debuggable test build must report the build flag",
            probes.debuggerSignals().contains(RaspSignalAnalysis.DEBUGGABLE_FLAG),
        )
    }

    @Test
    fun debuggableBuild_aloneIsNotReportedAsAttachedDebugger() {
        // The regression this detector exists to prevent, verified end-to-end on
        // a real device: a debug build with no debugger attached must not be
        // flagged. Otherwise every developer build looks like a live attack.
        val signals = probes.debuggerSignals()
        val runtimeSignals = signals.filter { it != RaspSignalAnalysis.DEBUGGABLE_FLAG }
        if (runtimeSignals.isEmpty()) {
            assertFalse(
                "build flag alone must not convict; signals=$signals",
                probes.isDebuggerAttached(),
            )
        }
        // If a debugger IS attached (someone is running these under a debugger),
        // the detector correctly reports true and there is nothing to assert
        // about a clean state — that case is covered by the unit tests.
    }

    @Test
    fun debuggerVerdict_isConsistentWithItsOwnSignals() {
        val signals = probes.debuggerSignals()
        assertEquals(
            RaspSignalAnalysis.debuggerVerdict(signals),
            probes.isDebuggerAttached(),
        )
    }

    @Test
    fun tracerPid_isZeroWhenNoDebuggerIsAttached() {
        // Instrumentation runs without a native tracer unless one is attached
        // deliberately, so this doubles as a false-positive check on the
        // load-bearing ptrace signal.
        val status = java.io.File("/proc/self/status").readText()
        val pid = RaspSignalAnalysis.parseTracerPid(status)
        if (pid == 0) {
            assertFalse(
                "tracer_pid must not fire when TracerPid is 0",
                probes.debuggerSignals().contains("tracer_pid"),
            )
        } else {
            // A tracer really is attached (e.g. run under a debugger).
            assertTrue(
                "tracer_pid must fire when TracerPid is non-zero",
                probes.debuggerSignals().contains("tracer_pid"),
            )
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // STABILITY / REPEATABILITY
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun repeatedScans_areStable() {
        // A detector that flickers between verdicts on an unchanged device
        // produces noise in the SOC console and erodes trust in real alerts.
        val first = probes.isFridaDetected()
        val second = probes.isFridaDetected()
        val third = probes.isFridaDetected()
        assertEquals(first, second)
        assertEquals(second, third)
    }

    @Test
    fun repeatedDebuggerScans_areStable() {
        val first = probes.isDebuggerAttached()
        val second = probes.isDebuggerAttached()
        assertEquals(first, second)
    }

    // ══════════════════════════════════════════════════════════════════════
    // EVIDENCE CAPTURE
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Not a pass/fail check — it records what this specific device actually
     * reported, so the validation report quotes measured output instead of an
     * assumption about what "a clean device" looks like.
     *
     * Read it back with:
     * `adb logcat -d -s RASP-VALIDATION:I`
     */
    @Test
    fun captureEvidenceForValidationReport() {
        val tag = "RASP-VALIDATION"
        val frida = probes.fridaSignals()
        val debugger = probes.debuggerSignals()

        android.util.Log.i(tag, "device=${android.os.Build.MODEL}")
        android.util.Log.i(tag, "fingerprint=${android.os.Build.FINGERPRINT}")
        android.util.Log.i(tag, "android_release=${android.os.Build.VERSION.RELEASE}")
        android.util.Log.i(tag, "android_sdk_int=${android.os.Build.VERSION.SDK_INT}")
        android.util.Log.i(tag, "frida_signals=$frida")
        android.util.Log.i(tag, "frida_verdict=${probes.isFridaDetected()}")
        android.util.Log.i(tag, "debugger_signals=$debugger")
        android.util.Log.i(tag, "debugger_verdict=${probes.isDebuggerAttached()}")
        android.util.Log.i(tag, "port_probe=${probes.probeFridaPorts()}")

        val started = System.currentTimeMillis()
        probes.fridaSignals()
        android.util.Log.i(tag, "frida_scan_ms=${System.currentTimeMillis() - started}")

        assertNotNull(frida)
        assertNotNull(debugger)
    }
}
