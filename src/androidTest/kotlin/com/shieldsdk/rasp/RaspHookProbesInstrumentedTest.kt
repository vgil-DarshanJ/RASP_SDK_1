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
 * # INSTRUMENTATION TESTS — hook detection against a real Android runtime
 *
 * Calls [RaspHookProbes] — the production implementation — with a real
 * `Context`. The maps it reads are this process's real mappings, and the
 * method-integrity check reflects on the real loaded classes.
 *
 * The method-integrity check in particular **cannot** be validated off-device:
 * whether ART reports a Kotlin function as `native` depends on the runtime, so
 * a JVM unit test proves nothing about it. That is the gap this file closes.
 *
 * ## Safety
 *
 * Read-only. No hooking framework is installed, no system partition or device
 * setting is touched, and nothing is injected into any process. The suite
 * validates the SDK's response to the environment as it is.
 *
 * ## NOT TESTED here
 *
 * Detection of a **live** hooking framework (LSPosed/Substrate actually
 * attached). That needs a rooted device with the framework installed — attack
 * tooling this harness will not install automatically. Recorded as NOT TESTED
 * in `docs/ANDROID_RUNTIME_SECURITY_VALIDATION.md`.
 */
@RunWith(AndroidJUnit4::class)
class RaspHookProbesInstrumentedTest {

    private lateinit var hooks: RaspHookProbes

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        hooks = RaspHookProbes(context)
    }

    // ── Method integrity ──────────────────────────────────────────────────

    @Test
    fun everyCriticalMethodResolves_onThisRuntime() {
        // If a method stops resolving — renamed by obfuscation, signature
        // changed — its protection silently disappears. UNAVAILABLE is the
        // honest report, but on a debug build every method should resolve, so
        // an UNAVAILABLE here is a real defect worth failing on.
        val integrity = hooks.criticalMethodIntegrity()
        assertTrue("expected a non-empty critical set", integrity.isNotEmpty())

        val unavailable = integrity.filterValues {
            it == RaspHookProbes.MethodIntegrity.UNAVAILABLE
        }
        assertTrue(
            "critical methods failed to resolve: ${unavailable.keys}",
            unavailable.isEmpty(),
        )
    }

    @Test
    fun criticalMethodsAreIntact_onACleanRuntime() {
        val integrity = hooks.criticalMethodIntegrity()
        val hooked = integrity.filterValues { it == RaspHookProbes.MethodIntegrity.HOOKED }
        assertTrue(
            "unhooked runtime reported hooked methods: ${hooked.keys}",
            hooked.isEmpty(),
        )
    }

    @Test
    fun criticalSetCoversTheDetectorsAndTheirVerdicts() {
        // Guards the minimum viable set: protecting the probe but not the
        // verdict function (or vice versa) leaves an obvious bypass.
        val keys = hooks.criticalMethodIntegrity().keys
        listOf(
            "RaspDeviceProbes.isFridaDetected",
            "RaspDeviceProbes.isDebuggerAttached",
            "RaspHookProbes.isHookingDetected",
            "RaspSignalAnalysis.fridaVerdict",
            "RaspSignalAnalysis.debuggerVerdict",
            "RaspHookAnalysis.hookVerdict",
        ).forEach {
            assertTrue("critical set must cover $it", keys.contains(it))
        }
    }

    @Test
    fun anUnknownMethodIsUNAVAILABLE_notINTACT() {
        // The fail-safe contract: a check that could not run must never be
        // reported as a clean bill of health.
        assertEquals(
            RaspHookProbes.MethodIntegrity.UNAVAILABLE,
            hooks.inspectMethod("com.example.NoSuchClass", "nope", emptyArray()),
        )
        assertEquals(
            RaspHookProbes.MethodIntegrity.UNAVAILABLE,
            hooks.inspectMethod(
                "com.shieldsdk.rasp.RaspHookAnalysis", "noSuchMethod", emptyArray()),
        )
    }

    // ── Signals / verdict ─────────────────────────────────────────────────

    @Test
    fun hookSignals_completeWithoutThrowing() {
        assertNotNull(hooks.hookSignals())
    }

    @Test
    fun hookSignals_returnOnlyKnownSignalIds() {
        val known = setOf(
            "hook_framework_lib", "hook_suspicious_lib_path",
            "hook_rwx_mapping", "hook_native_method",
        )
        hooks.hookSignals().forEach {
            assertTrue("unexpected signal id '$it'", it in known)
        }
    }

    @Test
    fun cleanRuntime_reportsNoHooking() {
        val signals = hooks.hookSignals()
        assertFalse(
            "clean runtime reported hooking; signals=$signals",
            hooks.isHookingDetected(),
        )
    }

    @Test
    fun hookVerdict_isConsistentWithItsOwnSignals() {
        val signals = hooks.hookSignals()
        assertEquals(RaspHookAnalysis.hookVerdict(signals), hooks.isHookingDetected())
    }

    @Test
    fun noHookingFrameworkIsResidentOnThisRuntime() {
        val frameworks = hooks.detectedFrameworks()
        assertTrue(
            "unexpected hooking framework mapped in: $frameworks",
            frameworks.isEmpty(),
        )
    }

    // ── Structured result contract ────────────────────────────────────────

    @Test
    fun detectionResult_carriesTheFullContract() {
        val result = hooks.hookDetectionResult()
        listOf(
            "detector_id", "detected", "severity", "confidence",
            "evidence", "timestamp", "platform", "detector_version",
        ).forEach {
            assertTrue("result must carry '$it'", result.containsKey(it))
        }
        assertEquals("hook_detection", result["detector_id"])
        assertEquals("android", result["platform"])
        assertTrue(result["detected"] is Boolean)
        assertTrue(result["confidence"] is Int)
        assertTrue(result["evidence"] is List<*>)
    }

    @Test
    fun detectionResult_leaksNoMemoryAddresses() {
        // Evidence is shipped to the host app and to the backend. Raw mapping
        // lines would disclose the process's memory layout for no detection
        // benefit, so evidence must stay at the level of signal ids.
        @Suppress("UNCHECKED_CAST")
        val evidence = hooks.hookDetectionResult()["evidence"] as List<String>
        evidence.forEach {
            assertFalse("evidence '$it' looks like an address", it.contains("-"))
            assertFalse("evidence '$it' looks like a path", it.contains("/"))
        }
    }

    @Test
    fun hookScan_isFastEnoughForTheScanPath() {
        val started = System.currentTimeMillis()
        hooks.hookSignals()
        val elapsed = System.currentTimeMillis() - started
        assertTrue("hookSignals took ${elapsed}ms, expected < 2000ms", elapsed < 2000)
    }

    @Test
    fun repeatedHookScans_areStable() {
        assertEquals(hooks.isHookingDetected(), hooks.isHookingDetected())
    }

    // ── Evidence capture ──────────────────────────────────────────────────

    /** Records measured output for the validation report. */
    @Test
    fun captureHookEvidenceForValidationReport() {
        val tag = "RASP-VALIDATION"
        val signals = hooks.hookSignals()
        android.util.Log.i(tag, "hook_signals=$signals")
        android.util.Log.i(tag, "hook_verdict=${hooks.isHookingDetected()}")
        android.util.Log.i(tag, "hook_severity=${RaspHookAnalysis.severityFor(signals)}")
        android.util.Log.i(tag, "hook_confidence=${RaspHookAnalysis.confidenceFor(signals)}")
        android.util.Log.i(tag, "hook_frameworks=${hooks.detectedFrameworks()}")
        android.util.Log.i(tag, "critical_methods=${hooks.criticalMethodIntegrity()}")

        val started = System.currentTimeMillis()
        hooks.hookSignals()
        android.util.Log.i(tag, "hook_scan_ms=${System.currentTimeMillis() - started}")

        assertNotNull(signals)
    }
}
