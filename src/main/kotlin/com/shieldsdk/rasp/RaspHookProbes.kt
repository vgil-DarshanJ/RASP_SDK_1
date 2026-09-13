package com.shieldsdk.rasp

import android.content.Context
import java.lang.reflect.Modifier

/**
 * The **I/O half** of the hook-detection engine.
 *
 * Reads the evidence [RaspHookAnalysis] classifies: mapped regions, the origin
 * of executable mappings, and the runtime's own view of security-critical
 * methods. Takes a [Context] rather than an `Activity` for the same reason as
 * [RaspDeviceProbes] — so instrumentation tests can call the real production
 * implementation with nothing mocked.
 *
 * ## Method integrity: the minimum viable set
 *
 * [criticalMethodSignals] does **not** walk every class in the app. Protecting
 * everything blindly costs startup time on the scan path and produces noise;
 * the set below is limited to methods where a successful hook would let an
 * attacker change a decision that actually matters:
 *
 * | Method | What a hook would achieve |
 * |---|---|
 * | `RaspDeviceProbes.isFridaDetected` | suppress instrumentation detection |
 * | `RaspDeviceProbes.isDebuggerAttached` | suppress debugger detection |
 * | `RaspHookProbes.isHookingDetected` | suppress hook detection itself |
 * | `RaspSignalAnalysis.fridaVerdict` | invert the instrumentation verdict |
 * | `RaspSignalAnalysis.debuggerVerdict` | invert the debugger verdict |
 * | `RaspHookAnalysis.hookVerdict` | invert the hook verdict |
 *
 * These are the native-side equivalents of the licence/binding/policy
 * functions named in the security brief. The licence handshake, device binding
 * and signing-certificate checks are enforced **server-side** as well
 * (`/api/v1/sdk/activate` recomputes the HMAC and compares the pinned
 * fingerprint), so a client-side hook on those cannot by itself mint a valid
 * activation — which is why the client-side integrity budget is spent here, on
 * the detectors whose verdicts have no server-side equivalent.
 *
 * ## Why "is it native?" is the check
 *
 * Java-level hooking frameworks in the Xposed/YAHFA/Epic family replace a
 * method's entry point, after which ART reports the method as `native`. A
 * normally-compiled Kotlin function is never `native`, so observing that flag
 * on one of the methods above is observing the hook's own mechanism rather
 * than an artefact it left behind.
 *
 * ## Unavailable is not "clean"
 *
 * If reflection cannot resolve a method — obfuscation renamed it, a future
 * Kotlin release changed the signature — the result is
 * [MethodIntegrity.UNAVAILABLE], never `INTACT`. Reporting "no hook found"
 * for a check that never ran is exactly the failure mode the SDK's four-state
 * `DetectionStatus` exists to prevent.
 */
class RaspHookProbes(private val context: Context) {

    /** Outcome of inspecting one security-critical method. */
    enum class MethodIntegrity { INTACT, HOOKED, UNAVAILABLE }

    /** One security-critical method, named for reflection. */
    private data class CriticalMethod(
        val owner: String,
        val method: String,
        val parameterTypes: Array<Class<*>> = emptyArray(),
    )

    private val criticalMethods = listOf(
        CriticalMethod("com.shieldsdk.rasp.RaspDeviceProbes", "isFridaDetected"),
        CriticalMethod("com.shieldsdk.rasp.RaspDeviceProbes", "isDebuggerAttached"),
        CriticalMethod("com.shieldsdk.rasp.RaspHookProbes", "isHookingDetected"),
        CriticalMethod(
            "com.shieldsdk.rasp.RaspSignalAnalysis", "fridaVerdict",
            arrayOf(List::class.java),
        ),
        CriticalMethod(
            "com.shieldsdk.rasp.RaspSignalAnalysis", "debuggerVerdict",
            arrayOf(List::class.java),
        ),
        CriticalMethod(
            "com.shieldsdk.rasp.RaspHookAnalysis", "hookVerdict",
            arrayOf(List::class.java),
        ),
    )

    /**
     * Inspects one method's runtime flags.
     *
     * A `native` flag on a method that is not declared `external` in Kotlin
     * means the runtime is dispatching it somewhere other than its compiled
     * body — the signature of a Java-level hook.
     */
    fun inspectMethod(owner: String, method: String, params: Array<Class<*>>): MethodIntegrity =
        try {
            val declared = Class.forName(owner).getDeclaredMethod(method, *params)
            if (Modifier.isNative(declared.modifiers)) {
                MethodIntegrity.HOOKED
            } else {
                MethodIntegrity.INTACT
            }
        } catch (e: ClassNotFoundException) {
            MethodIntegrity.UNAVAILABLE
        } catch (e: NoSuchMethodException) {
            MethodIntegrity.UNAVAILABLE
        } catch (e: Throwable) {
            // Never let an integrity probe crash the host app. Unknown state is
            // reported as UNAVAILABLE, not as INTACT.
            MethodIntegrity.UNAVAILABLE
        }

    /**
     * Per-method integrity across the critical set, keyed `Class.method`.
     * Exposed for evidence and for the report; the verdict uses
     * [criticalMethodSignals].
     */
    fun criticalMethodIntegrity(): Map<String, MethodIntegrity> =
        criticalMethods.associate { cm ->
            "${cm.owner.substringAfterLast('.')}.${cm.method}" to
                inspectMethod(cm.owner, cm.method, cm.parameterTypes)
        }

    /**
     * Signals from method integrity.
     *
     * `hook_native_method` fires only on a confirmed `HOOKED` result.
     * `UNAVAILABLE` deliberately produces **no signal** — an unresolvable
     * method is an unknown, and turning unknowns into threats would make every
     * obfuscated release build report itself as hooked.
     */
    fun criticalMethodSignals(): List<String> {
        val hits = mutableListOf<String>()
        try {
            if (criticalMethodIntegrity().values.any { it == MethodIntegrity.HOOKED }) {
                hits.add("hook_native_method")
            }
        } catch (e: Throwable) { /* probe must never crash the host */ }
        return hits
    }

    /**
     * Every hooking signal currently firing, as stable ids.
     *
     * Families are independent by construction — see [RaspHookAnalysis].
     */
    fun hookSignals(): List<String> {
        val hits = mutableListOf<String>()

        // 1. A hooking framework's library resident in this process.
        try {
            java.io.File("/proc/self/maps").bufferedReader().use { r ->
                val maps = r.readText()
                if (RaspHookAnalysis.mapsIndicateHookFramework(maps)) {
                    hits.add("hook_framework_lib")
                }
                // 2. Executable code mapped from a writable location.
                if (RaspHookAnalysis.suspiciousExecutableMappings(maps).isNotEmpty()) {
                    hits.add("hook_suspicious_lib_path")
                }
                // 3. Unusual amount of writable+executable memory.
                if (RaspHookAnalysis.countRwxMappings(maps) >
                    RaspHookAnalysis.RWX_MAPPING_THRESHOLD
                ) {
                    hits.add("hook_rwx_mapping")
                }
            }
        } catch (e: Exception) { /* unreadable on some hardened builds */ }

        // 4. The runtime's own view of security-critical methods.
        hits.addAll(criticalMethodSignals())

        return hits
    }

    /** Frameworks actually named in this process's mappings, for evidence. */
    fun detectedFrameworks(): List<String> = try {
        java.io.File("/proc/self/maps").bufferedReader().use {
            RaspHookAnalysis.hookFrameworksIn(it.readText())
        }
    } catch (e: Exception) {
        emptyList()
    }

    /** True when hooking is judged present. See [RaspHookAnalysis.hookVerdict]. */
    fun isHookingDetected(): Boolean = RaspHookAnalysis.hookVerdict(hookSignals())

    /**
     * The structured result the SDK reports upward.
     *
     * Mirrors the `DetectionResult` shape the Dart layer already uses
     * (`detected`/`severity`/`confidence`/`evidence`/`detector_id`/
     * `timestamp`/`platform`) so this detector needs no special case in the
     * telemetry mapper. Evidence carries **signal ids and framework names
     * only** — never memory addresses or full mapping lines, which would hand
     * a host app details about the device's layout that it has no need for.
     */
    fun hookDetectionResult(): Map<String, Any> {
        val signals = hookSignals()
        return mapOf(
            "detector_id" to "hook_detection",
            "detected" to RaspHookAnalysis.hookVerdict(signals),
            "severity" to RaspHookAnalysis.severityFor(signals),
            "confidence" to RaspHookAnalysis.confidenceFor(signals),
            "evidence" to signals,
            "frameworks" to detectedFrameworks(),
            "timestamp" to System.currentTimeMillis(),
            "platform" to "android",
            "detector_version" to DETECTOR_VERSION,
        )
    }

    companion object {
        const val DETECTOR_VERSION = "1.0.0"
    }
}
