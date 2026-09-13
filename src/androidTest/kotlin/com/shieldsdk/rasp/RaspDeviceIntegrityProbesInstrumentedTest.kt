package com.shieldsdk.rasp

import android.os.Build
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
 * # INSTRUMENTATION TESTS — real root/emulator device I/O
 *
 * Calls [RaspDeviceIntegrityProbes] — the production implementation — with a
 * real `Context`. The filesystem probes hit the real filesystem, `getprop`
 * really execs, package lookups go through the real `PackageManager`, and the
 * mount table is this process's real `/proc/self/mounts`.
 *
 * ## Runs on TWO validated environments — an emulator AND real hardware
 *
 * Originally written against only the AVD `rasp_verify` (Android 14 / API 34,
 * userdebug / dev-keys) — a developer image whose root-ish characteristics
 * (`test-keys`, `ro.debuggable=1`, writable system) are properties of *that
 * image*, not of a rooted retail handset. Physical-device validation on a
 * genuine retail Nokia 8.1 (Android 11 / API 30, `user`/`release-keys`) — see
 * `docs/PHYSICAL_ANDROID_SECURITY_VALIDATION.md` — confirmed two of this
 * file's original assumptions were **emulator-specific, not universal**:
 *
 * - `ro.debuggable`/`ro.secure` are unreadable from an app sandbox on API 34
 *   (SELinux-hardened), but **remain readable on API 30** — a real,
 *   physical-device-confirmed platform difference, not a probe defect. See
 *   [isPropertyAccessKnownHardened].
 * - `build_type_non_retail` fires on a `userdebug` image but correctly does
 *   **not** fire on a genuine `user` (retail) build — `Build.TYPE` is the
 *   independent, non-circular ground truth for which case applies.
 *
 * Both are now asserted conditionally rather than hardcoded to the one
 * environment this suite originally ran on — see each test's comment.
 *
 * These tests still deliberately do **not** assert that root detection
 * reports "clean" or "rooted" — either assertion would be misleading on a
 * shared/unknown-provenance test environment. They assert what is genuinely
 * verifiable:
 *
 * 1. every probe completes without throwing on a real Android runtime;
 * 2. the evidence sources are actually reachable (filesystem, getprop,
 *    PackageManager, `/proc/self/mounts`, sensors, telephony);
 * 3. emitted signal ids stay within the documented contract;
 * 4. verdicts agree with the signals the probe itself reported;
 * 5. a genuine virtual device is correctly *identified* as one, and a
 *    genuine physical device is not, without any hardcoded reference to one
 *    specific AVD or handset.
 *
 * Physical rooted-device validation remains **PENDING** — this suite's
 * physical run was against a stock, non-rooted retail device only; see
 * `docs/PHYSICAL_ANDROID_SECURITY_VALIDATION.md`.
 *
 * ## Safety
 *
 * Read-only. No system partition, bootloader, kernel, other app, or device
 * security setting is modified, and nothing is installed. The emulator is not
 * pushed into a compromised state to manufacture a PASS.
 */
@RunWith(AndroidJUnit4::class)
class RaspDeviceIntegrityProbesInstrumentedTest {

    private lateinit var probes: RaspDeviceIntegrityProbes

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        probes = RaspDeviceIntegrityProbes(context)
    }

    // ══════════════════════════════════════════════════════════════════════
    // I/O REACHABILITY — the evidence sources must work on a real runtime
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun procSelfMounts_isReadable_onThisRuntime() {
        // If this becomes unreadable under a future SELinux policy, the
        // mount_namespace signal silently stops firing forever. The probe
        // swallows that exception by design, so only a direct read catches it.
        val mounts = java.io.File("/proc/self/mounts")
        assertTrue("/proc/self/mounts must exist", mounts.exists())
        val text = mounts.readText()
        assertTrue("/proc/self/mounts must be non-empty", text.isNotEmpty())
        assertTrue("a real mount table should mention /data", text.contains("/data"))
    }

    private fun getprop(key: String): String {
        val p = Runtime.getRuntime().exec(arrayOf("getprop", key))
        val v = p.inputStream.bufferedReader().use { it.readText() }.trim()
        p.waitFor()
        return v
    }

    @Test
    fun getprop_isExecutable_onThisRuntime() {
        // The exec mechanism itself works from the app sandbox: a
        // non-privileged property comes back normally. This matters because it
        // means the empty reads below are a *permission* result, not a broken
        // readProp() implementation.
        val sdk = getprop("ro.build.version.sdk")
        assertEquals("exec must succeed", 0,
            Runtime.getRuntime().exec(arrayOf("getprop", "ro.build.version.sdk"))
                .also { it.waitFor() }.exitValue())
        assertTrue("ro.build.version.sdk should be numeric, got '$sdk'",
            sdk.toIntOrNull() != null)
    }

    /**
     * `true` on the API level where physical *and* emulator evidence agrees
     * `ro.debuggable`/`ro.secure` are SELinux-hardened unreadable from an app
     * sandbox. Independent of, and not derived from, any RASP probe under
     * test — this reads only the public `Build.VERSION.SDK_INT` framework
     * constant, so gating on it cannot be circular with the thing being
     * tested.
     *
     * The boundary is exactly API 34: confirmed hardened (empty read) on the
     * `rasp_verify` AVD (Android 14 / API 34) and confirmed **not** hardened
     * (real value read) on a physical Nokia 8.1 (Android 11 / API 30) — see
     * `docs/PHYSICAL_ANDROID_SECURITY_VALIDATION.md`. No data point exists yet
     * for API 31-33; this boundary will need revisiting if one is tested and
     * disagrees.
     */
    private fun isPropertyAccessKnownHardened(): Boolean = Build.VERSION.SDK_INT >= 34

    /**
     * Documents a **real weakness found by this test suite**, not a bug in the
     * test — and, per physical-device validation, an **API-level-dependent**
     * one, not a universal platform property.
     *
     * `readProp()` works — but the two *security-relevant* properties it reads
     * come back **empty** from inside the app sandbox on API 34, with exit code
     * 0 and no exception. `android.os.SystemProperties.get()` returns `""` for
     * the same keys. Meanwhile `adb shell getprop ro.debuggable` on that same
     * emulator returns `1`.
     *
     * The consequence, on API 34, is that the `ro_debuggable` and `ro_insecure`
     * root signals **cannot fire from an app process**, on any device, rooted
     * or not, at that API level. They are structurally blind rather than
     * merely quiet there.
     *
     * **Physical-device validation (Nokia 8.1, Android 11 / API 30) found the
     * opposite on that platform**: both properties are readable from the app
     * sandbox, returning their real values (`ro.debuggable` = `0` on this
     * genuine retail build). The two signals are live, not blind, on API 30 —
     * this was previously undocumented and could only be discovered by
     * testing a second, different API level on real hardware, which an
     * emulator-only test environment cannot provide.
     *
     * This test pins the observed behaviour **per API level**, so if a
     * platform change ever moves the hardening boundary, whichever branch
     * disagrees fails loudly and tells us which signal's liveness changed —
     * rather than the SDK silently carrying a wrong assumption either way.
     *
     * See `docs/PHYSICAL_ANDROID_SECURITY_VALIDATION.md` and
     * `docs/ANDROID_DEVICE_SECURITY_VALIDATION.md` § Security weaknesses.
     */
    @Test
    fun documented_securityPropsAreUnreadableFromTheAppSandbox() {
        if (isPropertyAccessKnownHardened()) {
            assertEquals(
                "ro.debuggable is expected to be unreadable from an app on API 34; " +
                    "a value here means the platform changed and ro_debuggable is viable again",
                "", getprop("ro.debuggable"),
            )
            assertEquals(
                "ro.secure is expected to be unreadable from an app on API 34; " +
                    "a value here means the platform changed and ro_insecure is viable again",
                "", getprop("ro.secure"),
            )
        } else {
            // Below the confirmed hardening boundary: both properties are
            // readable and must return the real, numeric flag value (not an
            // exception, not a placeholder) — proven on physical API 30
            // hardware, not assumed.
            val debuggable = getprop("ro.debuggable")
            val secure = getprop("ro.secure")
            assertTrue(
                "ro.debuggable should read a real 0/1 value below API 34, got '$debuggable'",
                debuggable == "0" || debuggable == "1",
            )
            assertTrue(
                "ro.secure should read a real 0/1 value below API 34, got '$secure'",
                secure == "0" || secure == "1",
            )
        }
    }

    @Test
    fun buildTags_areReadable_andAreTheViableAlternative() {
        // Build.TAGS is a framework field rather than a getprop read, so it
        // stays readable where ro.* does not. It is the surviving evidence
        // source for "is this a non-retail image", which is what makes the
        // test_keys signal the load-bearing one of that group.
        assertNotNull("Build.TAGS must be readable", android.os.Build.TAGS)
        assertTrue("Build.TAGS should be non-blank",
            android.os.Build.TAGS.isNotBlank())
    }

    /**
     * Documents a second **real limitation found by this suite**.
     *
     * `/system/xbin` and `/system/bin` are not listable from the app sandbox,
     * so `File.exists()` on a path inside them is unreliable: `adb shell`
     * (uid 2000) sees `/system/xbin/su` while the app process reads it as
     * absent. Direct existence checks still work for world-readable files
     * (`/system/bin/sh`), which is why the `su_binary` signal is weakened
     * rather than entirely dead.
     *
     * Pinned so a platform change that restores visibility is noticed.
     */
    @Test
    fun documented_systemBinariesAreNotListableFromTheAppSandbox() {
        assertTrue(
            "/system/xbin unexpectedly listable — su path coverage may have improved",
            !java.io.File("/system/xbin").canRead(),
        )
        // A world-readable file inside an unlistable directory is still
        // resolvable by exact path, which is what keeps su_binary partly alive.
        assertTrue(
            "direct-path existence should still work for world-readable binaries",
            java.io.File("/system/bin/sh").exists(),
        )
    }

    @Test
    fun packageManager_isQueryable_onThisRuntime() {
        // Android 11+ package-visibility rules can make lookups fail. Querying
        // our own package proves the mechanism works at all.
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        assertNotNull(info)
    }

    @Test
    fun buildProfile_isPopulated_onThisRuntime() {
        val profile = probes.buildProfile()
        assertTrue("Build.FINGERPRINT should be readable",
            profile.fingerprint.isNotBlank())
        assertTrue("Build.HARDWARE should be readable", profile.hardware.isNotBlank())
    }

    // ══════════════════════════════════════════════════════════════════════
    // ROOT — real probe, real I/O
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun rootSignals_completeWithoutThrowing() {
        // A probe must never crash the host app, whatever the filesystem or
        // /proc looks like.
        assertNotNull(probes.rootSignals())
    }

    @Test
    fun rootSignals_returnOnlyKnownSignalIds() {
        // Guards the wire contract: an id the backend does not know is scored
        // as nothing, so a typo would silently lose evidence.
        probes.rootSignals().forEach {
            assertTrue("unexpected root signal id '$it'",
                RaspRootAnalysis.allSignalIds.contains(it))
        }
    }

    @Test
    fun rootVerdict_isConsistentWithItsOwnSignals() {
        // The verdict must be derivable from the reported evidence, or the SOC
        // console shows evidence that does not justify the analyst's action.
        val signals = probes.rootSignals()
        assertEquals(RaspRootAnalysis.isRooted(signals), probes.isDeviceRooted())
    }

    @Test
    fun rootScan_isFastEnoughForTheScanPath() {
        // rootSignals() execs `which su` and `getprop` twice; on the scan path
        // that cost has to stay bounded.
        val started = System.currentTimeMillis()
        probes.rootSignals()
        val elapsed = System.currentTimeMillis() - started
        assertTrue("rootSignals took ${elapsed}ms, expected < 3000ms", elapsed < 3000)
    }

    @Test
    fun repeatedRootScans_areStable() {
        // A detector that flickers on an unchanged device produces SOC noise
        // and erodes trust in real alerts.
        assertEquals(probes.isDeviceRooted(), probes.isDeviceRooted())
        assertEquals(probes.rootSignals().toSet(), probes.rootSignals().toSet())
    }

    // ══════════════════════════════════════════════════════════════════════
    // EMULATOR — real probe, real I/O
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun emulatorSignals_completeWithoutThrowing() {
        assertNotNull(probes.emulatorSignals())
    }

    @Test
    fun emulatorSignals_returnOnlyKnownSignalIds() {
        probes.emulatorSignals().forEach {
            assertTrue("unexpected emulator signal id '$it'",
                RaspEmulatorAnalysis.allSignalIds.contains(it))
        }
    }

    @Test
    fun emulatorVerdict_isConsistentWithItsOwnSignals() {
        val signals = probes.emulatorSignals()
        assertEquals(RaspEmulatorAnalysis.isEmulator(signals), probes.isEmulator())
    }

    /**
     * `true` on a known-virtual-device build, using only standard
     * `android.os.Build` markers a real handset never carries — deliberately
     * **not** derived from [RaspEmulatorAnalysis]/[probes]: gating a test of
     * the emulator detector on the emulator detector's own output would be
     * circular and could not catch the detector being wrong. This mirrors the
     * same independence [isPropertyAccessKnownHardened] keeps for the
     * property-access tests below.
     */
    private fun isKnownVirtualDeviceEnvironment(): Boolean =
        Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.contains("generic") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
            Build.PRODUCT == "google_sdk" ||
            Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu")

    @Test
    fun thisEmulator_isIdentifiedAsAnEmulator() {
        // Physical-device validation (Nokia 8.1, API 30 — see
        // docs/PHYSICAL_ANDROID_SECURITY_VALIDATION.md) found the ORIGINAL,
        // unconditional form of this assertion false on real hardware: zero
        // emulator signals is the CORRECT verdict there, not a failure. This
        // is Phase 5's real-emulator-false-positive check passing, not the
        // detector breaking — gated here so the positive claim still runs,
        // and is still proven, on an actual virtual device.
        if (!isKnownVirtualDeviceEnvironment()) {
            val signals = probes.emulatorSignals()
            assertTrue(
                "a genuine physical device must not be misclassified as an " +
                    "emulator; signals=$signals",
                signals.isEmpty(),
            )
            assertFalse(
                "a genuine physical device must not be classified as an " +
                    "emulator; signals=$signals",
                probes.isEmulator(),
            )
            return
        }
        // The one positive detection claim a virtual-device environment
        // genuinely supports.
        //
        // Deliberately NOT `if (device == "rasp_verify") ...`: the assertion is
        // that the *generic* signal machinery fires on a virtual device, which
        // is what would also happen on Genymotion, Cuttlefish or BlueStacks.
        // A hardcoded AVD check would prove nothing about the detector.
        val signals = probes.emulatorSignals()
        assertTrue(
            "an emulator must produce at least one signal; got $signals",
            signals.isNotEmpty(),
        )
        assertTrue(
            "an emulator must be classified as one; signals=$signals",
            probes.isEmulator(),
        )
    }

    @Test
    fun thisEmulator_firesAtLeastOneHardSignal() {
        // See thisEmulator_isIdentifiedAsAnEmulator: this claim only applies
        // on a genuine virtual device. On physical hardware there should be
        // no signals — hard or soft — at all.
        if (!isKnownVirtualDeviceEnvironment()) {
            val signals = probes.emulatorSignals()
            assertTrue(
                "a genuine physical device must not fire any emulator signal, " +
                    "hard or soft; got $signals",
                signals.isEmpty(),
            )
            return
        }
        // Soft Build fields alone could be spoofed on a real device; a hard
        // signal (emulated SoC, qemu prop, missing sensor, fake carrier) is
        // what makes the verdict trustworthy rather than incidental.
        val signals = probes.emulatorSignals()
        val hard = signals.filter { it in RaspEmulatorAnalysis.hardSignals }
        assertTrue(
            "expected a hard emulator signal, got only $signals",
            hard.isNotEmpty(),
        )
    }

    @Test
    fun emulatorScan_isFastEnoughForTheScanPath() {
        val started = System.currentTimeMillis()
        probes.emulatorSignals()
        val elapsed = System.currentTimeMillis() - started
        assertTrue("emulatorSignals took ${elapsed}ms, expected < 3000ms", elapsed < 3000)
    }

    @Test
    fun repeatedEmulatorScans_areStable() {
        assertEquals(probes.isEmulator(), probes.isEmulator())
        assertEquals(probes.emulatorSignals().toSet(), probes.emulatorSignals().toSet())
    }

    // ══════════════════════════════════════════════════════════════════════
    // REMEDIATION — real I/O for the fixed signals
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun procMounts_isReadable_andCarriesProtectedPartitions() {
        // The replacement for File.canWrite() depends entirely on this being
        // readable from an app process. Verified: 125 lines on API 34.
        val mounts = java.io.File("/proc/mounts").readText()
        assertTrue("/proc/mounts must be readable and non-empty", mounts.isNotEmpty())
        assertTrue("mount table should list /data", mounts.contains("/data"))

        // At least one protected partition must be identifiable, otherwise the
        // system_writable signal has nothing to reason about on this platform.
        val states = probes.protectedPartitionStates()
        val identified = states.filterValues {
            it != RaspRootAnalysis.MountState.NOT_PRESENT &&
                it != RaspRootAnalysis.MountState.UNKNOWN
        }
        assertTrue("no protected partition could be identified: $states",
            identified.isNotEmpty())
    }

    @Test
    fun systemPartition_isMountedReadOnly_onThisRuntime() {
        // On a healthy device the system image is read-only. This is the
        // positive control for the mount-based replacement: if it cannot
        // observe a read-only system partition here, it cannot observe a
        // writable one on a rooted device either.
        val states = probes.protectedPartitionStates()
        val systemState = RaspRootAnalysis.systemMountPoints
            .map { states[it] }
            .firstOrNull { it == RaspRootAnalysis.MountState.READ_ONLY ||
                it == RaspRootAnalysis.MountState.WRITABLE }
        assertEquals(
            "system partition should be read-only on an unmodified device; states=$states",
            RaspRootAnalysis.MountState.READ_ONLY, systemState,
        )
    }

    @Test
    fun systemWritable_doesNotFire_onAnUnmodifiedRuntime() {
        val mounts = java.io.File("/proc/mounts").readText()
        assertFalse(
            "no protected partition should be writable here; writable=" +
                "${RaspRootAnalysis.writableProtectedPartitions(mounts)}",
            RaspRootAnalysis.anyProtectedPartitionWritable(mounts),
        )
    }

    /**
     * Documents the measured platform limitation and pins it — per API level,
     * per physical-device validation. See
     * [documented_securityPropsAreUnreadableFromTheAppSandbox] and
     * [isPropertyAccessKnownHardened] for the full evidence and the confirmed
     * API 34 boundary.
     *
     * `ro.debuggable` and `ro.secure` return `""` to an app on API 34 while
     * `adb shell` reads `1`; the probe reports that explicitly as
     * `NOT_ACCESSIBLE` instead of behaving as though the check ran. On a
     * physical Nokia 8.1 (API 30), both are genuinely `READABLE` — confirmed
     * by real hardware, not assumed.
     *
     * If a platform change ever moves the boundary, whichever branch
     * disagrees fails and tells us which signal's liveness changed.
     */
    @Test
    fun documented_securityPropertiesReportNotAccessible() {
        val access = probes.propertyAccess()
        if (isPropertyAccessKnownHardened()) {
            assertEquals(
                "ro.debuggable is expected to be unreadable from an app on API 34",
                RaspRootAnalysis.PropertyAccess.NOT_ACCESSIBLE, access["ro.debuggable"],
            )
            assertEquals(
                "ro.secure is expected to be unreadable from an app on API 34",
                RaspRootAnalysis.PropertyAccess.NOT_ACCESSIBLE, access["ro.secure"],
            )
        } else {
            assertEquals(
                "ro.debuggable is expected to be readable below API 34 — " +
                    "confirmed on physical API 30 hardware",
                RaspRootAnalysis.PropertyAccess.READABLE, access["ro.debuggable"],
            )
            assertEquals(
                "ro.secure is expected to be readable below API 34 — " +
                    "confirmed on physical API 30 hardware",
                RaspRootAnalysis.PropertyAccess.READABLE, access["ro.secure"],
            )
        }
    }

    @Test
    fun mountTableAccess_isReadableOnThisRuntime() {
        // If this ever reports NOT_ACCESSIBLE, both system_writable and
        // mount_namespace are unverifiable and their "false" means nothing.
        assertEquals(
            "the mount table must be readable for two root signals to function",
            RaspRootAnalysis.MountTableAccess.READABLE, probes.mountTableAccess(),
        )
    }

    @Test
    fun suPathStates_distinguishNotAccessibleFromAbsent() {
        // The measured defect this test originally pinned: /system/xbin is
        // unlistable, so a su binary there reads as absent unless
        // classifyPath() falls back to an exact-path stat. That is still
        // asserted below (NOT_ACCESSIBLE/PRESENT, never a false ABSENT for a
        // path whose parent can't be listed) — but a real rootable AVD
        // (Adversarial Validation milestone: `rasp_api30`, a `google_apis`,
        // non-Play-Store system image) genuinely ships an accessible `su` at
        // this exact path, and `File.exists()` resolves it directly by exact
        // path even though the parent directory is unlistable (see
        // classifyPath()'s own doc comment on this). So PRESENT here is
        // correct, measured evidence that the detector can see a real su
        // binary when one truly exists — not a false positive to suppress.
        // Ground truth is checked independently (bypassing the probe) so
        // this test verifies the probe against reality, on whichever kind of
        // image it happens to run on, rather than hardcoding one outcome.
        val states = probes.suPathStates()
        assertTrue("expected a state for every su path",
            states.size == RaspRootAnalysis.suPaths.size)

        val xbinPath = "/system/xbin/su"
        val xbinExistsInReality = java.io.File(xbinPath).exists()
        val xbin = states[xbinPath]
        if (xbinExistsInReality) {
            assertEquals(
                "a genuinely present su binary must read as PRESENT",
                RaspRootAnalysis.PathState.PRESENT, xbin,
            )
        } else {
            assertEquals(
                "an absent su binary behind an unlistable directory must " +
                    "yield NOT_ACCESSIBLE, never a false ABSENT",
                RaspRootAnalysis.PathState.NOT_ACCESSIBLE, xbin,
            )
        }
        // Every reported PRESENT must correspond to something that genuinely
        // exists — never a false positive fabricated by the probe.
        states.filterValues { it == RaspRootAnalysis.PathState.PRESENT }.keys.forEach { path ->
            assertTrue("probe reported PRESENT for $path but File.exists() disagrees",
                java.io.File(path).exists())
        }
    }

    @Test
    fun postureSignals_areReportedButDoNotAffectTheRootVerdict() {
        // `build_type_non_retail` depends on the OS build, not the emulator —
        // physical-device validation (Nokia 8.1, genuine Build.TYPE="user")
        // found the original unconditional "always userdebug" assumption
        // false on real retail hardware, which correctly does NOT fire this
        // posture signal. Build.TYPE is the independent, non-circular ground
        // truth for which case applies — see docs/PHYSICAL_ANDROID_SECURITY_VALIDATION.md.
        val posture = probes.posturesSignals()
        val nonRetailBuild = Build.TYPE == "userdebug" || Build.TYPE == "eng"
        if (nonRetailBuild) {
            assertTrue("expected build_type_non_retail on a userdebug/eng image " +
                "(Build.TYPE=${Build.TYPE})",
                posture.contains("build_type_non_retail"))
        } else {
            assertFalse("a genuine retail build (Build.TYPE=${Build.TYPE}) must not " +
                "report build_type_non_retail",
                posture.contains("build_type_non_retail"))
        }
        // The APK's own debuggable flag is independent of the OS build type —
        // this test suite always runs a debug-signed test APK (Flutter's
        // `androidTest` variant), on the emulator and on physical hardware
        // alike, so this claim holds in both environments unconditionally.
        assertTrue("expected app_debuggable on a debuggable test APK",
            posture.contains("app_debuggable"))

        posture.forEach {
            assertFalse("posture signal '$it' leaked into the root signal set",
                probes.rootSignals().contains(it))
        }
        // Adversarial Validation milestone — real evidence from a genuinely
        // rootable local test AVD (`rasp_api30`, `google_apis`, not
        // `google_apis_playstore`): this class of image ships an actually
        // accessible `su` binary for `adb root` support, so `su_binary`
        // legitimately and correctly fires as a ROOT signal here — this is
        // the detector working as designed against genuine su presence, not
        // a posture-signal leak (the assertion above already proves posture
        // signals stay out of the root set). The original claim ("a
        // userdebug emulator must not be reported as rooted") was true on
        // the non-rootable images this suite had run against before, but is
        // not a general property of Build.TYPE=userdebug — a real su binary
        // makes a device rooted regardless of build type, which is the
        // security-correct behavior. Ground truth is checked independently
        // so this assertion holds on both kinds of image.
        val suGenuinelyPresent = RaspRootAnalysis.suPaths.any { java.io.File(it).exists() }
        if (suGenuinelyPresent) {
            assertTrue(
                "su is genuinely present on this image but isDeviceRooted() " +
                    "did not report it; root=${probes.rootSignals()} posture=$posture",
                probes.isDeviceRooted(),
            )
        } else {
            assertFalse(
                "a userdebug emulator with no real su binary present must not " +
                    "be reported as rooted; root=${probes.rootSignals()} posture=$posture",
                probes.isDeviceRooted(),
            )
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // EVIDENCE CAPTURE
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Not a pass/fail check — records what this environment actually reported,
     * so the validation report quotes measured output rather than assumptions.
     *
     * Read back with: `adb logcat -d -s RASP-VALIDATION:I`
     */
    @Test
    fun captureDeviceIntegrityEvidenceForReport() {
        val tag = "RASP-VALIDATION"
        val rootSignals = probes.rootSignals()
        val emulatorSignals = probes.emulatorSignals()
        val profile = probes.buildProfile()

        android.util.Log.i(tag, "integrity_build_fingerprint=${profile.fingerprint}")
        android.util.Log.i(tag, "integrity_build_hardware=${profile.hardware}")
        android.util.Log.i(tag, "integrity_build_manufacturer=${profile.manufacturer}")
        android.util.Log.i(tag, "integrity_build_tags=${android.os.Build.TAGS}")
        android.util.Log.i(tag, "root_signals=$rootSignals")
        android.util.Log.i(tag, "root_verdict=${probes.isDeviceRooted()}")
        android.util.Log.i(tag, "posture_signals=${probes.posturesSignals()}")
        android.util.Log.i(tag, "property_access=${probes.propertyAccess()}")
        android.util.Log.i(tag, "partition_states=${probes.protectedPartitionStates()}")
        android.util.Log.i(tag, "su_path_states=" +
            "${probes.suPathStates().values.groupingBy { it }.eachCount()}")
        android.util.Log.i(tag, "emulator_signals=$emulatorSignals")
        android.util.Log.i(tag, "emulator_verdict=${probes.isEmulator()}")
        android.util.Log.i(tag, "emulator_hard_signals=" +
            "${emulatorSignals.filter { it in RaspEmulatorAnalysis.hardSignals }}")

        var started = System.currentTimeMillis()
        probes.rootSignals()
        android.util.Log.i(tag, "root_scan_ms=${System.currentTimeMillis() - started}")

        started = System.currentTimeMillis()
        probes.emulatorSignals()
        android.util.Log.i(tag, "emulator_scan_ms=${System.currentTimeMillis() - started}")

        assertNotNull(rootSignals)
        assertNotNull(emulatorSignals)
    }
}
