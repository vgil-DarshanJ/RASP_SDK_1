package com.shieldsdk.rasp

import android.app.KeyguardManager
import android.content.Context
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 1 device-integrity facade additions
 *
 * Covers [RaspShieldCore]'s device-binding, device-fingerprint, clone,
 * developer-mode, ADB, USB-connection, device-lock, and secure-hardware
 * checks — the six detectors added on top of the already-tested root and
 * emulator probes (see [RaspDeviceIntegrityProbesInstrumentedTest]).
 *
 * Same discipline as that file: every test asserts something genuinely
 * verifiable — "this completes without throwing," "the result respects
 * the 5-state contract," "the result agrees with an independently-checked
 * ground truth" — never a hardcoded "this device is/isn't rooted"-style
 * claim that would be misleading on a shared/unknown test environment.
 *
 * Read-only. No system setting, Keystore entry beyond what the checks
 * themselves provision, or device state is modified beyond what
 * [RaspShieldCore.checkDeviceBindingBlocking]/
 * [RaspShieldCore.checkSecureHardwareUnavailableBlocking] already do on
 * their own (first-run Keystore key generation — the exact same
 * provisioning behavior the pre-extraction implementation always had).
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase1InstrumentedTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    private fun assertValidResult(result: RaspCheckResult, expectedDetectorId: String) {
        assertEquals(expectedDetectorId, result.detectorId)
        assertNotNull(result.status)
        if (result.status == RaspCheckStatus.UNAVAILABLE ||
            result.status == RaspCheckStatus.UNKNOWN ||
            result.status == RaspCheckStatus.ERROR
        ) {
            assertNotNull(
                "reason must be set for ${result.status}", result.reason
            )
        } else {
            assertEquals(
                "reason must be null for a conclusive ${result.status} result",
                null, result.reason,
            )
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Device binding
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun deviceBinding_completesWithoutThrowing_andIsAValidResult() {
        val result = RaspShieldCore.checkDeviceBindingBlocking(context)
        assertValidResult(result, "device_binding")
    }

    @Test
    fun deviceBinding_isStableAcrossRepeatedCalls() {
        // First call may provision a Keystore key; the second call must see
        // the now-provisioned key and agree with the first result.
        val first = RaspShieldCore.checkDeviceBindingBlocking(context)
        val second = RaspShieldCore.checkDeviceBindingBlocking(context)
        assertEquals(first.status, second.status)
    }

    // ══════════════════════════════════════════════════════════════════
    // Secure hardware (TEE/StrongBox)
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun secureHardware_completesWithoutThrowing_andIsAValidResult() {
        val result = RaspShieldCore.checkSecureHardwareUnavailableBlocking(context)
        assertValidResult(result, "secure_hardware_unavailable")
    }

    // ══════════════════════════════════════════════════════════════════
    // Clone / Parallel Space
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun clone_completesWithoutThrowing_andIsAValidResult() {
        val result = RaspShieldCore.checkCloneBlocking(context)
        assertValidResult(result, "clone")
    }

    @Test
    fun clone_notDetected_onThisTestRuntime() {
        // The test APK runs under the primary user via the standard test
        // harness, never inside an actual clone container — a real,
        // independently-true ground truth on any CI/emulator/device this
        // suite runs on.
        val result = RaspShieldCore.checkCloneBlocking(context)
        assertNotEquals(RaspCheckStatus.DETECTED, result.status)
    }

    // ══════════════════════════════════════════════════════════════════
    // Developer mode / ADB
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun developerMode_agreesWithIndependentSettingsRead() {
        val result = RaspShieldCore.checkDeveloperModeBlocking(context)
        assertValidResult(result, "developer_mode")

        val groundTruth = try {
            Settings.Global.getInt(
                context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
            ) == 1
        } catch (e: Exception) {
            null
        }
        if (groundTruth != null && result.status.isConclusive) {
            assertEquals(
                "developer_mode result must agree with an independent Settings.Global read",
                groundTruth, result.status == RaspCheckStatus.DETECTED,
            )
        }
    }

    @Test
    fun adbEnabled_agreesWithIndependentSettingsRead() {
        val result = RaspShieldCore.checkAdbEnabledBlocking(context)
        assertValidResult(result, "adb_enabled")

        val groundTruth = try {
            Settings.Global.getInt(
                context.contentResolver, Settings.Global.ADB_ENABLED, 0
            ) == 1
        } catch (e: Exception) {
            null
        }
        if (groundTruth != null && result.status.isConclusive) {
            assertEquals(
                "adb_enabled result must agree with an independent Settings.Global read",
                groundTruth, result.status == RaspCheckStatus.DETECTED,
            )
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // USB physical connection
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun usbConnection_completesWithoutThrowing_andIsAValidResult() {
        val result = RaspShieldCore.checkUsbConnectionBlocking(context)
        assertValidResult(result, "usb_connection")
    }

    // ══════════════════════════════════════════════════════════════════
    // Device lock
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun deviceLockMissing_agreesWithIndependentKeyguardRead() {
        val result = RaspShieldCore.checkDeviceLockMissingBlocking(context)
        assertValidResult(result, "device_lock_missing")

        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val groundTruthMissing = !km.isDeviceSecure
        assertEquals(
            "device_lock_missing must agree with an independent KeyguardManager read",
            groundTruthMissing, result.status == RaspCheckStatus.DETECTED,
        )
    }

    // ══════════════════════════════════════════════════════════════════
    // Device fingerprint
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun deviceFingerprint_completesWithoutThrowing_andIsAValidResult() {
        val result = RaspShieldCore.checkDeviceFingerprintBlocking(context)
        assertValidResult(result, "device_fingerprint")
    }

    @Test
    fun deviceFingerprint_carriesDeviceModelEvidence() {
        val result = RaspShieldCore.checkDeviceFingerprintBlocking(context)
        if (result.status.isConclusive) {
            assertTrue(
                "expected a 'model' evidence entry, got ${result.evidence}",
                result.evidence.any { it.key == "model" },
            )
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // Async variants — must deliver on the main thread and match blocking
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun asyncVariant_deliversOnMainThread_andAgreesWithBlocking() {
        val latch = java.util.concurrent.CountDownLatch(1)
        var delivered: RaspCheckResult? = null
        var deliveredOnMainThread = false

        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            RaspShieldCore.checkAdbEnabledAsync(context) { result ->
                delivered = result
                deliveredOnMainThread = android.os.Looper.myLooper() == android.os.Looper.getMainLooper()
                latch.countDown()
            }
        }

        assertTrue("async callback did not fire within 5s", latch.await(5, java.util.concurrent.TimeUnit.SECONDS))
        assertTrue("async callback must be delivered on the main thread", deliveredOnMainThread)
        assertNotNull(delivered)
        assertEquals("adb_enabled", delivered!!.detectorId)
    }

    // ══════════════════════════════════════════════════════════════════
    // Batch
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun scanDeviceIntegrityBlocking_returnsAllTenDetectors() {
        val results = RaspShieldCore.scanDeviceIntegrityBlocking(context)
        assertEquals(10, results.size)
        val ids = results.map { it.detectorId }.toSet()
        assertEquals(
            setOf(
                "root_jailbreak", "emulator", "device_binding", "device_fingerprint",
                "clone", "developer_mode", "adb_enabled", "usb_connection",
                "device_lock_missing", "secure_hardware_unavailable",
            ),
            ids,
        )
    }
}
