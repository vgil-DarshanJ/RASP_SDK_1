package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase 5 privacy/screen facade + RaspScreenGuard
 *
 * `RaspScreenGuard` needs a live `Activity`, which a plain instrumentation
 * test (no `ActivityScenario`) does not have — its Activity-attach paths
 * (FLAG_SECURE apply, touch tracking, ScreenCaptureCallback registration)
 * are exercised by the *Flutter* app's own equivalent lifecycle instead
 * (`RaspShieldPlugin`, unchanged by this port) and by manual on-device
 * verification per `docs/LEAN_SECURITY_INTEGRATION_GUIDE.md`'s checklist.
 * What IS tested here without an Activity: that every no-Activity code
 * path degrades honestly (`null`, not a crash, not a false "active"), and
 * every Context-only detector in [RaspShieldCore].
 */
@RunWith(AndroidJUnit4::class)
class RaspShieldCorePhase5InstrumentedTest {

    private lateinit var context: android.content.Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
    }

    @Test
    fun overlay_completesWithoutThrowing_withNoScreenGuardSupplied() {
        val result = RaspShieldCore.checkOverlayBlocking(context)
        assertEquals("overlay", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun overlay_touchObscuredEvidence_isFalseWhenNoScreenGuardSupplied() {
        // No RaspScreenGuard means the touch signal was never observed —
        // must report as not-detected/inconclusive, never fabricated as
        // a positive "obscured" finding.
        val result = RaspShieldCore.checkOverlayBlocking(context)
        val touchEvidence = result.evidence.firstOrNull { it.key == "overlay_touch_obscured" }
        assertEquals(false, touchEvidence?.value)
    }

    @Test
    fun accessibility_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkAccessibilityBlocking(context)
        assertEquals("accessibility", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun externalDisplay_completesWithoutThrowing_andReturnsAValidResult() {
        val result = RaspShieldCore.checkExternalDisplayBlocking(context)
        assertEquals("external_display", result.detectorId)
        assertNotNull(result.status)
    }

    @Test
    fun externalDisplay_carriesCountEvidence_whenConclusive() {
        val result = RaspShieldCore.checkExternalDisplayBlocking(context)
        if (result.status.isConclusive) {
            assertTrue(result.evidence.any { it.key == "external_display_count" })
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // RaspScreenGuard — no-Activity degradation paths
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun screenGuard_isNeverAttached_returnsNullState_neverThrows() {
        val guard = RaspScreenGuard()
        assertNull(
            "a never-attached guard must report screenshot-protection state as null, not false",
            guard.isScreenshotProtectionActive(),
        )
        assertNull(
            "a never-attached guard must report touch-obscured state as null (never observed)",
            guard.currentTouchObscuredState(),
        )
    }

    @Test
    fun screenGuard_detach_isIdempotent_whenNeverAttached() {
        val guard = RaspScreenGuard()
        guard.detach() // must not throw
        guard.detach() // safe to call twice
    }

    @Test
    fun screenGuard_drainScreenshotEventEvidence_reportsZero_whenNeverAttached() {
        val guard = RaspScreenGuard()
        val evidence = guard.drainScreenshotEventEvidence()
        assertEquals(0, evidence.count)
        assertEquals(false, evidence.detected)
    }

    @Test
    fun screenGuard_capabilities_reflectRealSdkLevel() {
        val guard = RaspScreenGuard()
        val caps = guard.screenCaptureCapabilities()
        assertTrue("FLAG_SECURE is supported on every API level this SDK targets",
            caps.screenshotPreventionSupported)
        assertEquals(
            android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
            caps.screenshotDetectionSupported,
        )
        // No Android API level supports this — see the class doc.
        assertEquals(false, caps.screenRecordingDetectionSupported)
        assertEquals(false, caps.screenShareDetectionSupported)
    }

    // ══════════════════════════════════════════════════════════════════
    // Batch
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun scanPrivacyScreenBlocking_returnsAllThreeContextOnlyDetectors() {
        val results = RaspShieldCore.scanPrivacyScreenBlocking(context)
        assertEquals(3, results.size)
        assertEquals(
            setOf("overlay", "accessibility", "external_display"),
            results.map { it.detectorId }.toSet(),
        )
    }
}
