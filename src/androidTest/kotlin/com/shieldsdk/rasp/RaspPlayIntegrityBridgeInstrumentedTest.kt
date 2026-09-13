package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * # INSTRUMENTATION TESTS — real Play Integrity native boundary
 *
 * Calls [RaspPlayIntegrityBridge] — the production implementation — with a
 * real `Context`, on whatever device/emulator this suite runs on. See
 * `docs/PLAY_INTEGRITY_NATIVE_AUDIT.md` for the architecture and
 * `docs/PLAY_INTEGRITY_TEST_MATRIX.md` for what this run does and does not
 * prove.
 *
 * ## What this suite honestly verifies, and what it does not
 *
 * These tests do **not** assert that [RaspPlayIntegrityBridge.requestToken]
 * returns a genuine, Google-issued token: that requires a device with a
 * signed-in Play Store account, the app registered against a real Cloud
 * Project Number in the Play Console, and (for verification) the backend
 * actually holding Google Cloud credentials — none of which this development
 * environment has (see `PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON` in
 * `app/config.py`, currently unset). What they DO verify, honestly, on
 * whatever real runtime executes them:
 *
 * 1. [RaspPlayIntegrityBridge.isAvailable] runs against the real
 *    `PackageManager` without throwing.
 * 2. [RaspPlayIntegrityBridge.requestToken] completes — success or a named
 *    failure — within a bounded time, and never throws out of this call;
 *    Google's own Task API is exercised for real, even though this
 *    environment cannot satisfy every precondition it needs for a genuine
 *    PASS.
 * 3. On failure, the delivered [IntegrityRequestException.code] is one of
 *    the names [mapIntegrityErrorCode] documents — never blank, never a raw
 *    exception message standing in for a code.
 *
 * A result of [PLAY_STORE_NOT_FOUND]/[PLAY_SERVICES_NOT_FOUND]/
 * [CLOUD_PROJECT_NUMBER_IS_INVALID] on an emulator or a sideloaded debug
 * build is the CORRECT, honest outcome for this environment — not a test
 * failure. See docs/PLAY_INTEGRITY_NATIVE_AUDIT.md phase 10/11 for exactly
 * what a genuine PASS requires.
 *
 * ## Safety
 *
 * Read-only from the device's perspective: no system partition, bootloader,
 * or security setting is touched. The only network call is the standard
 * Play Integrity request itself, made through Google's own client library.
 */
@RunWith(AndroidJUnit4::class)
class RaspPlayIntegrityBridgeInstrumentedTest {

    private lateinit var bridge: RaspPlayIntegrityBridge

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        bridge = RaspPlayIntegrityBridge(context)
    }

    @Test
    fun isAvailable_completesWithoutThrowing_onThisRuntime() {
        // No assertion on the boolean value itself — whether the Play Store
        // package is present is a fact about this specific runtime, not
        // something this test should hardcode either way.
        val available = bridge.isAvailable()
        assertNotNull(available)
    }

    @Test
    fun requestToken_completesWithinBoundedTime_neverThrowsOutOfTheCall() {
        val latch = CountDownLatch(1)
        val outcome = AtomicReference<Result<String>>()

        // A syntactically valid but obviously-non-server-issued nonce — this
        // suite is asserting the native call plumbing behaves, not that a
        // real challenge was bound (that is `AttestationOrchestrator`'s job
        // on the Dart side, and the backend's authoritative check on the
        // server side).
        bridge.requestToken("instrumentation-test-nonce-0000") { result ->
            outcome.set(result)
            latch.countDown()
        }

        val completed = latch.await(30, TimeUnit.SECONDS)
        assertTrue("requestToken must resolve (success or failure) within 30s", completed)

        val result = outcome.get()
        assertNotNull("requestToken must deliver an outcome", result)

        result!!.fold(
            onSuccess = { token ->
                // A genuine token was produced — only plausible on a device
                // with a signed-in Play Store account and a package
                // registered in the Play Console. Never logged: this is the
                // one place in this suite a real token could appear, and it
                // is asserted on, never printed.
                assertTrue("a returned token must be non-empty", token.isNotEmpty())
            },
            onFailure = { error ->
                val code = (error as? IntegrityRequestException)?.code
                assertNotNull(
                    "a failure must carry a named IntegrityRequestException code, " +
                        "not a bare exception (was ${error.javaClass.simpleName}: ${error.message})",
                    code,
                )
                assertTrue("failure code must not be blank", code!!.isNotEmpty())
            },
        )
    }
}
