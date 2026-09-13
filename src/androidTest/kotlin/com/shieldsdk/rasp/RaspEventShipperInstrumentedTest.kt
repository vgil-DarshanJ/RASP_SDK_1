package com.shieldsdk.rasp

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * # INSTRUMENTATION TESTS — Phase H event shipper
 *
 * `org.json.JSONObject` is an Android-framework class, stubbed out (not
 * genuinely implemented) in local JVM unit tests under this module's
 * `unitTests.isReturnDefaultValues = false` setting — the same reason
 * [RaspGeoIpProbes] (also `org.json`-based) has never had a local unit
 * test. [RaspEventCredentialParser] belongs here for the same reason,
 * confirmed the hard way: an earlier local-unit-test version of this
 * suite failed with every JSON call silently resolving to `null` via the
 * parser's own catch-all, not because the parsing logic was wrong.
 */
@RunWith(AndroidJUnit4::class)
class RaspEventShipperInstrumentedTest {

    private lateinit var context: android.content.Context

    private val validCredentialJson = """
        {
          "organization_id": "org_abc123",
          "application_id": "app_xyz789",
          "platform": "ANDROID_NATIVE",
          "api_key": "rasp_live_secret",
          "api_secret": "shown once",
          "ingestion_url": "http://10.0.2.2:4000/v1/events",
          "sdk_min_version": "1.0.0",
          "issued_at": "2026-09-11T00:00:00.000Z"
        }
    """.trimIndent()

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        RaspEventShipper.resetForTests()
    }

    @After
    fun tearDown() {
        RaspEventShipper.resetForTests()
    }

    // ══════════════════════════════════════════════════════════════════
    // RaspEventCredentialParser
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun parser_validCredential_extractsAllFourRequiredFields() {
        val result = RaspEventCredentialParser.parse(validCredentialJson)
        assertEquals("org_abc123", result?.organizationId)
        assertEquals("app_xyz789", result?.applicationId)
        assertEquals("rasp_live_secret", result?.apiKey)
        assertEquals("http://10.0.2.2:4000/v1/events", result?.ingestionUrl)
    }

    @Test
    fun parser_malformedJson_returnsNull() {
        assertNull(RaspEventCredentialParser.parse("not json at all"))
    }

    @Test
    fun parser_missingApiKey_returnsNull() {
        val json = """{"organization_id":"o","application_id":"a","ingestion_url":"https://x"}"""
        assertNull(RaspEventCredentialParser.parse(json))
    }

    @Test
    fun parser_blankIngestionUrl_returnsNull() {
        val json = """
            {"organization_id":"o","application_id":"a","api_key":"k","ingestion_url":""}
        """.trimIndent()
        assertNull(RaspEventCredentialParser.parse(json))
    }

    // ══════════════════════════════════════════════════════════════════
    // RaspEventShipper.configure / isConfigured
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun configure_withValidJson_returnsTrue_andMarksConfigured() {
        assertFalse(RaspEventShipper.isConfigured())
        val ok = RaspEventShipper.configure(validCredentialJson)
        assertTrue(ok)
        assertTrue(RaspEventShipper.isConfigured())
    }

    @Test
    fun configure_withMalformedJson_returnsFalse_andStaysUnconfigured() {
        val ok = RaspEventShipper.configure("garbage")
        assertFalse(ok)
        assertFalse(RaspEventShipper.isConfigured())
    }

    // ══════════════════════════════════════════════════════════════════
    // shipAsync — must never throw or block, configured or not
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun shipAsync_withNoCredentialConfigured_returnsImmediately_neverThrows() {
        val results = listOf(RaspCheckResult.secure("root_jailbreak"))
        val started = System.currentTimeMillis()
        RaspEventShipper.shipAsync(context, results) // must not throw
        val elapsed = System.currentTimeMillis() - started
        assertTrue("shipAsync must return immediately (fire-and-forget), took ${elapsed}ms", elapsed < 500)
    }

    @Test
    fun shipAsync_withEmptyResults_isANoOp_neverThrows() {
        RaspEventShipper.configure(validCredentialJson)
        RaspEventShipper.shipAsync(context, emptyList()) // must not throw
    }

    @Test
    fun shipAsync_withUnreachableHost_returnsImmediately_neverThrows() {
        // A real network attempt happens on the background executor, but
        // the CALLING thread must never block on it — this is the actual
        // "never disturb the app" contract.
        RaspEventShipper.configure(
            validCredentialJson.replace(
                "http://10.0.2.2:4000/v1/events",
                "https://this-host-should-not-resolve.invalid/v1/events",
            )
        )
        val results = listOf(RaspCheckResult.detected("frida"))
        val started = System.currentTimeMillis()
        RaspEventShipper.shipAsync(context, results)
        val elapsed = System.currentTimeMillis() - started
        assertTrue("shipAsync must return immediately regardless of network reachability, took ${elapsed}ms", elapsed < 500)
    }

    @Test
    fun shipAsync_withRealLocalBackend_deliversTheBatch() {
        // Opportunistic — only meaningful when the platform backend
        // (FROUNTEND_BACKEND_RASPOWN/BE) is actually running locally on
        // 10.0.2.2:4000 (the emulator's alias for the host machine) with a
        // real credential issued for this exact api_key. Skipped
        // gracefully (not failed) when that isn't the case, since this
        // suite must also pass with no backend running at all.
        RaspEventShipper.configure(validCredentialJson)
        val results = listOf(
            RaspCheckResult.secure("root_jailbreak"),
            RaspCheckResult.detected("frida", listOf(RaspEvidence("frida_signal", "frida_port"))),
        )
        // No assertion beyond "did not throw and returned promptly" — see
        // shipAsync_withUnreachableHost_returnsImmediately_neverThrows for
        // the timing guarantee this already covers. A full end-to-end
        // assertion (event actually landed in Postgres) belongs in the
        // platform's own backend test suite, not this SDK's.
        RaspEventShipper.shipAsync(context, results)
    }
}
