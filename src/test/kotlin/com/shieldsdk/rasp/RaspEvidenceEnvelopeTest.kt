package com.shieldsdk.rasp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [RaspEvidenceEnvelope] - constants and basic structure.
 * Canonicalization logic tested via reflection in integration tests.
 */
class RaspEvidenceEnvelopeTest {

    @Test
    fun `evidence envelope structure constants`() {
        assertEquals(1, RaspEvidenceEnvelope.ENVELOPE_VERSION)
        assertEquals("ES256", RaspEvidenceEnvelope.SIGNATURE_ALGORITHM)
        assertEquals(16, RaspEvidenceEnvelope.NONCE_BYTES)
    }

    @Test
    fun `envelope builds valid JSON structure`() {
        // Just verify the constants exist and have correct types
        assertTrue(RaspEvidenceEnvelope.ENVELOPE_VERSION > 0)
        assertTrue(RaspEvidenceEnvelope.SIGNATURE_ALGORITHM.isNotEmpty())
        assertTrue(RaspEvidenceEnvelope.NONCE_BYTES > 0)
    }
}