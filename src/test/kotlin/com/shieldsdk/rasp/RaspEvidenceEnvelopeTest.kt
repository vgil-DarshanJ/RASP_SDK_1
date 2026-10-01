package com.shieldsdk.rasp

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for [RaspEvidenceEnvelope] - envelope structure, constants.
 *
 * ## Test component usage:
 * - Tests REAL RaspEvidenceEnvelope constants
 * - No external mocking frameworks used
 */
class RaspEvidenceEnvelopeTest {

    @Test
    fun `evidence envelope structure constants`() {
        assertEquals(1, RaspEvidenceEnvelope.ENVELOPE_VERSION)
        assertEquals("ES256", RaspEvidenceEnvelope.SIGNATURE_ALGORITHM)
        assertEquals(16, RaspEvidenceEnvelope.NONCE_BYTES)
    }

    @Test
    fun `signature algorithm is ES256`() {
        assertEquals("ES256", RaspEvidenceEnvelope.SIGNATURE_ALGORITHM)
    }

    @Test
    fun `envelope version is 1`() {
        assertEquals(1, RaspEvidenceEnvelope.ENVELOPE_VERSION)
    }

    @Test
    fun `nonce bytes is 16`() {
        assertEquals(16, RaspEvidenceEnvelope.NONCE_BYTES)
    }
}