package com.shieldsdk.rasp

import com.google.android.play.core.integrity.model.IntegrityErrorCode
import com.google.android.play.core.integrity.testIntegrityServiceException
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * # UNIT TESTS — Play Integrity error-code mapping
 *
 * Executes the real production [mapIntegrityErrorCode] function on the JVM —
 * pure logic, no Context, no Android runtime, no native device I/O. Confirms
 * every documented [IntegrityErrorCode] value maps to its own explicit,
 * stable string (never silently swallowed into one generic bucket), and that
 * a non-`IntegrityServiceException` failure still resolves to a named
 * fallback rather than throwing.
 *
 * See docs/PLAY_INTEGRITY_NATIVE_AUDIT.md and
 * `RaspPlayIntegrityBridge.mapIntegrityErrorCode`'s doc comment.
 */
class RaspPlayIntegrityErrorMappingTest {

    @Test
    fun `every documented error code maps to its own explicit string`() {
        val cases = mapOf(
            IntegrityErrorCode.API_NOT_AVAILABLE to "API_NOT_AVAILABLE",
            IntegrityErrorCode.PLAY_STORE_NOT_FOUND to "PLAY_STORE_NOT_FOUND",
            IntegrityErrorCode.NETWORK_ERROR to "NETWORK_ERROR",
            IntegrityErrorCode.PLAY_STORE_ACCOUNT_NOT_FOUND to "PLAY_STORE_ACCOUNT_NOT_FOUND",
            IntegrityErrorCode.APP_NOT_INSTALLED to "APP_NOT_INSTALLED",
            IntegrityErrorCode.PLAY_SERVICES_NOT_FOUND to "PLAY_SERVICES_NOT_FOUND",
            IntegrityErrorCode.APP_UID_MISMATCH to "APP_UID_MISMATCH",
            IntegrityErrorCode.TOO_MANY_REQUESTS to "TOO_MANY_REQUESTS",
            IntegrityErrorCode.CANNOT_BIND_TO_SERVICE to "CANNOT_BIND_TO_SERVICE",
            IntegrityErrorCode.NONCE_TOO_SHORT to "NONCE_TOO_SHORT",
            IntegrityErrorCode.NONCE_TOO_LONG to "NONCE_TOO_LONG",
            IntegrityErrorCode.GOOGLE_SERVER_UNAVAILABLE to "GOOGLE_SERVER_UNAVAILABLE",
            IntegrityErrorCode.NONCE_IS_NOT_BASE64 to "NONCE_IS_NOT_BASE64",
            IntegrityErrorCode.INTERNAL_ERROR to "INTERNAL_ERROR",
            IntegrityErrorCode.PLAY_STORE_VERSION_OUTDATED to "PLAY_STORE_VERSION_OUTDATED",
            IntegrityErrorCode.PLAY_SERVICES_VERSION_OUTDATED to "PLAY_SERVICES_VERSION_OUTDATED",
            IntegrityErrorCode.CLOUD_PROJECT_NUMBER_IS_INVALID to "CLOUD_PROJECT_NUMBER_IS_INVALID",
            IntegrityErrorCode.CLIENT_TRANSIENT_ERROR to "CLIENT_TRANSIENT_ERROR",
        )

        for ((code, expected) in cases) {
            val mapped = mapIntegrityErrorCode(testIntegrityServiceException(code))
            assertEquals("errorCode=$code", expected, mapped)
        }
    }

    @Test
    fun `an unrecognized IntegrityServiceException code falls back to the generic bucket`() {
        // -999 is not a documented IntegrityErrorCode value — models a future
        // code this mapping has not been updated for yet.
        val mapped = mapIntegrityErrorCode(testIntegrityServiceException(-999))
        assertEquals("INTEGRITY_UNKNOWN_ERROR", mapped)
    }

    @Test
    fun `a non-IntegrityServiceException failure never throws and still resolves`() {
        val mapped = mapIntegrityErrorCode(RuntimeException("boom"))
        assertEquals("INTEGRITY_UNKNOWN_ERROR", mapped)
    }
}
