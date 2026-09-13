package com.google.android.play.core.integrity

/**
 * Test-only factory for [IntegrityServiceException].
 *
 * Its real constructor is package-private inside the Play Integrity client
 * library (`IntegrityServiceException(int, Throwable)`), so this proxy —
 * placed in the same package on the test classpath — is how
 * `RaspPlayIntegrityErrorMappingTest` constructs fixtures for
 * `mapIntegrityErrorCode` without reflection. Test-only: nothing in
 * `src/main` references this.
 */
fun testIntegrityServiceException(errorCode: Int): IntegrityServiceException =
    IntegrityServiceException(errorCode, null)
