package com.shieldsdk.rasp

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * On the JVM there is no Android build of libraspshield.so: loading must
 * fail quietly so every caller takes its Kotlin fallback. (Loading on a
 * device is in the phone checklist.)
 */
class RaspNativeFallbackTest {
    @Test fun `library unavailable off-device is reported, not thrown`() {
        assertFalse(RaspNative.available)
        assertNotNull(RaspNative.loadError)
    }
}
