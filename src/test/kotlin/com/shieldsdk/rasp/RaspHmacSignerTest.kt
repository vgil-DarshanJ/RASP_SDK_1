package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Local JVM unit tests — `javax.crypto` (unlike `org.json`) is a real,
 * fully-functional JVM implementation in the unit test environment, not
 * an Android-framework stub, so this class is directly and fully
 * testable here.
 */
class RaspHmacSignerTest {

    @Test
    fun sign_isDeterministic_forIdenticalInputs() {
        val body = "test-body".toByteArray()
        val a = RaspHmacSigner.sign("secret", "1234567890", body)
        val b = RaspHmacSigner.sign("secret", "1234567890", body)
        assertEquals(a, b)
    }

    @Test
    fun sign_producesLowercaseHex_ofExpectedLength() {
        val signature = RaspHmacSigner.sign("secret", "1234567890", "body".toByteArray())
        // SHA-256 digest = 32 bytes = 64 hex chars.
        assertEquals(64, signature.length)
        assertEquals(signature, signature.lowercase())
        assertEquals(true, signature.all { it in "0123456789abcdef" })
    }

    @Test
    fun sign_differsWhenBodyDiffers() {
        val a = RaspHmacSigner.sign("secret", "1234567890", "body-a".toByteArray())
        val b = RaspHmacSigner.sign("secret", "1234567890", "body-b".toByteArray())
        assertNotEquals(a, b)
    }

    @Test
    fun sign_differsWhenTimestampDiffers() {
        val body = "same-body".toByteArray()
        val a = RaspHmacSigner.sign("secret", "1000", body)
        val b = RaspHmacSigner.sign("secret", "2000", body)
        assertNotEquals(a, b)
    }

    @Test
    fun sign_differsWhenSecretDiffers() {
        val body = "same-body".toByteArray()
        val a = RaspHmacSigner.sign("secret-one", "1234567890", body)
        val b = RaspHmacSigner.sign("secret-two", "1234567890", body)
        assertNotEquals(
            "a different secret must never produce the same signature — this is " +
                "the entire point of moving off api_key-only authentication",
            a, b,
        )
    }

    @Test
    fun sign_matchesIndependentlyComputedVector_crossCheckedAgainstTheBackend() {
        // This exact value was computed independently via Node — the
        // backend's own runtime — as:
        //   crypto.createHmac('sha256', 'secret').update('1000.hello').digest('hex')
        // A match here proves this Kotlin implementation's signing-string
        // format ("<timestamp>." + body) and digest encoding are
        // byte-for-byte interoperable with what
        // FROUNTEND_BACKEND_RASPOWN/BE/src/crypto/hmac.ts will
        // independently recompute for the same inputs — not just
        // internally self-consistent.
        val signature = RaspHmacSigner.sign("secret", "1000", "hello".toByteArray())
        assertEquals(
            "68b4e0f3cbf572d8f2a61a0a26389c0880345705e6cbca10add63a2651feefb0",
            signature,
        )
    }
}
