package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Evidence envelope: signing, tamper detection, counter, nonce, canonical form.
 *
 * Real components: [RaspEvidenceEnvelope], [RaspCanonicalJson], [RaspBase64],
 * and JCA ECDSA P-256 / SHA256withECDSA — the same algorithm and DER signature
 * format Android Keystore produces.
 *
 * Test doubles: [SoftwareSigner] (a JCA software key instead of the Android
 * Keystore key, which does not exist on the JVM) and [MemoryCounter] (instead
 * of the EncryptedSharedPreferences counter). [RaspDeviceKey] and
 * `RaspEncryptedCounterStore` themselves are not exercised here.
 */
class RaspEvidenceEnvelopeTest {

    private class SoftwareSigner(val keyPair: KeyPair = newKeyPair()) : RaspEnvelopeSigner {
        var failNext = false
        override fun publicKeySpki(): ByteArray = keyPair.public.encoded
        override fun signDer(payload: ByteArray): ByteArray? {
            if (failNext) { failNext = false; return null }
            return Signature.getInstance("SHA256withECDSA").run {
                initSign(keyPair.private); update(payload); sign()
            }
        }
    }

    private class MemoryCounter(start: Long = 0) : RaspEnvelopeCounterStore {
        val value = AtomicLong(start)
        var persistFails = false
        override fun next(): Long? = if (persistFails) null else value.incrementAndGet()
    }

    private companion object {
        fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1")); generateKeyPair()
        }

        /** Plain JCA verification over the canonical text of every field except `signature`. */
        fun rawVerify(fields: Map<String, Any?>, key: PublicKey): Boolean = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(RaspCanonicalJson.encode(fields - "signature").toByteArray(Charsets.UTF_8))
                verify(java.util.Base64.getDecoder().decode(fields["signature"] as String))
            }
        } catch (e: Exception) {
            false
        }
    }

    private val results = listOf(
        RaspCheckResult(
            "root_jailbreak", RaspCheckStatus.DETECTED,
            listOf(RaspEvidence("signal", "su_binary", "hard"), RaspEvidence("path", "/system/xbin/su")),
            observedAtMillis = 1_700_000_000_000,
        ),
        RaspCheckResult(
            "mitm", RaspCheckStatus.UNKNOWN,
            reason = "pin probe not attempted", observedAtMillis = 1_700_000_000_001,
        ),
    )

    private fun builder(
        signer: RaspEnvelopeSigner = SoftwareSigner(),
        counter: RaspEnvelopeCounterStore = MemoryCounter(),
    ) = RaspEvidenceEnvelope(signer, counter, appId = "com.example.bank", sdkVersion = "test")

    // ── Sign / verify ────────────────────────────────────────────────────

    @Test
    fun `sign then verify with the public key`() {
        val signer = SoftwareSigner()
        val fields = builder(signer).buildFields(results)!!

        assertTrue(RaspEvidenceEnvelope.verify(fields, signer.publicKeySpki()))
        assertTrue("independent JCA check", rawVerify(fields, signer.keyPair.public))
        // The algorithm label is inside the signed bytes.
        assertTrue(String(RaspEvidenceEnvelope.signingInput(fields)).contains("\"signatureAlgorithm\":\"ES256\""))
        assertFalse(String(RaspEvidenceEnvelope.signingInput(fields)).contains("\"signature\":"))
    }

    @Test
    fun `verification fails with another device's public key`() {
        val fields = builder().buildFields(results)!!
        assertFalse(RaspEvidenceEnvelope.verify(fields, newKeyPair().public.encoded))
    }

    @Test
    fun `changing any field fails verification`() {
        val signer = SoftwareSigner()
        val fields = builder(signer).buildFields(results)!!
        val spki = signer.publicKeySpki()
        val signedKeys = fields.keys - "signature"
        assertEquals(
            setOf(
                "envelopeVersion", "eventId", "eventTimeMillis", "monotonicCounter", "nonce", "sdkVersion",
                "appId", "deviceKeyId", "detectorResults", "signatureAlgorithm",
            ),
            signedKeys,
        )

        for (key in signedKeys) {
            val tampered = fields.toMutableMap().apply { put(key, mutate(get(key))) }
            assertFalse("changing '$key' must fail verify()", RaspEvidenceEnvelope.verify(tampered, spki))
            assertFalse("changing '$key' must fail the raw signature check", rawVerify(tampered, signer.keyPair.public))
        }
        for (key in signedKeys) {
            assertFalse("removing '$key' must fail", RaspEvidenceEnvelope.verify(fields - key, spki))
        }
        assertFalse("adding a field must fail", RaspEvidenceEnvelope.verify(fields + ("extra" to 1), spki))
    }

    @Test
    fun `flipping a nested detection to SECURE fails verification`() {
        val signer = SoftwareSigner()
        val fields = builder(signer).buildFields(results)!!

        @Suppress("UNCHECKED_CAST")
        val detectors = fields["detectorResults"] as List<Map<String, Any?>>
        val flipped = listOf(detectors[0] + ("status" to "SECURE")) + detectors.drop(1)
        assertFalse(RaspEvidenceEnvelope.verify(fields + ("detectorResults" to flipped), signer.publicKeySpki()))

        @Suppress("UNCHECKED_CAST")
        val evidence = detectors[0]["evidence"] as List<Map<String, Any?>>
        val newEvidence = listOf(evidence[0] + ("value" to "none")) + evidence.drop(1)
        val editedDetector = detectors[0] + ("evidence" to newEvidence)
        val edited = listOf(editedDetector) + detectors.drop(1)
        assertFalse(RaspEvidenceEnvelope.verify(fields + ("detectorResults" to edited), signer.publicKeySpki()))
    }

    @Test
    fun `a modified signature fails verification`() {
        val signer = SoftwareSigner()
        val fields = builder(signer).buildFields(results)!!
        val sig = java.util.Base64.getDecoder().decode(fields["signature"] as String)
        sig[sig.size - 1] = (sig[sig.size - 1].toInt() xor 1).toByte()
        val tampered = fields + ("signature" to java.util.Base64.getEncoder().encodeToString(sig))
        assertFalse(RaspEvidenceEnvelope.verify(tampered, signer.publicKeySpki()))
    }

    private fun mutate(v: Any?): Any? = when (v) {
        is String -> v + "x"
        is Int -> v + 1
        is Long -> v + 1
        is List<*> -> v.dropLast(1)
        else -> "changed"
    }

    // ── Counter ──────────────────────────────────────────────────────────

    @Test
    fun `counter strictly increases`() {
        val counter = MemoryCounter()
        val b = builder(counter = counter)
        val counters = (1..200).map { b.buildFields(results)!!["monotonicCounter"] as Long }
        assertTrue(counters.zipWithNext().all { (a, c) -> c > a })

        // A new builder on the same store (a process restart) continues above.
        val afterRestart = builder(counter = counter).buildFields(results)!!["monotonicCounter"] as Long
        assertTrue(afterRestart > counters.last())
    }

    @Test
    fun `counter is unique and per-thread increasing under concurrency`() {
        val b = builder()
        val pool = Executors.newFixedThreadPool(8)
        val futures = (1..8).map {
            pool.submit(Callable { (1..50).map { b.buildFields(results)!!["monotonicCounter"] as Long } })
        }
        val perThread = futures.map { it.get(60, TimeUnit.SECONDS) } // rethrows any failure
        pool.shutdown()
        perThread.forEach { mine -> assertTrue(mine.zipWithNext().all { (a, c) -> c > a }) }
        val all = perThread.flatten()
        assertEquals(400, all.size)
        assertEquals(400, all.toSet().size)
    }

    @Test
    fun `a failed signature consumes its counter value and is never reused`() {
        val signer = SoftwareSigner()
        val counter = MemoryCounter()
        val b = builder(signer, counter)
        val first = b.buildFields(results)!!["monotonicCounter"] as Long
        signer.failNext = true
        assertNull(b.buildFields(results))
        val third = b.buildFields(results)!!["monotonicCounter"] as Long
        assertEquals(first + 2, third)
    }

    @Test
    fun `no envelope when the counter cannot be persisted`() {
        val counter = MemoryCounter().apply { persistFails = true }
        assertNull(builder(counter = counter).buildFields(results))
    }

    @Test
    fun `no envelope without a device key`() {
        val noKey = object : RaspEnvelopeSigner {
            override fun publicKeySpki(): ByteArray? = null
            override fun signDer(payload: ByteArray): ByteArray? = null
        }
        assertNull(builder(signer = noKey).build(results))
    }

    // ── Nonce / ids ──────────────────────────────────────────────────────

    @Test
    fun `two envelopes never share a nonce`() {
        val b1 = builder()
        val b2 = builder()
        val nonces = (1..3000).map { b1.buildFields(results)!!["nonce"] as String } +
            (1..3000).map { b2.buildFields(results)!!["nonce"] as String }
        assertEquals(nonces.size, nonces.toSet().size)
        assertTrue(nonces.all { it.matches(Regex("[0-9a-f]{32}")) })
    }

    @Test
    fun `event ids are distinct UUIDs`() {
        val b = builder()
        val ids = (1..500).map { b.buildFields(results)!!["eventId"] as String }
        assertEquals(ids.size, ids.toSet().size)
        ids.forEach { java.util.UUID.fromString(it) }
    }

    @Test
    fun `deviceKeyId is Base64 of SHA-256 of the SPKI`() {
        val signer = SoftwareSigner()
        val fields = builder(signer).buildFields(results)!!
        val expected = java.util.Base64.getEncoder()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(signer.publicKeySpki()))
        assertEquals(expected, fields["deviceKeyId"])
    }

    // ── Wire format ──────────────────────────────────────────────────────

    @Test
    fun `body is the canonical JSON of the fields`() {
        val signer = SoftwareSigner()
        val b = builder(signer)
        val body = b.build(results)!!
        assertTrue(body.startsWith("{\"appId\":\"com.example.bank\",\"detectorResults\":["))
        assertFalse("org.json-style \\/ escaping must not appear", body.contains("\\/"))
        assertTrue(body.contains("\"value\":\"/system/xbin/su\""))
    }

    /**
     * Expected string produced by Node 24 running the backend's own
     * `canonicalizeValue` (copied from BE/src/crypto/ecdsa.ts) on the same
     * value after a JSON.parse round-trip.
     */
    @Test
    fun `canonical JSON matches the backend's JSON stringify of sorted keys`() {
        val value = linkedMapOf<String, Any?>(
            "b" to "slash/and\"quote\\back",
            "a" to listOf(1, -2, 9007199254740991L, 1.5, 0.000001, 1e21, 1e-7, 123456789.125, -0.0, 100L, 0.1),
            "10" to "ten", "2" to "two",
            "ctl" to "\u0001\n\t\u001f\b\u000C\r",
            "uni" to "\u00e9\u20ac\ud83d\ude00", "lone" to "\ud800x",
            "Z" to true, "n" to null,
            "nested" to linkedMapOf("y" to 1, "x" to listOf(mapOf("k" to "v"))),
        )
        val expected = "{\"2\":\"two\",\"10\":\"ten\",\"Z\":true,\"a\":[1,-2,9007199254740991,1.5,0.000001,1e+21,1e-7,123456789.125,0,100,0.1],\"b\":\"slash/and\\\"quote\\\\back\",\"ctl\":\"\\u0001\\n\\t\\u001f\\b\\f\\r\",\"lone\":\"\\ud800x\",\"n\":null,\"nested\":{\"x\":[{\"k\":\"v\"}],\"y\":1},\"uni\":\"\u00e9\u20ac\ud83d\ude00\"}"
        assertEquals(expected, RaspCanonicalJson.encode(value))
    }

    @Test
    fun `integers beyond JavaScript's safe range are written as strings`() {
        assertEquals("[9007199254740991,\"9007199254740992\",\"-9223372036854775808\"]",
            RaspCanonicalJson.encode(listOf(9007199254740991L, 9007199254740992L, Long.MIN_VALUE)))
        assertEquals("[null,null]", RaspCanonicalJson.encode(listOf(Double.NaN, Double.POSITIVE_INFINITY)))
    }

    @Test
    fun `Base64 matches java util Base64 and round-trips`() {
        val random = java.util.Random(42)
        for (len in 0..64) {
            val bytes = ByteArray(len).also { random.nextBytes(it) }
            val encoded = RaspBase64.encode(bytes)
            assertEquals(java.util.Base64.getEncoder().encodeToString(bytes), encoded)
            assertTrue(bytes.contentEquals(RaspBase64.decode(encoded)))
        }
        assertNull(RaspBase64.decode("not base64!"))
    }

    @Test
    fun `constants`() {
        assertEquals(1, RaspEvidenceEnvelope.ENVELOPE_VERSION)
        assertEquals("ES256", RaspEvidenceEnvelope.SIGNATURE_ALGORITHM)
        assertEquals(16, RaspEvidenceEnvelope.NONCE_BYTES)
    }

    /**
     * Writes a signed envelope, its public key, and a tampered copy to
     * `build/envelope-interop/fixture.json`, so the backend's verifier can be
     * run on Kotlin output (see the Task 1 report). Asserts only that the
     * fixture was written.
     */
    @Test
    fun `writes a cross-language interop fixture`() {
        val signer = SoftwareSigner()
        val fields = builder(signer).buildFields(results)!!
        @Suppress("UNCHECKED_CAST")
        val detectors = fields["detectorResults"] as List<Map<String, Any?>>
        val tampered = fields + ("detectorResults" to (listOf(detectors[0] + ("status" to "SECURE")) + detectors.drop(1)))
        val fixture = RaspCanonicalJson.encode(
            mapOf(
                "publicKeySpkiBase64" to RaspBase64.encode(signer.publicKeySpki()),
                "body" to RaspCanonicalJson.encode(fields),
                "tamperedBody" to RaspCanonicalJson.encode(tampered),
            ),
        )
        val out = File("build/envelope-interop/fixture.json")
        out.parentFile.mkdirs()
        out.writeText(fixture)
        assertNotNull(out.readText())
    }

    // ── Device info ──────────────────────────────────────────────────────

    @Test
    fun `device info is signed and tampering with it fails verification`() {
        val signer = SoftwareSigner()
        val device = RaspEvidenceEnvelope.deviceInfo("OnePlus", "CPH2581", "15", "1.0.0")
        val fields = RaspEvidenceEnvelope(signer, MemoryCounter(), "com.example.bank", "test", device = device)
            .buildFields(results)!!

        assertEquals(
            mapOf("manufacturer" to "OnePlus", "model" to "CPH2581", "osPlatform" to "android", "osVersion" to "15", "appVersion" to "1.0.0"),
            fields["device"],
        )
        val spki = signer.publicKeySpki()
        assertTrue(RaspEvidenceEnvelope.verify(fields, spki))
        assertTrue(rawVerify(fields, signer.keyPair.public))
        assertFalse("changed model", RaspEvidenceEnvelope.verify(fields + ("device" to device + ("model" to "Pixel 9")), spki))
        assertFalse("removed device", RaspEvidenceEnvelope.verify(fields - "device", spki))
    }

    @Test
    fun `device info leaves out blank values and caps length, and is absent when not given`() {
        val info = RaspEvidenceEnvelope.deviceInfo(" Samsung ", "", "14", null)
        assertEquals(mapOf("manufacturer" to "Samsung", "osPlatform" to "android", "osVersion" to "14"), info)
        assertEquals(100, RaspEvidenceEnvelope.deviceInfo("x".repeat(300), null, null, null)["manufacturer"]!!.length)
        assertFalse(builder().buildFields(results)!!.containsKey("device"))
    }
}
