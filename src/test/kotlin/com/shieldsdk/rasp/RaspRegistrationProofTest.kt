package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Registration with proof of possession (F-13), the stable device id
 * (F-15) and re-registration of keys registered in an older format.
 *
 * Real: [RaspDeviceRegistrar], [RaspHttpExchange.URL_CONNECTION] and
 * [RaspHttpPost.URL_CONNECTION] over HTTP to [FakeHttpServer], ECDSA P-256
 * signing and verification (a software key standing in for the Keystore
 * key), [RaspDeviceIdentity], [RaspAccountHasher].
 * Doubles: the key source and the registration store.
 */
class RaspRegistrationProofTest {
    private val now = 1_790_000_000_000L
    private val challenge = "Y2hhbGxlbmdlLWZvci10ZXN0cw"

    private class SoftwareKey : RaspRegistrationKeySource {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        override fun deviceKeyId() = RaspEvidenceEnvelope.deviceKeyId(pair.public.encoded)
        override fun publicKeyBase64() = Base64.getEncoder().encodeToString(pair.public.encoded)
        override fun attestationChainBase64() = listOf("LEAF", "ROOT")
        override fun signDer(payload: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(payload); sign() }
    }

    private class VersionedStore : RaspRegistrationStore {
        var keyId: String? = null
        var version = 0
        override fun registeredKeyId() = keyId
        override fun setRegisteredKeyId(keyId: String?): Boolean { this.keyId = keyId; return true }
        override fun registrationVersion() = version
        override fun setRegistrationVersion(version: Int): Boolean { this.version = version; return true }
    }

    private fun server(challengeStatus: Int, registerStatus: Int = 201) = FakeHttpServer(
        bodyFor = { if (it.path == "/v1/devices/challenge") """{"challenge":"$challenge","expiresInSeconds":300}""" else "{}" },
        respond = { if (it.path == "/v1/devices/challenge") challengeStatus else registerStatus },
    )

    private fun registrar(key: SoftwareKey, store: VersionedStore, deviceId: String? = "d".repeat(64)) = RaspDeviceRegistrar(
        key, store, appId = "com.example.bank", sdkVersion = "test", clock = { now },
        deviceId = { deviceId }, exchange = RaspHttpExchange.URL_CONNECTION,
    )

    private fun credential(server: FakeHttpServer) = RaspEventCredential("org", "app", "api-key-1", "secret-1", "${server.baseUrl}/v1/events")

    @Test fun `registration signs the backend's challenge with the device key and sends the device id`() {
        server(challengeStatus = 200).use { s ->
            val key = SoftwareKey()
            val store = VersionedStore()
            assertEquals(RaspDeviceRegistrar.Result.REGISTERED, registrar(key, store).ensureRegistered(credential(s)))
            assertEquals(listOf("/v1/devices/challenge", "/v1/devices/register"), s.requests.map { it.path })

            val ask = s.requests[0]
            assertEquals("api-key-1", ask.headers["x-api-key"])
            assertEquals(RaspHmacSigner.sign("secret-1", now.toString(), ask.body.toByteArray()), ask.headers["x-signature"])

            val body = RaspJson.parse(s.requests[1].body) as Map<*, *>
            assertEquals(challenge, body["challenge"])
            assertEquals("d".repeat(64), body["deviceId"])
            val signature = Base64.getDecoder().decode(body["challengeSignature"] as String)
            val verified = Signature.getInstance("SHA256withECDSA").run {
                initVerify(key.pair.public)
                update(RaspDeviceRegistrar.possessionMessage(challenge, key.deviceKeyId()))
                verify(signature)
            }
            assertTrue("signature over rasp-register-v1:<challenge>:<keyId>", verified)
            assertEquals(RaspDeviceRegistrar.REGISTRATION_VERSION, store.version)
        }
    }

    @Test fun `an older backend without the challenge endpoint gets a registration without proof`() {
        server(challengeStatus = 404).use { s ->
            assertEquals(RaspDeviceRegistrar.Result.REGISTERED, registrar(SoftwareKey(), VersionedStore()).ensureRegistered(credential(s)))
            val body = RaspJson.parse(s.requests.last().body) as Map<*, *>
            assertFalse(body.containsKey("challenge"))
            assertFalse(body.containsKey("challengeSignature"))
        }
    }

    @Test fun `challenge unavailable (5xx) - retry later, no registration sent`() {
        server(challengeStatus = 503).use { s ->
            val store = VersionedStore()
            assertEquals(RaspDeviceRegistrar.Result.RETRY_LATER, registrar(SoftwareKey(), store).ensureRegistered(credential(s)))
            assertEquals(listOf("/v1/devices/challenge"), s.requests.map { it.path })
            assertNull(store.keyId)
        }
    }

    @Test fun `a key registered in the old format registers once more, then not again`() {
        server(challengeStatus = 200).use { s ->
            val key = SoftwareKey()
            val store = VersionedStore().apply { keyId = key.deviceKeyId(); version = 0 }
            val r = registrar(key, store)
            assertEquals(RaspDeviceRegistrar.Result.REGISTERED, r.ensureRegistered(credential(s)))
            assertEquals(2, s.requests.size)
            assertEquals(RaspDeviceRegistrar.Result.REGISTERED, r.ensureRegistered(credential(s)))
            assertEquals("no further request", 2, s.requests.size)
        }
    }

    @Test fun `no device id - the field is left out`() {
        server(challengeStatus = 404).use { s ->
            registrar(SoftwareKey(), VersionedStore(), deviceId = null).ensureRegistered(credential(s))
            assertFalse((RaspJson.parse(s.requests.last().body) as Map<*, *>).containsKey("deviceId"))
        }
    }

    // ── RaspDeviceIdentity ───────────────────────────────────────────────

    @Test fun `device id - HMAC with the app salt, SHA-256 without, never the raw ANDROID_ID`() {
        val salt = "ab".repeat(32)
        val salted = RaspDeviceIdentity.deviceId("1A2B3C4D5E6F7788", "com.example.bank", salt)!!
        assertEquals(RaspAccountHasher.hash(salt, "android_id:1a2b3c4d5e6f7788"), salted)
        assertTrue(salted.matches(Regex("[0-9a-f]{64}")))
        assertEquals("case of ANDROID_ID does not matter", salted, RaspDeviceIdentity.deviceId("1a2b3c4d5e6f7788", "x", salt))
        assertNotEquals("another app's salt gives another id", salted, RaspDeviceIdentity.deviceId("1a2b3c4d5e6f7788", "com.example.bank", "cd".repeat(32)))

        val unsalted = RaspDeviceIdentity.deviceId("1a2b3c4d5e6f7788", "com.example.bank", null)!!
        val expected = java.security.MessageDigest.getInstance("SHA-256")
            .digest("rasp-device-id-v1:com.example.bank:1a2b3c4d5e6f7788".toByteArray()).joinToString("") { "%02x".format(it) }
        assertEquals(expected, unsalted)
        assertFalse(unsalted.contains("1a2b3c4d5e6f7788"))
    }

    @Test fun `device id - missing, blank or the known broken ANDROID_ID gives none`() {
        assertNull(RaspDeviceIdentity.deviceId(null, "p", null))
        assertNull(RaspDeviceIdentity.deviceId("  ", "p", null))
        assertNull(RaspDeviceIdentity.deviceId("9774d56d682e549c", "p", null))
    }

    // ── F-16 / F-03 ──────────────────────────────────────────────────────

    @Test fun `shared location on detector results is rounded to 3 decimals`() {
        val result = withSharedLocation(
            RaspCheckResult.secure("vpn"),
            RaspLocationSnapshot(latitude = 21.1458291, longitude = 79.0881546, accuracyMeters = 12.0, capturedAtMillis = now, shareWithBackend = true),
        )
        val evidence = result.evidence.associate { it.key to it.value }
        assertEquals(21.146, evidence["latitude"])
        assertEquals(79.088, evidence["longitude"])
    }

    @Test fun `signed envelopes are the default`() {
        assertTrue(RaspLeanConfig().useEvidenceEnvelope)
    }
}
