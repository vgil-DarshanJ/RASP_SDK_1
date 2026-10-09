package com.shieldsdk.rasp

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * Keeping the malware reputation list current from the backend (3a), and the
 * empty-list verdict.
 *
 * Real: RaspReputationListUpdater (version and signature rules, storage in a
 * temporary folder, URL), RaspMalwareReputationProbes.loadList/evaluate,
 * Ed25519 signatures made with the JDK.
 * Double: the HTTP GET (`fetch`).
 * Not exercised: RaspEventCredentialParser (org.json is Android-only; phone
 * test plan) and the session wiring.
 */
class RaspReputationListUpdaterTest {
    private val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val publicKey = RaspBase64.encode(keys.public.encoded)
    private lateinit var dir: File
    private val requests = mutableListOf<Pair<String, Map<String, String>>>()
    private val original = RaspReputationListUpdater.fetch
    private val credential = RaspEventCredential("org", "app", "api-key-1", "secret", "https://api.bank.test/v1/events")

    private fun signed(version: Int, vararg packages: String, key: java.security.PrivateKey = keys.private): String {
        val entries = packages.joinToString(",") { """{"package":"$it","category":"banking_trojan","severity":"critical"}""" }
        val payload = """{"version":$version,"entries":[$entries]}"""
        val sig = Signature.getInstance("Ed25519").run { initSign(key); update(payload.toByteArray()); sign() }
        return RaspCanonicalJson.encode(mapOf("payload" to payload, "signature" to RaspBase64.encode(sig)))
    }

    private fun serve(status: Int, body: String?) {
        RaspReputationListUpdater.fetch = { url, headers ->
            requests += url to headers
            RaspHttpResponse(status, body)
        }
    }

    private fun versionOf(list: String?) =
        (RaspMalwareReputationProbes.loadList(list, publicKey) as? RaspMalwareReputationProbes.Load.Ok)?.list?.version

    @Before fun setUp() {
        dir = Files.createTempDirectory("rasp-reputation").toFile()
        RaspReputationListUpdater.resetForTests()
    }

    @After fun tearDown() {
        RaspReputationListUpdater.fetch = original
        RaspReputationListUpdater.resetForTests()
        dir.deleteRecursively()
    }

    @Test fun `a newer signed list from the backend is stored and used instead of the bundled one`() {
        serve(200, signed(5, "com.bad.trojan"))
        assertTrue(RaspReputationListUpdater.refreshNow(dir, credential, publicKey, bundled = signed(2, "com.old.entry")))
        assertEquals("https://api.bank.test/v1/reputation/list", requests.single().first)
        assertEquals("api-key-1", requests.single().second["X-Api-Key"])
        assertEquals(5L, versionOf(RaspReputationListUpdater.listFor(dir, signed(2, "com.old.entry"), publicKey)))
        RaspReputationListUpdater.resetForTests()
        assertEquals("kept across restarts", 5L, versionOf(RaspReputationListUpdater.listFor(dir, null, publicKey)))
    }

    @Test fun `an older version, a wrong signature or a failed request changes nothing`() {
        serve(200, signed(5, "com.bad.trojan"))
        RaspReputationListUpdater.refreshNow(dir, credential, publicKey, null)
        for ((status, body) in listOf(
            200 to signed(4, "com.rollback"),
            200 to signed(9, "com.forged", key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().private),
            200 to "not json",
            503 to null,
            -1 to null,
        )) {
            serve(status, body)
            assertFalse("$status $body", RaspReputationListUpdater.refreshNow(dir, credential, publicKey, null))
            assertEquals(5L, versionOf(RaspReputationListUpdater.listFor(dir, null, publicKey)))
        }
    }

    @Test fun `a bundled list newer than the downloaded one wins`() {
        serve(200, signed(3, "com.a"))
        RaspReputationListUpdater.refreshNow(dir, credential, publicKey, null)
        assertEquals(8L, versionOf(RaspReputationListUpdater.listFor(dir, signed(8, "com.b"), publicKey)))
    }

    @Test fun `without a key or a credential nothing is fetched`() {
        serve(200, signed(5, "com.bad.trojan"))
        RaspReputationListUpdater.refreshIfDue(dir, null, publicKey, null)
        RaspReputationListUpdater.refreshIfDue(dir, credential, null, null)
        Thread.sleep(100)
        assertTrue(requests.isEmpty())
        assertNull(RaspReputationListUpdater.listFor(dir, null, publicKey))
    }

    @Test fun `an empty verified list cannot decide - UNKNOWN, never SECURE`() {
        val r = RaspMalwareReputationProbes.evaluate(
            RaspMalwareReputationProbes.Observation(RaspMalwareReputationProbes.loadList(signed(1), publicKey), emptyList(), "all"),
        )
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("Reputation list is empty", r.reason)
    }
}
