package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * Task 3c detectors — device_state_attestation, malware_reputation — plus
 * their building blocks (DER/attestation parser, Ed25519 verifier, JSON parser).
 *
 * Real: RaspDeviceStateAttestationProbes.observeChain/evaluate on X.509
 * certificates made by `tools/make-attestation-fixture.js` (openssl, real
 * attestation OID and KeyDescription structure); RaspEd25519 against the
 * RFC 8032 vectors and the JDK's Ed25519; RaspMalwareReputationProbes.loadList
 * on a list signed by `tools/sign-reputation-list.js` (Node) and lists signed
 * here with the JDK; RaspJson.
 * Not exercised (need a device): reading the real Keystore attestation chain
 * and the PackageManager lookups in `observe`.
 */
class RaspTask3cDetectorsTest {

    private fun resource(name: String): Map<*, *> =
        RaspJson.parse(javaClass.classLoader!!.getResourceAsStream(name)!!.readBytes().toString(Charsets.UTF_8)) as Map<*, *>

    private val certs = resource("attestation-fixtures.json")
    private val oct2026 = RaspDeviceStateAttestationProbes.epochDay(2026, 10, 1)

    private fun attest(fixture: String?, maxAge: Int? = null) =
        RaspDeviceStateAttestationProbes.evaluate(
            RaspDeviceStateAttestationProbes.observeChain(fixture?.let { listOf(certs[it] as String) }),
            maxAge, oct2026,
        )

    private fun signals(r: RaspCheckResult, key: String) = r.evidence.filter { it.key == key }.map { it.value }

    // ── device_state_attestation ─────────────────────────────────────────

    @Test fun `attestation detected for unlocked bootloader and unverified boot`() {
        val r = attest("unlockedUnverifiedTee")
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("bootloader_unlocked", "verified_boot_unverified"), signals(r, "attestation_signal"))
        assertEquals("2026-08", r.evidence.first { it.key == "os_patch_level" }.value)
        assertEquals("2026-08-05", r.evidence.first { it.key == "vendor_patch_level" }.value)
        assertEquals(1, r.evidence.first { it.key == "attestation_security_level" }.value)
    }

    @Test fun `attestation clean for a locked, verified device`() {
        val r = attest("lockedVerifiedStrongBox")
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals("verified", r.evidence.first { it.key == "verified_boot_state" }.value)
        assertEquals(2, r.evidence.first { it.key == "attestation_security_level" }.value)
    }

    @Test fun `attestation patch age is evidence, and a detection only when the limit is configured`() {
        val r = attest("lockedVerifiedStrongBox", maxAge = 90)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("patch_too_old"), signals(r, "attestation_signal"))
        assertEquals(oct2026 - RaspDeviceStateAttestationProbes.epochDay(2024, 1, 1),
            r.evidence.first { it.key == "patch_age_days" }.value)
        assertEquals(RaspCheckStatus.SECURE, attest("lockedVerifiedStrongBox", maxAge = 2000).status)
    }

    @Test fun `attestation cannot decide for software-level or unparseable attestation`() {
        assertEquals(RaspCheckStatus.UNKNOWN, attest("softwareLevel").status)
        val garbage = RaspDeviceStateAttestationProbes.evaluate(
            RaspDeviceStateAttestationProbes.observeChain(listOf("bm90IGEgY2VydA==")), null, oct2026,
        )
        assertEquals(RaspCheckStatus.UNKNOWN, garbage.status)
    }

    @Test fun `attestation unavailable without a chain`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE, attest(null).status)
    }

    @Test fun `DER parser rejects truncated and trailing input`() {
        assertTrue(runCatching { RaspDer.parse(byteArrayOf(0x30, 0x05, 0x02)) }.isFailure)
        assertTrue(runCatching { RaspDer.parse(byteArrayOf(0x02, 0x01, 0x05, 0x00)) }.isFailure)
        assertEquals(5, RaspDer.parse(byteArrayOf(0x02, 0x01, 0x05)).integer().toInt())
        // High tag number [704]: BF 85 40
        val tagged = RaspDer.parse(byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40, 0x03, 0x02, 0x01, 0x07))
        assertEquals(2, tagged.tagClass)
        assertEquals(704, tagged.tagNumber)
        assertEquals(7, tagged.children().single().integer().toInt())
    }

    @Test fun `patch dates and epoch days`() {
        assertEquals(0L, RaspDeviceStateAttestationProbes.epochDay(1970, 1, 1))
        assertEquals(20727L, RaspDeviceStateAttestationProbes.epochDay(2026, 10, 1)) // Node Date.UTC
        assertEquals(19723L, RaspDeviceStateAttestationProbes.epochDay(2024, 1, 1))
        assertEquals(11016L, RaspDeviceStateAttestationProbes.epochDay(2000, 2, 29))
        assertEquals("2026-08", RaspDeviceStateAttestationProbes.patchDate(202608).toString())
        assertEquals("2026-08-05", RaspDeviceStateAttestationProbes.patchDate(20260805).toString())
        assertNull(RaspDeviceStateAttestationProbes.patchDate(202613))
        assertNull(RaspDeviceStateAttestationProbes.patchDate(0))
    }

    // ── Ed25519 ──────────────────────────────────────────────────────────

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test fun `Ed25519 accepts the RFC 8032 test vectors and rejects altered ones`() {
        val vectors = listOf(
            Triple("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
            Triple("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            Triple("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        )
        for ((pk, msg, sig) in vectors) {
            assertTrue(pk.take(8), RaspEd25519.verify(hex(pk), hex(msg), hex(sig)))
            assertFalse(RaspEd25519.verify(hex(pk), hex(msg) + byteArrayOf(1), hex(sig)))
            val badSig = hex(sig).also { it[10] = (it[10].toInt() xor 1).toByte() }
            assertFalse(RaspEd25519.verify(hex(pk), hex(msg), badSig))
        }
        assertFalse(RaspEd25519.verify(ByteArray(31), ByteArray(0), ByteArray(64)))
    }

    @Test fun `Ed25519 agrees with the JDK implementation`() {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        repeat(20) { i ->
            val kp = kpg.generateKeyPair()
            val message = "message $i".toByteArray()
            val sig = Signature.getInstance("Ed25519").run { initSign(kp.private); update(message); sign() }
            val raw = RaspEd25519.rawPublicKey(kp.public.encoded)!!
            assertTrue(RaspEd25519.verify(raw, message, sig))
            assertFalse(RaspEd25519.verify(raw, "message ${i + 1}".toByteArray(), sig))
        }
    }

    // ── JSON ─────────────────────────────────────────────────────────────

    @Test fun `JSON parser handles nesting, escapes and numbers and rejects bad input`() {
        val v = RaspJson.parse("""{"a":[1,-2,3.5,1e3,true,null],"s":"x\"\u00e9\n","o":{}}""") as Map<*, *>
        assertEquals(listOf(1L, -2L, 3.5, 1000.0, true, null), v["a"])
        assertEquals("x\"\u00e9\n", v["s"])
        assertEquals(emptyMap<String, Any?>(), v["o"])
        for (bad in listOf("{\"a\":1} x", "{\"a\":1,\"a\":2}", "[1,]", "\"\\q\"", "01", "{\"a\" 1}", "\"\\u+041\"")) {
            assertTrue(bad, runCatching { RaspJson.parse(bad) }.isFailure)
        }
    }

    // ── malware_reputation ───────────────────────────────────────────────

    private val nodeFixture = resource("reputation-list-fixture.json")
    private val nodeKey = nodeFixture["publicKey"] as String
    private val nodeList = nodeFixture["list"] as String

    @Test fun `a list signed by the Node tool verifies and parses`() {
        val load = RaspMalwareReputationProbes.loadList(nodeList, nodeKey)
        assertTrue(load.toString(), load is RaspMalwareReputationProbes.Load.Ok)
        val list = (load as RaspMalwareReputationProbes.Load.Ok).list
        assertEquals(7L, list.version)
        assertEquals(listOf("com.bad.trojan", "com.sketchy.remote"), list.entries.map { it.packageName })
    }

    @Test fun `a changed list or a different key is rejected`() {
        val tampered = nodeList.replace("com.bad.trojan", "com.good.app")
        assertTrue(RaspMalwareReputationProbes.loadList(tampered, nodeKey) is RaspMalwareReputationProbes.Load.Invalid)
        val otherKey = RaspBase64.encode(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public.encoded)
        assertTrue(RaspMalwareReputationProbes.loadList(nodeList, otherKey) is RaspMalwareReputationProbes.Load.Invalid)
        assertTrue(RaspMalwareReputationProbes.loadList(null, nodeKey) is RaspMalwareReputationProbes.Load.Invalid)
        assertTrue(RaspMalwareReputationProbes.loadList(nodeList, null) is RaspMalwareReputationProbes.Load.Invalid)
        assertTrue(RaspMalwareReputationProbes.loadList("not json", nodeKey) is RaspMalwareReputationProbes.Load.Invalid)
    }

    @Test fun `a validly signed payload without version or entries is rejected`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        fun signed(payload: String): String {
            val sig = Signature.getInstance("Ed25519").run { initSign(kp.private); update(payload.toByteArray()); sign() }
            return RaspCanonicalJson.encode(mapOf("payload" to payload, "signature" to RaspBase64.encode(sig)))
        }
        val key = RaspBase64.encode(kp.public.encoded)
        assertTrue(RaspMalwareReputationProbes.loadList(signed("""{"entries":[]}"""), key) is RaspMalwareReputationProbes.Load.Invalid)
        assertTrue(RaspMalwareReputationProbes.loadList(signed("""{"version":1}"""), key) is RaspMalwareReputationProbes.Load.Invalid)
        assertTrue(RaspMalwareReputationProbes.loadList(signed("""{"version":1,"entries":[]}"""), key) is RaspMalwareReputationProbes.Load.Ok)
    }

    private fun reputation(installed: List<String>?) = RaspMalwareReputationProbes.evaluate(
        RaspMalwareReputationProbes.Observation(
            RaspMalwareReputationProbes.loadList(nodeList, nodeKey),
            installed?.map { RaspMalwareReputationProbes.Entry(it, "banking_trojan", "critical") },
            "declared_queries_and_launcher_apps",
        ),
    )

    @Test fun `malware_reputation detected when a listed package is installed`() {
        val r = reputation(listOf("com.bad.trojan"))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("com.bad.trojan"), signals(r, "matched_package"))
        assertEquals(7L, r.evidence.first { it.key == "list_version" }.value)
    }

    @Test fun `malware_reputation clean when no listed package is installed`() {
        assertEquals(RaspCheckStatus.SECURE, reputation(emptyList()).status)
    }

    @Test fun `malware_reputation cannot decide when the package scan failed`() {
        assertEquals(RaspCheckStatus.UNKNOWN, reputation(null).status)
    }

    @Test fun `malware_reputation unavailable for a missing or invalid list`() {
        val r = RaspMalwareReputationProbes.evaluate(
            RaspMalwareReputationProbes.Observation(RaspMalwareReputationProbes.loadList(null, null), emptyList(), "all"),
        )
        assertEquals(RaspCheckStatus.UNAVAILABLE, r.status)
    }
}
