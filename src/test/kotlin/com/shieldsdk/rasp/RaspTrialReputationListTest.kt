package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The trial app's test reputation list (Task 4.8 item 3): the exact list and
 * public key the trial app ships (written to `trial-reputation-list-fixture.json`
 * by the trial app's `tool/make_test_reputation_list.js`, which signs with
 * this repo's `tools/sign-reputation-list.js`).
 *
 * Real: [RaspMalwareReputationProbes.loadList] (Ed25519 verification, JSON
 * parsing) and [RaspMalwareReputationProbes.evaluate].
 * Doubles: the installed-package scan result is passed in (PackageManager
 * needs a device).
 */
class RaspTrialReputationListTest {

    private val fixture = RaspJson.parse(
        javaClass.classLoader!!.getResourceAsStream("trial-reputation-list-fixture.json")!!.readBytes().toString(Charsets.UTF_8),
    ) as Map<*, *>
    private val testPackage = fixture["package"] as String
    private val key = fixture["publicKey"] as String
    private val list = fixture["list"] as String

    private fun verdict(listJson: String?, publicKey: String?, installed: List<String> = listOf(testPackage)): RaspCheckResult {
        val load = RaspMalwareReputationProbes.loadList(listJson, publicKey)
        val entries = (load as? RaspMalwareReputationProbes.Load.Ok)?.list?.entries.orEmpty()
        return RaspMalwareReputationProbes.evaluate(
            RaspMalwareReputationProbes.Observation(load, entries.filter { it.packageName in installed }, "declared_queries_and_launcher_apps"),
        )
    }

    @Test fun `the trial list verifies and names the one test package`() {
        val load = RaspMalwareReputationProbes.loadList(list, key)
        assertTrue(load.toString(), load is RaspMalwareReputationProbes.Load.Ok)
        assertEquals(listOf(testPackage), (load as RaspMalwareReputationProbes.Load.Ok).list.entries.map { it.packageName })
    }

    @Test fun `test package installed - DETECTED with the package in evidence`() {
        val r = verdict(list, key)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf(testPackage), r.evidence.filter { it.key == "matched_package" }.map { it.value })
        assertEquals("test_entry/low", r.evidence.first { it.key == "matched_package" }.note)
    }

    @Test fun `test package not installed - SECURE`() {
        assertEquals(RaspCheckStatus.SECURE, verdict(list, key, installed = emptyList()).status)
    }

    @Test fun `tampered list - UNAVAILABLE, never DETECTED or SECURE`() {
        val signature = Regex("\"signature\":\"([^\"]+)\"").find(list)!!.groupValues[1]
        val flipped = RaspBase64.decode(signature)!!.also { it[10] = (it[10].toInt() xor 1).toByte() }
        val otherFixtureKey = "MCowBQYDK2VwAyEAiFUHkoUhBf3bo2hEhiEYynU1oVKYvzmNCPKWPtq40RI=" // reputation-list-fixture.json
        val tampered = mapOf(
            "package renamed in the payload" to list.replace(testPackage, "com.example.other"),
            "severity changed in the payload" to list.replace("\\\"low\\\"", "\\\"critical\\\""),
            "one signature bit flipped" to list.replace(signature, RaspBase64.encode(flipped)),
            "signature removed" to list.replace(",\"signature\":\"$signature\"", ""),
        )
        for ((what, changed) in tampered) {
            assertTrue("$what: the edit applied", changed != list)
            val r = verdict(changed, key)
            assertEquals(what, RaspCheckStatus.UNAVAILABLE, r.status)
        }
        val wrongKey = verdict(list, otherFixtureKey)
        assertEquals("signed by another key", RaspCheckStatus.UNAVAILABLE, wrongKey.status)
        assertEquals("List signature does not verify", wrongKey.reason)
    }
}
