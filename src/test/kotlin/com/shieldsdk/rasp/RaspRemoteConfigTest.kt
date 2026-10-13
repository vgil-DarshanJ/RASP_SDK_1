package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * Signed remote configuration (Task 10.0).
 *
 * Real: RaspRemoteConfig.verify / apply (signature, application binding,
 * expiry, rollback, bounds, unknown fields, ceiling), RaspRemoteConfigClient
 * (fetch headers, storage, status, the `remote_config_rejected` result),
 * pure-Kotlin Ed25519 (RaspEd25519), RaspJson. The signed configs come from
 * the backend's own TypeScript signing code (src/test/resources/remote-config/
 * fixture.json, written by BE scripts/remote-config-fixture.ts).
 * Doubles: the HTTP GET and the encrypted store (in memory).
 * Not exercised: the Keystore-backed store, RaspEventCredentialParser
 * (org.json is Android-only) and the session's live re-scheduling (phone
 * test plan).
 */
class RaspRemoteConfigTest {
    @Suppress("UNCHECKED_CAST")
    private val fixture = RaspJson.parse(javaClass.getResource("/remote-config/fixture.json")!!.readText()) as Map<String, Any?>
    private val publicKey = fixture["publicKey"] as String
    private val app = fixture["applicationId"] as String

    @Suppress("UNCHECKED_CAST")
    private fun case(name: String): String = RaspCanonicalJson.encode((fixture["cases"] as Map<String, Any?>)[name] as Map<String, Any?>)

    private val now = 1_792_000_000_000L // 2026-10-14
    private val local = RaspLeanConfig(remoteConfigEnabled = true, remoteManagedDetectors = setOf("root_jailbreak", "frida"))

    private fun verify(name: String, last: Long? = null, lastPayload: String? = null, config: RaspLeanConfig = local) =
        RaspRemoteConfig.verify(case(name), publicKey, app, config, last, lastPayload, now)

    private fun rejected(name: String, last: Long? = null) = verify(name, last) as RaspRemoteConfig.Verdict.Rejected

    @Test fun `a backend-signed config verifies and applies every allowed setting`() {
        val ok = (verify("valid_v5") as RaspRemoteConfig.Verdict.Ok).config
        assertEquals(5L, ok.version)
        val c = ok.effective
        assertTrue(c.rootDetection)
        assertFalse(c.fridaDetection)
        assertEquals(10_000L, c.pollIntervalMillis)
        assertEquals(60_000L, c.heartbeatIntervalMillis)
        assertEquals(120_000L, c.locationHeartbeatIntervalMillis)
        assertEquals(25 to 70, c.riskMediumThreshold to c.riskHighThreshold)
        assertEquals(50, c.stepUpThreshold)
        assertTrue(c.highRiskTransactionMode)
        assertEquals(12, c.malwareReputationRefreshHours)
        assertEquals(listOf("IN") to listOf("KP"), ok.settings.allowedCountries to ok.settings.blockedCountries)
    }

    @Test fun `the ceiling - a detector outside remoteManagedDetectors is never switched, and is reported as ignored`() {
        val ok = (verify("valid_v5") as RaspRemoteConfig.Verdict.Ok).config
        assertFalse("vpn is not in the ceiling", ok.effective.vpnDetection)
        assertEquals(listOf("vpn"), ok.ignoredDetectors)
        val none = (verify("valid_v5", config = local.copy(remoteManagedDetectors = emptySet())) as RaspRemoteConfig.Verdict.Ok).config
        assertFalse(none.effective.rootDetection)
        assertEquals(listOf("frida", "root_jailbreak", "vpn"), none.ignoredDetectors)
    }

    @Test fun `what the payload cannot express stays as the app set it`() {
        val pinned = local.copy(certificatePinHost = "api.bank.test", certificatePins = listOf("sha256/AAAA"), useEvidenceEnvelope = true, screenshotProtection = true)
        val c = (verify("valid_v5", config = pinned) as RaspRemoteConfig.Verdict.Ok).config.effective
        assertEquals(pinned.certificatePinHost to pinned.certificatePins, c.certificatePinHost to c.certificatePins)
        assertTrue(c.useEvidenceEnvelope && c.screenshotProtection && c.remoteConfigEnabled)
        assertEquals(pinned.remoteManagedDetectors, c.remoteManagedDetectors)
        val empty = (verify("valid_v6_empty") as RaspRemoteConfig.Verdict.Ok).config
        assertEquals("an empty config is the app's own", local, empty.effective)
    }

    @Test fun `tampered payload or another key - bad_signature`() {
        assertEquals(RaspRemoteConfig.Reason.BAD_SIGNATURE, rejected("tampered_v5").reason)
        assertEquals(RaspRemoteConfig.Reason.BAD_SIGNATURE, rejected("wrong_key_v12").reason)
    }

    @Test fun `rollback - a lower version is refused, the same version and payload is unchanged`() {
        assertEquals(RaspRemoteConfig.Reason.ROLLBACK, rejected("older_v4", last = 5).reason)
        val payload = (verify("valid_v5") as RaspRemoteConfig.Verdict.Ok).config.payload
        assertEquals(RaspRemoteConfig.Verdict.Unchanged, verify("valid_v5", 5, payload))
        assertEquals("same version, different payload", RaspRemoteConfig.Reason.ROLLBACK, rejected("valid_v5", last = 5).reason)
        assertEquals(RaspRemoteConfig.Reason.ROLLBACK, rejected("valid_v5", last = 6).reason)
    }

    @Test fun `expired, another application, out of bounds, unknown field, unknown detector`() {
        assertEquals(RaspRemoteConfig.Reason.EXPIRED, rejected("expired_v7").reason)
        for (name in listOf("other_app_v8", "out_of_bounds_v9", "unknown_field_v10", "unknown_detector_v11")) {
            assertEquals(name, RaspRemoteConfig.Reason.INVALID, rejected(name).reason)
        }
        assertTrue(rejected("unknown_field_v10").detail.contains("ingestionUrl"))
    }

    @Test fun `the fixture's limits are the engine's own (backend and phone agree)`() {
        @Suppress("UNCHECKED_CAST")
        val limits = fixture["limits"] as Map<String, Any?>
        assertEquals(RaspRemoteConfig.MANAGEABLE_DETECTORS.toList(), limits["detectors"])
        @Suppress("UNCHECKED_CAST")
        val bounds = limits["bounds"] as Map<String, Map<String, Long>>
        fun range(name: String) = bounds.getValue(name).let { it.getValue("min").toInt()..it.getValue("max").toInt() }
        assertEquals(RaspRemoteConfig.POLL_SECONDS, range("pollIntervalSeconds"))
        assertEquals(RaspRemoteConfig.HEARTBEAT_SECONDS, range("heartbeatIntervalSeconds"))
        assertEquals(RaspRemoteConfig.LOCATION_HEARTBEAT_SECONDS, range("locationHeartbeatIntervalSeconds"))
        assertEquals(RaspRemoteConfig.RISK_THRESHOLD, range("riskThreshold"))
        assertEquals(RaspRemoteConfig.REPUTATION_REFRESH_HOURS, range("reputationRefreshHours"))
    }

    @Test fun `every manageable detector maps to a config switch`() {
        val off = RaspLeanConfig()
        for (id in RaspRemoteConfig.MANAGEABLE_DETECTORS) {
            assertTrue(id, RaspRemoteConfig.withDetector(off, id, true) != off)
        }
        assertEquals(off, RaspRemoteConfig.withDetector(off, "screenshot_protection", true))
    }

    // Own-signed payloads (JDK Ed25519) for cases the fixture does not hold.
    private val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val ownKey = RaspBase64.encode(keys.public.encoded)
    private fun own(settings: String, version: Int = 1, extra: String = ""): String {
        val payload = """{"schema":1,"applicationId":"$app","version":$version,"issuedAt":"2026-10-13T00:00:00.000Z","expiresAt":"2099-01-01T00:00:00.000Z","settings":$settings$extra}"""
        val sig = Signature.getInstance("Ed25519").run { initSign(keys.private); update(payload.toByteArray()); sign() }
        return RaspCanonicalJson.encode(mapOf("payload" to payload, "signature" to RaspBase64.encode(sig)))
    }

    @Test fun `bounds are checked again on the phone, edges included, thresholds must stay consistent with the app's`() {
        fun reason(settings: String, extra: String = "") =
            (RaspRemoteConfig.verify(own(settings, extra = extra), ownKey, app, local, null, null, now) as? RaspRemoteConfig.Verdict.Rejected)?.reason
        assertNull(reason("""{"pollIntervalSeconds":2,"heartbeatIntervalSeconds":300,"locationHeartbeatIntervalSeconds":30}"""))
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"pollIntervalSeconds":61}"""))
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"heartbeatIntervalSeconds":9}"""))
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"locationHeartbeatIntervalSeconds":601}"""))
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"pollIntervalSeconds":4.5}"""))
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"riskMediumThreshold":80}"""), )
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"blockedCountries":["India"]}"""))
        assertEquals(RaspRemoteConfig.Reason.INVALID, reason("""{"detectors":{"root_jailbreak":"yes"}}"""))
        assertEquals("unknown top-level field", RaspRemoteConfig.Reason.INVALID, reason("{}", extra = ""","certificatePins":[]"""))
        val stepUp = RaspRemoteConfig.verify(own("""{"stepUpThreshold":null}"""), ownKey, app, local.copy(stepUpThreshold = 40), null, null, now)
        assertNull((stepUp as RaspRemoteConfig.Verdict.Ok).config.effective.stepUpThreshold)
    }

    // ── client ───────────────────────────────────────────────────────────

    private class MemoryStore(var value: String? = null) : RaspRemoteConfigClient.Store {
        override fun load() = value
        override fun save(signedJson: String): Boolean { value = signedJson; return true }
        override fun clear() { value = null }
    }

    private val credential = RaspEventCredential("org", app, "rasp_live_key", "secret", "https://api.bank.test/v1/events", configPublicKey = publicKey)
    private val requests = mutableListOf<Pair<String, Map<String, String>>>()
    private val applied = mutableListOf<RaspLeanConfig>()
    private var clockMillis = now

    private fun client(
        responses: MutableList<RaspHttpResponse>,
        store: MemoryStore = MemoryStore(),
        cred: RaspEventCredential? = credential,
        config: RaspLeanConfig = local,
    ) = RaspRemoteConfigClient(
        local = config, store = store, credential = { cred }, deviceKeyId = { "KEYID-1" }, onApplied = { applied += it },
        clock = { clockMillis },
        fetch = { url, headers -> requests += url to headers; responses.removeAt(0) },
    )

    @Test fun `fetch - applies a valid config, stores it, asks with If-None-Match next time, 304 keeps it`() {
        val store = MemoryStore()
        val c = client(mutableListOf(RaspHttpResponse(200, case("valid_v5")), RaspHttpResponse(304, null)), store)
        assertEquals(RaspCheckStatus.UNKNOWN, c.result().status)
        c.refreshNow()
        assertEquals(RaspRemoteConfigStatus.APPLIED, c.status)
        assertEquals(5L, c.version)
        assertEquals(case("valid_v5"), store.value)
        assertTrue(applied.single().rootDetection)
        val r = c.result()
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertTrue(r.evidence.contains(RaspEvidence("remote_config_version", 5L)))
        c.refreshNow()
        assertEquals("https://api.bank.test/v1/config", requests[0].first)
        assertEquals("rasp_live_key", requests[0].second["X-Api-Key"])
        assertEquals("KEYID-1", requests[0].second["X-Device-Key-Id"])
        assertNull(requests[0].second["If-None-Match"])
        assertEquals("\"5\"", requests[1].second["If-None-Match"])
        assertEquals(RaspRemoteConfigStatus.APPLIED, c.status)
        assertEquals(1, applied.size)
    }

    @Test fun `a refused config is reported (DETECTED with the reason) and the last good one stays`() {
        val c = client(mutableListOf(RaspHttpResponse(200, case("valid_v5")), RaspHttpResponse(200, case("tampered_v5")), RaspHttpResponse(200, case("older_v4"))))
        c.refreshNow()
        c.refreshNow()
        var r = c.result()
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertTrue(r.evidence.contains(RaspEvidence("reason", "bad_signature")))
        assertEquals(RaspRemoteConfigStatus.REJECTED, c.status)
        assertEquals("the last good config stays", 5L, c.version)
        c.refreshNow()
        r = c.result()
        assertTrue(r.evidence.contains(RaspEvidence("reason", "rollback")))
        assertEquals(1, applied.size)
    }

    @Test fun `expired from the server is reported as expired`() {
        val c = client(mutableListOf(RaspHttpResponse(200, case("expired_v7"))))
        c.refreshNow()
        assertTrue(c.result().evidence.contains(RaspEvidence("reason", "expired")))
        assertNull(c.version)
        assertTrue(applied.isEmpty())
    }

    @Test fun `offline - the stored config is used without the network, and kept when the fetch fails`() {
        val c = client(mutableListOf(RaspHttpResponse(-1, null), RaspHttpResponse(503, null)), MemoryStore(case("valid_v5")))
        c.loadCached()
        assertEquals(RaspRemoteConfigStatus.APPLIED, c.status)
        assertTrue(applied.single().rootDetection)
        c.refreshNow()
        c.refreshNow()
        assertEquals(5L, c.version)
        assertEquals(RaspCheckStatus.SECURE, c.result().status)
    }

    @Test fun `a stored config that has expired is dropped, the app's own config applies again`() {
        val store = MemoryStore(case("valid_v5"))
        val c = client(mutableListOf(), store)
        c.loadCached()
        clockMillis = 4_070_908_800_001L // just after 2099-01-01
        val r = c.result()
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals(RaspRemoteConfigStatus.EXPIRED, c.status)
        assertNull(store.value)
        assertEquals(local, applied.last())
    }

    @Test fun `no config key or no credential - UNAVAILABLE, nothing fetched`() {
        val noKey = client(mutableListOf(), cred = credential.copy(configPublicKey = null))
        noKey.refreshNow()
        assertEquals(RaspCheckStatus.UNAVAILABLE, noKey.result().status)
        assertEquals(RaspRemoteConfigStatus.UNAVAILABLE, noKey.status)
        val noCredential = client(mutableListOf(), cred = null)
        noCredential.refreshNow()
        assertEquals(RaspCheckStatus.UNAVAILABLE, noCredential.result().status)
        assertTrue(requests.isEmpty())
        val pinned = client(mutableListOf(RaspHttpResponse(200, case("valid_v5"))), cred = credential.copy(configPublicKey = null), config = local.copy(remoteConfigPublicKey = publicKey))
        pinned.refreshNow()
        assertEquals("an app-pinned key works without the credential's", 5L, pinned.version)
    }

    @Test fun `nothing published - UNKNOWN, never SECURE`() {
        val c = client(mutableListOf(RaspHttpResponse(404, null)))
        c.refreshNow()
        val r = c.result()
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("No remote config published for this app", r.reason)
        assertEquals(RaspRemoteConfigStatus.WAITING, c.status)
    }

    @Test fun `remote config off - status OFF`() {
        assertEquals(RaspRemoteConfigStatus.OFF, client(mutableListOf(), config = RaspLeanConfig()).status)
    }

    @Test fun `ISO dates - only the backend's exact format`() {
        assertEquals(4_070_908_800_000L, RaspRemoteConfig.parseIso("2099-01-01T00:00:00.000Z"))
        assertNull(RaspRemoteConfig.parseIso("2099-01-01"))
        assertNull(RaspRemoteConfig.parseIso("2099-13-01T00:00:00.000Z"))
    }
}
