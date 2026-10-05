package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Task 6.0 engine side: mock_location with opted-in fixes, tamper checks,
 * the backend URL builder and the extended high_risk_ip answer, location
 * opt-in on shipped results, and the signing hash in device registration.
 *
 * Real: RaspMockLocationProbes.evaluate / impliedJump / Movement,
 * RaspTamperAnalysis.evaluate / dexSha256, RaspBackendUrls,
 * RaspGeoIpProbes.check / evaluate (HttpURLConnection against a local socket
 * server), withSharedLocation, RaspDeviceRegistrar.register.
 * Fixed inputs: observations are passed in (location services, PackageManager
 * and the APK file need a device).
 */
class RaspTask60Test {

    private fun RaspCheckResult.values(key: String) = evidence.filter { it.key == key }.map { it.value }

    // ── mock_location ────────────────────────────────────────────────────

    private fun mock(
        isMock: Boolean?,
        apps: List<String>? = emptyList(),
        age: Long? = 5,
        jump: RaspMockLocationProbes.Jump? = null,
    ) = RaspMockLocationProbes.evaluate(
        RaspMockLocationProbes.Observation(true, isMock, apps, ageSeconds = age, accuracyM = 12.5, provider = "fused", jump = jump),
    )

    private val bigJump = RaspMockLocationProbes.Jump(distanceM = 1_000_000.0, seconds = 60.0, speedMps = 16_666.0)

    @Test fun `mock flag true is DETECTED, with the new evidence`() {
        val r = mock(true)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>(5L), r.values("location_age_seconds"))
        assertEquals(listOf<Any?>(12.5), r.values("accuracy_m"))
        assertEquals(listOf<Any?>("fused"), r.values("provider"))
        assertEquals(listOf<Any?>(false), r.values("mock_app_selected"))
    }

    @Test fun `mock flag false is SECURE`() {
        assertEquals(RaspCheckStatus.SECURE, mock(false).status)
    }

    @Test fun `mock flag missing is UNKNOWN`() {
        val r = mock(null)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("Location supplied without its mock flag", r.reason)
    }

    @Test fun `a fix older than 2 minutes is UNKNOWN stale location, even when flagged`() {
        assertEquals(RaspCheckStatus.SECURE, mock(false, age = 120).status)
        for (flag in listOf(true, false, null)) {
            val r = mock(flag, age = 121)
            assertEquals("$flag", RaspCheckStatus.UNKNOWN, r.status)
            assertEquals("stale location", r.reason)
        }
    }

    @Test fun `a selected mock-location app is reported as a soft signal and does not convict alone`() {
        val r = mock(false, apps = listOf("com.lexa.fakegps"))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf<Any?>(true), r.values("mock_app_selected"))
        assertEquals("soft", r.evidence.first { it.key == "mock_app_selected" }.note)
        assertEquals(listOf<Any?>("unreadable"), mock(false, apps = null).values("mock_app_selected"))
    }

    @Test fun `impossible movement is detected from two fixes and is soft`() {
        val delhi = RaspLocationSnapshot(28.6139, 77.2090, capturedAtMillis = 1_000_000)
        val mumbai60s = RaspLocationSnapshot(19.0760, 72.8777, capturedAtMillis = 1_060_000)
        val jump = RaspMockLocationProbes.impliedJump(delhi, mumbai60s)
        assertNotNull(jump)
        assertTrue(jump!!.distanceM in 1_100_000.0..1_200_000.0)
        assertTrue(jump.speedMps > RaspMockLocationProbes.MAX_SPEED_MPS)
        // A plausible move (5 km in 10 minutes) is not a jump.
        assertNull(RaspMockLocationProbes.impliedJump(delhi, RaspLocationSnapshot(28.65, 77.21, capturedAtMillis = 1_600_000)))

        val movement = RaspMockLocationProbes.Movement()
        movement.record(delhi)
        assertNull("one fix is not enough", movement.jump())
        movement.record(mumbai60s)
        assertNotNull(movement.jump())

        val r = mock(false, jump = bigJump)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals("soft", r.evidence.first { it.key == "location_jump" }.note!!.substringBefore(";"))
    }

    @Test fun `two soft signals (jump plus selected mock app) are DETECTED even without the flag`() {
        assertEquals(RaspCheckStatus.DETECTED, mock(null, apps = listOf("com.lexa.fakegps"), jump = bigJump).status)
    }

    @Test fun `no location from the host stays UNAVAILABLE`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE,
            RaspMockLocationProbes.evaluate(RaspMockLocationProbes.Observation(false, null, null)).status)
    }

    // ── location opt-in on shipped results ───────────────────────────────

    @Test fun `coordinates are shipped only with the user opt-in, flagged location_opt_in`() {
        val result = RaspCheckResult.detected("root_jailbreak")
        val notShared = RaspLocationSnapshot(28.6, 77.2, 10.0, 5, isMock = false)
        assertEquals(result, withSharedLocation(result, notShared))
        assertEquals(result, withSharedLocation(result, null))

        val shared = withSharedLocation(RaspCheckResult.secure("vpn"), notShared.copy(shareWithBackend = true))
        assertEquals(listOf<Any?>(true), shared.values("location_opt_in"))
        assertEquals(listOf<Any?>(28.6), shared.values("latitude"))
        assertEquals(listOf<Any?>(77.2), shared.values("longitude"))
    }

    // ── tamper ───────────────────────────────────────────────────────────

    private val cert = "AB".repeat(32)
    private val dex = "11".repeat(32)
    private val arsc = "22".repeat(32)

    private fun obs(
        certSeen: String? = cert,
        installer: String? = "com.android.vending",
        installerReadable: Boolean = true,
        path: String? = "/data/app/~~a==/com.example.rasp_trial-b==/base.apk",
        missing: Boolean? = false,
        dexSeen: String? = dex,
        arscSeen: String? = arsc,
        readable: Boolean = true,
    ) = RaspTamperAnalysis.Observation(certSeen, installerReadable, installer, path, missing, dexSeen, arscSeen, readable)

    private val all = RaspTamperAnalysis.Expected(cert, setOf("com.android.vending"), dex, arsc)

    private fun failed(r: RaspCheckResult) = r.values("failed_check")

    @Test fun `tamper - every check matching is SECURE`() {
        val r = RaspTamperAnalysis.evaluate(obs(), all)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf<Any?>("match"), r.values("check_signing_certificate"))
        assertEquals(listOf<Any?>(cert), r.values("signing_cert_sha256"))
    }

    @Test fun `tamper - each mismatch is DETECTED and named`() {
        val cases = mapOf(
            "signing_certificate" to obs(certSeen = "CD".repeat(32)),
            "installer" to obs(installer = null),
            "apk_path" to obs(path = "/data/local/tmp/base.apk"),
            "classes_dex" to obs(dexSeen = "33".repeat(32)),
            "resources_arsc" to obs(arscSeen = "44".repeat(32)),
        )
        for ((check, o) in cases) {
            val r = RaspTamperAnalysis.evaluate(o, all)
            assertEquals(check, RaspCheckStatus.DETECTED, r.status)
            assertEquals(check, listOf<Any?>(check), failed(r))
        }
        val missingDir = RaspTamperAnalysis.evaluate(obs(missing = true), all)
        assertEquals(listOf<Any?>("apk_path"), failed(missingDir))
    }

    @Test fun `tamper - nothing configured is UNKNOWN not configured, even with a good path`() {
        val r = RaspTamperAnalysis.evaluate(obs(), RaspTamperAnalysis.Expected())
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("not configured", r.reason)
        assertEquals(listOf<Any?>("not_configured"), r.values("check_signing_certificate"))
        // ...but a bad path still convicts with nothing configured.
        assertEquals(RaspCheckStatus.DETECTED,
            RaspTamperAnalysis.evaluate(obs(path = "/sdcard/base.apk"), RaspTamperAnalysis.Expected()).status)
    }

    @Test fun `tamper - unreadable checks are ERROR`() {
        for (o in listOf(obs(certSeen = null), obs(installerReadable = false), obs(path = null), obs(readable = false, dexSeen = null, arscSeen = null))) {
            assertEquals("$o", RaspCheckStatus.ERROR, RaspTamperAnalysis.evaluate(o, all).status)
        }
    }

    @Test fun `tamper - expected APK locations, and look-alike paths are not`() {
        for (p in listOf("/data/app/~~x==/pkg-y==/base.apk", "/mnt/expand/1234-abcd/app/pkg-1/base.apk", "/system/priv-app/X/X.apk")) {
            assertTrue(p, RaspTamperAnalysis.isExpectedApkPath(p))
        }
        for (p in listOf("/data/local/tmp/base.apk", "/sdcard/Download/base.apk", "/data/user/0/com.other.app/files/base.apk", "/data/app/../local/tmp/x.apk")) {
            assertFalse(p, RaspTamperAnalysis.isExpectedApkPath(p))
        }
    }

    @Test fun `tamper - dex digest covers every classes dex in order, by name and content`() {
        val a = RaspTamperAnalysis.dexSha256(listOf("classes2.dex" to byteArrayOf(2), "classes.dex" to byteArrayOf(1)))
        val b = RaspTamperAnalysis.dexSha256(listOf("classes.dex" to byteArrayOf(1), "classes2.dex" to byteArrayOf(2)))
        assertEquals("order of the input list does not matter", a, b)
        assertFalse(a == RaspTamperAnalysis.dexSha256(listOf("classes.dex" to byteArrayOf(1), "classes2.dex" to byteArrayOf(3))))
        assertEquals(10, RaspTamperAnalysis.dexIndex("classes10.dex"))
        assertNull(RaspTamperAnalysis.dexSha256(emptyList()))
        assertEquals("AB12", RaspTamperAnalysis.normalizeHex("ab:12"))
    }

    // ── backend URLs (Task 6.0 Part 3.1) ─────────────────────────────────

    @Test fun `endpoint URLs are built from the ingestion URL safely`() {
        assertEquals("https://api.bank.test/v1/ip-risk", RaspBackendUrls.endpoint("https://api.bank.test/v1/events", "ip-risk"))
        assertEquals("http://10.0.2.2:4000/v1/ip-risk", RaspBackendUrls.endpoint("http://10.0.2.2:4000/v1/events/", "ip-risk"))
        assertEquals("http://host:4000/v1/ip-risk", RaspBackendUrls.endpoint("http://host:4000", "ip-risk"))
        assertEquals("https://h.test/api/v1/devices/register", RaspBackendUrls.endpoint("https://h.test/api/v1/events?x=1#y", "devices/register"))
        assertEquals("https://h.test/v1/ip-risk", RaspBackendUrls.endpoint("https://user:pw@h.test/v1/events", "ip-risk"))
        assertNull(RaspBackendUrls.endpoint("ftp://h.test/v1/events", "ip-risk"))
        assertNull(RaspBackendUrls.endpoint("not a url", "ip-risk"))
        assertEquals("192.168.2.208:4000", RaspBackendUrls.hostOf("http://192.168.2.208:4000/v1/ip-risk"))
        assertEquals("https://api.bank.test/v1/devices/register", RaspDeviceRegistrar.registrationUrl("https://api.bank.test/v1/events"))
    }

    // ── high_risk_ip extended answer (Task 6.0 Part 3.3) ─────────────────

    private fun answer(country: String?, risk: String?, reasons: List<String>, blocked: Boolean? = false) =
        """{"country":${country?.let { "\"$it\"" } ?: "null"},"region":null,"city":null,"is_proxy":false,"is_hosting":false,"is_tor":false,""" +
            """"risk_level":${risk?.let { "\"$it\"" } ?: "null"},"reasons":[${reasons.joinToString(",") { "\"$it\"" }}],""" +
            """"flags":{"blocked_country":$blocked,"proxy":false,"hosting":false,"tor":false,"private_address":false,"country_not_allowed":false,"country_changed":false},""" +
            """"source":"lookup","reason":null,"cached":false}"""

    private fun ip(body: String) = RaspGeoIpProbes.evaluate(RaspGeoIpProbes.Response(200, body))

    @Test fun `high_risk_ip - low is SECURE, medium is SECURE with soft reasons, high is DETECTED`() {
        val low = ip(answer("IN", "low", emptyList()))
        assertEquals(RaspCheckStatus.SECURE, low.status)
        assertEquals(listOf<Any?>("low"), low.values("risk_level"))

        val medium = ip(answer("IN", "medium", listOf("country_changed")))
        assertEquals(RaspCheckStatus.SECURE, medium.status)
        assertEquals("soft", medium.evidence.first { it.key == "risk_level" }.note)
        assertEquals(listOf<Any?>(listOf("country_changed")), medium.values("reasons"))

        for (reason in listOf("tor", "country_not_allowed", "proxy")) {
            assertEquals(reason, RaspCheckStatus.DETECTED, ip(answer("IN", "high", listOf(reason))).status)
        }
        assertEquals(RaspCheckStatus.DETECTED, ip(answer("KP", "high", listOf("blocked_country"), blocked = true)).status)
        assertEquals(RaspCheckStatus.UNKNOWN, ip(answer(null, null, emptyList(), blocked = null)).status)
    }

    @Test fun `high_risk_ip - request carries the device key id and the result names the endpoint host only`() {
        val now = 1_790_000_000_000L
        FakeHttpServer(bodyFor = { answer("IN", "low", emptyList()) }) { 200 }.use { server ->
            val credential = RaspEventCredential("org", "app", "key-1", "secret-1", "${server.baseUrl}/v1/events")
            val r = RaspGeoIpProbes.check(credential, RaspGeoIpProbes.HttpTransport, now, deviceKeyId = "dev-key-1")
            assertEquals(RaspCheckStatus.SECURE, r.status)
            assertEquals("dev-key-1", server.requests.single().headers["x-device-key-id"])
            assertEquals(listOf<Any?>("127.0.0.1:${server.port}"), r.values("endpoint_host"))
            assertTrue(r.evidence.none { "$it".contains("key-1") || "$it".contains("secret-1") })
        }
    }

    // ── device registration carries the signing hash (Task 6.0 Part 2.3) ──

    @Test fun `registration body includes signingCertSha256 when known`() {
        var body = ""
        val http = RaspHttpPost { _, _, b -> body = String(b, Charsets.UTF_8); 201 }
        val key = object : RaspRegistrationKeySource {
            override fun deviceKeyId() = "kid"
            override fun publicKeyBase64() = "pk"
            override fun attestationChainBase64() = listOf("c1")
        }
        val store = object : RaspRegistrationStore {
            var id: String? = null
            override fun registeredKeyId() = id
            override fun setRegisteredKeyId(keyId: String?): Boolean { id = keyId; return true }
        }
        val credential = RaspEventCredential("org", "app", "k", "s", "https://h.test/v1/events")
        RaspDeviceRegistrar(key, store, "com.example.bank", "test", http, { 1L }, signingCertSha256 = { cert }).register(credential)
        assertTrue(body, body.contains("\"signingCertSha256\":\"$cert\""))

        RaspDeviceRegistrar(key, store, "com.example.bank", "test", http, { 1L }).register(credential)
        assertFalse(body, body.contains("signingCertSha256"))
    }
}
