package com.shieldsdk.rasp

import android.accessibilityservice.AccessibilityServiceInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicLong

/**
 * Task 8.1 engine side: the five fraud detectors (three outcomes each), the
 * independence-grouped session risk score, id hashing, the session and
 * transaction API and risk-event delivery.
 *
 * Real: every `evaluate`, RaspSignalCombiner, RaspRiskScore.assess,
 * RaspAccountHasher (vector cross-checked with Node's crypto.createHmac),
 * RaspFraudApi (with a software EC P-256 key in place of the Keystore key and
 * an in-memory counter in place of EncryptedSharedPreferences), signature
 * checks with plain JCA, RaspRiskEventDelivery + RaspDeviceRegistrar over
 * real HTTP to a local socket server (FakeHttpServer).
 * Fixed inputs: observations are passed in (PackageManager, AccessibilityManager,
 * Settings.Secure, DisplayManager and the recording callback need a device).
 */
class RaspTask81Test {

    private fun RaspCheckResult.values(key: String) = evidence.filter { it.key == key }.map { it.value }

    private val noDisplay = RaspPrivacyScreenProbes.ExternalDisplayState(supported = true)
    private val castDisplay = RaspPrivacyScreenProbes.ExternalDisplayState(
        supported = true, externalDisplayCount = 1, externalDisplayDetected = true, displayNames = listOf("Chromecast"),
    )

    // ── remote_control_app ───────────────────────────────────────────────

    private fun remote(
        builtIn: List<String>? = emptyList(),
        load: RaspMalwareReputationProbes.Load? = null,
        listInstalled: List<String>? = null,
        recording: RaspScreenRecordingProbes.State? = null,
        observable: Boolean = false,
        display: RaspPrivacyScreenProbes.ExternalDisplayState = noDisplay,
    ) = RaspRemoteControlProbes.evaluate(
        RaspRemoteControlProbes.Observation(builtIn, load, listInstalled, recording, observable, display, "declared_queries_and_launcher_apps"),
    )

    private val okList = RaspMalwareReputationProbes.Load.Ok(
        RaspMalwareReputationProbes.ReputationList(7, listOf(RaspMalwareReputationProbes.Entry("com.example.remote", "remote_access", "high"))),
    )

    @Test fun `remote_control_app - built-in package installed is DETECTED with the package in evidence`() {
        val r = remote(builtIn = listOf("com.anydesk.anydeskandroid"))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>("com.anydesk.anydeskandroid"), r.values("remote_control_package"))
    }

    @Test fun `remote_control_app - signed-list package installed is DETECTED`() {
        val r = remote(load = okList, listInstalled = listOf("com.example.remote"))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>("com.example.remote"), r.values("remote_control_package"))
        assertEquals(listOf<Any?>(7L), r.values("list_version"))
    }

    @Test fun `remote_control_app - active cast display or recording is DETECTED`() {
        assertEquals(RaspCheckStatus.DETECTED, remote(display = castDisplay).status)
        val recorded = remote(recording = RaspScreenRecordingProbes.State.RECORDED, observable = true)
        assertEquals(RaspCheckStatus.DETECTED, recorded.status)
        assertEquals(listOf<Any?>("screen_recording"), recorded.values("active_screen_session"))
    }

    @Test fun `remote_control_app - nothing installed and no session is SECURE`() {
        val r = remote()
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf<Any?>("not_observable"), r.values("screen_recording_state"))
        assertEquals(RaspCheckStatus.SECURE, remote(load = okList, listInstalled = emptyList()).status)
    }

    @Test fun `remote_control_app - package check failed or list rejected is UNKNOWN`() {
        assertEquals(RaspCheckStatus.UNKNOWN, remote(builtIn = null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, remote(load = okList, listInstalled = null).status)
        val rejected = remote(load = RaspMalwareReputationProbes.Load.Invalid("List signature does not verify"))
        assertEquals(RaspCheckStatus.UNKNOWN, rejected.status)
        assertTrue(rejected.reason!!.contains("List signature does not verify"))
        assertEquals(RaspCheckStatus.UNKNOWN, remote(display = RaspPrivacyScreenProbes.ExternalDisplayState(supported = false)).status)
    }

    @Test fun `remote_control_app - a configured list with a bad signature is rejected by the shared list loader`() {
        assertTrue(RaspRemoteControlProbes.loadList("""{"payload":"{}","signature":"AAAA"}""", "AAAA") is RaspMalwareReputationProbes.Load.Invalid)
        assertNull("no list configured", RaspRemoteControlProbes.loadList(null, null))
    }

    // ── screen_sharing_risk ──────────────────────────────────────────────

    private fun sharing(
        foreground: Boolean?,
        recording: RaspScreenRecordingProbes.State? = RaspScreenRecordingProbes.State.NOT_RECORDED,
        observable: Boolean = true,
        display: RaspPrivacyScreenProbes.ExternalDisplayState = noDisplay,
    ) = RaspScreenSharingProbes.evaluate(RaspScreenSharingProbes.Observation(foreground, recording, observable, display))

    @Test fun `screen_sharing_risk - capture or cast while in the foreground is DETECTED`() {
        assertEquals(RaspCheckStatus.DETECTED, sharing(true, RaspScreenRecordingProbes.State.RECORDED).status)
        assertEquals(RaspCheckStatus.DETECTED, sharing(true, null, observable = false, display = castDisplay).status)
    }

    @Test fun `screen_sharing_risk - foreground without capture or cast is SECURE, background is SECURE`() {
        assertEquals(RaspCheckStatus.SECURE, sharing(true).status)
        val background = sharing(false, RaspScreenRecordingProbes.State.RECORDED)
        assertEquals(RaspCheckStatus.SECURE, background.status)
        assertEquals(listOf<Any?>(false), background.values("app_in_foreground"))
    }

    @Test fun `screen_sharing_risk - capture not observable, foreground unknown or displays unreadable is UNKNOWN`() {
        val notObservable = sharing(true, null, observable = false)
        assertEquals(RaspCheckStatus.UNKNOWN, notObservable.status)
        assertTrue(notObservable.reason!!.contains("Android 15"))
        assertEquals(RaspCheckStatus.UNKNOWN, sharing(null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, sharing(true, display = RaspPrivacyScreenProbes.ExternalDisplayState(supported = false)).status)
        assertEquals("no state reported yet", RaspCheckStatus.UNKNOWN, sharing(true, null, observable = true).status)
    }

    // ── otp_interception_risk ────────────────────────────────────────────

    private val readsWindows = AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT
    private val gestures = AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES
    private fun app(pkg: String, visible: Boolean = true, system: Boolean = false) = RaspAppFacts(pkg, visible, system)

    private fun interception(
        services: List<Pair<String?, Int>>? = emptyList(),
        listeners: List<RaspAppFacts>? = emptyList(),
        allowlist: List<String> = emptyList(),
        touchObscured: Boolean? = false,
        overlayHolder: Boolean? = null,
        remote: List<String>? = emptyList(),
    ) = RaspOtpInterceptionProbes.evaluate(
        RaspOtpInterceptionProbes.Observation("com.example.bank", services, listeners, allowlist, touchObscured, overlayHolder, remote),
    )

    @Test fun `otp_interception_risk - one hard signal is DETECTED and evidence names it`() {
        val a11y = interception(services = listOf("com.evil.reader" to readsWindows))
        assertEquals(RaspCheckStatus.DETECTED, a11y.status)
        assertEquals(listOf<Any?>("accessibility_abuse"), a11y.values("contributing_signal"))
        assertEquals(listOf<Any?>("com.evil.reader"), a11y.values("accessibility_abuse_detail"))

        val listener = interception(listeners = listOf(app("com.evil.notify")))
        assertEquals(RaspCheckStatus.DETECTED, listener.status)
        assertEquals(listOf<Any?>("unknown_notification_listener"), listener.values("contributing_signal"))
    }

    @Test fun `otp_interception_risk - two soft signals are DETECTED, one is not`() {
        val two = interception(touchObscured = true, remote = listOf("com.anydesk.anydeskandroid"))
        assertEquals(RaspCheckStatus.DETECTED, two.status)
        assertEquals(listOf<Any?>("overlay", "remote_control_app"), two.values("contributing_signal"))
        assertEquals(RaspCheckStatus.SECURE, interception(remote = listOf("com.anydesk.anydeskandroid")).status)
    }

    @Test fun `otp_interception_risk - trusted listeners and allowlisted services are SECURE`() {
        val r = interception(
            services = listOf("com.google.android.marvin.talkback" to readsWindows, "com.example.helper" to 0),
            listeners = listOf(app("com.example.bank"), app("com.google.android.gms"), app("com.oem.system", system = true), app("com.watch.companion")),
            allowlist = listOf("com.watch.companion"),
        )
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertTrue(r.values("contributing_signal").isEmpty())
    }

    @Test fun `otp_interception_risk - unreadable inputs are UNKNOWN, never SECURE`() {
        val listenersUnreadable = interception(listeners = null)
        assertEquals(RaspCheckStatus.UNKNOWN, listenersUnreadable.status)
        assertTrue(listenersUnreadable.reason!!.contains("unknown_notification_listener"))
        assertEquals(RaspCheckStatus.UNKNOWN, interception(services = null).status)
        assertEquals("invisible listener", RaspCheckStatus.UNKNOWN, interception(listeners = listOf(app("com.hidden", visible = false))).status)
        assertEquals(
            "one soft present + one soft undecided could reach two",
            RaspCheckStatus.UNKNOWN, interception(touchObscured = null, remote = listOf("com.anydesk.anydeskandroid")).status,
        )
    }

    @Test fun `otp_interception_risk - an undecided soft signal alone cannot change a clean verdict`() {
        assertEquals(RaspCheckStatus.SECURE, interception(touchObscured = null).status)
    }

    @Test fun `otp_interception_risk - an overlay-permission holder is evidence only, not the overlay signal`() {
        val r = interception(touchObscured = false, overlayHolder = true, remote = listOf("com.anydesk.anydeskandroid"))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf<Any?>(true), r.values("overlay_permission_holder"))
        assertEquals(listOf<Any?>("remote_control_app"), r.values("contributing_signal"))
    }

    @Test fun `notification listener setting is parsed into package names`() {
        assertEquals(
            listOf("com.a", "com.b"),
            RaspFraudEnvironment.parseListenerSetting("com.a/com.a.Listener:com.b/.Svc:com.a/com.a.Other"),
        )
        assertEquals(emptyList<String>(), RaspFraudEnvironment.parseListenerSetting(null))
        assertEquals(emptyList<String>(), RaspFraudEnvironment.parseListenerSetting(""))
    }

    // ── sms_reader_abuse ─────────────────────────────────────────────────

    private fun sms(
        packages: List<RaspSmsReaderProbes.AppSms>? = emptyList(),
        listeners: List<RaspAppFacts>? = emptyList(),
        complete: Boolean = true,
        allowlist: List<String> = emptyList(),
    ) = RaspSmsReaderProbes.evaluate(RaspSmsReaderProbes.Observation("com.example.bank", packages, listeners, "com.sms.default", allowlist, complete))

    @Test fun `sms_reader_abuse - non-system app with a granted SMS permission is DETECTED`() {
        val r = sms(packages = listOf(RaspSmsReaderProbes.AppSms("com.evil.sms", false, listOf("android.permission.RECEIVE_SMS"))))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>("com.evil.sms"), r.values("sms_permission_app"))
        assertEquals(listOf<Any?>(false), r.values("message_content_read"))
    }

    @Test fun `sms_reader_abuse - unknown notification listener is DETECTED, even with limited visibility`() {
        val r = sms(listeners = listOf(app("com.evil.notify")), complete = false)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>("com.evil.notify"), r.values("notification_listener_app"))
    }

    @Test fun `sms_reader_abuse - system, default SMS, allowlisted and host apps are SECURE with full visibility`() {
        val granted = listOf("android.permission.READ_SMS")
        val r = sms(
            packages = listOf(
                RaspSmsReaderProbes.AppSms("com.android.messaging", true, granted),
                RaspSmsReaderProbes.AppSms("com.sms.default", false, granted),
                RaspSmsReaderProbes.AppSms("com.allowed.sms", false, granted),
                RaspSmsReaderProbes.AppSms("com.example.bank", false, granted),
                RaspSmsReaderProbes.AppSms("com.plain.app", false, emptyList()),
            ),
            allowlist = listOf("com.allowed.sms"),
        )
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf<Any?>(5), r.values("packages_checked"))
    }

    @Test fun `sms_reader_abuse - clean but limited package visibility is UNKNOWN with the reason`() {
        val r = sms(complete = false)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertTrue(r.reason!!.contains("visibility is limited"))
        assertEquals(listOf<Any?>("declared_queries_and_launcher_apps"), r.values("visibility"))
    }

    @Test fun `sms_reader_abuse - unreadable packages or listeners are UNKNOWN`() {
        assertEquals(RaspCheckStatus.UNKNOWN, sms(packages = null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, sms(listeners = null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, sms(listeners = listOf(app("com.hidden", visible = false))).status)
    }

    @Test fun `granted SMS permissions are read from the requested-permission flags only`() {
        val granted = 2 // PackageInfo.REQUESTED_PERMISSION_GRANTED
        assertEquals(
            listOf("android.permission.READ_SMS"),
            RaspSmsReaderProbes.grantedSms(
                arrayOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"),
                intArrayOf(granted, 0, granted),
            ),
        )
        assertEquals(emptyList<String>(), RaspSmsReaderProbes.grantedSms(null, null))
    }

    // ── otp_forwarding_risk ──────────────────────────────────────────────

    private fun forwarding(apps: List<String>? = emptyList(), services: List<Pair<String?, Int>>? = emptyList(), remote: List<String>? = emptyList()) =
        RaspOtpForwardingProbes.evaluate(RaspOtpForwardingProbes.Observation(apps, services, remote))

    @Test fun `otp_forwarding_risk - any environment signal is DETECTED and marked as a hint`() {
        val r = forwarding(apps = listOf("com.frzinapps.smsforward"))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf<Any?>(true), r.values("risk_hint"))
        assertTrue(r.evidence.first { it.key == "risk_hint" }.note!!.contains("not proof"))
        assertEquals(RaspCheckStatus.DETECTED, forwarding(services = listOf("com.evil.clicker" to gestures)).status)
        assertEquals(RaspCheckStatus.DETECTED, forwarding(remote = listOf("com.sand.airdroid")).status)
    }

    @Test fun `otp_forwarding_risk - nothing present is SECURE, call forwarding reported as not checked`() {
        val r = forwarding(services = listOf("com.google.android.marvin.talkback" to gestures, "com.reader.only" to readsWindows))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf<Any?>("not_checked"), r.values("call_forwarding"))
    }

    @Test fun `otp_forwarding_risk - unreadable inputs are UNKNOWN`() {
        assertEquals(RaspCheckStatus.UNKNOWN, forwarding(apps = null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, forwarding(services = null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, forwarding(remote = null).status)
    }

    // ── session risk score ───────────────────────────────────────────────

    private fun r(id: String, status: RaspCheckStatus) = RaspCheckResult(id, status)
    private val secure = RaspCheckStatus.SECURE
    private val detected = RaspCheckStatus.DETECTED

    @Test fun `correlated detectors in one group count once - root plus hooking plus frida is 40, not 120`() {
        val a = RaspRiskScore.assess(listOf(r("root_jailbreak", detected), r("hook_detection", detected), r("frida", detected)))
        assertEquals(40, a.score)
        assertEquals(RaspRiskVerdict.MEDIUM, a.verdict)
        assertEquals(listOf("device_compromise"), a.firedGroups)
        assertEquals(listOf("root_jailbreak", "hook_detection", "frida").sorted(), a.contributingDetectors.sorted())
        assertFalse(a.stepUpRecommended)
    }

    @Test fun `independent groups add up - compromise plus remote access is HIGH with step-up`() {
        val a = RaspRiskScore.assess(listOf(r("root_jailbreak", detected), r("remote_control_app", detected), r("vpn", secure)))
        assertEquals(75, a.score)
        assertEquals(RaspRiskVerdict.HIGH, a.verdict)
        assertTrue(a.stepUpRecommended)
    }

    @Test fun `all scored detectors clean is LOW`() {
        val a = RaspRiskScore.assess(listOf(r("root_jailbreak", secure), r("tamper", secure), r("sms_reader_abuse", secure)))
        assertEquals(0, a.score)
        assertEquals(RaspRiskVerdict.LOW, a.verdict)
        assertEquals(0, a.maxPossibleScore)
    }

    @Test fun `undecided input that could raise LOW gives UNKNOWN, never LOW`() {
        // device_compromise (40) undecided: 0 now, up to 40 (MEDIUM), so not LOW.
        val a = RaspRiskScore.assess(listOf(r("tamper", secure), r("root_jailbreak", RaspCheckStatus.UNKNOWN)))
        assertEquals(RaspRiskVerdict.UNKNOWN, a.verdict)
        assertEquals(listOf("device_compromise"), a.undecidedGroups)
        assertEquals(0, a.score)
        assertEquals(40, a.maxPossibleScore)
        val error = RaspRiskScore.assess(listOf(r("root_jailbreak", RaspCheckStatus.ERROR)))
        assertEquals(RaspRiskVerdict.UNKNOWN, error.verdict)
    }

    @Test fun `small undecided weight that cannot cross the threshold keeps LOW`() {
        // network (15) or sms_access (25) undecided: below 30 either way, LOW whatever it turns out to be.
        val a = RaspRiskScore.assess(listOf(r("root_jailbreak", secure), r("vpn", RaspCheckStatus.UNKNOWN)))
        assertEquals(RaspRiskVerdict.LOW, a.verdict)
        assertEquals(listOf("network"), a.undecidedGroups)
        val sms = RaspRiskScore.assess(listOf(r("root_jailbreak", secure), r("sms_reader_abuse", RaspCheckStatus.UNKNOWN)))
        assertEquals(RaspRiskVerdict.LOW, sms.verdict)
        assertEquals(25, sms.maxPossibleScore)
        // Both undecided: up to 40, so no longer LOW.
        val both = RaspRiskScore.assess(listOf(r("vpn", RaspCheckStatus.UNKNOWN), r("sms_reader_abuse", RaspCheckStatus.UNKNOWN)))
        assertEquals(RaspRiskVerdict.UNKNOWN, both.verdict)
    }

    @Test fun `MEDIUM with undecided groups is a lower bound`() {
        val a = RaspRiskScore.assess(listOf(r("root_jailbreak", detected), r("tamper", RaspCheckStatus.UNKNOWN)))
        assertEquals(RaspRiskVerdict.MEDIUM, a.verdict)
        assertEquals(70, a.maxPossibleScore)
    }

    @Test fun `no scored results at all is UNKNOWN`() {
        assertEquals(RaspRiskVerdict.UNKNOWN, RaspRiskScore.assess(emptyList()).verdict)
        assertEquals(RaspRiskVerdict.UNKNOWN, RaspRiskScore.assess(listOf(r("usb_connection", detected))).verdict)
        assertNull(RaspRiskScore.assess(emptyList()).score)
    }

    @Test fun `UNAVAILABLE results are not inputs - a group with only those is not scored`() {
        val a = RaspRiskScore.assess(listOf(r("root_jailbreak", secure), r("screen_recording", RaspCheckStatus.UNAVAILABLE)))
        assertTrue(a.undecidedGroups.isEmpty())
        assertEquals(RaspRiskVerdict.LOW, a.verdict)
        assertEquals(
            "nothing that ran means nothing scored",
            RaspRiskVerdict.UNKNOWN, RaspRiskScore.assess(listOf(r("screen_recording", RaspCheckStatus.UNAVAILABLE))).verdict,
        )
        val mixed = RaspRiskScore.assess(listOf(r("overlay", RaspCheckStatus.UNKNOWN), r("screen_recording", RaspCheckStatus.UNAVAILABLE)))
        assertEquals(listOf("remote_access_overlay"), mixed.undecidedGroups)
        assertEquals(RaspRiskVerdict.UNKNOWN, mixed.verdict)
    }

    @Test fun `step-up threshold and high-risk transaction mode`() {
        val medium = listOf(r("root_jailbreak", detected))
        assertFalse(RaspRiskScore.assess(medium).stepUpRecommended)
        assertTrue(RaspRiskScore.assess(medium, RaspRiskPolicy(stepUpThreshold = 40)).stepUpRecommended)
        val strict = RaspRiskPolicy(highRiskTransactionMode = true)
        assertTrue("MEDIUM in high-risk mode", RaspRiskScore.assess(medium, strict).stepUpRecommended)
        assertTrue("UNKNOWN in high-risk mode", RaspRiskScore.assess(listOf(r("root_jailbreak", RaspCheckStatus.UNKNOWN)), strict).stepUpRecommended)
        assertFalse("LOW in high-risk mode", RaspRiskScore.assess(listOf(r("root_jailbreak", secure)), strict).stepUpRecommended)
        assertTrue(RaspRiskScore.assess(medium, strict).highRiskTransactionMode)
    }

    @Test fun `score is capped at 100`() {
        val all = RaspRiskScore.GROUPS.map { r(it.detectors.first(), detected) }
        assertEquals(100, RaspRiskScore.assess(all).score)
    }

    @Test fun `invalid thresholds are rejected`() {
        assertThrows(IllegalArgumentException::class.java) { RaspRiskPolicy(mediumThreshold = 60, highThreshold = 30) }
        assertThrows(IllegalArgumentException::class.java) { RaspRiskPolicy(stepUpThreshold = 0) }
    }

    @Test fun `every detector is in at most one group`() {
        val all = RaspRiskScore.GROUPS.flatMap { it.detectors }
        assertEquals(all.size, all.toSet().size)
    }

    // ── id hashing ───────────────────────────────────────────────────────

    private val salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    @Test fun `account hash matches the Node vector`() {
        // node: crypto.createHmac('sha256', Buffer.from(salt, 'hex')).update('acct-42').digest('hex')
        assertEquals("c71dfb3e5fa15696b3ab71f524f584139168e39b45d50853a900730323f7aae7", RaspAccountHasher.hash(salt, "acct-42"))
        assertFalse(RaspAccountHasher.hash(salt, "acct-42") == RaspAccountHasher.hash(salt.replace('0', '1'), "acct-42"))
    }

    @Test fun `bad salts and ids are rejected`() {
        assertFalse(RaspAccountHasher.isValidSalt(null))
        assertFalse(RaspAccountHasher.isValidSalt("abc"))
        assertFalse(RaspAccountHasher.isValidSalt("zz".repeat(32)))
        assertThrows(IllegalArgumentException::class.java) { RaspAccountHasher.hash(salt, "") }
        assertThrows(IllegalArgumentException::class.java) { RaspAccountHasher.hash(salt, "x".repeat(257)) }
        assertThrows(IllegalArgumentException::class.java) { RaspAccountHasher.hash(salt, "a\nb") }
    }

    // ── session and transaction API ──────────────────────────────────────

    private class SoftwareSigner(val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1")); generateKeyPair()
    }) : RaspEnvelopeSigner {
        override fun publicKeySpki(): ByteArray = keyPair.public.encoded
        override fun signDer(payload: ByteArray): ByteArray? = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private); update(payload); sign()
        }
    }

    private class MemoryCounter : RaspEnvelopeCounterStore {
        val value = AtomicLong()
        override fun next(): Long = value.incrementAndGet()
    }

    private inner class Api(
        saltValue: String? = salt,
        val risk: RaspRiskAssessment = RaspRiskScore.assess(listOf(r("root_jailbreak", detected)), nowMillis = 1L),
        location: RaspLocationSnapshot? = null,
    ) {
        val signer = SoftwareSigner()
        val counter = MemoryCounter()
        val sent = mutableListOf<String>()
        val api = RaspFraudApi(
            signer, counter, "com.example.bank", { saltValue }, { risk },
            sender = { sent += it; true }, locationProvider = { location },
            sdkVersion = "test", clock = { 1_790_000_000_000L },
        )
        fun sentFields(i: Int) = RaspJson.parse(sent[i]) as Map<*, *>
    }

    @Suppress("UNCHECKED_CAST")
    private fun verify(fields: Map<*, *>, signer: SoftwareSigner) =
        RaspEvidenceEnvelope.verify(fields as Map<String, Any?>, signer.publicKeySpki())

    @Test fun `reportSession sends a signed event with hashes only`() {
        val t = Api()
        val report = t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        assertEquals(RaspAccountHasher.hash(salt, "acct-42"), report.accountHash)
        assertTrue(report.sentToBackend)
        assertEquals(1, t.sent.size)
        assertFalse("raw account id never sent", t.sent[0].contains("acct-42"))
        assertFalse("raw session id never sent", t.sent[0].contains("session-1"))
        val f = t.sentFields(0)
        assertEquals(
            setOf(
                "riskEnvelopeVersion", "type", "eventId", "eventTimeMillis", "monotonicCounter", "nonce", "appId", "deviceKeyId",
                "sdkVersion", "accountHash", "sessionHash", "sessionEvent", "riskScore", "riskVerdict", "location",
                "signatureAlgorithm", "signature",
            ),
            f.keys,
        )
        assertEquals("session", f["type"])
        assertEquals("login", f["sessionEvent"])
        assertEquals(40L, f["riskScore"])
        assertEquals("MEDIUM", f["riskVerdict"])
        assertNull("no location without opt-in", f["location"])
        assertEquals(32, (f["nonce"] as String).length)
        assertTrue(verify(f, t.signer))
        assertEquals(report.accountHash, t.api.currentAccountHash())
    }

    @Test fun `a changed field breaks the signature`() {
        val t = Api()
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        @Suppress("UNCHECKED_CAST")
        val tampered = (t.sentFields(0) as Map<String, Any?>) + ("riskVerdict" to "LOW")
        assertFalse(verify(tampered, t.signer))
    }

    @Test fun `logout clears the session, transactions then need a new login`() {
        val t = Api()
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGOUT)
        assertNull(t.api.currentAccountHash())
        assertThrows(IllegalStateException::class.java) { t.api.signTransaction("10", "INR", "benef-1") }
    }

    @Test fun `signTransaction binds amount, currency, beneficiary hash, nonce, time and counter, signed by the device key`() {
        val t = Api()
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        val s = t.api.signTransaction("0100.50", "INR", "benef-1")
        val beneficiaryHash = RaspAccountHasher.hash(salt, "benef-1")
        assertEquals("rasp-txn-v1|100.5|INR|$beneficiaryHash|${s.nonce}|1790000000000|${s.counter}", s.canonical)
        assertEquals(RaspFraudApi.sha256Hex(s.canonical), s.bindingSha256)
        assertEquals(RaspEvidenceEnvelope.deviceKeyId(t.signer.publicKeySpki()), s.deviceKeyId)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(t.signer.keyPair.public); update(s.canonical.toByteArray()); verify(java.util.Base64.getDecoder().decode(s.signatureBase64))
        }
        assertTrue(ok)
        assertEquals(40, s.risk.score)
        assertEquals("signTransaction sends nothing", 1, t.sent.size)
        val second = t.api.signTransaction("100.5", "INR", "benef-1")
        assertTrue("counter strictly increases", second.counter > s.counter)
        assertFalse("fresh nonce", second.nonce == s.nonce)
    }

    @Test fun `reportTransaction sends hashes and the binding digest, never the amount`() {
        val t = Api()
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        val report = t.api.reportTransaction("98765.43", "INR", "benef-1", "upi")
        assertTrue(report.sentToBackend)
        val json = t.sent[1]
        assertFalse(json.contains("98765.43"))
        assertFalse(json.contains("benef-1"))
        val f = t.sentFields(1)
        assertEquals("transaction", f["type"])
        assertEquals(report.transaction.bindingSha256, f["bindingSha256"])
        assertEquals(report.transaction.beneficiaryHash, f["beneficiaryHash"])
        assertEquals("INR", f["currency"])
        assertEquals("upi", f["channel"])
        assertNull(f["sessionEvent"])
        assertTrue(verify(f, t.signer))
        assertTrue((f["monotonicCounter"] as Long) > report.transaction.counter)
    }

    @Test fun `invalid amounts, currencies, channels and ids are rejected`() {
        val t = Api()
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        for (amount in listOf("", "-1", "0", "0.000", "1e5", "1,000", "12.1234567", "1234567890123456")) {
            assertThrows(amount, IllegalArgumentException::class.java) { t.api.signTransaction(amount, "INR", "b") }
        }
        assertThrows(IllegalArgumentException::class.java) { t.api.signTransaction("1", "inr", "b") }
        assertThrows(IllegalArgumentException::class.java) { t.api.signTransaction("1", "INR", "") }
        assertThrows(IllegalArgumentException::class.java) { t.api.reportTransaction("1", "INR", "b", "UPI") }
        assertThrows(IllegalArgumentException::class.java) { t.api.reportTransaction("1", "INR", "b", "x".repeat(33)) }
        assertThrows(IllegalArgumentException::class.java) { t.api.reportSession("", "s", RaspSessionEvent.LOGIN) }
    }

    @Test fun `no salt means no hashing at all`() {
        val t = Api(saltValue = null)
        assertThrows(IllegalStateException::class.java) { t.api.reportSession("acct-42", "s", RaspSessionEvent.LOGIN) }
        assertTrue(t.sent.isEmpty())
    }

    @Test fun `location is attached only with opt-in`() {
        val optIn = Api(location = RaspLocationSnapshot(12.5, 77.25, capturedAtMillis = 5L, shareWithBackend = true))
        optIn.api.reportSession("a", "s", RaspSessionEvent.RESUME)
        assertEquals(mapOf("capturedAtMillis" to 5L, "latitude" to 12.5, "longitude" to 77.25), optIn.sentFields(0)["location"])
        val deviceOnly = Api(location = RaspLocationSnapshot(12.5, 77.25, shareWithBackend = false))
        deviceOnly.api.reportSession("a", "s", RaspSessionEvent.RESUME)
        assertNull(deviceOnly.sentFields(0)["location"])
    }

    /**
     * Writes real engine output (a signed session event with an opted-in
     * location, a signed transaction event and its binding) to
     * build/rasp-risk-fixture.json. The backend test
     * test/riskSdkInterop.test.ts checks a copy of this file with its real
     * schema, canonical JSON and ES256 verification.
     */
    @Test fun `writes the cross-language fixture for the backend`() {
        val t = Api(location = RaspLocationSnapshot(12.9716, 77.5946, capturedAtMillis = 1_789_999_990_000L, shareWithBackend = true))
        t.api.reportSession("acct-42", "session-1", RaspSessionEvent.LOGIN)
        val tx = t.api.reportTransaction("1500.00", "INR", "benef-1", "upi").transaction
        val fixture = linkedMapOf<String, Any?>(
            "note" to "Generated by RaspTask81Test in rashield-sdk-publish; do not edit by hand.",
            "publicKeySpkiBase64" to RaspBase64.encode(t.signer.publicKeySpki()),
            "appId" to "com.example.bank",
            "eventTimeMillis" to 1_790_000_000_000L,
            "sessionEvent" to t.sent[0],
            "transactionEvent" to t.sent[1],
            "binding" to linkedMapOf("canonical" to tx.canonical, "signature" to tx.signatureBase64, "bindingSha256" to tx.bindingSha256),
        )
        val out = java.io.File("build/rasp-risk-fixture.json")
        out.parentFile?.mkdirs()
        out.writeText(RaspCanonicalJson.encode(fixture))
        assertTrue(out.length() > 0)
    }

    @Test fun `session events map to their wire names`() {
        assertEquals(listOf("login", "resume", "logout"), RaspSessionEvent.entries.map { it.wire })
        assertEquals(RaspSessionEvent.RESUME, RaspSessionEvent.fromWire("resume"))
        assertNull(RaspSessionEvent.fromWire("LOGIN"))
    }

    // ── risk-event delivery (real HTTP to a local server) ────────────────

    private class FixedKey : RaspRegistrationKeySource {
        override fun deviceKeyId() = "key-1"
        override fun publicKeyBase64() = "PUBLIC"
        override fun attestationChainBase64() = listOf("LEAF")
    }

    private class MemoryStore : RaspRegistrationStore {
        @Volatile var keyId: String? = null
        override fun registeredKeyId() = keyId
        override fun setRegisteredKeyId(keyId: String?): Boolean { this.keyId = keyId; return true }
    }

    private fun delivery(server: FakeHttpServer, store: MemoryStore = MemoryStore()): RaspRiskEventDelivery {
        val credential = RaspEventCredential("org", "app", "api-key-1", "secret-1", "${server.baseUrl}/v1/events", salt)
        val registrar = RaspDeviceRegistrar(FixedKey(), store, appId = "com.example.bank", sdkVersion = "test")
        return RaspRiskEventDelivery({ credential }, registrar, sleep = {})
    }

    @Test fun `risk events go to v1 risk events with the API key only, after registration`() {
        val server = FakeHttpServer { if (it.path == "/v1/devices/register") 201 else 202 }
        server.use {
            assertEquals(RaspRiskEventDelivery.Outcome.DELIVERED, delivery(server).deliver("""{"type":"session"}"""))
            assertEquals(listOf("/v1/devices/register", "/v1/risk/events"), server.requests.map { it.path })
            val post = server.requests[1]
            assertEquals("api-key-1", post.headers["x-api-key"])
            assertNull(post.headers["x-signature"])
            assertFalse(server.requests.any { it.body.contains("secret-1") || it.headers.values.any { v -> v.contains("secret-1") } })
        }
    }

    @Test fun `401 registers again and retries once, 409 replay is dropped, 5xx retries then fails`() {
        var riskAnswers = ArrayDeque(listOf(401, 202))
        val server = FakeHttpServer { if (it.path == "/v1/devices/register") 201 else riskAnswers.removeFirst() }
        server.use {
            assertEquals(RaspRiskEventDelivery.Outcome.DELIVERED, delivery(server).deliver("{}"))
            assertEquals(2, server.requests.count { it.path == "/v1/devices/register" })

            riskAnswers = ArrayDeque(listOf(409))
            assertEquals(RaspRiskEventDelivery.Outcome.DROPPED, delivery(server).deliver("{}"))

            riskAnswers = ArrayDeque(listOf(503, 503, 503))
            assertEquals(RaspRiskEventDelivery.Outcome.FAILED, delivery(server).deliver("{}"))
        }
    }

    @Test fun `no credential means nothing is sent`() {
        val registrar = RaspDeviceRegistrar(FixedKey(), MemoryStore(), appId = "a")
        val d = RaspRiskEventDelivery({ null }, registrar, http = { _, _, _ -> error("must not post") }, sleep = {})
        assertFalse(d.sendAsync("{}"))
        assertEquals(RaspRiskEventDelivery.Outcome.NOT_CONFIGURED, d.deliver("{}"))
        assertNotNull(RaspBackendUrls.endpoint("https://x.test/v1/events", "risk/events"))
    }
}
