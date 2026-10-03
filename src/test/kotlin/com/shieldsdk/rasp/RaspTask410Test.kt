package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Task 4.10: undecided reads are never SECURE (risky_app, re_tools,
 * device_fingerprint), tamper without a configured certificate, the root
 * hard/soft rule, and strict SPKI pin validation.
 *
 * Real: every evaluate / verdict function, RaspRootAnalysis.classifyRootVerdict,
 * RaspCertificatePinProbes.isPin / checkCertificatePinDetailed (invalid pins
 * return before any network I/O) and RaspMitmAnalysis.
 * Doubles: probe results are passed in (PackageManager, Settings and the
 * file system need a device).
 */
class RaspTask410Test {

    // ── risky_app ────────────────────────────────────────────────────────

    private val anydesk = RiskyAppSignal("com.anydesk.anydeskandroid", RiskyAppCategory.KNOWN_RISKY_PACKAGE, "remote_access")

    @Test fun `risky_app - listed package found is DETECTED with the same evidence name`() {
        val r = RaspRiskyAppProbes.evaluate(RaspRiskyAppProbes.Observation(listOf(anydesk), emptyList()))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals("known_risky_package", r.evidence.first().key)
        assertEquals("remote_access", r.evidence.first().note)
    }

    @Test fun `risky_app - nothing found and every query answered is SECURE`() {
        assertEquals(RaspCheckStatus.SECURE, RaspRiskyAppProbes.evaluate(RaspRiskyAppProbes.Observation(emptyList(), emptyList())).status)
    }

    @Test fun `risky_app - a failed package query is UNKNOWN, never SECURE`() {
        val r = RaspRiskyAppProbes.evaluate(RaspRiskyAppProbes.Observation(emptyList(), listOf("com.teamviewer.host.market")))
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals(listOf<Any?>("com.teamviewer.host.market"), r.evidence.filter { it.key == "query_failed" }.map { it.value })
    }

    @Test fun `risky_app - a match still decides when another query failed`() {
        val r = RaspRiskyAppProbes.evaluate(RaspRiskyAppProbes.Observation(listOf(anydesk), listOf("com.teamviewer.host.market")))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
    }

    // ── re_tools ─────────────────────────────────────────────────────────

    @Test fun `re_tools - found is DETECTED, clean is SECURE, failed query is UNKNOWN`() {
        assertEquals(RaspCheckStatus.DETECTED,
            RaspReverseEngineeringToolsProbe.evaluate(RaspReverseEngineeringToolsProbe.Observation(listOf("com.chelpus.lackypatch"), emptyList())).status)
        assertEquals(RaspCheckStatus.SECURE,
            RaspReverseEngineeringToolsProbe.evaluate(RaspReverseEngineeringToolsProbe.Observation(emptyList(), emptyList())).status)
        val failed = RaspReverseEngineeringToolsProbe.evaluate(RaspReverseEngineeringToolsProbe.Observation(emptyList(), listOf("io.va.exposed")))
        assertEquals(RaspCheckStatus.UNKNOWN, failed.status)
        assertEquals("re_tool_package",
            RaspReverseEngineeringToolsProbe.evaluate(RaspReverseEngineeringToolsProbe.Observation(listOf("io.va.exposed"), emptyList())).evidence.first().key)
    }

    // ── device_fingerprint ───────────────────────────────────────────────

    private fun fp(lock: Boolean? = true, adb: Boolean? = false, selinux: Boolean? = true, installer: String? = "com.android.vending") =
        RaspDeviceFingerprintProbes.Fingerprint(null, "Model", "Maker", "board", "hw", "fp", lock, adb, installer, selinux)

    private fun fpStatus(f: RaspDeviceFingerprintProbes.Fingerprint?) = RaspDeviceFingerprintProbes.evaluate(f).status

    @Test fun `device_fingerprint - everything readable and fine is SECURE`() {
        assertEquals(RaspCheckStatus.SECURE, fpStatus(fp()))
    }

    @Test fun `device_fingerprint - unreadable ADB setting is UNKNOWN, not ADB off`() {
        val r = RaspDeviceFingerprintProbes.evaluate(fp(adb = null))
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertTrue(r.evidence.any { it.key == "device_fingerprint_unknown" && it.value == "adb_unknown" })
    }

    @Test fun `device_fingerprint - unreadable install source is UNKNOWN, not a sideload`() {
        val r = RaspDeviceFingerprintProbes.evaluate(fp(installer = null))
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("unreadable", r.evidence.first { it.key == "install_source" }.value)
    }

    @Test fun `device_fingerprint - other unreadable states and no fingerprint are UNKNOWN`() {
        assertEquals(RaspCheckStatus.UNKNOWN, fpStatus(fp(lock = null)))
        assertEquals(RaspCheckStatus.UNKNOWN, fpStatus(fp(selinux = null)))
        assertEquals(RaspCheckStatus.UNKNOWN, fpStatus(null))
    }

    @Test fun `device_fingerprint - a failed check is DETECTED even when another is unreadable`() {
        assertEquals(RaspCheckStatus.DETECTED, fpStatus(fp(adb = true)))
        assertEquals(RaspCheckStatus.DETECTED, fpStatus(fp(installer = "unknown", adb = null)))
    }

    // ── tamper ───────────────────────────────────────────────────────────

    @Test fun `tamper - no expected certificate configured is UNKNOWN not configured`() {
        val r = RaspSigningProbes.tamperVerdict(expectedConfigured = false, mismatch = null, installMissing = false)
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertEquals("not configured", r.reason)
    }

    @Test fun `tamper - configured certificate decides, unreadable own certificate is ERROR`() {
        assertEquals(RaspCheckStatus.SECURE, RaspSigningProbes.tamperVerdict(true, mismatch = false, installMissing = false).status)
        assertEquals(RaspCheckStatus.DETECTED, RaspSigningProbes.tamperVerdict(true, mismatch = true, installMissing = false).status)
        assertEquals(RaspCheckStatus.ERROR, RaspSigningProbes.tamperVerdict(true, mismatch = null, installMissing = false).status)
    }

    @Test fun `tamper - missing install directory is DETECTED even without a certificate, unreadable one is not SECURE`() {
        assertEquals(RaspCheckStatus.DETECTED, RaspSigningProbes.tamperVerdict(false, mismatch = null, installMissing = true).status)
        assertEquals(RaspCheckStatus.UNKNOWN, RaspSigningProbes.tamperVerdict(true, mismatch = false, installMissing = null).status)
    }

    // ── root_jailbreak ───────────────────────────────────────────────────

    private fun root(vararg signals: String) =
        RaspRootAnalysis.classifyRootVerdict(signals.toList(), RaspRootAnalysis.MountTableAccess.READABLE)

    @Test fun `root - a root manager app alone is not DETECTED`() {
        assertEquals(RaspRootAnalysis.RootVerdict.CLEAN, root("root_manager_app"))
        assertFalse(RaspRootAnalysis.isRooted(listOf("root_manager_app")))
        assertFalse("the same soft signal twice is still one", RaspRootAnalysis.isRooted(listOf("busybox", "busybox")))
    }

    @Test fun `root - two soft signals are DETECTED`() {
        assertEquals(RaspRootAnalysis.RootVerdict.DETECTED, root("root_manager_app", "root_cloaking_app"))
        assertEquals(RaspRootAnalysis.RootVerdict.DETECTED, root("root_manager_app", "busybox"))
    }

    @Test fun `root - each hard signal alone is DETECTED`() {
        for (signal in listOf("su_binary", "su_on_path", "magisk_artifact", "mount_namespace", "system_writable", "ro_insecure")) {
            assertEquals(signal, RaspRootAnalysis.RootVerdict.DETECTED, root(signal))
        }
    }

    @Test fun `root - one soft signal with an unreadable mount table is UNAVAILABLE, never CLEAN`() {
        assertEquals(RaspRootAnalysis.RootVerdict.UNAVAILABLE,
            RaspRootAnalysis.classifyRootVerdict(listOf("root_manager_app"), RaspRootAnalysis.MountTableAccess.NOT_ACCESSIBLE))
    }

    @Test fun `root - hard and soft sets split the signal ids exactly, names unchanged`() {
        assertEquals(RaspRootAnalysis.allSignalIds.toSet(), RaspRootAnalysis.hardSignalIds + RaspRootAnalysis.softSignalIds)
        assertTrue((RaspRootAnalysis.hardSignalIds intersect RaspRootAnalysis.softSignalIds).isEmpty())
    }

    // ── SPKI pin validation ──────────────────────────────────────────────

    private val pin32 = "sha256/" + RaspBase64.encode(ByteArray(32) { it.toByte() })

    @Test fun `pin - sha256 prefix plus Base64 of exactly 32 bytes is valid`() {
        assertTrue(RaspCertificatePinProbes.isPin(pin32))
    }

    @Test fun `pin - anything else is invalid`() {
        for (bad in listOf(
            "sha256/AAAA",                                               // 3 bytes
            "sha256/" + RaspBase64.encode(ByteArray(31)),
            "sha256/" + RaspBase64.encode(ByteArray(33)),
            pin32.removePrefix("sha256/"),                               // no prefix
            "sha1/" + RaspBase64.encode(ByteArray(32)),
            "sha256/%%%%",
            "sha256/",
        )) {
            assertFalse(bad, RaspCertificatePinProbes.isPin(bad))
        }
    }

    @Test fun `pin - an invalid pin gives ERROR invalid pin through the real pin check`() {
        for (bad in listOf("sha256/AAAA", "sha256/%%%%")) {
            val pin = RaspMitmAnalysis.PinConfig("api.example.com", RaspCertificatePinProbes.PinSet(setOf(bad)))
            val r = RaspMitmAnalysis.evaluate(RaspNetworkProbes.MitmProbe(emptySet(), emptySet()), pin) {
                RaspCertificatePinProbes.checkCertificatePinDetailed(it.host, it.pins)
            }
            assertEquals(bad, RaspCheckStatus.ERROR, r.status)
            assertEquals("invalid pin", r.reason)
        }
        // A bad revoked pin also makes the configuration invalid.
        val revokedBad = RaspCertificatePinProbes.PinSet(setOf(pin32), revoked = setOf("sha256/AAAA"))
        assertEquals(CertificatePinCheckResult.INVALID_CONFIGURATION,
            RaspCertificatePinProbes.checkCertificatePinDetailed("api.example.com", revokedBad).result)
    }
}
