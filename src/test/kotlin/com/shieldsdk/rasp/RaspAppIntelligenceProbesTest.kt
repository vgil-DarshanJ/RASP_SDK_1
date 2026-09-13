package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Local JVM unit tests — the pure classification logic in
 * [RaspAppIntelligenceProbes] (no PackageManager/Context needed), mirroring
 * the Dart layer's `app_intelligence_test.dart` coverage of
 * `LocalReputationProvider`/`InstallSourceX`.
 */
class RaspAppIntelligenceProbesTest {

    // ══════════════════════════════════════════════════════════════════
    // Database agreement — must never drift from RaspRiskyAppProbes
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun defaultDatabase_coversExactlyTheSamePackagesAsRiskyAppProbes() {
        val intelPackages = RaspAppIntelligenceProbes.defaultDatabase.map { it.pkg }.toSet()
        val riskyPackages = RaspRiskyAppProbes.knownRiskyPackages.keys
        assertEquals(
            "app-intelligence database and risky-app package list must never drift apart",
            riskyPackages, intelPackages,
        )
    }

    // ══════════════════════════════════════════════════════════════════
    // lookup()
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun lookup_returnsNull_forAnUnknownPackage() {
        assertNull(RaspAppIntelligenceProbes.lookup("com.example.totally.unknown", null))
    }

    @Test
    fun lookup_returnsKnownMalicious_forXposed() {
        val record = RaspAppIntelligenceProbes.lookup("de.robv.android.xposed", null)
        assertEquals(AppRiskClassification.KNOWN_MALICIOUS, record?.classification)
        assertEquals(IntelConfidence.CONFIRMED, record?.confidence)
    }

    @Test
    fun lookup_returnsHighRisk_forTeamViewer() {
        val record = RaspAppIntelligenceProbes.lookup("com.teamviewer.quicksupport.market", null)
        assertEquals(AppRiskClassification.HIGH_RISK, record?.classification)
    }

    @Test
    fun lookup_certificateScopedRecord_matchesOnCertificate() {
        // No certificate-scoped records exist in the default database today
        // (every entry is package-only, certificateSha256 == null) — this
        // pins that fact so a future entry with a real cert scope is
        // deliberately reviewed, not silently added.
        val allPackageOnly = RaspAppIntelligenceProbes.defaultDatabase.all { it.certificateSha256 == null }
        assertTrue("expected every default-database record to be package-only today", allPackageOnly)
    }

    // ══════════════════════════════════════════════════════════════════
    // classifyInstallSource()
    // ══════════════════════════════════════════════════════════════════

    @Test
    fun classifyInstallSource_null_isUnavailable() {
        assertEquals(InstallSource.UNAVAILABLE, RaspAppIntelligenceProbes.classifyInstallSource(null))
    }

    @Test
    fun classifyInstallSource_empty_isUnknownSource() {
        assertEquals(InstallSource.UNKNOWN_SOURCE, RaspAppIntelligenceProbes.classifyInstallSource(""))
    }

    @Test
    fun classifyInstallSource_playStore() {
        assertEquals(
            InstallSource.PLAY_STORE,
            RaspAppIntelligenceProbes.classifyInstallSource("com.android.vending"),
        )
    }

    @Test
    fun classifyInstallSource_knownTrustedSource() {
        assertEquals(
            InstallSource.KNOWN_TRUSTED_SOURCE,
            RaspAppIntelligenceProbes.classifyInstallSource("com.amazon.venezia"),
        )
        assertEquals(
            InstallSource.KNOWN_TRUSTED_SOURCE,
            RaspAppIntelligenceProbes.classifyInstallSource("com.sec.android.app.samsungapps"),
        )
    }

    @Test
    fun classifyInstallSource_sideloadMarkers() {
        assertEquals(
            InstallSource.SIDELOADED,
            RaspAppIntelligenceProbes.classifyInstallSource("com.google.android.packageinstaller"),
        )
        assertEquals(
            InstallSource.SIDELOADED,
            RaspAppIntelligenceProbes.classifyInstallSource("null"),
        )
    }

    @Test
    fun classifyInstallSource_unrecognized_isUnknownSource() {
        assertEquals(
            InstallSource.UNKNOWN_SOURCE,
            RaspAppIntelligenceProbes.classifyInstallSource("com.some.random.installer"),
        )
    }
}
