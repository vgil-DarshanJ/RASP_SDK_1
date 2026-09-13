package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Malware & Risky-App Intelligence — signing identity, install source, and
 * threat-intelligence classification for the same curated
 * `<queries>`-visible packages [RaspRiskyAppProbes] checks by presence.
 *
 * Verbatim port of the Dart layer's `AppIntelligenceDetector`/
 * `LocalReputationProvider`/`InstallSourceX` classification rules — see
 * `lib/sdk/detectors/app_intelligence.dart` and `reputation_provider.dart`
 * in the Flutter plugin, which this file mirrors field-for-field so a
 * finding classifies identically whichever consumption path produced it.
 *
 * **Not a malware scanner.** Android 11+ package-visibility rules mean this
 * (and every consumer of this SDK) can only see packages named in the
 * `<queries>` manifest block — a small, curated, auditable list, never
 * expanded at runtime. This SDK does not request `QUERY_ALL_PACKAGES`
 * (a sensitive Play Store permission requiring justification) on a
 * consuming app's behalf.
 */
public enum class AppRiskClassification { KNOWN_MALICIOUS, HIGH_RISK, SUSPICIOUS, CLEAN, UNKNOWN, UNAVAILABLE }

public enum class IntelConfidence { CONFIRMED, HIGH, MEDIUM, LOW }

public enum class InstallSource { PLAY_STORE, KNOWN_TRUSTED_SOURCE, UNKNOWN_SOURCE, SIDELOADED, UNAVAILABLE }

public data class ThreatIntelRecord(
    val pkg: String,
    val certificateSha256: String? = null,
    val threatClass: String,
    val classification: AppRiskClassification,
    val confidence: IntelConfidence,
    val source: String = "rasp_local_db",
    val description: String,
)

public data class AppRiskProfile(
    val pkg: String,
    val versionName: String?,
    val versionCode: Long?,
    val installSource: InstallSource,
    val observedCertificateSha256: String?,
    val signingMismatch: Boolean,
    val classification: AppRiskClassification,
    val confidence: IntelConfidence,
    val evidence: List<String>,
)

public object RaspAppIntelligenceProbes {

    /**
     * The same seven packages as [RaspRiskyAppProbes.knownRiskyPackages] —
     * kept in exact agreement (asserted by a unit test) since both must stay
     * scoped to what `<queries>` actually declares.
     */
    val defaultDatabase: List<ThreatIntelRecord> = listOf(
        ThreatIntelRecord(
            pkg = "com.teamviewer.quicksupport.market",
            threatClass = "remote_access_tool",
            classification = AppRiskClassification.HIGH_RISK,
            confidence = IntelConfidence.HIGH,
            description = "TeamViewer QuickSupport — legitimate remote-support tool, high " +
                "risk when present alongside a banking session.",
        ),
        ThreatIntelRecord(
            pkg = "com.teamviewer.host.market",
            threatClass = "remote_access_tool",
            classification = AppRiskClassification.HIGH_RISK,
            confidence = IntelConfidence.HIGH,
            description = "TeamViewer Host — persistent unattended remote access.",
        ),
        ThreatIntelRecord(
            pkg = "com.anydesk.anydeskandroid",
            threatClass = "remote_access_tool",
            classification = AppRiskClassification.HIGH_RISK,
            confidence = IntelConfidence.HIGH,
            description = "AnyDesk remote desktop client.",
        ),
        ThreatIntelRecord(
            pkg = "com.rsupport.mobizen.remote",
            threatClass = "remote_access_tool",
            classification = AppRiskClassification.HIGH_RISK,
            confidence = IntelConfidence.HIGH,
            description = "Mobizen remote control / screen mirroring.",
        ),
        ThreatIntelRecord(
            pkg = "com.remotepc.rpcmobile",
            threatClass = "remote_access_tool",
            classification = AppRiskClassification.HIGH_RISK,
            confidence = IntelConfidence.HIGH,
            description = "RemotePC mobile remote-access client.",
        ),
        ThreatIntelRecord(
            pkg = "de.robv.android.xposed",
            threatClass = "instrumentation_framework",
            classification = AppRiskClassification.KNOWN_MALICIOUS,
            confidence = IntelConfidence.CONFIRMED,
            description = "Xposed framework — runtime code injection into every app on " +
                "the device, including this one.",
        ),
        ThreatIntelRecord(
            pkg = "com.saurik.substrate",
            threatClass = "instrumentation_framework",
            classification = AppRiskClassification.KNOWN_MALICIOUS,
            confidence = IntelConfidence.CONFIRMED,
            description = "Cydia Substrate — native/Java hooking framework.",
        ),
    )

    private val byPackage: Map<String, List<ThreatIntelRecord>> =
        defaultDatabase.groupBy { it.pkg }

    /**
     * Certificate-scoped records are checked first so a counterfeit
     * reference outranks a looser package-only entry. When every candidate
     * is certificate-scoped and none match, a synthetic
     * `unexpected_signing_identity` record is returned — the counterfeit
     * signal itself, not a lookup failure.
     */
    fun lookup(pkg: String, certificateSha256: String?): ThreatIntelRecord? {
        val candidates = byPackage[pkg] ?: return null
        candidates.firstOrNull { it.certificateSha256 != null && it.certificateSha256 == certificateSha256 }
            ?.let { return it }
        candidates.firstOrNull { it.certificateSha256 == null }?.let { return it }
        val reference = candidates.first()
        return ThreatIntelRecord(
            pkg = pkg,
            certificateSha256 = certificateSha256,
            threatClass = "unexpected_signing_identity",
            classification = AppRiskClassification.SUSPICIOUS,
            confidence = IntelConfidence.MEDIUM,
            source = "rasp_local_db",
            description = "Package name matches a known entry (${reference.threatClass}) but " +
                "the observed signing certificate does not match any expected certificate for it.",
        )
    }

    private val trustedInstallerPackages = setOf(
        "com.android.vending",
        "com.amazon.venezia",
        "com.sec.android.app.samsungapps",
        "com.huawei.appmarket",
        "com.xiaomi.market",
    )

    private val sideloadMarkers = setOf(
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "null",
    )

    fun classifyInstallSource(installerPackage: String?): InstallSource = when {
        installerPackage == null -> InstallSource.UNAVAILABLE
        installerPackage.isEmpty() -> InstallSource.UNKNOWN_SOURCE
        installerPackage == "com.android.vending" -> InstallSource.PLAY_STORE
        installerPackage in trustedInstallerPackages -> InstallSource.KNOWN_TRUSTED_SOURCE
        installerPackage in sideloadMarkers -> InstallSource.SIDELOADED
        else -> InstallSource.UNKNOWN_SOURCE
    }

    /** SHA-256 of [pkg]'s signing certificate, or `null` if unreadable. */
    fun packageSigningSha256(context: Context, pkg: String): String? = try {
        val pm = context.packageManager
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            val signingInfo = info.signingInfo ?: return null
            if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
            else signingInfo.signingCertificateHistory
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures
        }
        val first = signatures?.firstOrNull() ?: return null
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
        digest.joinToString("") { "%02x".format(it) }
    } catch (e: Exception) {
        null
    }

    private fun installerPackageName(context: Context, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(pkg)
        }
    } catch (e: Exception) {
        null
    }

    /**
     * One [AppRiskProfile] per installed, `<queries>`-visible package from
     * [RaspRiskyAppProbes.knownRiskyPackages] — only packages actually
     * installed are profiled (matching the Dart layer's
     * `getAppIntelligence` contract, which only reports rows for installed
     * packages).
     */
    fun profileInstalledPackages(context: Context): List<AppRiskProfile> {
        val pm = context.packageManager
        return RaspRiskyAppProbes.knownRiskyPackages.keys.mapNotNull { pkg ->
            val installed = try {
                pm.getPackageInfo(pkg, 0)
            } catch (e: Exception) {
                null
            } ?: return@mapNotNull null

            buildProfile(
                context = context,
                pkg = pkg,
                versionName = installed.versionName,
                versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    installed.longVersionCode
                } else {
                    @Suppress("DEPRECATION")
                    installed.versionCode.toLong()
                },
            )
        }
    }

    /**
     * Pure, deterministic — same signature-shape as the Dart layer's
     * `AppIntelligenceDetector.buildProfile` static method, and testable
     * the same way (feed it fixed inputs, assert the classification, no
     * PackageManager needed).
     */
    fun buildProfile(
        context: Context,
        pkg: String,
        versionName: String?,
        versionCode: Long?,
    ): AppRiskProfile {
        val signingSha256 = packageSigningSha256(context, pkg)
        val installerPackage = installerPackageName(context, pkg)
        val installSource = classifyInstallSource(installerPackage)

        val record = lookup(pkg, signingSha256)
        val evidence = mutableListOf<String>()
        var classification: AppRiskClassification
        val confidence: IntelConfidence
        var signingMismatch = false

        if (record == null) {
            classification = AppRiskClassification.UNKNOWN
            confidence = IntelConfidence.LOW
            evidence.add("no_reputation_record")
        } else {
            classification = record.classification
            confidence = record.confidence
            evidence.add(record.threatClass)
            if (record.threatClass == "unexpected_signing_identity") {
                signingMismatch = true
                evidence.add("signing_mismatch")
            }
        }

        if (installSource == InstallSource.SIDELOADED || installSource == InstallSource.UNKNOWN_SOURCE) {
            evidence.add("untrusted_install_source")
            if (classification == AppRiskClassification.SUSPICIOUS) {
                classification = AppRiskClassification.HIGH_RISK
            }
        }

        return AppRiskProfile(
            pkg = pkg,
            versionName = versionName,
            versionCode = versionCode,
            installSource = installSource,
            observedCertificateSha256 = signingSha256,
            signingMismatch = signingMismatch,
            classification = classification,
            confidence = confidence,
            evidence = evidence,
        )
    }
}
