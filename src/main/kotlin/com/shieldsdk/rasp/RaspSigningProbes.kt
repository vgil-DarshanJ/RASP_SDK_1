package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * App-integrity probes: signing-certificate fingerprint, tamper detection,
 * and untrusted install source. Verbatim port of the logic inline in
 * `RaspSecurityChannelHandler.kt` (`signingCertSha256`/`verifySignature`/
 * `isAppTampered`/`isUntrustedInstallSource`), **except** for one
 * deliberate change: [signingIdentity] never reflects into a host app's
 * generated `BuildConfig` class.
 *
 * ## The reflection dependency this port removes
 *
 * The original `readHostSigningBuildConfig()` reflectively read
 * `<hostPackage>.BuildConfig.RASP_RELEASE_SIGNING_CONFIGURED`/
 * `RASP_SIGNING_MODE` — a convention specific to the Flutter reference
 * app, which happens to declare those exact custom BuildConfig fields in
 * its own `build.gradle.kts`. A native host has no reason to know that
 * convention exists, let alone declare those fields, so the reflection
 * would silently and permanently report `signing_configured=false,
 * signing_mode="unknown"` for every native consumer — a magic dependency
 * on an undocumented host-app convention. This port drops it entirely:
 * [RaspShieldCore.configureExpectedSigningCertificate] is the one explicit
 * configuration surface, matching the pattern the Dart side's own
 * `RepackagingDetector` already uses.
 */
public object RaspSigningProbes {

    /** `""` when it could not be determined — callers must treat that as
     *  "unknown," never as a mismatch or a match. */
    fun signingCertSha256(context: Context): String = try {
        val pm = context.packageManager
        val pkgName = context.packageName
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signingInfo = info.signingInfo ?: return ""
            if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
            else signingInfo.signingCertificateHistory
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES).signatures
        }

        val first = signatures?.firstOrNull() ?: return ""
        val digest = MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
        digest.joinToString("") { "%02X".format(it) }
    } catch (e: Exception) {
        ""
    }

    /** `null` when it could not be determined (certificate unreadable). */
    fun isDebugCertificate(context: Context): Boolean? = try {
        val pm = context.packageManager
        val pkgName = context.packageName
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signingInfo = info.signingInfo
            if (signingInfo == null) null
            else if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
            else signingInfo.signingCertificateHistory
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES).signatures
        }
        val raw = signatures?.firstOrNull()?.toByteArray() ?: return null
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(raw.inputStream()) as X509Certificate
        cert.subjectX500Principal.name.contains("CN=Android Debug", ignoreCase = true)
    } catch (e: Exception) {
        null
    }

    /**
     * `true` when the running build's certificate does NOT match
     * [expectedFingerprintSha256Hex] (already normalized — no `:`/spaces/
     * dashes, uppercase). `null` when the running certificate could not be
     * read at all (distinct from "does not match").
     */
    fun signatureMismatches(context: Context, expectedFingerprintSha256Hex: String): Boolean? {
        val actual = signingCertSha256(context)
        if (actual.isEmpty()) return null
        return actual != expectedFingerprintSha256Hex
    }

    /**
     * `true` when the APK's own install directory is missing — the
     * cheaper of [isAppTampered]'s two signals, checked independently of
     * signature configuration so tamper detection still means something
     * even with no expected fingerprint configured.
     */
    fun installDirectoryMissing(context: Context): Boolean = try {
        val sourceDir = context.applicationInfo.sourceDir
        sourceDir == null || !java.io.File(sourceDir).exists()
    } catch (e: Exception) {
        true
    }

    private val trustedInstallers = setOf(
        "com.android.vending",
        "com.google.android.feedback",
        "com.amazon.venezia",
        "com.huawei.appmarket",
        "com.sec.android.app.samsungapps",
    )

    /** `null` only on a catastrophic PackageManager failure. */
    fun isUntrustedInstallSource(context: Context): Boolean? = try {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager
                .getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(context.packageName)
        }
        installer == null || installer !in trustedInstallers
    } catch (e: Exception) {
        null
    }
}
