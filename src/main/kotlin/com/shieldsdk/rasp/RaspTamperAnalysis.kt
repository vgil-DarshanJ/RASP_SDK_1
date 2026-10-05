package com.shieldsdk.rasp

import android.content.Context
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipFile

/**
 * `tamper` — has this installed app been modified or moved since it was built?
 *
 * Checks (each reported as `check_<name>` evidence):
 * - `signing_certificate`: the APK's signing certificate SHA-256 against the
 *   expected one (RaspLeanConfig.expectedSigningCertSha256 /
 *   RaspShieldCore.configureExpectedSigningCertificate);
 * - `installer`: the installing package against [Expected.installers]
 *   (e.g. `com.android.vending`); empty = not configured;
 * - `apk_path`: the base APK lives where Android installs apps
 *   (`/data/app/…`, adoptable storage `/mnt/expand/<uuid>/app/…`, or a system
 *   partition) and its directory exists — always checked;
 * - `classes_dex` / `resources_arsc`: SHA-256 of the APK's dex code and
 *   resource table against values baked at build time, when present
 *   (see [dexSha256] for the exact digest).
 *
 * Verdict: any mismatch → DETECTED (each failed check named in `failed_check`);
 * else a check that could not be read → ERROR; else nothing configured beyond
 * the built-in path check → UNKNOWN "not configured"; else SECURE.
 *
 * The observed `signing_cert_sha256` is always reported so the backend can
 * compare it with the hash stored at device registration.
 */
object RaspTamperAnalysis {

    const val DETECTOR_ID = "tamper"
    const val NOT_CONFIGURED = "not configured"

    data class Expected(
        /** Normalized uppercase hex, no separators; `null` = not configured. */
        val signingCertSha256: String? = null,
        val installers: Set<String> = emptySet(),
        val classesDexSha256: String? = null,
        val resourcesArscSha256: String? = null,
    ) {
        val anythingConfigured: Boolean
            get() = signingCertSha256 != null || installers.isNotEmpty() ||
                classesDexSha256 != null || resourcesArscSha256 != null
    }

    data class Observation(
        /** Uppercase hex; `null` when it could not be read. */
        val signingCertSha256: String?,
        /** `false` when the installer could not be read at all. */
        val installerReadable: Boolean,
        /** The installing package; `null` when none is recorded (adb, file manager). */
        val installer: String?,
        /** Base APK path; `null` when it could not be read. */
        val apkPath: String?,
        val installDirectoryMissing: Boolean?,
        /** `null` when not computed (not configured) or unreadable — see [apkEntriesReadable]. */
        val classesDexSha256: String? = null,
        val resourcesArscSha256: String? = null,
        /** `false` when the APK could not be read for the hashes that were asked for. */
        val apkEntriesReadable: Boolean = true,
    )

    enum class Check { MATCH, MISMATCH, NOT_CONFIGURED, UNREADABLE }

    /** Where Android puts installed APKs. Anything else (e.g. /data/local/tmp, /sdcard, another app's data) is unexpected. */
    fun isExpectedApkPath(path: String): Boolean {
        if (path.contains("/../")) return false
        return path.startsWith("/data/app/") ||
            Regex("^/mnt/expand/[^/]+/app/").containsMatchIn(path) ||
            listOf("/system/app/", "/system/priv-app/", "/product/app/", "/product/priv-app/",
                "/system_ext/app/", "/system_ext/priv-app/", "/vendor/app/").any { path.startsWith(it) }
    }

    fun normalizeHex(value: String?): String? =
        value?.replace(Regex("[:\\s-]"), "")?.uppercase()?.takeIf { it.isNotEmpty() }

    fun evaluate(o: Observation, e: Expected): RaspCheckResult {
        val checks = linkedMapOf<String, Check>()
        checks["signing_certificate"] = when {
            e.signingCertSha256 == null -> Check.NOT_CONFIGURED
            o.signingCertSha256 == null -> Check.UNREADABLE
            o.signingCertSha256 == e.signingCertSha256 -> Check.MATCH
            else -> Check.MISMATCH
        }
        checks["installer"] = when {
            e.installers.isEmpty() -> Check.NOT_CONFIGURED
            !o.installerReadable -> Check.UNREADABLE
            o.installer != null && o.installer in e.installers -> Check.MATCH
            else -> Check.MISMATCH
        }
        checks["apk_path"] = when {
            o.installDirectoryMissing == true -> Check.MISMATCH
            o.apkPath == null || o.installDirectoryMissing == null -> Check.UNREADABLE
            isExpectedApkPath(o.apkPath) -> Check.MATCH
            else -> Check.MISMATCH
        }
        checks["classes_dex"] = hashCheck(e.classesDexSha256, o.classesDexSha256, o.apkEntriesReadable)
        checks["resources_arsc"] = hashCheck(e.resourcesArscSha256, o.resourcesArscSha256, o.apkEntriesReadable)

        val failed = checks.filterValues { it == Check.MISMATCH }.keys
        val unreadable = checks.filterValues { it == Check.UNREADABLE }.keys
        val evidence = buildList {
            failed.forEach { add(RaspEvidence("failed_check", it)) }
            checks.forEach { (name, c) -> add(RaspEvidence("check_$name", c.name.lowercase())) }
            o.signingCertSha256?.let { add(RaspEvidence("signing_cert_sha256", it)) }
            if (e.installers.isNotEmpty()) add(RaspEvidence("installer", o.installer ?: "none"))
            add(RaspEvidence("install_directory_missing", o.installDirectoryMissing ?: "unreadable"))
            if (o.apkPath != null && checks["apk_path"] == Check.MISMATCH) add(RaspEvidence("apk_path", o.apkPath))
            o.classesDexSha256?.let { add(RaspEvidence("classes_dex_sha256", it)) }
            o.resourcesArscSha256?.let { add(RaspEvidence("resources_arsc_sha256", it)) }
            if (e.signingCertSha256 == null) {
                add(RaspEvidence("expected_signing_certificate", "not_configured",
                    "Set RaspLeanConfig.expectedSigningCertSha256 / configureExpectedSigningCertificate()"))
            }
        }
        return when {
            failed.isNotEmpty() -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            unreadable.isNotEmpty() -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.ERROR, evidence,
                reason = "Could not read: ${unreadable.joinToString(", ")}",
            )
            !e.anythingConfigured -> RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = NOT_CONFIGURED)
            else -> RaspCheckResult.secure(DETECTOR_ID, evidence)
        }
    }

    private fun hashCheck(expected: String?, observed: String?, readable: Boolean): Check = when {
        expected == null -> Check.NOT_CONFIGURED
        !readable || observed == null -> Check.UNREADABLE
        observed == expected -> Check.MATCH
        else -> Check.MISMATCH
    }

    // ── Reading the device ────────────────────────────────────────────

    /** Dex / arsc hashes for one APK file, computed once per (path, size, mtime). */
    private val hashCache = AtomicReference<Pair<String, Pair<String?, String?>>?>(null)

    fun observe(context: Context, e: Expected): Observation {
        val apkPath = try { context.applicationInfo.sourceDir } catch (ex: Exception) { null }
        val installer: Pair<Boolean, String?> = try {
            true to if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        } catch (ex: Exception) {
            false to null
        }
        var dex: String? = null
        var arsc: String? = null
        var entriesReadable = true
        if ((e.classesDexSha256 != null || e.resourcesArscSha256 != null) && apkPath != null) {
            val hashes = apkHashes(apkPath)
            if (hashes == null) entriesReadable = false else { dex = hashes.first; arsc = hashes.second }
        }
        return Observation(
            signingCertSha256 = normalizeHex(RaspSigningProbes.signingCertSha256(context)),
            installerReadable = installer.first,
            installer = installer.second,
            apkPath = apkPath,
            installDirectoryMissing = RaspSigningProbes.installDirectoryMissing(context),
            classesDexSha256 = dex,
            resourcesArscSha256 = arsc,
            apkEntriesReadable = entriesReadable,
        )
    }

    /** (dex digest, arsc digest) of [apkPath]; `null` when the APK cannot be read. Cached per file version. */
    private fun apkHashes(apkPath: String): Pair<String?, String?>? = try {
        val file = File(apkPath)
        val key = "$apkPath|${file.length()}|${file.lastModified()}"
        hashCache.get()?.takeIf { it.first == key }?.second ?: ZipFile(file).use { zip ->
            val entries = zip.entries().toList().associateBy { it.name }
            val dexNames = entries.keys.filter { DEX_ENTRY.matches(it) }.sortedBy(::dexIndex)
            val dexes = dexNames.map { name -> name to zip.getInputStream(entries.getValue(name)).use { it.readBytes() } }
            val arsc = entries["resources.arsc"]?.let { entry -> zip.getInputStream(entry).use { it.readBytes() } }
            (dexSha256(dexes) to arsc?.let(::sha256Hex)).also { hashCache.set(key to it) }
        }
    } catch (ex: Exception) {
        null
    }

    private val DEX_ENTRY = Regex("^classes(\\d*)\\.dex$")

    /** `classes.dex` = 1, `classesN.dex` = N. */
    fun dexIndex(name: String): Int = DEX_ENTRY.find(name)?.groupValues?.get(1)?.ifEmpty { "1" }?.toInt() ?: Int.MAX_VALUE

    /**
     * The dex digest baked at build time must use the same definition:
     * SHA-256 over, for each `classes*.dex` entry in [dexIndex] order, the
     * entry name (UTF-8), one 0 byte, then the entry's bytes. `null` when the
     * APK has no dex entry.
     */
    fun dexSha256(entries: List<Pair<String, ByteArray>>): String? {
        if (entries.isEmpty()) return null
        val md = MessageDigest.getInstance("SHA-256")
        entries.sortedBy { dexIndex(it.first) }.forEach { (name, bytes) ->
            md.update(name.toByteArray(Charsets.UTF_8))
            md.update(0.toByte())
            md.update(bytes)
        }
        return md.digest().joinToString("") { "%02X".format(it) }
    }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02X".format(it) }
}
