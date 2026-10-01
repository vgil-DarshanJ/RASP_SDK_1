package com.shieldsdk.rasp

import android.content.Context
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * `device_state_attestation` — what does the hardware Keystore attest about
 * the device's boot state?
 *
 * Reads the attestation certificate chain of the device key
 * ([RaspDeviceKey.exportAttestationChainBase64]) and decodes the leaf's key
 * attestation extension ([RaspKeyAttestation]):
 *
 * | Field | Verdict |
 * |---|---|
 * | `deviceLocked` false | `bootloader_unlocked` → DETECTED |
 * | verified boot state Unverified / Failed | `verified_boot_unverified` / `verified_boot_failed` → DETECTED |
 * | OS patch level older than `maxSecurityPatchAgeDays` (when configured) | `patch_too_old` → DETECTED |
 * | OS / vendor / boot patch levels | evidence |
 *
 * - No device key / no chain → UNAVAILABLE.
 * - No attestation extension, or software-level attestation → UNKNOWN
 *   (nothing hardware-backed to judge).
 * - Root of trust missing from the hardware-enforced list → UNKNOWN.
 *
 * Read on the device itself, this is evidence, not proof: a compromised OS
 * can hand the app a forged chain. The chain is not verified against the
 * Google attestation roots here; the authoritative check belongs on the
 * backend, using the chain sent to `POST /v1/devices/register`.
 */
object RaspDeviceStateAttestationProbes {

    const val DETECTOR_ID = "device_state_attestation"

    data class Observation(
        /** `false` when the device key or its chain could not be obtained. */
        val chainAvailable: Boolean,
        /** `null` when the leaf has no attestation extension or it could not be parsed. */
        val attestation: RaspKeyAttestation?,
        val parseError: String? = null,
    )

    /** A calendar date; avoids java.time, which needs API 26. */
    data class PatchDate(val year: Int, val month: Int, val day: Int?) {
        /** Days since 1970-01-01 (day 1 of the month when [day] is absent). */
        fun epochDay(): Long = epochDay(year, month, day ?: 1)
        override fun toString(): String =
            "%04d-%02d".format(year, month) + (day?.let { "-%02d".format(it) } ?: "")
    }

    /** Parses an attested YYYYMM or YYYYMMDD patch level; `null` if absent or malformed. */
    fun patchDate(level: Int?): PatchDate? {
        if (level == null || level <= 0) return null
        val date = if (level > 999_999) PatchDate(level / 10_000, (level / 100) % 100, (level % 100).takeIf { it > 0 })
        else PatchDate(level / 100, level % 100, null)
        return date.takeIf { it.year in 2000..2200 && it.month in 1..12 && (it.day == null || it.day in 1..31) }
    }

    /** Days since 1970-01-01 for a proleptic Gregorian date (civil-from-days inverse). */
    fun epochDay(year: Int, month: Int, day: Int): Long {
        val y = (if (month <= 2) year - 1 else year).toLong()
        val era = y / 400 // years here are positive, so this equals floorDiv (API 24+)
        val yoe = y - era * 400
        val mp = (month + 9) % 12
        val doy = (153 * mp + 2) / 5 + day - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    fun evaluate(o: Observation, maxSecurityPatchAgeDays: Int?, todayEpochDay: Long): RaspCheckResult {
        if (!o.chainAvailable) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "Device key attestation chain unavailable")
        }
        val att = o.attestation ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN,
            reason = o.parseError ?: "No key attestation extension on the device key",
        )
        val baseEvidence = listOf(
            RaspEvidence("attestation_security_level", att.attestationSecurityLevel),
            RaspEvidence("attestation_version", att.attestationVersion),
            RaspEvidence("os_patch_level", patchDate(att.osPatchLevel)?.toString()),
            RaspEvidence("vendor_patch_level", patchDate(att.vendorPatchLevel)?.toString()),
            RaspEvidence("boot_patch_level", patchDate(att.bootPatchLevel)?.toString()),
            RaspEvidence("root_verified", false, "not checked against the Google attestation roots on device"),
        )
        if (att.attestationSecurityLevel == RaspKeyAttestation.SECURITY_LEVEL_SOFTWARE) {
            return RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, baseEvidence,
                reason = "Software-only attestation; boot state is not hardware-attested",
            )
        }
        val rot = att.rootOfTrust ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN, baseEvidence,
            reason = "No hardware-enforced root of trust in the attestation",
        )

        val patchAge = patchDate(att.osPatchLevel)?.let { todayEpochDay - it.epochDay() }
        val signals = buildList {
            if (!rot.deviceLocked) add("bootloader_unlocked")
            if (rot.verifiedBootState == RaspKeyAttestation.BOOT_UNVERIFIED) add("verified_boot_unverified")
            if (rot.verifiedBootState == RaspKeyAttestation.BOOT_FAILED) add("verified_boot_failed")
            if (maxSecurityPatchAgeDays != null && patchAge != null && patchAge > maxSecurityPatchAgeDays) add("patch_too_old")
        }
        val evidence = signals.map { RaspEvidence("attestation_signal", it) } + baseEvidence + listOf(
            RaspEvidence("device_locked", rot.deviceLocked),
            RaspEvidence("verified_boot_state", RaspKeyAttestation.bootStateName(rot.verifiedBootState)),
            RaspEvidence("patch_age_days", patchAge),
        )
        return if (signals.isNotEmpty()) RaspCheckResult.detected(DETECTOR_ID, evidence)
        else RaspCheckResult.secure(DETECTOR_ID, evidence)
    }

    /** Decodes the leaf certificate (Base64 DER) of a chain. */
    fun observeChain(chainBase64: List<String>?): Observation {
        val leafB64 = chainBase64?.firstOrNull() ?: return Observation(false, null)
        return try {
            val der = RaspBase64.decode(leafB64) ?: return Observation(true, null, "Leaf certificate is not Base64")
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            val ext = cert.getExtensionValue(RaspKeyAttestation.OID)
                ?: return Observation(true, null, "No key attestation extension on the device key")
            Observation(true, RaspKeyAttestation.fromExtensionValue(ext))
        } catch (e: Exception) {
            Observation(true, null, "Attestation could not be parsed: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    fun observe(context: Context): Observation =
        observeChain(RaspDeviceKey(context).exportAttestationChainBase64())
}
