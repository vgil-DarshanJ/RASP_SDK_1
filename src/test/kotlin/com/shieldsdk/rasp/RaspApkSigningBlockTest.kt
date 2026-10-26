package com.shieldsdk.rasp

import com.shieldsdk.rasp.RaspApkSigningBlock.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * APK signing-block parser against APKs signed by `apksigner`
 * (src/test/resources/apk-signing/README.md), plus damaged copies of them,
 * and the `tamper` check built on it.
 */
class RaspApkSigningBlockTest {

    private val rsaCert = "7D1D7C9238B9935EFD87874B41D7131AE6058D167654C2C2791470655193C09C"
    private val ecCert = "ED729484B004A83B1622BC656BC374BB85DA79C0EB16E448F21D89660D57515A"
    private val attackerCert = "E7C44C89912F26543B92CA5476B1EDC829295CCF266E38BED1840382AD5C2DAA"

    private fun fixture(name: String): ByteArray =
        requireNotNull(javaClass.getResourceAsStream("/apk-signing/$name")) { name }.use { it.readBytes() }

    @Test fun `RSA v2 + v3 APK - both schemes, the signing certificate, signatures verify`() {
        val info = RaspApkSigningBlock.parse(fixture("rsa_v2v3.apk"))
        assertEquals(info.problem, Status.VERIFIED, info.status)
        assertEquals(listOf("v2", "v3"), info.schemes)
        assertEquals(listOf(rsaCert), info.certificatesSha256)
        assertNull(info.problem)
    }

    @Test fun `EC P-256 v2-only APK verifies with ECDSA`() {
        val info = RaspApkSigningBlock.parse(fixture("ec_v2.apk"))
        assertEquals(info.problem, Status.VERIFIED, info.status)
        assertEquals(listOf("v2"), info.schemes)
        assertEquals(listOf(ecCert), info.certificatesSha256)
    }

    @Test fun `v1-only APK and an unsigned zip have no signing block`() {
        assertEquals(Status.ABSENT, RaspApkSigningBlock.parse(fixture("rsa_v1only.apk")).status)
        val zip = java.io.ByteArrayOutputStream().also { out ->
            java.util.zip.ZipOutputStream(out).use { z ->
                z.putNextEntry(java.util.zip.ZipEntry("a.txt")); z.write(1); z.closeEntry()
            }
        }.toByteArray()
        assertEquals(Status.ABSENT, RaspApkSigningBlock.parse(zip).status)
    }

    @Test fun `not a zip is INVALID, never a crash`() {
        for (bytes in listOf(ByteArray(0), ByteArray(21), ByteArray(4096) { it.toByte() }, "PK\u0005\u0006".toByteArray())) {
            val status = RaspApkSigningBlock.parse(bytes).status
            assertTrue("$status", status == Status.INVALID || status == Status.ABSENT)
        }
    }

    /** Offset of the signed-data certificate bytes: the DER of the certificate starts with 0x30 0x82. */
    private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int {
        outer@ for (i in from..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    @Test fun `a changed byte in the signed data fails the signature - INVALID`() {
        val apk = fixture("rsa_v2v3.apk")
        val magic = indexOf(apk, "APK Sig Block 42".toByteArray())
        assertTrue(magic > 0)
        // Inside the first signer's certificate (DER SEQUENCE 30 82 …), well past its header.
        val cert = indexOf(apk, byteArrayOf(0x30, 0x82.toByte()), from = (magic - 4000).coerceAtLeast(0))
        assertTrue(cert in 0 until magic)
        val damaged = apk.copyOf().also { it[cert + 200] = (it[cert + 200].toInt() xor 0x01).toByte() }
        val info = RaspApkSigningBlock.parse(damaged)
        assertEquals(Status.INVALID, info.status)
    }

    @Test fun `a broken block size is INVALID`() {
        val apk = fixture("ec_v2.apk")
        val magic = indexOf(apk, "APK Sig Block 42".toByteArray())
        val damaged = apk.copyOf().also { it[magic - 8] = (it[magic - 8] + 3).toByte() }
        assertEquals(Status.INVALID, RaspApkSigningBlock.parse(damaged).status)
    }

    @Test fun `random damage anywhere never throws`() {
        val apk = fixture("rsa_v2v3.apk")
        val random = java.util.Random(42)
        repeat(500) {
            val damaged = apk.copyOf()
            repeat(1 + random.nextInt(4)) { damaged[random.nextInt(damaged.size)] = random.nextInt(256).toByte() }
            RaspApkSigningBlock.parse(damaged)
        }
    }

    // ── tamper: apk_signing_block ───────────────────────────────────────

    private fun obs(block: RaspApkSigningBlock.Info?, pm: List<String>, seen: String? = pm.firstOrNull()) = RaspTamperAnalysis.Observation(
        signingCertSha256 = seen, installerReadable = true, installer = null,
        apkPath = "/data/app/~~x==/com.example-y==/base.apk", installDirectoryMissing = false,
        apkSigningBlock = block, packageManagerCertsSha256 = pm,
    )
    private fun verified(vararg certs: String) = RaspApkSigningBlock.Info(Status.VERIFIED, listOf("v2"), certs.toList())

    private fun tamper(o: RaspTamperAnalysis.Observation, expected: String? = rsaCert) =
        RaspTamperAnalysis.evaluate(o, RaspTamperAnalysis.Expected(signingCertSha256 = expected))

    @Test fun `tamper - file and PackageManager agree with the expected certificate - SECURE`() {
        val r = tamper(obs(verified(rsaCert), listOf(rsaCert)))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertTrue(r.evidence.any { it.key == "check_apk_signing_block" && it.value == "match" })
    }

    @Test fun `tamper - signature kill - PackageManager says original, file was signed by another key - DETECTED`() {
        val r = tamper(obs(verified(attackerCert), listOf(rsaCert)))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertTrue(r.evidence.any { it.key == "failed_check" && it.value == "apk_signing_block" })
        assertTrue(r.evidence.any { it.key == "package_manager_cert_spoofed" })
        // Also without an expected certificate configured: the two sources disagree.
        assertEquals(RaspCheckStatus.DETECTED, tamper(obs(verified(attackerCert), listOf(rsaCert)), expected = null).status)
    }

    @Test fun `key rotation APK - v2 by the old key, v3 by the new key with a verified lineage old to new`() {
        val info = RaspApkSigningBlock.parse(fixture("rotated.apk"))
        assertEquals(info.problem, Status.VERIFIED, info.status)
        assertEquals(listOf("v2", "v3"), info.schemes)
        assertEquals(listOf(rsaCert, ecCert), info.certificatesSha256)
        assertEquals(listOf(rsaCert, ecCert), info.lineageSha256)
    }

    @Test fun `key rotation APK - a changed byte in the lineage is INVALID`() {
        val apk = fixture("rotated.apk")
        // The lineage repeats the old certificate after the v2 signer's copy; damage the last copy.
        val certDer = indexOf(apk, byteArrayOf(0x30, 0x82.toByte(), 0x02), from = 0)
        var last = certDer
        while (true) { val next = indexOf(apk, apk.copyOfRange(certDer, certDer + 16), from = last + 1); if (next < 0) break; last = next }
        assertTrue(last > certDer)
        val damaged = apk.copyOf().also { it[last + 100] = (it[last + 100].toInt() xor 0x01).toByte() }
        assertEquals(Status.INVALID, RaspApkSigningBlock.parse(damaged).status)
    }

    @Test fun `tamper - key rotation - expected is the original certificate, the file proves the rotation - SECURE`() {
        val block = RaspApkSigningBlock.parse(fixture("rotated.apk"))
        // PackageManager: signingCertificateHistory, original first.
        assertEquals(RaspCheckStatus.SECURE, tamper(obs(block, listOf(rsaCert, ecCert)), expected = rsaCert).status)
        assertEquals(RaspCheckStatus.SECURE, tamper(obs(block, listOf(rsaCert, ecCert), seen = ecCert), expected = ecCert).status)
    }

    @Test fun `tamper - an invalid block is DETECTED, an absent or unread one changes nothing`() {
        assertEquals(RaspCheckStatus.DETECTED, tamper(obs(RaspApkSigningBlock.Info(Status.INVALID, problem = "x"), listOf(rsaCert))).status)
        assertEquals(RaspCheckStatus.SECURE, tamper(obs(RaspApkSigningBlock.Info(Status.ABSENT), listOf(rsaCert))).status)
        assertEquals(RaspCheckStatus.SECURE, tamper(obs(null, listOf(rsaCert))).status)
        assertEquals(RaspCheckStatus.ERROR, tamper(obs(RaspApkSigningBlock.Info(Status.UNREADABLE), listOf(rsaCert))).status)
    }

    @Test fun `tamper - the real fixture end to end`() {
        val block = RaspApkSigningBlock.parse(fixture("attacker_v2v3.apk"))
        assertEquals(listOf(attackerCert), block.certificatesSha256)
        assertEquals(RaspCheckStatus.DETECTED, tamper(obs(block, listOf(rsaCert))).status)
    }
}
