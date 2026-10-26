package com.shieldsdk.rasp

import java.io.File
import java.io.RandomAccessFile
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicReference

/**
 * Reads the signing certificates straight from the installed APK file's
 * APK Signing Block (signature schemes v2, v3 and v3.1), without asking
 * PackageManager.
 *
 * Why: `PackageManager.getPackageInfo(…, GET_SIGNING_CERTIFICATES)` is the
 * classic place a repackaging kit hooks ("signature kill"): the app is
 * re-signed with the attacker's key and the hook hands back the original
 * certificate, so [RaspSigningProbes.signingCertSha256] still matches. The
 * file on disk cannot lie the same way: Android only installs an APK whose
 * signing block verifies, so the certificate in the block is the one that
 * really signed it.
 *
 * For each signer this checks that the signer's public key equals its first
 * certificate's key and that one signature over the signed-data section
 * verifies with that key. It does not recompute the content digests (that
 * means hashing the whole APK, which Android already did at install).
 *
 * Format (AOSP apksig, `ApkSigningBlockUtils` / `V2SchemeVerifier`):
 * `[zip entries][APK Signing Block][central directory][EOCD]`; the block
 * ends with its size (uint64) and the magic `APK Sig Block 42`, and holds
 * (uint64 length, uint32 id, value) pairs. All integers are little-endian;
 * nested fields are uint32-length-prefixed.
 *
 * Pure JVM: no Android API, so it runs in unit tests on real APK fixtures.
 */
object RaspApkSigningBlock {

    const val V2_ID = 0x7109871a
    const val V3_ID = 0xf05368c0.toInt()
    const val V31_ID = 0x1b93ad61

    enum class Status {
        /** Block found, every signer's key matched its certificate and a signature verified. */
        VERIFIED,
        /** No APK Signing Block (v1/JAR-only signing); nothing to compare. */
        ABSENT,
        /** The file could not be opened or read. */
        UNREADABLE,
        /** The block is present but structurally wrong, or a signer did not verify. */
        INVALID,
    }

    data class Info(
        val status: Status,
        /** Schemes present, e.g. `["v2", "v3"]`. */
        val schemes: List<String> = emptyList(),
        /** SHA-256 (uppercase hex) of each signer's first certificate, all schemes, de-duplicated. */
        val certificatesSha256: List<String> = emptyList(),
        /** What went wrong for [Status.INVALID] / [Status.UNREADABLE]. */
        val problem: String? = null,
        /**
         * After a key rotation: SHA-256 of every certificate in the v3
         * proof-of-rotation lineage, oldest first (each link's signature
         * verified). Empty when the app never rotated its key.
         */
        val lineageSha256: List<String> = emptyList(),
    ) {
        /** Certificates this APK proves it is signed by or rotated from. */
        val provenCertificatesSha256: List<String> get() = (certificatesSha256 + lineageSha256).distinct()
    }

    /** Random access to the APK bytes (a file on the device, a byte array in tests). */
    interface Source {
        val size: Long
        fun read(offset: Long, length: Int): ByteArray
    }

    private const val EOCD_MIN = 22
    private const val EOCD_SIGNATURE = 0x06054b50
    private const val MAX_COMMENT = 0xFFFF
    private const val MAGIC = "APK Sig Block 42"
    /** Real blocks are a few KB; anything this large is not one we read into memory. */
    private const val MAX_BLOCK_BYTES = 16L * 1024 * 1024

    private val cache = AtomicReference<Pair<String, Info>?>(null)

    /** [parse] of [apkPath], cached per (path, size, mtime). */
    fun read(apkPath: String): Info = try {
        val file = File(apkPath)
        val key = "$apkPath|${file.length()}|${file.lastModified()}"
        cache.get()?.takeIf { it.first == key }?.second ?: RandomAccessFile(file, "r").use { raf ->
            parse(object : Source {
                override val size = raf.length()
                override fun read(offset: Long, length: Int): ByteArray {
                    val out = ByteArray(length)
                    raf.seek(offset)
                    raf.readFully(out)
                    return out
                }
            })
        }.also { if (it.status != Status.UNREADABLE) cache.set(key to it) }
    } catch (e: Exception) {
        Info(Status.UNREADABLE, problem = e.javaClass.simpleName)
    }

    fun parse(bytes: ByteArray): Info = parse(object : Source {
        override val size = bytes.size.toLong()
        override fun read(offset: Long, length: Int): ByteArray {
            if (offset < 0 || length < 0 || offset + length > bytes.size) throw IndexOutOfBoundsException()
            return bytes.copyOfRange(offset.toInt(), offset.toInt() + length)
        }
    })

    fun parse(source: Source): Info {
        val block = try {
            locateBlock(source) ?: return Info(Status.ABSENT)
        } catch (e: Malformed) {
            return Info(Status.INVALID, problem = e.message)
        } catch (e: Exception) {
            return Info(Status.UNREADABLE, problem = e.javaClass.simpleName)
        }
        return try {
            val pairs = pairsOf(block)
            val schemes = mutableListOf<String>()
            val certs = linkedSetOf<String>()
            val lineage = linkedSetOf<String>()
            for ((id, name) in listOf(V2_ID to "v2", V3_ID to "v3", V31_ID to "v3.1")) {
                val value = pairs[id] ?: continue
                schemes += name
                signers(value, isV3 = id != V2_ID).forEach { (cert, history) ->
                    certs += cert
                    lineage += history
                }
            }
            if (schemes.isEmpty()) Info(Status.ABSENT)
            else Info(Status.VERIFIED, schemes, certs.toList(), lineageSha256 = lineage.toList())
        } catch (e: Malformed) {
            Info(Status.INVALID, problem = e.message)
        } catch (e: Exception) {
            Info(Status.INVALID, problem = e.javaClass.simpleName)
        }
    }

    private class Malformed(message: String) : Exception(message)

    // ── Locating the block ──────────────────────────────────────────────

    /** The block's pair section, or `null` when the APK has no signing block. */
    private fun locateBlock(src: Source): ByteArray? {
        val size = src.size
        if (size < EOCD_MIN) throw Malformed("too small for a zip")
        val tailLength = minOf(size, (EOCD_MIN + MAX_COMMENT).toLong()).toInt()
        val tail = src.read(size - tailLength, tailLength)
        var eocd = -1
        for (i in tail.size - EOCD_MIN downTo 0) {
            if (Le(tail, i).u32(0) == EOCD_SIGNATURE.toLong() && Le(tail, i).u16(20) == tail.size - i - EOCD_MIN) {
                eocd = i
                break
            }
        }
        if (eocd < 0) throw Malformed("no end of central directory")
        val cdOffset = Le(tail, eocd).u32(16)
        if (cdOffset < 32 || cdOffset > size - tailLength + eocd) return null
        val footer = src.read(cdOffset - 24, 24)
        if (String(footer, 8, 16, Charsets.US_ASCII) != MAGIC) return null
        val blockSize = Le(footer, 0).u64(0)
        if (blockSize < 24 || blockSize > MAX_BLOCK_BYTES || blockSize + 8 > cdOffset) throw Malformed("bad block size")
        val start = cdOffset - blockSize - 8
        val whole = src.read(start, (blockSize + 8).toInt())
        if (Le(whole, 0).u64(0) != blockSize) throw Malformed("block sizes differ")
        return whole.copyOfRange(8, whole.size - 24)
    }

    /** id → value of each (uint64 length, uint32 id, value) pair. */
    private fun pairsOf(section: ByteArray): Map<Int, ByteArray> {
        val out = HashMap<Int, ByteArray>()
        var at = 0
        while (at < section.size) {
            if (section.size - at < 12) throw Malformed("truncated pair")
            val length = Le(section, at).u64(0)
            if (length < 4 || length > section.size - at - 8) throw Malformed("bad pair length")
            val id = Le(section, at).u32(8).toInt()
            out.putIfAbsent(id, section.copyOfRange(at + 12, at + 8 + length.toInt()))
            at += 8 + length.toInt()
        }
        return out
    }

    // ── Signers ─────────────────────────────────────────────────────────

    /**
     * v2 signer: signed data, signatures, public key.
     * v3 signer: signed data, minSdk, maxSdk, signatures, public key.
     * Signed data: digests, certificates, then (v3) minSdk, maxSdk and
     * additional attributes, which may hold the proof-of-rotation lineage.
     *
     * Returns (certificate SHA-256, lineage SHA-256s) per signer.
     */
    private fun signers(value: ByteArray, isV3: Boolean): List<Pair<String, List<String>>> {
        val signers = Reader(value).prefixed().items()
        if (signers.isEmpty()) throw Malformed("no signers")
        return signers.map { signerBytes ->
            val signer = Reader(signerBytes)
            val signedData = signer.prefixedBytes()
            if (isV3) signer.skip(8)
            val signatures = signer.prefixed().items().map { Reader(it).let { s -> s.u32().toInt() to s.prefixedBytes() } }
            val publicKey = signer.prefixedBytes()

            val data = Reader(signedData)
            data.prefixedBytes() // digests
            val certificate = data.prefixed().items().firstOrNull() ?: throw Malformed("signer without certificate")
            val cert = x509(certificate)
            if (!MessageDigest.isEqual(cert.publicKey.encoded, publicKey)) throw Malformed("signer key is not its certificate's key")
            if (!verifiesAny(signedData, signatures, cert.publicKey, publicKey)) throw Malformed("signer signature does not verify")
            val lineage = if (!isV3) emptyList() else {
                data.skip(8)
                data.prefixed().items()
                    .map { Reader(it).let { attr -> attr.u32().toInt() to attr.rest() } }
                    .firstOrNull { it.first == PROOF_OF_ROTATION_ID }
                    ?.let { lineage(it.second, certificate) }
                    .orEmpty()
            }
            sha256Hex(certificate) to lineage
        }
    }

    private const val PROOF_OF_ROTATION_ID = 0x3ba06f8c

    /**
     * AOSP `SigningCertificateLineage` (v3 proof of rotation): uint32 version,
     * then nodes of (signed data = certificate + uint32 algorithm the
     * previous node signed it with; uint32 flags; uint32 algorithm this
     * certificate signs the next node with; signature by the previous
     * node's key over this node's signed data). The signed algorithm must be
     * the previous node's (apksig `readSigningCertificateLineage`).
     * The first node is unsigned; the last node must be the signer itself.
     * Any link that does not verify makes the whole APK INVALID — a lineage
     * an attacker could forge would let a re-signed APK claim the original
     * certificate.
     */
    private fun lineage(value: ByteArray, signerCertificate: ByteArray): List<String> {
        val reader = Reader(value)
        reader.u32() // version
        val nodes = reader.items()
        if (nodes.isEmpty()) throw Malformed("empty lineage")
        var previous: X509Certificate? = null
        var previousAlgorithm = 0
        var lastCertificate = ByteArray(0)
        val out = mutableListOf<String>()
        for (nodeBytes in nodes) {
            val node = Reader(nodeBytes)
            val signedData = node.prefixedBytes()
            node.skip(4) // flags
            val algorithm = node.u32().toInt()
            val signature = node.prefixedBytes()
            val data = Reader(signedData)
            val certificate = data.prefixedBytes()
            val signedAlgorithm = data.u32().toInt()
            val cert = x509(certificate)
            previous?.let { prev ->
                if (signedAlgorithm != previousAlgorithm) throw Malformed("lineage algorithm fields differ")
                val verifier = verifierFor(previousAlgorithm, prev.publicKey, prev.publicKey.encoded) ?: throw Malformed("lineage algorithm unsupported")
                val ok = try { verifier.update(signedData); verifier.verify(signature) } catch (e: Exception) { false }
                if (!ok) throw Malformed("lineage link does not verify")
            }
            previous = cert
            previousAlgorithm = algorithm
            lastCertificate = certificate
            out += sha256Hex(certificate)
        }
        if (!MessageDigest.isEqual(lastCertificate, signerCertificate)) throw Malformed("lineage does not end at the signer")
        return out
    }

    private fun x509(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    /** `true` when a signature with an algorithm this runtime supports verifies; `false` when none does. */
    private fun verifiesAny(signedData: ByteArray, signatures: List<Pair<Int, ByteArray>>, certKey: PublicKey, spki: ByteArray): Boolean {
        var tried = false
        for ((algorithm, signature) in signatures) {
            val verifier = verifierFor(algorithm, certKey, spki) ?: continue
            tried = true
            val ok = try {
                verifier.update(signedData)
                verifier.verify(signature)
            } catch (e: Exception) {
                false
            }
            if (ok) return true
        }
        if (!tried) throw Malformed("no supported signature algorithm")
        return false
    }

    /** IDs from AOSP `SignatureAlgorithm`; the verity variants sign the same signed data. */
    private fun verifierFor(algorithm: Int, certKey: PublicKey, spki: ByteArray): Signature? {
        val (name, keyType, pss) = when (algorithm) {
            0x0101 -> Triple("SHA256withRSA/PSS", "RSA", PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            0x0102 -> Triple("SHA512withRSA/PSS", "RSA", PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
            0x0103, 0x0421 -> Triple("SHA256withRSA", "RSA", null)
            0x0104 -> Triple("SHA512withRSA", "RSA", null)
            0x0201, 0x0423 -> Triple("SHA256withECDSA", "EC", null)
            0x0202 -> Triple("SHA512withECDSA", "EC", null)
            0x0301, 0x0425 -> Triple("SHA256withDSA", "DSA", null)
            else -> return null
        }
        return try {
            val key = try { KeyFactory.getInstance(keyType).generatePublic(X509EncodedKeySpec(spki)) } catch (e: Exception) { certKey }
            val signature = if (pss == null) Signature.getInstance(name) else pssSignature(name, pss)
            signature.initVerify(key)
            signature
        } catch (e: Exception) {
            null
        }
    }

    /** Android providers know `SHA256withRSA/PSS`; a desktop JVM knows `RSASSA-PSS` + parameters. */
    private fun pssSignature(androidName: String, spec: PSSParameterSpec): Signature = try {
        Signature.getInstance(androidName)
    } catch (e: Exception) {
        Signature.getInstance("RSASSA-PSS").apply { setParameter(spec) }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02X".format(it) }

    // ── Little-endian helpers ───────────────────────────────────────────

    private class Le(private val b: ByteArray, private val base: Int) {
        fun u16(at: Int): Int = byte(at) or (byte(at + 1) shl 8)
        fun u32(at: Int): Long = (0 until 4).fold(0L) { acc, i -> acc or (byte(at + i).toLong() shl (8 * i)) }
        fun u64(at: Int): Long {
            val high = u32(at + 4)
            if (high != 0L) throw Malformed("64-bit size")
            return u32(at)
        }
        private fun byte(at: Int): Int {
            val i = base + at
            if (i < 0 || i >= b.size) throw Malformed("read past end")
            return b[i].toInt() and 0xff
        }
    }

    /** Cursor over uint32-length-prefixed fields. */
    private class Reader(private val b: ByteArray) {
        private var at = 0
        fun u32(): Long = Le(b, at).u32(0).also { at += 4 }
        fun skip(n: Int) {
            if (b.size - at < n) throw Malformed("truncated field")
            at += n
        }
        fun prefixedBytes(): ByteArray {
            val length = u32()
            if (length > b.size - at) throw Malformed("field longer than its parent")
            return b.copyOfRange(at, at + length.toInt()).also { at += length.toInt() }
        }
        fun prefixed(): Reader = Reader(prefixedBytes())
        fun rest(): ByteArray = b.copyOfRange(at, b.size).also { at = b.size }
        fun items(): List<ByteArray> = buildList { while (at < b.size) add(prefixedBytes()) }
    }
}
