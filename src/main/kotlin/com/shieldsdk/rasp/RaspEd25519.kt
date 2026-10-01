package com.shieldsdk.rasp

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Ed25519 signature verification (RFC 8032 §5.1.7), pure Kotlin.
 *
 * Android ships Ed25519 in its crypto provider only from API 33; this SDK
 * supports API 23+. Verification only (no signing, no secret keys), so the
 * non-constant-time BigInteger arithmetic leaks nothing secret. Written
 * after the RFC's reference implementation; checked against the RFC 8032
 * test vectors and the JDK's own Ed25519 in unit tests.
 */
object RaspEd25519 {

    // Declaration order matters: object properties initialize top to bottom.
    private val TWO: BigInteger = BigInteger.valueOf(2)
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val Q: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
    private val D: BigInteger = BigInteger.valueOf(-121665).multiply(inv(BigInteger.valueOf(121666))).mod(P)
    private val SQRT_M1: BigInteger = TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P)

    /** Extended coordinates (X, Y, Z, T). */
    private class Point(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private val NEUTRAL = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
    private val G: Point = run {
        val y = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(P)
        val x = recoverX(y, 0)!!
        Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    private fun inv(x: BigInteger): BigInteger = x.modPow(P.subtract(TWO), P)

    private fun add(a: Point, b: Point): Point {
        val aa = a.y.subtract(a.x).multiply(b.y.subtract(b.x)).mod(P)
        val bb = a.y.add(a.x).multiply(b.y.add(b.x)).mod(P)
        val cc = TWO.multiply(a.t).multiply(b.t).multiply(D).mod(P)
        val dd = TWO.multiply(a.z).multiply(b.z).mod(P)
        val e = bb.subtract(aa)
        val f = dd.subtract(cc)
        val g = dd.add(cc)
        val h = bb.add(aa)
        return Point(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
    }

    private fun mul(scalar: BigInteger, point: Point): Point {
        var s = scalar
        var q = NEUTRAL
        var p = point
        while (s.signum() > 0) {
            if (s.testBit(0)) q = add(q, p)
            p = add(p, p)
            s = s.shiftRight(1)
        }
        return q
    }

    private fun equal(a: Point, b: Point): Boolean =
        a.x.multiply(b.z).subtract(b.x.multiply(a.z)).mod(P).signum() == 0 &&
            a.y.multiply(b.z).subtract(b.y.multiply(a.z)).mod(P).signum() == 0

    private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
        if (y >= P) return null
        val y2 = y.multiply(y)
        val x2 = y2.subtract(BigInteger.ONE).multiply(inv(D.multiply(y2).add(BigInteger.ONE))).mod(P)
        if (x2.signum() == 0) return if (sign == 1) null else BigInteger.ZERO
        var x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) x = x.multiply(SQRT_M1).mod(P)
        if (x.multiply(x).subtract(x2).mod(P).signum() != 0) return null
        if ((if (x.testBit(0)) 1 else 0) != sign) x = P.subtract(x)
        return x
    }

    private fun littleEndian(bytes: ByteArray): BigInteger = BigInteger(1, bytes.reversedArray())

    private fun decompress(bytes: ByteArray): Point? {
        if (bytes.size != 32) return null
        var y = littleEndian(bytes)
        val sign = if (y.testBit(255)) 1 else 0
        y = y.clearBit(255)
        val x = recoverX(y, sign) ?: return null
        return Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    /**
     * `true` only for a valid signature by [publicKey] (32 raw bytes) over
     * [message]. Any malformed input is `false`, never an exception.
     */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        if (publicKey.size != 32 || signature.size != 64) {
            false
        } else {
            val a = decompress(publicKey)
            val rBytes = signature.copyOfRange(0, 32)
            val r = decompress(rBytes)
            val s = littleEndian(signature.copyOfRange(32, 64))
            if (a == null || r == null || s >= Q) {
                false
            } else {
                val h = littleEndian(
                    MessageDigest.getInstance("SHA-512").run {
                        update(rBytes); update(publicKey); update(message); digest()
                    },
                ).mod(Q)
                equal(mul(s, G), add(r, mul(h, a)))
            }
        }
    } catch (e: Exception) {
        false
    }

    /**
     * Accepts a public key as 32 raw bytes or as an X.509 SPKI (the 44-byte
     * DER form `openssl` and Node export). Returns the 32 raw bytes, or `null`.
     */
    fun rawPublicKey(encoded: ByteArray): ByteArray? = when {
        encoded.size == 32 -> encoded
        encoded.size == 44 && encoded.copyOfRange(0, 12).contentEquals(SPKI_PREFIX) -> encoded.copyOfRange(12, 44)
        else -> null
    }

    /** DER prefix of an Ed25519 SubjectPublicKeyInfo (OID 1.3.101.112). */
    private val SPKI_PREFIX = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
}
