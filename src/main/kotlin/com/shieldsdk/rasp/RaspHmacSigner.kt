package com.shieldsdk.rasp

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC-SHA256 request signing for the ingestion API — the exact wire
 * contract `FROUNTEND_BACKEND_RASPOWN/BE/src/crypto/hmac.ts` verifies,
 * reproduced here byte-for-byte:
 *
 *   signingString = "<timestamp>." + <raw request body bytes>
 *   signature     = hex(HMAC-SHA256(apiSecret, signingString))
 *
 * Pure JVM crypto (`javax.crypto`), no Android framework or Context
 * dependency — directly unit-testable on a plain JVM, unlike most of
 * this SDK's `org.json`-based classes.
 */
public object RaspHmacSigner {

    private const val HMAC_ALGORITHM = "HmacSHA256"

    /** [body] must be the EXACT bytes that will be sent as the request
     *  body — never a re-serialization of a parsed/round-tripped JSON
     *  object, which can differ in whitespace or key order from what the
     *  server will receive and therefore verify against. */
    public fun sign(apiSecret: String, timestampMillis: String, body: ByteArray): String {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(apiSecret.toByteArray(Charsets.UTF_8), HMAC_ALGORITHM))
        val prefix = "$timestampMillis.".toByteArray(Charsets.UTF_8)
        mac.update(prefix)
        val digest = mac.doFinal(body)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
