package com.shieldsdk.rasp

import java.math.BigDecimal

/**
 * Canonical JSON for signed evidence envelopes.
 *
 * The backend verifies a signature over its own re-serialization of the body:
 * `JSON.stringify(canonicalize(JSON.parse(body)))` with object keys sorted
 * (`BE/src/ingestion/routes.ts`). The bytes signed here must equal that text
 * exactly, so this writer reproduces JavaScript's `JSON.stringify`, not
 * `org.json`'s `toString()`, which differs in ways that break the signature:
 *
 * - `/` is written as-is (`org.json` writes `\/`; Base64 key ids and file
 *   paths contain `/`).
 * - Strings escape only `"`, `\`, `\b \f \n \r \t`, other controls as
 *   lower-case `\u00xx`, and lone surrogates as `\udxxx`.
 * - Object keys: array-index keys (`"0"`, `"17"`) first in numeric order, then
 *   the rest in UTF-16 code-unit order — the order a JS object built in sorted
 *   order enumerates in.
 * - Numbers: integers as plain digits; integers beyond ±(2^53−1) are written
 *   as strings, because JavaScript would round them on parse and re-serialize
 *   different digits. Non-integral doubles use JavaScript's Number-to-String
 *   layout; NaN and ±Infinity become `null`, as in `JSON.stringify`.
 *
 * Limitation: the digits of a non-integral double come from
 * `Double.toString`, which on some runtimes is not always the shortest
 * round-trip form JavaScript prints. Evidence values should stay integers,
 * booleans and strings; a mismatch shows up as ENVELOPE_SIGNATURE_INVALID,
 * never as a wrongly accepted envelope.
 */
internal object RaspCanonicalJson {

    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private const val MAX_ARRAY_INDEX = 4_294_967_294L

    fun encode(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    private fun write(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is String -> writeString(out, value)
            is Boolean -> out.append(value)
            is Int, is Long, is Short, is Byte -> writeLong(out, (value as Number).toLong())
            is Double -> writeDouble(out, value)
            is Float -> writeDouble(out, value.toDouble())
            is Map<*, *> -> writeObject(out, value)
            is Iterable<*> -> writeArray(out, value)
            is Array<*> -> writeArray(out, value.asIterable())
            is Enum<*> -> writeString(out, value.name)
            else -> writeString(out, value.toString())
        }
    }

    private fun writeLong(out: StringBuilder, v: Long) {
        if (v > MAX_SAFE_INTEGER || v < -MAX_SAFE_INTEGER) writeString(out, v.toString())
        else out.append(v)
    }

    private fun writeDouble(out: StringBuilder, d: Double) {
        when {
            d.isNaN() || d.isInfinite() -> out.append("null")
            d == 0.0 -> out.append('0') // JS prints -0 as "0"
            else -> out.append(jsNumberString(d))
        }
    }

    /** ECMAScript Number::toString layout for a finite, non-zero double. */
    internal fun jsNumberString(d: Double): String {
        val bd = BigDecimal(java.lang.Double.toString(Math.abs(d))).stripTrailingZeros()
        val digits = bd.unscaledValue().toString()
        val k = digits.length
        val n = k - bd.scale() // position of the decimal point relative to the digits
        val body = when {
            n in k..21 -> digits + "0".repeat(n - k)
            n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
            n in -5..0 -> "0." + "0".repeat(-n) + digits
            else -> {
                val e = n - 1
                val exp = if (e >= 0) "+$e" else "$e"
                if (k == 1) "${digits}e$exp" else "${digits[0]}.${digits.substring(1)}e$exp"
            }
        }
        return if (d < 0) "-$body" else body
    }

    private fun writeString(out: StringBuilder, s: String) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\b' -> out.append("\\b")
                c == '\u000C' -> out.append("\\f")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> appendUnicodeEscape(out, c)
                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> {
                    out.append(c).append(s[i + 1])
                    i++
                }
                c.isSurrogate() -> appendUnicodeEscape(out, c) // lone surrogate
                else -> out.append(c)
            }
            i++
        }
        out.append('"')
    }

    private fun appendUnicodeEscape(out: StringBuilder, c: Char) {
        out.append("\\u").append(Integer.toHexString(c.code).padStart(4, '0'))
    }

    private fun writeArray(out: StringBuilder, items: Iterable<*>) {
        out.append('[')
        var first = true
        for (item in items) {
            if (!first) out.append(',')
            write(out, item)
            first = false
        }
        out.append(']')
    }

    private fun writeObject(out: StringBuilder, map: Map<*, *>) {
        val byKey = map.entries.associate { (k, v) -> k.toString() to v }
        val (indexKeys, otherKeys) = byKey.keys.partition(::isArrayIndex)
        val ordered = indexKeys.sortedBy { it.toLong() } + otherKeys.sorted()
        out.append('{')
        ordered.forEachIndexed { i, key ->
            if (i > 0) out.append(',')
            writeString(out, key)
            out.append(':')
            write(out, byKey[key])
        }
        out.append('}')
    }

    private fun isArrayIndex(key: String): Boolean {
        if (key.isEmpty() || key.length > 10) return false
        if (key == "0") return true
        if (key[0] !in '1'..'9' || !key.all { it in '0'..'9' }) return false
        return key.toLong() <= MAX_ARRAY_INDEX
    }
}

/**
 * Standard Base64 (RFC 4648 §4, with padding). `java.util.Base64` needs API 26
 * and `android.util.Base64` is not available in JVM unit tests; this works on
 * minSdk 23 and in both.
 */
internal object RaspBase64 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i + 2 < bytes.size) {
            val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8) or (bytes[i + 2].toInt() and 0xff)
            out.append(ALPHABET[n shr 18 and 63]).append(ALPHABET[n shr 12 and 63])
                .append(ALPHABET[n shr 6 and 63]).append(ALPHABET[n and 63])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val n = bytes[i].toInt() and 0xff shl 16
                out.append(ALPHABET[n shr 18 and 63]).append(ALPHABET[n shr 12 and 63]).append("==")
            }
            2 -> {
                val n = (bytes[i].toInt() and 0xff shl 16) or (bytes[i + 1].toInt() and 0xff shl 8)
                out.append(ALPHABET[n shr 18 and 63]).append(ALPHABET[n shr 12 and 63])
                    .append(ALPHABET[n shr 6 and 63]).append('=')
            }
        }
        return out.toString()
    }

    /** Decodes standard Base64; `null` for malformed input. */
    fun decode(text: String): ByteArray? {
        val s = text.trimEnd('=')
        if (s.any { ALPHABET.indexOf(it) < 0 }) return null
        if (s.length % 4 == 1) return null
        val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (c in s) {
            buffer = (buffer shl 6) or ALPHABET.indexOf(c)
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write(buffer shr bits and 0xff)
            }
        }
        return out.toByteArray()
    }
}
