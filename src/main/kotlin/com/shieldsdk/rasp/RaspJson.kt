package com.shieldsdk.rasp

/**
 * Small strict JSON parser (RFC 8259) for signed documents the SDK verifies:
 * objects → `Map<String, Any?>` (insertion order), arrays → `List<Any?>`,
 * integers → `Long` (or `Double` beyond Long range), other numbers →
 * `Double`, plus `String`, `Boolean`, `null`. Trailing content, duplicate
 * keys and nesting deeper than 64 levels are rejected.
 *
 * Exists so the same parsing runs on the device and in JVM unit tests
 * (Android's `org.json` is a stub off-device).
 */
internal object RaspJson {

    class ParseException(message: String) : IllegalArgumentException(message)

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWhitespace()
        val value = p.readValue(0)
        p.skipWhitespace()
        if (p.pos != text.length) throw ParseException("trailing content at ${p.pos}")
        return value
    }

    private class Parser(val s: String) {
        var pos = 0

        fun fail(what: String): Nothing = throw ParseException("$what at $pos")

        fun skipWhitespace() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\n' || s[pos] == '\r' || s[pos] == '\t')) pos++
        }

        fun readValue(depth: Int): Any? {
            if (depth > 64) fail("nesting too deep")
            if (pos >= s.length) fail("unexpected end")
            return when (val c = s[pos]) {
                '{' -> readObject(depth)
                '[' -> readArray(depth)
                '"' -> readString()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') readNumber() else fail("unexpected '$c'")
            }
        }

        fun literal(word: String, value: Any?): Any? {
            if (!s.startsWith(word, pos)) fail("invalid literal")
            pos += word.length
            return value
        }

        fun readObject(depth: Int): Map<String, Any?> {
            val map = LinkedHashMap<String, Any?>()
            pos++
            skipWhitespace()
            if (pos < s.length && s[pos] == '}') { pos++; return map }
            while (true) {
                skipWhitespace()
                if (pos >= s.length || s[pos] != '"') fail("expected key")
                val key = readString()
                if (map.containsKey(key)) fail("duplicate key '$key'")
                skipWhitespace()
                if (pos >= s.length || s[pos] != ':') fail("expected ':'")
                pos++
                skipWhitespace()
                map[key] = readValue(depth + 1)
                skipWhitespace()
                when {
                    pos < s.length && s[pos] == ',' -> pos++
                    pos < s.length && s[pos] == '}' -> { pos++; return map }
                    else -> fail("expected ',' or '}'")
                }
            }
        }

        fun readArray(depth: Int): List<Any?> {
            val list = ArrayList<Any?>()
            pos++
            skipWhitespace()
            if (pos < s.length && s[pos] == ']') { pos++; return list }
            while (true) {
                skipWhitespace()
                list.add(readValue(depth + 1))
                skipWhitespace()
                when {
                    pos < s.length && s[pos] == ',' -> pos++
                    pos < s.length && s[pos] == ']' -> { pos++; return list }
                    else -> fail("expected ',' or ']'")
                }
            }
        }

        fun readString(): String {
            pos++ // opening quote
            val out = StringBuilder()
            while (true) {
                if (pos >= s.length) fail("unterminated string")
                val c = s[pos++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> {
                        if (pos >= s.length) fail("unterminated escape")
                        when (val e = s[pos++]) {
                            '"' -> out.append('"'); '\\' -> out.append('\\'); '/' -> out.append('/')
                            'b' -> out.append('\b'); 'f' -> out.append('\u000C'); 'n' -> out.append('\n')
                            'r' -> out.append('\r'); 't' -> out.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) fail("short unicode escape")
                                val hex = s.substring(pos, pos + 4)
                                if (hex.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) fail("bad unicode escape")
                                out.append(hex.toInt(16).toChar())
                                pos += 4
                            }
                            else -> fail("bad escape '\\$e'")
                        }
                    }
                    c < ' ' -> fail("control character in string")
                    else -> out.append(c)
                }
            }
        }

        fun readNumber(): Any {
            val start = pos
            if (s[pos] == '-') pos++
            if (pos < s.length && s[pos] == '0') pos++
            else if (pos < s.length && s[pos] in '1'..'9') while (pos < s.length && s[pos] in '0'..'9') pos++
            else fail("bad number")
            var isInteger = true
            if (pos < s.length && s[pos] == '.') {
                isInteger = false
                pos++
                if (pos >= s.length || s[pos] !in '0'..'9') fail("bad fraction")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                isInteger = false
                pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                if (pos >= s.length || s[pos] !in '0'..'9') fail("bad exponent")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            val text = s.substring(start, pos)
            return if (isInteger) text.toLongOrNull() ?: text.toDouble() else text.toDouble()
        }
    }
}
