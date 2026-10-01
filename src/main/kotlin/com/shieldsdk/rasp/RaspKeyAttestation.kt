package com.shieldsdk.rasp

import java.math.BigInteger

/**
 * Minimal DER reader — enough to decode the Android key attestation
 * extension. Handles high tag numbers (e.g. `[704]`) and long-form lengths.
 * Throws [IllegalArgumentException] on malformed input; callers treat that
 * as "could not parse".
 */
internal class RaspDer private constructor(private val bytes: ByteArray, private var pos: Int, private val end: Int) {

    /** One TLV element. [tagClass]: 0 universal, 2 context-specific. */
    class Element(val tagClass: Int, val constructed: Boolean, val tagNumber: Int, val content: ByteArray) {
        fun children(): List<Element> = RaspDer(content, 0, content.size).readAll()
        fun integer(): BigInteger = BigInteger(content)
        fun boolean(): Boolean = content.size == 1 && content[0] != 0.toByte()
    }

    private fun readAll(): List<Element> = buildList { while (pos < end) add(read()) }

    private fun next(): Int {
        require(pos < end) { "truncated DER" }
        return bytes[pos++].toInt() and 0xff
    }

    private fun read(): Element {
        val first = next()
        val tagClass = first shr 6
        val constructed = first and 0x20 != 0
        var tagNumber = first and 0x1f
        if (tagNumber == 0x1f) {
            tagNumber = 0
            do {
                val b = next()
                require(tagNumber < (1 shl 23)) { "tag number too large" }
                tagNumber = (tagNumber shl 7) or (b and 0x7f)
            } while (b and 0x80 != 0)
        }
        var length = next()
        if (length and 0x80 != 0) {
            val count = length and 0x7f
            require(count in 1..4) { "unsupported DER length" }
            length = 0
            repeat(count) { length = (length shl 8) or next() }
            require(length >= 0) { "negative DER length" }
        }
        require(length <= end - pos) { "DER length exceeds input" }
        val content = bytes.copyOfRange(pos, pos + length)
        pos += length
        return Element(tagClass, constructed, tagNumber, content)
    }

    companion object {
        /** Parses exactly one element; trailing bytes are rejected. */
        fun parse(bytes: ByteArray): Element {
            val reader = RaspDer(bytes, 0, bytes.size)
            val element = reader.read()
            require(reader.pos == bytes.size) { "trailing bytes after DER element" }
            return element
        }
    }
}

/**
 * The fields of the Android key attestation extension
 * (OID 1.3.6.1.4.1.11129.2.1.17, `KeyDescription`) this SDK uses.
 * Field numbers follow the Android "Verifying hardware-backed key pairs with
 * key attestation" schema.
 */
data class RaspKeyAttestation(
    val attestationVersion: Int,
    /** 0 Software, 1 TrustedEnvironment, 2 StrongBox. */
    val attestationSecurityLevel: Int,
    /** From the hardware-enforced list; `null` when absent. */
    val rootOfTrust: RootOfTrust?,
    /** YYYYMM, e.g. 202608; `null` when absent. */
    val osPatchLevel: Int?,
    /** YYYYMMDD; `null` when absent. */
    val vendorPatchLevel: Int?,
    /** YYYYMMDD; `null` when absent. */
    val bootPatchLevel: Int?,
) {
    data class RootOfTrust(
        val deviceLocked: Boolean,
        /** 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed. */
        val verifiedBootState: Int,
    )

    companion object {
        const val OID = "1.3.6.1.4.1.11129.2.1.17"
        const val SECURITY_LEVEL_SOFTWARE = 0
        const val BOOT_VERIFIED = 0
        const val BOOT_SELF_SIGNED = 1
        const val BOOT_UNVERIFIED = 2
        const val BOOT_FAILED = 3

        private const val TAG_ROOT_OF_TRUST = 704
        private const val TAG_OS_PATCH_LEVEL = 706
        private const val TAG_VENDOR_PATCH_LEVEL = 718
        private const val TAG_BOOT_PATCH_LEVEL = 719

        fun bootStateName(state: Int): String = when (state) {
            BOOT_VERIFIED -> "verified"
            BOOT_SELF_SIGNED -> "self_signed"
            BOOT_UNVERIFIED -> "unverified"
            BOOT_FAILED -> "failed"
            else -> "unknown($state)"
        }

        /**
         * Parses the value returned by `X509Certificate.getExtensionValue(OID)`:
         * a DER OCTET STRING wrapping the `KeyDescription` SEQUENCE.
         */
        fun fromExtensionValue(extensionValue: ByteArray): RaspKeyAttestation {
            val octets = RaspDer.parse(extensionValue)
            require(octets.tagClass == 0 && octets.tagNumber == 4) { "extension value is not an OCTET STRING" }
            return fromKeyDescription(octets.content)
        }

        /** Parses the raw `KeyDescription` SEQUENCE. */
        fun fromKeyDescription(der: ByteArray): RaspKeyAttestation {
            val seq = RaspDer.parse(der)
            require(seq.tagClass == 0 && seq.tagNumber == 16 && seq.constructed) { "KeyDescription is not a SEQUENCE" }
            val fields = seq.children()
            require(fields.size >= 8) { "KeyDescription has ${fields.size} fields, expected 8" }
            val softwareEnforced = fields[6].children()
            val hardwareEnforced = fields[7].children()

            fun tagged(list: List<RaspDer.Element>, tag: Int): RaspDer.Element? =
                list.firstOrNull { it.tagClass == 2 && it.tagNumber == tag }?.children()?.singleOrNull()

            fun intTag(tag: Int): Int? =
                (tagged(hardwareEnforced, tag) ?: tagged(softwareEnforced, tag))?.integer()?.toInt()

            // Root of trust is only meaningful when hardware-enforced.
            val rootOfTrust = tagged(hardwareEnforced, TAG_ROOT_OF_TRUST)?.children()?.let { rot ->
                require(rot.size >= 3) { "RootOfTrust has ${rot.size} fields" }
                RootOfTrust(deviceLocked = rot[1].boolean(), verifiedBootState = rot[2].integer().toInt())
            }
            return RaspKeyAttestation(
                attestationVersion = fields[0].integer().toInt(),
                attestationSecurityLevel = fields[1].integer().toInt(),
                rootOfTrust = rootOfTrust,
                osPatchLevel = intTag(TAG_OS_PATCH_LEVEL),
                vendorPatchLevel = intTag(TAG_VENDOR_PATCH_LEVEL),
                bootPatchLevel = intTag(TAG_BOOT_PATCH_LEVEL),
            )
        }
    }
}
