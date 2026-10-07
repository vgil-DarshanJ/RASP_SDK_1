package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The native core is used only after [RaspNative.ensureLoaded] verified and
 * loaded it; on the JVM nothing is loaded, every call answers `null` and
 * the callers run Kotlin. The integrity hash is checked here against the
 * libraries this build produced (build/rustJniLibs) and the hashes the
 * build baked into RaspNativeHashes.
 *
 * Real: RaspNative's not-loaded path, RaspNativeIntegrity on the real
 * libraspshield.so files, the generated RaspNativeHashes. Loading on a
 * device is in the phone checklist.
 */
class RaspNativeFallbackTest {
    @Test fun `without ensureLoaded nothing is loaded, every call falls back, evidence says why`() {
        assertFalse(RaspNative.available)
        assertEquals(RaspNative.Status.NOT_LOADED, RaspNative.status)
        assertNotNull(RaspNative.loadError)
        assertNull(RaspNative.hookMapsScan("x"))
        assertNull(RaspNative.rootScan())
        assertNull(RaspNative.sha256Hex(byteArrayOf(1)))
        assertNull(RaspNative.hashEquals("A", "A"))
        val evidence = RaspNative.unavailableEvidence().single()
        assertEquals("native_core_unavailable", evidence.key)
        assertEquals(true, evidence.value)
        // Kotlin fallbacks give the reference answers.
        assertEquals(RaspTamperAnalysis.kotlinSha256Hex("abc".toByteArray()), RaspTamperAnalysis.sha256Hex("abc".toByteArray()))
        assertTrue(RaspTamperAnalysis.hashesEqual("AB", "AB"))
        assertFalse(RaspTamperAnalysis.hashesEqual("AB", "AC"))
        assertFalse(RaspTamperAnalysis.hashesEqual(null, "AB"))
    }

    @Test fun `the integrity hash of every built library matches the baked value`() {
        for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86_64")) {
            val so = File("build/rustJniLibs/$abi/libraspshield.so")
            assertTrue("$so was not built", so.isFile)
            assertEquals(abi, RaspNativeHashes.EXPECTED[abi], RaspNativeIntegrity.loadSegmentsSha256(so.readBytes()))
        }
    }

    @Test fun `the integrity hash ignores section headers but not code`() {
        val so = File("build/rustJniLibs/arm64-v8a/libraspshield.so").readBytes()
        val reference = RaspNativeIntegrity.loadSegmentsSha256(so)
        // Section-table fields (what an app build's strip rewrites) do not count.
        val sectionsMoved = so.copyOf().also { it[0x28] = (it[0x28] + 8).toByte() }
        assertEquals(reference, RaspNativeIntegrity.loadSegmentsSha256(sectionsMoved))
        // One flipped byte inside the first LOAD segment (past the ELF header) does.
        val patched = so.copyOf().also { it[0x200] = (it[0x200].toInt() xor 1).toByte() }
        assertFalse(reference == RaspNativeIntegrity.loadSegmentsSha256(patched))
        // Not an ELF file, or truncated: no hash (never a match).
        assertNull(RaspNativeIntegrity.loadSegmentsSha256(ByteArray(64)))
        assertNull(RaspNativeIntegrity.loadSegmentsSha256(so.copyOf(0x30)))
        assertNull(RaspNativeIntegrity.loadSegmentsSha256(so.copyOf(0x1000)))
    }

    @Test fun `install directory names map to ABIs`() {
        assertEquals("arm64-v8a", RaspNative.abiOf("/data/app/~~x==/com.example-y==/lib/arm64"))
        assertEquals("armeabi-v7a", RaspNative.abiOf("/data/app/a/lib/arm/"))
        assertEquals("x86_64", RaspNative.abiOf("/data/app/a/lib/x86_64"))
        assertNull(RaspNative.abiOf("/data/app/a/lib/mips"))
        assertNull(RaspNative.abiOf(null))
    }
}
