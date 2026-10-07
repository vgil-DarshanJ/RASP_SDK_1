package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Parity between the Kotlin checks and their Rust ports (Task 9.0): the
 * Kotlin side computes its result for every input in native/fixtures and
 * must equal the expected file there; `cargo test` (native/tests/parity.rs)
 * checks the Rust side against the SAME expected files. Same inputs, same
 * results on both sides.
 *
 * Expected files are written from Kotlin once (environment variable
 * RASP_UPDATE_PARITY=1) and reviewed; a normal run only compares.
 *
 * Real: RaspHookAnalysis.summarizeMaps, RaspRootAnalysis.analyzeMounts and
 * path lists, RaspTamperAnalysis.kotlinSha256Hex / kotlinDexSha256 /
 * normalizeHex, RaspCertificatePinProbes.kotlinSpkiPin / isPin,
 * MessageDigest.isEqual. No doubles.
 */
class RaspNativeParityTest {
    private val fixtures = File("native/fixtures")
    private val update = System.getenv("RASP_UPDATE_PARITY") == "1"

    private fun check(expectedFile: File, actual: String) {
        if (update) {
            expectedFile.writeText(actual)
            return
        }
        assertTrue("missing $expectedFile — run once with RASP_UPDATE_PARITY=1", expectedFile.isFile)
        assertEquals(expectedFile.name, expectedFile.readText(), actual)
    }

    private fun inputs(dir: String) =
        (File(fixtures, dir).listFiles() ?: emptyArray()).filter { it.name.endsWith(".txt") }.sortedBy { it.name }

    @Test fun `maps summaries`() {
        val files = inputs("maps")
        assertTrue(files.size >= 7)
        for (file in files) {
            val summary = RaspHookAnalysis.summarizeMaps(file.readText())
            check(File(file.parentFile, file.name.removeSuffix(".txt") + ".expected.json"), RaspCanonicalJson.encode(summary.toMap()) + "\n")
        }
    }

    @Test fun `mount-table findings`() {
        val files = inputs("mounts")
        assertTrue(files.size >= 5)
        for (file in files) {
            val findings = RaspRootAnalysis.analyzeMounts(file.readText())
            check(File(file.parentFile, file.name.removeSuffix(".txt") + ".expected.json"), RaspCanonicalJson.encode(findings.toMap()) + "\n")
        }
    }

    @Test fun `root path lists`() {
        val lines = RaspRootAnalysis.suPaths.map { "su\t$it" } +
            RaspRootAnalysis.magiskPaths.map { "magisk\t$it" } +
            RaspRootAnalysis.busyboxPaths.map { "busybox\t$it" } +
            RaspRootAnalysis.protectedMountPoints.map { "protected_mount\t$it" }
        check(File(fixtures, "root_lists.tsv"), lines.joinToString("\n") + "\n")
    }

    @Test fun `hash helpers`() {
        fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
        fun utf8(text: String) = hex(text.toByteArray(Charsets.UTF_8))
        val lines = mutableListOf<String>()
        for (input in listOf("", "abc", "The quick brown fox jumps over the lazy dog", "\u0000ÿ…", "a".repeat(1000))) {
            lines += "sha256\t${utf8(input)}\t${RaspTamperAnalysis.kotlinSha256Hex(input.toByteArray(Charsets.UTF_8))}"
            lines += "spki_pin\t${utf8(input)}\t${RaspCertificatePinProbes.kotlinSpkiPin(input.toByteArray(Charsets.UTF_8))}"
        }
        val dexCases = listOf(
            listOf("classes.dex" to "A"),
            listOf("classes2.dex" to "B", "classes.dex" to "A", "classes10.dex" to "J"),
            listOf("classes3.dex" to "", "classes.dex" to "x"),
        )
        for (case in dexCases) {
            val digest = RaspTamperAnalysis.kotlinDexSha256(case.map { it.first to it.second.toByteArray() })
            lines += "dex\t${case.joinToString(";") { "${it.first}=${utf8(it.second)}" }}\t${digest ?: "none"}"
        }
        for (input in listOf("ab:cd:ef", " AB CD\tEF-01 ", "", " : - ", "b741…")) {
            lines += "normalize_hex\t${utf8(input)}\t${RaspTamperAnalysis.normalizeHex(input) ?: "none"}"
        }
        val validPin = RaspCertificatePinProbes.kotlinSpkiPin("spki".toByteArray())
        for (value in listOf(validPin, "sha256/AAAA", "sha1/${validPin.removePrefix("sha256/")}", "sha256/", "sha256/a\$b", "${validPin}==")) {
            lines += "is_pin\t$value\t${RaspCertificatePinProbes.isPin(value)}"
        }
        for ((a, b) in listOf("ABC" to "ABC", "ABC" to "ABD", "ABC" to "AB", "" to "")) {
            lines += "hash_equals\t${utf8(a)}\t${utf8(b)}\t${RaspTamperAnalysis.hashesEqual(a, b)}"
        }
        check(File(fixtures, "hashes.tsv"), lines.joinToString("\n") + "\n")
    }
}
