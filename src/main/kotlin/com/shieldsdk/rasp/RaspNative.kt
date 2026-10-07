package com.shieldsdk.rasp

import android.content.Context
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Loader and bindings for `libraspshield.so` (Rust, `native/`).
 *
 * ## Integrity check before loading
 * [ensureLoaded] reads the library the system will load for this app's ABI
 * (the extracted file in `nativeLibraryDir`, or the `lib/<abi>/` entry of the
 * base or split APK), computes [RaspNativeIntegrity.loadSegmentsSha256] and
 * compares it (constant time) with the value the build baked into
 * [RaspNativeHashes]. Only on a match is `System.loadLibrary` called. Any
 * failure — missing library, unknown ABI, hash mismatch, load error, wrong
 * native API version — leaves the native core unused: every caller then
 * runs its Kotlin implementation, and the detectors that would have used
 * native code add `native_core_unavailable` evidence. A failed load never
 * makes a result SECURE. (The file is read and then loaded by path name, so
 * a swap between the two calls is not excluded; the check catches a
 * library replaced at rest, not a live race.)
 *
 * Nothing here throws and nothing is loaded until [ensureLoaded] is called
 * with a Context, so JVM unit tests always take the Kotlin path. Reasons
 * never contain file paths.
 */
internal object RaspNative {

    /** Must match NATIVE_API_VERSION in native/src/lib.rs. */
    const val API_VERSION = 2

    enum class Status { NOT_LOADED, LOADED, FAILED }

    /** Largest library file read for the integrity check. */
    private const val MAX_LIBRARY_BYTES = 16 * 1024 * 1024

    private const val LIBRARY_FILE = "libraspshield.so"

    @Volatile var status: Status = Status.NOT_LOADED
        private set

    /** Why the native core is not in use (no paths); `null` when [available]. */
    @Volatile var loadError: String? = "not initialized"
        private set

    val available: Boolean get() = status == Status.LOADED

    /** Loads and verifies the library once per process. `true` when the native core is usable. */
    @Synchronized
    fun ensureLoaded(context: Context): Boolean {
        if (status != Status.NOT_LOADED) return available
        val failure = try {
            verifyAndLoad(context.applicationContext ?: context)
        } catch (t: Throwable) {
            t.javaClass.simpleName
        }
        if (failure == null) {
            status = Status.LOADED
            loadError = null
        } else {
            status = Status.FAILED
            loadError = failure
        }
        return available
    }

    /** `null` on success, otherwise the reason (no paths). */
    private fun verifyAndLoad(context: Context): String? {
        val info = context.applicationInfo
        val abi = abiOf(info.nativeLibraryDir) ?: Build.SUPPORTED_ABIS.firstOrNull() ?: return "unknown ABI"
        val expected = RaspNativeHashes.EXPECTED[abi] ?: return "no native library built for $abi"
        val bytes = libraryBytes(info.nativeLibraryDir, listOfNotNull(info.sourceDir) + (info.splitSourceDirs?.toList() ?: emptyList()), abi)
            ?: return "native library not found"
        val actual = RaspNativeIntegrity.loadSegmentsSha256(bytes) ?: return "native library is not a valid ELF file"
        if (!MessageDigest.isEqual(actual.toByteArray(), expected.toByteArray())) return "native library hash mismatch"
        try {
            System.loadLibrary("raspshield")
        } catch (t: Throwable) {
            return "native library load failed: ${t.javaClass.simpleName}"
        }
        val version = try { nativeApiVersion() } catch (t: Throwable) { return "native API unavailable: ${t.javaClass.simpleName}" }
        return if (version == API_VERSION) null else "native API version $version, expected $API_VERSION"
    }

    /** `…/lib/arm64` → `arm64-v8a` (the install directory names the primary ABI). */
    internal fun abiOf(nativeLibraryDir: String?): String? = when (nativeLibraryDir?.trimEnd('/')?.substringAfterLast('/')) {
        "arm64" -> "arm64-v8a"
        "arm" -> "armeabi-v7a"
        "x86_64" -> "x86_64"
        "x86" -> "x86"
        else -> null
    }

    private fun libraryBytes(nativeLibraryDir: String?, apks: List<String>, abi: String): ByteArray? {
        nativeLibraryDir?.let { File(it, LIBRARY_FILE) }?.takeIf { it.isFile }?.let { file ->
            if (file.length() > MAX_LIBRARY_BYTES) return null
            return file.readBytes()
        }
        // Not extracted (extractNativeLibs=false): the system maps it from the APK.
        for (apk in apks) {
            try {
                ZipFile(apk).use { zip ->
                    val entry = zip.getEntry("lib/$abi/$LIBRARY_FILE") ?: return@use
                    if (entry.size < 0 || entry.size > MAX_LIBRARY_BYTES) return null
                    return zip.getInputStream(entry).use { it.readBytes() }
                }
            } catch (e: Exception) {
                // try the next APK
            }
        }
        return null
    }

    // ── Calls; each returns null when the native core cannot answer ────

    /** Maps summary; [content] `null` = the library reads `/proc/self/maps` itself. */
    fun hookMapsScan(content: String?): RaspHookAnalysis.MapsSummary? {
        if (!available) return null
        val json = try { nativeHookMapsScan(content) } catch (t: Throwable) { null } ?: return null
        return RaspHookAnalysis.MapsSummary.fromJson(json)
    }

    /** File and mount root findings, or `null`. */
    fun rootScan(): RaspRootAnalysis.NativeRootScan? {
        if (!available) return null
        val json = try { nativeRootScan() } catch (t: Throwable) { null } ?: return null
        return RaspRootAnalysis.NativeRootScan.fromJson(json)
    }

    fun sha256Hex(bytes: ByteArray): String? =
        if (!available) null else try { nativeSha256Hex(bytes) } catch (t: Throwable) { null }

    fun dexSha256(entries: List<Pair<String, ByteArray>>): String? =
        if (!available || entries.isEmpty()) null
        else try {
            nativeDexSha256(entries.map { it.first }.toTypedArray(), entries.map { it.second }.toTypedArray())
        } catch (t: Throwable) {
            null
        }

    fun spkiPin(spkiDer: ByteArray): String? =
        if (!available) null else try { nativeSpkiPin(spkiDer) } catch (t: Throwable) { null }

    /** Constant-time equality of two hash strings; `null` when the native core is not in use. */
    fun hashEquals(a: String, b: String): Boolean? =
        if (!available) null else try { nativeHashEquals(a, b) } catch (t: Throwable) { null }

    @JvmStatic private external fun nativeApiVersion(): Int
    @JvmStatic private external fun nativeHookMapsScan(content: String?): String?
    @JvmStatic private external fun nativeRootScan(): String?
    @JvmStatic private external fun nativeSha256Hex(bytes: ByteArray): String?
    @JvmStatic private external fun nativeDexSha256(names: Array<String>, contents: Array<ByteArray>): String?
    @JvmStatic private external fun nativeSpkiPin(spkiDer: ByteArray): String?
    @JvmStatic private external fun nativeHashEquals(a: String, b: String): Boolean

    /** Evidence for a detector that would have used the native core, when it is not in use. */
    fun unavailableEvidence(): List<RaspEvidence> =
        if (available) emptyList() else listOf(RaspEvidence("native_core_unavailable", true, loadError))
}

/**
 * The integrity hash of an ELF shared library: SHA-256 over the file bytes
 * of every PT_LOAD segment, in program-header order, with the ELF header's
 * section-table fields (e_shoff, e_shentsize, e_shnum, e_shstrndx) zeroed.
 * The loadable segments are everything the dynamic loader maps; the section
 * table is not used at load time and is rewritten when an app build strips
 * the library again, so it is left out. The build computes the same value
 * (build.gradle.kts, generateRaspNativeHashes). Uppercase hex; `null` for a
 * file that is not a well-formed little-endian ELF.
 */
internal object RaspNativeIntegrity {
    private const val PT_LOAD = 1

    fun loadSegmentsSha256(file: ByteArray): String? {
        if (file.size < 0x34 || file[0] != 0x7f.toByte() || file[1] != 'E'.code.toByte() ||
            file[2] != 'L'.code.toByte() || file[3] != 'F'.code.toByte() || file[5] != 1.toByte()
        ) return null
        val is64 = when (file[4].toInt()) {
            2 -> true
            1 -> false
            else -> return null
        }
        if (is64 && file.size < 0x40) return null
        val data = file.copyOf()
        val sectionFields = if (is64) listOf(0x28 to 8, 0x3A to 2, 0x3C to 2, 0x3E to 2) else listOf(0x20 to 4, 0x2E to 2, 0x30 to 2, 0x32 to 2)
        sectionFields.forEach { (offset, length) -> data.fill(0, offset, offset + length) }
        val phoff = if (is64) u64(data, 0x20) else u32(data, 0x1C)
        val phentsize = u16(data, if (is64) 0x36 else 0x2A)
        val phnum = u16(data, if (is64) 0x38 else 0x2C)
        if (phoff == null || phentsize == null || phnum == null) return null
        val digest = MessageDigest.getInstance("SHA-256")
        var loads = 0
        for (i in 0 until phnum) {
            val base = phoff + i.toLong() * phentsize
            if (base < 0 || base + phentsize > data.size) return null
            val type = u32(data, base.toInt()) ?: return null
            if (type != PT_LOAD.toLong()) continue
            val offset = (if (is64) u64(data, base.toInt() + 8) else u32(data, base.toInt() + 4)) ?: return null
            val size = (if (is64) u64(data, base.toInt() + 32) else u32(data, base.toInt() + 16)) ?: return null
            if (offset < 0 || size < 0 || offset + size > data.size) return null
            digest.update(data, offset.toInt(), size.toInt())
            loads++
        }
        if (loads == 0) return null
        return digest.digest().joinToString("") { "%02X".format(it) }
    }

    private fun u16(b: ByteArray, at: Int): Int? =
        if (at < 0 || at + 2 > b.size) null else (b[at].toInt() and 0xff) or ((b[at + 1].toInt() and 0xff) shl 8)

    private fun u32(b: ByteArray, at: Int): Long? =
        if (at < 0 || at + 4 > b.size) null
        else (0 until 4).fold(0L) { acc, i -> acc or ((b[at + i].toLong() and 0xff) shl (8 * i)) }

    private fun u64(b: ByteArray, at: Int): Long? {
        if (at < 0 || at + 8 > b.size) return null
        val value = (0 until 8).fold(0L) { acc, i -> acc or ((b[at + i].toLong() and 0xff) shl (8 * i)) }
        return if (value < 0 || value > Int.MAX_VALUE) null else value
    }
}
