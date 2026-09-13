package com.shieldsdk.rasp

/**
 * Classification logic and signal data for root detection.
 *
 * ## Extraction, not redesign
 *
 * Every path, package name, predicate and threshold here is a **verbatim move**
 * from `MainActivity.rootSignals()`. No signal was added, removed, weakened or
 * reordered. The detection algorithm is unchanged; only its location is.
 *
 * ## Why the split
 *
 * Root detection was the SDK's strongest native code and its least verified —
 * it had no test of any kind, because the logic lived in a `private fun` on a
 * `FlutterActivity` where nothing could reach it. Separating the *deciding*
 * from the *reading* makes the decisions testable on any JVM, exactly as
 * [RaspSignalAnalysis] and [RaspHookAnalysis] already are.
 *
 * ```
 *   RaspDeviceIntegrityProbes — reads evidence  (needs a device)
 *   RaspRootAnalysis          — decides meaning (pure; this file)
 * ```
 *
 * ## Verdict model: deliberately different from the emulator detector
 *
 * [isRooted] is `isNotEmpty()` — **any** signal convicts. That asymmetry
 * against [RaspEmulatorAnalysis.isEmulator] is intentional and predates this
 * extraction: a `su` binary or a Magisk artefact has no innocent explanation on
 * a retail handset, whereas `Build.MANUFACTURER == "unknown"` genuinely does.
 * Preserved as-is.
 */
object RaspRootAnalysis {

    /** `su` in every location the common root packages install it. */
    val suPaths: List<String> = listOf(
        "/sbin/su", "/system/bin/su", "/system/xbin/su", "/vendor/bin/su",
        "/system/sbin/su", "/su/bin/su", "/data/local/su",
        "/data/local/bin/su", "/data/local/xbin/su", "/system/bin/failsafe/su",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu",
    )

    /**
     * Magisk (incl. its hidden/DenyList layout) and other root managers. Magisk
     * is what real attackers use, so it gets explicit coverage rather than
     * relying on a generic `su` lookup that Magisk deliberately hides.
     */
    val magiskPaths: List<String> = listOf(
        "/sbin/.magisk", "/sbin/.core/mirror", "/sbin/.core/img",
        "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk.img",
        "/data/adb/modules", "/data/adb/ksu", "/data/adb/ap",
        "/cache/.disable_magisk", "/dev/.magisk.unblock",
        "/system/etc/init/magisk", "/data/adb/magisk_simple",
    )

    val rootPackages: List<String> = listOf(
        "com.topjohnwu.magisk", "com.noshufou.android.su",
        "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser",
        "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root",
        "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
        "com.alephzain.framaroot", "me.weishu.kernelsu",
        "com.ramdroid.appquarantine", "de.robv.android.xposed.installer",
        "org.lsposed.manager", "io.va.exposed", "com.formyhm.hideroot",
    )

    val rootCloakingPackages: List<String> = listOf(
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "com.saurik.substrate", "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot", "com.formyhm.hiderootPremium",
    )

    /** Partitions that are read-only on a stock device. */
    val readOnlyMountPoints: List<String> = listOf("/system", "/vendor", "/product")

    /** BusyBox lands in one of these when a rooting toolkit installs it. */
    val busyboxPaths: List<String> = listOf(
        "/system/xbin/busybox", "/system/bin/busybox", "/data/local/busybox",
    )

    /** A production build signed with test-keys is not a retail image. */
    fun tagsIndicateTestKeys(buildTags: String?): Boolean =
        (buildTags ?: "").contains("test-keys")

    // ── Tri-state models ──────────────────────────────────────────────────
    //
    // Android denies an ordinary app a great deal of what root detection would
    // like to read. The failure mode that matters is **silent**: `getprop`
    // returns an empty string with exit code 0, and `File.exists()` returns
    // false for a file the app simply may not see. Collapsing either into
    // "clean" is how a RASP SDK ends up reporting a rooted device as safe.
    //
    // These states keep "I could not look" distinct from "I looked and found
    // nothing", so the difference survives into evidence instead of being lost.

    /** Whether a system property could be read at all. */
    enum class PropertyAccess { READABLE, NOT_ACCESSIBLE }

    /** Whether a path is present, absent, or simply not visible to this app. */
    enum class PathState { PRESENT, ABSENT, NOT_ACCESSIBLE }

    /** The state of a protected partition, per the kernel's own mount table. */
    enum class MountState { READ_ONLY, WRITABLE, NOT_PRESENT, UNKNOWN }

    /**
     * Whether the mount table could be read at all.
     *
     * Two root signals depend on it — `system_writable` and `mount_namespace` —
     * and both are boolean, so an unreadable table makes them indistinguishable
     * from a clean device. This state exists so that "the mount table was
     * unavailable" is reportable rather than silently equivalent to "no root
     * traces found".
     */
    enum class MountTableAccess { READABLE, NOT_ACCESSIBLE }

    /** Classifies a mount-table read. An empty dump means the read failed. */
    fun classifyMountTable(content: String): MountTableAccess =
        if (content.isBlank()) MountTableAccess.NOT_ACCESSIBLE else MountTableAccess.READABLE

    /**
     * Classifies a `getprop` result.
     *
     * An empty value is **not** "the property is 0". On API 34 the
     * security-relevant `ro.*` properties return `""` to an app with exit code
     * 0 — indistinguishable from an unset property without this distinction.
     */
    fun classifyPropertyRead(value: String?): PropertyAccess =
        if (value.isNullOrBlank()) PropertyAccess.NOT_ACCESSIBLE else PropertyAccess.READABLE

    /**
     * `ro.debuggable=1` — retained for compatibility and for the day the
     * property becomes readable again.
     *
     * **Currently unreachable from an app process.** See
     * [buildTypeIndicatesNonRetail] for what is actually observable, and
     * `docs/ANDROID_DEVICE_SECURITY_VALIDATION.md` for why the two are not
     * equivalent.
     */
    fun propIndicatesDebuggable(value: String): Boolean = value == "1"

    /** `ro.secure=0` — the security model is off. Also unreachable; see above. */
    fun propIndicatesInsecure(value: String): Boolean = value == "0"

    // ── Build-variant posture (NOT root evidence) ─────────────────────────
    //
    // ⚠️ These deliberately do **not** contribute to the root verdict.
    //
    // `Build.TYPE` is the closest app-accessible relative of `ro.debuggable`,
    // but it answers a different question: *which build variant is this?*, not
    // *has this device been tampered with?* Every AOSP emulator, every CI
    // device farm and every OEM engineering handset is `userdebug` while being
    // entirely un-rooted. Feeding that into a verdict that convicts on a single
    // signal would flag all of them as compromised.
    //
    // Likewise `ApplicationInfo.FLAG_DEBUGGABLE` describes how *this APK* was
    // built. It is an application property, not a device one, and is already
    // reported by the debugger detector as `debuggable_flag`.
    //
    // They are reported as posture evidence so an analyst can see them, and
    // scored nowhere.

    /** Build variants that are not retail images. */
    val nonRetailBuildTypes: List<String> = listOf("userdebug", "eng")

    /**
     * `true` for a `userdebug`/`eng` image.
     *
     * Posture only — see the note above. A device being non-retail is worth
     * showing an analyst; it is not proof of root.
     */
    fun buildTypeIndicatesNonRetail(buildType: String?): Boolean =
        (buildType ?: "").lowercase().trim() in nonRetailBuildTypes

    /**
     * Posture signals, reported separately from [allSignalIds] so they can
     * never reach the root verdict.
     */
    val posturesSignalIds: List<String> = listOf("build_type_non_retail", "app_debuggable")

    // ── Filesystem / partition state ──────────────────────────────────────

    /**
     * Classifies a path lookup, keeping "not visible" separate from "absent".
     *
     * `/system/xbin` and `/system/bin` are **not listable** by an app on
     * API 34, so a `su` binary inside them can read as absent even when
     * `adb shell` sees it plainly. When the file does not appear *and* its
     * directory could not be read, the honest answer is
     * [PathState.NOT_ACCESSIBLE], not [PathState.ABSENT].
     *
     * A world-readable file inside an unlistable directory still resolves by
     * exact path (`/system/bin/sh` does), which is why a positive result is
     * still trustworthy.
     */
    fun classifyPath(exists: Boolean, parentReadable: Boolean): PathState = when {
        exists -> PathState.PRESENT
        parentReadable -> PathState.ABSENT
        else -> PathState.NOT_ACCESSIBLE
    }

    /**
     * Mount points that hold the system partition.
     *
     * `/` is included because modern Android is **system-as-root**: on API 29+
     * the system image is mounted at `/`, and there is no `/system` line in
     * `/proc/mounts` at all. A check that looked only for `/system` would find
     * nothing and silently report the partition as fine — verified on
     * Android 14, where the mount table carries `/dev/block/dm-5 / ext4 ro,…`
     * and no `/system` entry whatsoever.
     */
    val systemMountPoints: List<String> = listOf("/system", "/")

    /** Protected partitions whose writability is checked. */
    val protectedMountPoints: List<String> = listOf("/system", "/", "/vendor", "/product")

    /**
     * Parses one `/proc/mounts` line into `(mountPoint, options)`.
     *
     * Format is `device mountpoint fstype options dump pass`. Returns `null`
     * for a malformed line rather than guessing.
     */
    fun parseMountLine(line: String): Pair<String, List<String>>? {
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size < 4) return null
        val mountPoint = parts[1]
        val options = parts[3].split(",").map { it.trim() }
        if (mountPoint.isEmpty()) return null
        return mountPoint to options
    }

    /**
     * The mount state of [mountPoint] according to a `/proc/mounts` dump.
     *
     * Returns [MountState.NOT_PRESENT] when the dump is readable but has no
     * such mount, and [MountState.UNKNOWN] when the dump itself is empty —
     * "I could not read the mount table" must not look like "the partition is
     * fine".
     *
     * `rw`/`ro` are matched as whole options, never as substrings: `relatime`
     * contains neither, but a naive `contains("rw")` would also match a
     * filesystem option like `errors=remount-ro`.
     */
    fun mountStateOf(mountsContent: String, mountPoint: String): MountState {
        if (mountsContent.isBlank()) return MountState.UNKNOWN
        var found = false
        mountsContent.lineSequence().forEach { line ->
            val parsed = parseMountLine(line) ?: return@forEach
            if (parsed.first != mountPoint) return@forEach
            found = true
            // A partition remounted rw is the interesting case; the last
            // matching entry wins, mirroring how the kernel stacks mounts.
            if (parsed.second.contains("rw")) return MountState.WRITABLE
        }
        return if (found) MountState.READ_ONLY else MountState.NOT_PRESENT
    }

    /**
     * `true` when any protected partition is mounted writable.
     *
     * This replaces `File.canWrite()`, which is unreliable here: the app cannot
     * even read `/`, so `canWrite()` reflects the app's own DAC permissions
     * rather than the partition's mount flags. The kernel's mount table is the
     * authoritative source and is readable by an ordinary app.
     */
    fun anyProtectedPartitionWritable(mountsContent: String): Boolean =
        protectedMountPoints.any { mountStateOf(mountsContent, it) == MountState.WRITABLE }

    /** Protected partitions currently mounted writable, for evidence. */
    fun writableProtectedPartitions(mountsContent: String): List<String> =
        protectedMountPoints.filter {
            mountStateOf(mountsContent, it) == MountState.WRITABLE
        }

    /**
     * `true` when a `/proc/self/mounts` dump carries Magisk/KernelSU traces.
     *
     * Magisk's mount namespace leaves these even when the paths themselves are
     * hidden from the app by DenyList, which is why the mount table is checked
     * separately from the filesystem.
     */
    fun mountsIndicateRoot(mountsContent: String): Boolean =
        mountsContent.contains("magisk") ||
            mountsContent.contains("KSU") ||
            mountsContent.contains("/data/adb")

    /**
     * `true` when **any** root signal fired.
     *
     * Unlike the emulator verdict this is intentionally unweighted — see the
     * class docs.
     */
    fun isRooted(signals: List<String>): Boolean = signals.isNotEmpty()

    // ── Verdict-level tri-state (Anti-Bypass Resilience milestone) ────────
    //
    // [isRooted] answers "did any signal fire?" and stays exactly as it was —
    // every signal in [allSignalIds] already has no innocent reading on a
    // retail device, so a flat "any signal convicts" rule for THAT question
    // remains correct and is not touched.
    //
    // What [isRooted] cannot say is whether an EMPTY result means "checked
    // thoroughly, genuinely clean" or "could not check". Both currently
    // collapse to the same `false`. On a device where every probe returned
    // NOT_ACCESSIBLE — e.g. a restrictive OEM SELinux policy blocking both
    // `/proc/mounts` and `getprop` — a rooted device and a clean one produce
    // an identical, empty [rootSignals] list. Reporting that as "not rooted"
    // is exactly the "UNAVAILABLE == CLEAN" failure the tri-state probe
    // enums elsewhere in this file exist to prevent; the verdict itself had
    // not yet been extended to use them.

    enum class RootVerdict {
        /** At least one signal fired. Unchanged meaning from [isRooted]. */
        DETECTED,

        /** No signal fired, and at least the mount table — the single most
         * informative probe [rootSignals] runs — was actually readable. */
        CLEAN,

        /** No signal fired, but the mount table could not be read either.
         * An empty signal list here proves nothing: the probe most capable of
         * finding root evidence never got to look. */
        UNAVAILABLE,
    }

    /**
     * The tri-state root verdict.
     *
     * [mountTableAccess] is a proxy for "did the probes have real visibility
     * at all?" rather than a complete inventory of every individual probe's
     * outcome — deliberately, so this stays a small, honest addition rather
     * than a wholesale rewrite of [rootSignals]'s data shape. The mount table
     * is the right proxy: it is the broadest single read [rootSignals]
     * performs (two signals, `system_writable` and `mount_namespace`, both
     * depend on it), and a device that cannot produce it is missing real
     * detection surface, not passing a clean bill of health.
     */
    fun classifyRootVerdict(
        signals: List<String>,
        mountTableAccess: MountTableAccess,
    ): RootVerdict = when {
        signals.isNotEmpty() -> RootVerdict.DETECTED
        mountTableAccess == MountTableAccess.NOT_ACCESSIBLE -> RootVerdict.UNAVAILABLE
        else -> RootVerdict.CLEAN
    }

    /**
     * Every signal id this detector can emit, in the order
     * `RaspDeviceIntegrityProbes.rootSignals()` produces them.
     *
     * Used by tests to guard the wire contract: an id that reaches the backend
     * without being in this set is scored as nothing.
     */
    val allSignalIds: List<String> = listOf(
        "su_binary", "magisk_artifact", "su_on_path", "root_manager_app",
        "root_cloaking_app", "test_keys", "ro_debuggable", "ro_insecure",
        "system_writable", "busybox", "mount_namespace",
    )
}
