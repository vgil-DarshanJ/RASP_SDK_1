package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * # UNIT TESTS — root-detection classification logic
 *
 * Executes the real production classifier in [RaspRootAnalysis] on the JVM.
 * The device-I/O half is covered separately by
 * `src/androidTest/.../RaspDeviceIntegrityProbesInstrumentedTest`.
 *
 * Root detection was previously the SDK's least-verified code — it had no test
 * of any kind, because it lived in a `private fun` on a `FlutterActivity`.
 * These are its first tests.
 *
 * Fixtures are realistic captured shapes. Nothing is installed or launched, and
 * no device is modified.
 */
class RaspRootAnalysisTest {

    private val cleanMounts = """
        /dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0
        tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0
        /dev/block/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,noatime 0 0
        tmpfs /storage tmpfs rw,seclabel,nosuid,nodev,noexec 0 0
    """.trimIndent()

    private val magiskMounts = """
        /dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0
        magisk /sbin tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0
        /dev/block/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,noatime 0 0
    """.trimIndent()

    private val kernelSuMounts = """
        /dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0
        KSU /system/bin overlay rw,seclabel,relatime 0 0
    """.trimIndent()

    private val dataAdbMounts = """
        /dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0
        /dev/block/loop6 /data/adb/modules ext4 rw,seclabel,relatime 0 0
    """.trimIndent()

    // ── Positive root signals ─────────────────────────────────────────────

    @Test
    fun `test-keys tags indicate a non-retail image`() {
        assertTrue(RaspRootAnalysis.tagsIndicateTestKeys("test-keys"))
        assertTrue(RaspRootAnalysis.tagsIndicateTestKeys("dev-keys,test-keys"))
    }

    @Test
    fun `ro_debuggable of 1 is a root signal`() {
        assertTrue(RaspRootAnalysis.propIndicatesDebuggable("1"))
    }

    @Test
    fun `ro_secure of 0 is a root signal`() {
        assertTrue(RaspRootAnalysis.propIndicatesInsecure("0"))
    }

    @Test
    fun `magisk traces in the mount table are detected`() {
        assertTrue(RaspRootAnalysis.mountsIndicateRoot(magiskMounts))
    }

    @Test
    fun `KernelSU traces in the mount table are detected`() {
        assertTrue(RaspRootAnalysis.mountsIndicateRoot(kernelSuMounts))
    }

    @Test
    fun `a data-adb mount is detected even without a framework name`() {
        // Magisk DenyList can hide the paths themselves; the mount namespace
        // still shows /data/adb, which is why this is checked separately.
        assertTrue(RaspRootAnalysis.mountsIndicateRoot(dataAdbMounts))
    }

    // ── Negative / clean signals ──────────────────────────────────────────

    @Test
    fun `release-keys tags are not a root signal`() {
        assertFalse(RaspRootAnalysis.tagsIndicateTestKeys("release-keys"))
    }

    @Test
    fun `a retail prop set produces no root signal`() {
        assertFalse(RaspRootAnalysis.propIndicatesDebuggable("0"))
        assertFalse(RaspRootAnalysis.propIndicatesInsecure("1"))
    }

    @Test
    fun `a clean mount table produces no root signal`() {
        assertFalse(RaspRootAnalysis.mountsIndicateRoot(cleanMounts))
    }

    @Test
    fun `no signals means not rooted`() {
        assertFalse(RaspRootAnalysis.isRooted(emptyList()))
    }

    // ── Unknown / unavailable states ──────────────────────────────────────

    @Test
    fun `an unreadable prop is never treated as a root signal`() {
        // readProp returns "" when getprop fails. Unknown must not become
        // "compromised" any more than it becomes "clean".
        assertFalse(RaspRootAnalysis.propIndicatesDebuggable(""))
        assertFalse(RaspRootAnalysis.propIndicatesInsecure(""))
    }

    @Test
    fun `null build tags do not throw and do not convict`() {
        assertFalse(RaspRootAnalysis.tagsIndicateTestKeys(null))
    }

    @Test
    fun `an empty mount dump produces no signal`() {
        assertFalse(RaspRootAnalysis.mountsIndicateRoot(""))
    }

    // ── Combinations / verdict ────────────────────────────────────────────

    @Test
    fun `any single root signal convicts`() {
        // Deliberately unweighted, unlike the emulator verdict: a su binary or
        // a Magisk artefact has no innocent explanation on a retail handset.
        RaspRootAnalysis.allSignalIds.forEach {
            assertTrue("'$it' must convict alone", RaspRootAnalysis.isRooted(listOf(it)))
        }
    }

    @Test
    fun `multiple root signals still convict`() {
        assertTrue(RaspRootAnalysis.isRooted(
            listOf("su_binary", "magisk_artifact", "mount_namespace")))
    }

    // ── Signal data integrity ─────────────────────────────────────────────

    @Test
    fun `su path coverage includes the standard install locations`() {
        listOf("/sbin/su", "/system/bin/su", "/system/xbin/su", "/vendor/bin/su")
            .forEach {
                assertTrue("$it must be covered", RaspRootAnalysis.suPaths.contains(it))
            }
        assertEquals("su path list changed size", 13, RaspRootAnalysis.suPaths.size)
    }

    @Test
    fun `magisk coverage includes the hidden DenyList layout and KernelSU`() {
        assertTrue(RaspRootAnalysis.magiskPaths.any { it.contains("/data/adb/magisk") })
        assertTrue(RaspRootAnalysis.magiskPaths.contains("/data/adb/ksu"))
        assertTrue(RaspRootAnalysis.magiskPaths.contains("/sbin/.magisk"))
        assertEquals("magisk path list changed size", 13, RaspRootAnalysis.magiskPaths.size)
    }

    @Test
    fun `root manager and cloaking package lists are preserved`() {
        assertTrue(RaspRootAnalysis.rootPackages.contains("com.topjohnwu.magisk"))
        assertTrue(RaspRootAnalysis.rootPackages.contains("me.weishu.kernelsu"))
        assertTrue(RaspRootAnalysis.rootCloakingPackages.contains("com.devadvance.rootcloak"))
        assertEquals(18, RaspRootAnalysis.rootPackages.size)
        assertEquals(6, RaspRootAnalysis.rootCloakingPackages.size)
    }

    @Test
    fun `detection does not rely on package names alone`() {
        // The brief's explicit requirement. Packages are 2 of 11 signal
        // families; the rest are filesystem, PATH, props, mounts and BusyBox.
        val packageBased = setOf("root_manager_app", "root_cloaking_app")
        val nonPackage = RaspRootAnalysis.allSignalIds.filterNot { it in packageBased }
        assertTrue(
            "most root signals must be independent of package lookup",
            nonPackage.size >= 8,
        )
    }

    @Test
    fun `read-only mount points and busybox paths are preserved`() {
        assertEquals(listOf("/system", "/vendor", "/product"),
            RaspRootAnalysis.readOnlyMountPoints)
        assertEquals(3, RaspRootAnalysis.busyboxPaths.size)
    }

    @Test
    fun `the signal id set is exactly the eleven documented ids`() {
        // Guards the wire contract: an id the backend does not know is scored
        // as nothing, so silently adding or renaming one is a real defect.
        assertEquals(11, RaspRootAnalysis.allSignalIds.size)
        assertEquals(
            RaspRootAnalysis.allSignalIds.size,
            RaspRootAnalysis.allSignalIds.toSet().size,
        )
    }

    // ── False positives ───────────────────────────────────────────────────

    @Test
    fun `a stock retail profile produces no root signals end to end`() {
        val signals = buildList {
            if (RaspRootAnalysis.tagsIndicateTestKeys("release-keys")) add("test_keys")
            if (RaspRootAnalysis.propIndicatesDebuggable("0")) add("ro_debuggable")
            if (RaspRootAnalysis.propIndicatesInsecure("1")) add("ro_insecure")
            if (RaspRootAnalysis.mountsIndicateRoot(cleanMounts)) add("mount_namespace")
        }
        assertTrue("stock device produced signals: $signals", signals.isEmpty())
        assertFalse(RaspRootAnalysis.isRooted(signals))
    }

    @Test
    fun `ordinary mount entries are not mistaken for root traces`() {
        listOf(
            "/dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0",
            "tmpfs /apex/com.android.runtime tmpfs ro,seclabel 0 0",
            "/data/media /storage/emulated sdcardfs rw 0 0",
        ).forEach {
            assertFalse("'$it' must not look like root", RaspRootAnalysis.mountsIndicateRoot(it))
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // REMEDIATION — property accessibility (ro_debuggable / ro_insecure)
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `an empty property read is NOT_ACCESSIBLE, never a clean result`() {
        // The defect this models: on API 34 `getprop ro.debuggable` returns ""
        // with exit code 0. Treating that as "property is 0" silently reports a
        // check that never ran as a pass.
        assertEquals(RaspRootAnalysis.PropertyAccess.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyPropertyRead(""))
        assertEquals(RaspRootAnalysis.PropertyAccess.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyPropertyRead("   "))
        assertEquals(RaspRootAnalysis.PropertyAccess.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyPropertyRead(null))
    }

    @Test
    fun `a real property value is READABLE`() {
        assertEquals(RaspRootAnalysis.PropertyAccess.READABLE,
            RaspRootAnalysis.classifyPropertyRead("1"))
        assertEquals(RaspRootAnalysis.PropertyAccess.READABLE,
            RaspRootAnalysis.classifyPropertyRead("0"))
    }

    @Test
    fun `the legacy property predicates still work if the value ever returns`() {
        // Kept so the signals revive automatically should a platform or OEM
        // make these readable again.
        assertTrue(RaspRootAnalysis.propIndicatesDebuggable("1"))
        assertFalse(RaspRootAnalysis.propIndicatesDebuggable("0"))
        assertTrue(RaspRootAnalysis.propIndicatesInsecure("0"))
        assertFalse(RaspRootAnalysis.propIndicatesInsecure("1"))
    }

    @Test
    fun `an unreadable property never produces a root signal`() {
        // The empty string must not satisfy either predicate.
        assertFalse(RaspRootAnalysis.propIndicatesDebuggable(""))
        assertFalse(RaspRootAnalysis.propIndicatesInsecure(""))
    }

    // ══════════════════════════════════════════════════════════════════════
    // REMEDIATION — build-variant posture (explicitly NOT root evidence)
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `userdebug and eng builds are recognised as non-retail`() {
        assertTrue(RaspRootAnalysis.buildTypeIndicatesNonRetail("userdebug"))
        assertTrue(RaspRootAnalysis.buildTypeIndicatesNonRetail("eng"))
        assertTrue(RaspRootAnalysis.buildTypeIndicatesNonRetail("USERDEBUG"))
        assertTrue(RaspRootAnalysis.buildTypeIndicatesNonRetail(" userdebug "))
    }

    @Test
    fun `a retail user build is not non-retail`() {
        assertFalse(RaspRootAnalysis.buildTypeIndicatesNonRetail("user"))
        assertFalse(RaspRootAnalysis.buildTypeIndicatesNonRetail(""))
        assertFalse(RaspRootAnalysis.buildTypeIndicatesNonRetail(null))
    }

    @Test
    fun `posture signals are NOT part of the root signal set`() {
        // The failure mode this prevents: "dev-keys / userdebug interpreted as
        // automatic root". Every CI emulator and OEM engineering handset is
        // userdebug while being entirely un-rooted, and the root verdict
        // convicts on a single signal — so these must never reach it.
        RaspRootAnalysis.posturesSignalIds.forEach {
            assertFalse(
                "posture signal '$it' must not be a root signal",
                RaspRootAnalysis.allSignalIds.contains(it),
            )
        }
    }

    @Test
    fun `a userdebug device does not become rooted through posture alone`() {
        // Simulates this project's own emulator: userdebug, dev-keys,
        // debuggable APK, and nothing else. Root verdict must stay false.
        val rootSignals = emptyList<String>()
        assertFalse(RaspRootAnalysis.isRooted(rootSignals))
        assertTrue(RaspRootAnalysis.buildTypeIndicatesNonRetail("userdebug"))
        assertFalse("dev-keys is not test-keys",
            RaspRootAnalysis.tagsIndicateTestKeys("dev-keys"))
    }

    // ══════════════════════════════════════════════════════════════════════
    // REMEDIATION — path tri-state (inaccessible ≠ absent)
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `a visible file is PRESENT`() {
        assertEquals(RaspRootAnalysis.PathState.PRESENT,
            RaspRootAnalysis.classifyPath(exists = true, parentReadable = true))
        assertEquals(RaspRootAnalysis.PathState.PRESENT,
            RaspRootAnalysis.classifyPath(exists = true, parentReadable = false))
    }

    @Test
    fun `absent from a readable directory is ABSENT`() {
        assertEquals(RaspRootAnalysis.PathState.ABSENT,
            RaspRootAnalysis.classifyPath(exists = false, parentReadable = true))
    }

    @Test
    fun `absent from an UNREADABLE directory is NOT_ACCESSIBLE, not ABSENT`() {
        // The measured defect: adb shell sees /system/xbin/su while the app
        // reads it as absent, because /system/xbin is not listable. Calling
        // that "absent" converts missing visibility into a clean result.
        assertEquals(RaspRootAnalysis.PathState.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyPath(exists = false, parentReadable = false))
    }

    // ══════════════════════════════════════════════════════════════════════
    // REMEDIATION — /proc/mounts partition state
    // ══════════════════════════════════════════════════════════════════════

    /** Real Android 14 shape: system-as-root, no /system entry at all. */
    private val android14Mounts = """
        /dev/block/dm-5 / ext4 ro,seclabel,relatime 0 0
        /dev/block/dm-4 /vendor ext4 ro,seclabel,relatime 0 0
        /dev/block/dm-3 /product ext4 ro,seclabel,relatime 0 0
        /dev/block/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,noatime 0 0
        tmpfs /storage tmpfs rw,seclabel,nosuid,nodev,noexec 0 0
    """.trimIndent()

    /** The same device with the system partition remounted writable. */
    private val remountedSystem = """
        /dev/block/dm-5 / ext4 rw,seclabel,relatime 0 0
        /dev/block/dm-4 /vendor ext4 ro,seclabel,relatime 0 0
    """.trimIndent()

    private val legacySystemMount = """
        /dev/block/mmcblk0p1 /system ext4 ro,seclabel,relatime 0 0
        /dev/block/mmcblk0p2 /vendor ext4 ro,seclabel,relatime 0 0
    """.trimIndent()

    @Test
    fun `a mount line parses into mount point and options`() {
        val parsed = RaspRootAnalysis.parseMountLine(
            "/dev/block/dm-5 / ext4 ro,seclabel,relatime 0 0")
        assertEquals("/", parsed!!.first)
        assertTrue(parsed.second.contains("ro"))
        assertTrue(parsed.second.contains("seclabel"))
    }

    @Test
    fun `a malformed mount line is rejected rather than guessed`() {
        assertEquals(null, RaspRootAnalysis.parseMountLine(""))
        assertEquals(null, RaspRootAnalysis.parseMountLine("garbage"))
        assertEquals(null, RaspRootAnalysis.parseMountLine("only three fields"))
    }

    @Test
    fun `system-as-root is detected via the root mount point`() {
        // The bug this prevents: on API 29+ there is no /system line at all, so
        // a check looking only for "/system" finds nothing and reports the
        // partition as fine. Verified against a real Android 14 mount table.
        assertEquals(RaspRootAnalysis.MountState.NOT_PRESENT,
            RaspRootAnalysis.mountStateOf(android14Mounts, "/system"))
        assertEquals(RaspRootAnalysis.MountState.READ_ONLY,
            RaspRootAnalysis.mountStateOf(android14Mounts, "/"))
        assertTrue(RaspRootAnalysis.systemMountPoints.contains("/"))
    }

    @Test
    fun `a normal mount configuration reports no writable partition`() {
        assertFalse(RaspRootAnalysis.anyProtectedPartitionWritable(android14Mounts))
        assertTrue(RaspRootAnalysis.writableProtectedPartitions(android14Mounts).isEmpty())
    }

    @Test
    fun `a remounted system partition is detected as writable`() {
        assertEquals(RaspRootAnalysis.MountState.WRITABLE,
            RaspRootAnalysis.mountStateOf(remountedSystem, "/"))
        assertTrue(RaspRootAnalysis.anyProtectedPartitionWritable(remountedSystem))
        assertEquals(listOf("/"), RaspRootAnalysis.writableProtectedPartitions(remountedSystem))
    }

    @Test
    fun `a legacy device with a real system mount still works`() {
        assertEquals(RaspRootAnalysis.MountState.READ_ONLY,
            RaspRootAnalysis.mountStateOf(legacySystemMount, "/system"))
        assertFalse(RaspRootAnalysis.anyProtectedPartitionWritable(legacySystemMount))
    }

    @Test
    fun `an unreadable mount table is UNKNOWN, not clean`() {
        // readMounts() returns "" on failure. That must not look like a
        // read-only partition.
        assertEquals(RaspRootAnalysis.MountState.UNKNOWN,
            RaspRootAnalysis.mountStateOf("", "/"))
        assertEquals(RaspRootAnalysis.MountState.UNKNOWN,
            RaspRootAnalysis.mountStateOf("   ", "/system"))
    }

    @Test
    fun `a missing mount point is NOT_PRESENT rather than writable`() {
        assertEquals(RaspRootAnalysis.MountState.NOT_PRESENT,
            RaspRootAnalysis.mountStateOf(android14Mounts, "/odm"))
    }

    @Test
    fun `rw and ro are matched as whole options, not substrings`() {
        // 'relatime' contains neither; 'errors=remount-ro' would fool a naive
        // contains("ro") check into calling a writable partition read-only.
        val tricky = "/dev/block/dm-5 / ext4 rw,errors=remount-ro,relatime 0 0"
        assertEquals(RaspRootAnalysis.MountState.WRITABLE,
            RaspRootAnalysis.mountStateOf(tricky, "/"))

        val roWithRwSubstring = "/dev/block/dm-5 / ext4 ro,rwlocks,relatime 0 0"
        assertEquals(RaspRootAnalysis.MountState.READ_ONLY,
            RaspRootAnalysis.mountStateOf(roWithRwSubstring, "/"))
    }

    @Test
    fun `a writable data partition is not a protected-partition finding`() {
        // /data is rw on every healthy device. Flagging it would fire on 100%
        // of devices — the definitive false positive.
        assertFalse(RaspRootAnalysis.protectedMountPoints.contains("/data"))
        assertFalse(RaspRootAnalysis.anyProtectedPartitionWritable(android14Mounts))
    }

    @Test
    fun `an unreadable mount table is reportable, not silently clean`() {
        // Found by reviewing the fix itself: system_writable and
        // mount_namespace are both booleans derived from the mount table, so an
        // unreadable table makes them indistinguishable from a clean device.
        // The access state is what lets a caller tell those apart.
        assertEquals(RaspRootAnalysis.MountTableAccess.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyMountTable(""))
        assertEquals(RaspRootAnalysis.MountTableAccess.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyMountTable("   "))
        assertEquals(RaspRootAnalysis.MountTableAccess.READABLE,
            RaspRootAnalysis.classifyMountTable(android14Mounts))
    }

    @Test
    fun `an empty mount table yields no root traces AND no writable finding`() {
        // Both must be false — and the caller must consult classifyMountTable
        // to know that these falses mean "unknown", not "clean".
        assertFalse(RaspRootAnalysis.mountsIndicateRoot(""))
        assertFalse(RaspRootAnalysis.anyProtectedPartitionWritable(""))
        assertEquals(RaspRootAnalysis.MountTableAccess.NOT_ACCESSIBLE,
            RaspRootAnalysis.classifyMountTable(""))
    }

    @Test
    fun `mount point matching is exact, not prefix-based`() {
        // "/" must not match "/vendor"; "/system" must not match "/system_ext".
        val systemExt = "/dev/block/dm-9 /system_ext ext4 rw,seclabel 0 0"
        assertEquals(RaspRootAnalysis.MountState.NOT_PRESENT,
            RaspRootAnalysis.mountStateOf(systemExt, "/system"))
        assertEquals(RaspRootAnalysis.MountState.NOT_PRESENT,
            RaspRootAnalysis.mountStateOf(systemExt, "/"))
    }
    // ── RootVerdict tri-state (Anti-Bypass Resilience milestone) ──────────

    @Test
    fun `any signal fired means DETECTED regardless of mount table access`() {
        assertEquals(RaspRootAnalysis.RootVerdict.DETECTED,
            RaspRootAnalysis.classifyRootVerdict(listOf("su_binary"),
                RaspRootAnalysis.MountTableAccess.READABLE))
        assertEquals(RaspRootAnalysis.RootVerdict.DETECTED,
            RaspRootAnalysis.classifyRootVerdict(listOf("magisk_artifact"),
                RaspRootAnalysis.MountTableAccess.NOT_ACCESSIBLE))
    }

    @Test
    fun `no signals and a readable mount table means CLEAN`() {
        assertEquals(RaspRootAnalysis.RootVerdict.CLEAN,
            RaspRootAnalysis.classifyRootVerdict(emptyList(),
                RaspRootAnalysis.MountTableAccess.READABLE))
    }

    @Test
    fun `no signals and an unreadable mount table means UNAVAILABLE, never CLEAN`() {
        // The exact failure this verdict exists to prevent: an empty signal
        // list is not evidence of safety when the probe most capable of
        // finding root evidence never got to look.
        assertEquals(RaspRootAnalysis.RootVerdict.UNAVAILABLE,
            RaspRootAnalysis.classifyRootVerdict(emptyList(),
                RaspRootAnalysis.MountTableAccess.NOT_ACCESSIBLE))
    }

    @Test
    fun `UNAVAILABLE and CLEAN are never equal`() {
        assertTrue(RaspRootAnalysis.RootVerdict.UNAVAILABLE !=
            RaspRootAnalysis.RootVerdict.CLEAN)
    }
}
