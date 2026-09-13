package com.shieldsdk.rasp

import android.content.Context
import android.os.Build

/**
 * The **I/O half** of root and emulator detection.
 *
 * Root and emulator share one class because they share all three low-level
 * accessors — filesystem existence, `getprop`, and package lookup. Splitting
 * them would duplicate those helpers for no benefit; both are device-integrity
 * questions answered from the same three sources.
 *
 * Takes a [Context] rather than an `Activity`, for the same reason as
 * [RaspDeviceProbes] and [RaspHookProbes]: an instrumentation test can call the
 * real production implementation with no Activity, no Flutter engine, and
 * nothing mocked.
 *
 * ```
 *   RaspDeviceIntegrityProbes — reads evidence   (this class; needs a device)
 *   RaspRootAnalysis          — decides "rooted?"     (pure JVM)
 *   RaspEmulatorAnalysis      — decides "emulated?"   (pure JVM)
 * ```
 *
 * The bodies below are a **verbatim move** from `MainActivity`. Signal ids,
 * their order, the nested `try`/`catch` structure and both verdict models are
 * unchanged — including the deliberate asymmetry that root convicts on any
 * signal while emulator requires a hard signal or two soft ones.
 */
class RaspDeviceIntegrityProbes(private val context: Context) {

    // ── Low-level accessors ───────────────────────────────────────────────

    private fun fileExistsQuietly(path: String): Boolean =
        try { java.io.File(path).exists() } catch (e: Exception) { false }

    private fun isPackageInstalled(pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (e: Exception) {
        false
    }

    // Bounded via RaspProcessUtils — a hung/wedged `getprop` shell must
    // never hang the calling thread indefinitely. See that object's doc.
    private fun readProp(key: String): String =
        RaspProcessUtils.firstLineOf(arrayOf("getprop", key))?.trim() ?: ""

    // ── Root ──────────────────────────────────────────────────────────────

    /**
     * Every root signal that currently fires, as stable ids.
     *
     * Returned as evidence rather than a bare boolean so the backend can score
     * *how* rooted a device looks and show an analyst what actually matched —
     * one weak signal is noise, five together is not.
     */
    fun rootSignals(): List<String> {
        val hits = mutableListOf<String>()

        try {
            if (RaspRootAnalysis.suPaths.any { fileExistsQuietly(it) }) hits.add("su_binary")
            if (RaspRootAnalysis.magiskPaths.any { fileExistsQuietly(it) }) {
                hits.add("magisk_artifact")
            }

            // `which su` resolves through PATH, catching installs outside the
            // hardcoded list above. Bounded via RaspProcessUtils.
            val whichSuLine = RaspProcessUtils.firstLineOf(arrayOf("which", "su"))
            if (!whichSuLine.isNullOrBlank()) hits.add("su_on_path")

            if (RaspRootAnalysis.rootPackages.any { isPackageInstalled(it) }) {
                hits.add("root_manager_app")
            }
            if (RaspRootAnalysis.rootCloakingPackages.any { isPackageInstalled(it) }) {
                hits.add("root_cloaking_app")
            }

            if (RaspRootAnalysis.tagsIndicateTestKeys(Build.TAGS)) hits.add("test_keys")

            // `ro.debuggable` / `ro.secure` are not readable by an app on
            // modern Android: `getprop` returns "" with exit code 0. The reads
            // are kept so the signals revive automatically if a platform or
            // OEM makes them visible again, but the *silent* failure is now
            // explicit — an unreadable property is NOT_ACCESSIBLE, never a
            // clean result. See propertyAccess() and the validation doc.
            if (RaspRootAnalysis.propIndicatesDebuggable(readProp("ro.debuggable"))) {
                hits.add("ro_debuggable")
            }
            if (RaspRootAnalysis.propIndicatesInsecure(readProp("ro.secure"))) {
                hits.add("ro_insecure")
            }

            // Protected-partition state from the kernel's own mount table.
            // `File.canWrite()` was unreliable here: an app cannot even read
            // `/`, so canWrite() reported the app's DAC permissions rather than
            // the partition's mount flags. /proc/mounts is readable and
            // authoritative, and it also covers system-as-root, where the
            // system image is mounted at `/` and no `/system` entry exists.
            if (RaspRootAnalysis.anyProtectedPartitionWritable(readMounts())) {
                hits.add("system_writable")
            }

            if (RaspRootAnalysis.busyboxPaths.any { fileExistsQuietly(it) }) hits.add("busybox")

            // Magisk's mount namespace leaves traces even when paths are hidden.
            if (RaspRootAnalysis.mountsIndicateRoot(readMounts())) {
                hits.add("mount_namespace")
            }
        } catch (e: Exception) {
            // Never let a probe crash the host app; partial evidence still counts.
        }
        return hits
    }

    /** True when any root signal fires. Evidence is available via [rootSignals]. */
    fun isDeviceRooted(): Boolean = RaspRootAnalysis.isRooted(rootSignals())

    /**
     * [rootSignals] plus the tri-state verdict, in one call.
     *
     * Reads `/proc/mounts` exactly once and reuses it for both — [rootSignals]
     * already depends on it for `system_writable`/`mount_namespace`, so a
     * second, separate read purely to classify [RaspRootAnalysis.RootVerdict]
     * would double the cost of the single most expensive probe here for no
     * benefit. Callers that only need the boolean keep using [isDeviceRooted];
     * this is for callers that need to tell UNAVAILABLE apart from CLEAN.
     */
    fun rootAssessment(): Pair<List<String>, RaspRootAnalysis.RootVerdict> {
        val mounts = readMounts()
        val hits = rootSignalsUsing(mounts)
        val access = RaspRootAnalysis.classifyMountTable(mounts)
        return hits to RaspRootAnalysis.classifyRootVerdict(hits, access)
    }

    /**
     * [rootSignals], but against an already-read mount table rather than
     * reading it again — the shared implementation [rootSignals] and
     * [rootAssessment] both call.
     */
    private fun rootSignalsUsing(mounts: String): List<String> {
        val hits = mutableListOf<String>()
        try {
            if (RaspRootAnalysis.suPaths.any { fileExistsQuietly(it) }) hits.add("su_binary")
            if (RaspRootAnalysis.magiskPaths.any { fileExistsQuietly(it) }) {
                hits.add("magisk_artifact")
            }
            val whichSuLine = RaspProcessUtils.firstLineOf(arrayOf("which", "su"))
            if (!whichSuLine.isNullOrBlank()) hits.add("su_on_path")

            if (RaspRootAnalysis.rootPackages.any { isPackageInstalled(it) }) {
                hits.add("root_manager_app")
            }
            if (RaspRootAnalysis.rootCloakingPackages.any { isPackageInstalled(it) }) {
                hits.add("root_cloaking_app")
            }
            if (RaspRootAnalysis.tagsIndicateTestKeys(Build.TAGS)) hits.add("test_keys")
            if (RaspRootAnalysis.propIndicatesDebuggable(readProp("ro.debuggable"))) {
                hits.add("ro_debuggable")
            }
            if (RaspRootAnalysis.propIndicatesInsecure(readProp("ro.secure"))) {
                hits.add("ro_insecure")
            }
            if (RaspRootAnalysis.anyProtectedPartitionWritable(mounts)) hits.add("system_writable")
            if (RaspRootAnalysis.busyboxPaths.any { fileExistsQuietly(it) }) hits.add("busybox")
            if (RaspRootAnalysis.mountsIndicateRoot(mounts)) hits.add("mount_namespace")
        } catch (e: Exception) {
            // Never let a probe crash the host app; partial evidence still counts.
        }
        return hits
    }

    /**
     * The kernel mount table, or `""` when it cannot be read.
     *
     * `/proc/mounts` and `/proc/self/mounts` carry the same content; the former
     * is used because it is the conventional path and was verified readable
     * from an ordinary app on API 34. An empty return is classified as
     * [RaspRootAnalysis.MountState.UNKNOWN] rather than as a clean partition.
     */
    private fun readMounts(): String = try {
        java.io.File("/proc/mounts").readText()
    } catch (e: Exception) {
        ""
    }

    // ── Explicit accessibility reporting ──────────────────────────────────

    /**
     * Whether each security-relevant property can actually be read here.
     *
     * Exists so the SDK can *state* that `ro.debuggable`/`ro.secure` are
     * unavailable instead of quietly behaving as though they were checked. A
     * check that never ran is not a clean bill of health.
     */
    fun propertyAccess(): Map<String, RaspRootAnalysis.PropertyAccess> =
        listOf("ro.debuggable", "ro.secure").associateWith {
            RaspRootAnalysis.classifyPropertyRead(readProp(it))
        }

    /**
     * Per-path state for the `su` locations, distinguishing "absent" from
     * "this app may not look".
     *
     * `/system/xbin` and `/system/bin` are unlistable to an app on API 34, so a
     * plain `exists() == false` there means *unknown*, not *clean*.
     */
    fun suPathStates(): Map<String, RaspRootAnalysis.PathState> =
        RaspRootAnalysis.suPaths.associateWith { path ->
            val file = java.io.File(path)
            val exists = try { file.exists() } catch (e: Exception) { false }
            val parentReadable = try {
                file.parentFile?.canRead() ?: false
            } catch (e: Exception) { false }
            RaspRootAnalysis.classifyPath(exists, parentReadable)
        }

    /** Mount state of every protected partition, for evidence and diagnostics. */
    fun protectedPartitionStates(): Map<String, RaspRootAnalysis.MountState> {
        val mounts = readMounts()
        return RaspRootAnalysis.protectedMountPoints.associateWith {
            RaspRootAnalysis.mountStateOf(mounts, it)
        }
    }

    /**
     * Whether the mount table was readable on this run.
     *
     * Both `system_writable` and `mount_namespace` are boolean signals derived
     * from it, so when this reports `NOT_ACCESSIBLE` **neither signal is
     * meaningful** — their absence says nothing about the device. Exposed so a
     * caller can tell "checked, clean" from "could not check", which the
     * booleans alone cannot express.
     */
    fun mountTableAccess(): RaspRootAnalysis.MountTableAccess =
        RaspRootAnalysis.classifyMountTable(readMounts())

    /**
     * Build-variant posture — reported, never scored as root.
     *
     * See the note in [RaspRootAnalysis]: a `userdebug` image and a debuggable
     * APK are both worth showing an analyst and neither is evidence that the
     * device has been rooted.
     */
    fun posturesSignals(): List<String> {
        val hits = mutableListOf<String>()
        try {
            if (RaspRootAnalysis.buildTypeIndicatesNonRetail(Build.TYPE)) {
                hits.add("build_type_non_retail")
            }
        } catch (e: Exception) { /* Build unavailable */ }
        try {
            val debuggable = (context.applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
            if (debuggable) hits.add("app_debuggable")
        } catch (e: Exception) { /* applicationInfo unavailable */ }
        return hits
    }

    // ── Emulator ──────────────────────────────────────────────────────────

    /** This device's `android.os.Build` fields, normalised for classification. */
    fun buildProfile(): RaspEmulatorAnalysis.BuildProfile =
        RaspEmulatorAnalysis.BuildProfile.fromRaw(
            fingerprint = Build.FINGERPRINT,
            model = Build.MODEL,
            product = Build.PRODUCT,
            hardware = Build.HARDWARE,
            manufacturer = Build.MANUFACTURER,
            brand = Build.BRAND,
            device = Build.DEVICE,
        )

    /**
     * Every emulator signal that currently fires, as stable ids.
     *
     * Signals are grouped by what they'd cost an attacker to forge: Build
     * fields are cheap to spoof on a rooted guest, files and props much less
     * so, and the absence of real sensors/telephony is awkward to fake at all.
     * All of them are reported so the scorer can weigh a combination.
     */
    fun emulatorSignals(): List<String> {
        val hits = mutableListOf<String>()

        try {
            hits.addAll(RaspEmulatorAnalysis.buildFieldSignals(buildProfile()))

            if (RaspEmulatorAnalysis.emulatorFiles.any { fileExistsQuietly(it) }) {
                hits.add("emulator_file")
            }
            if (RaspEmulatorAnalysis.emulatorPackages.any { isPackageInstalled(it) }) {
                hits.add("emulator_package")
            }

            if (RaspEmulatorAnalysis.propIndicatesQemu(readProp("ro.kernel.qemu"))) {
                hits.add("qemu_prop")
            }
            if (RaspEmulatorAnalysis.propIndicatesQemu(readProp("ro.boot.qemu"))) {
                hits.add("qemu_boot_prop")
            }
            if (RaspEmulatorAnalysis.propIndicatesVirtualDevice(
                    readProp("ro.hardware.virtual_device")
                )
            ) hits.add("virtual_device_prop")

            // A real handset has an accelerometer. Emulators frequently expose
            // no sensors at all, and this is expensive to fake convincingly.
            try {
                val sm = context.getSystemService(Context.SENSOR_SERVICE)
                    as android.hardware.SensorManager
                if (sm.getDefaultSensor(android.hardware.Sensor.TYPE_ACCELEROMETER) == null) {
                    hits.add("no_accelerometer")
                }
            } catch (e: Exception) { /* sensor service unavailable — skip */ }

            // The AOSP emulator's fake carrier is literally "Android".
            try {
                val tm = context.getSystemService(Context.TELEPHONY_SERVICE)
                    as android.telephony.TelephonyManager
                if (RaspEmulatorAnalysis.carrierIndicatesEmulator(tm.networkOperatorName)) {
                    hits.add("emulator_carrier")
                }
            } catch (e: Exception) { /* no telephony on wifi-only hardware */ }
        } catch (e: Exception) {
            // Never let a probe crash the host app; partial evidence still counts.
        }
        return hits
    }

    /**
     * True when the emulator evidence is strong enough to act on.
     *
     * Deliberately not `isNotEmpty()`, unlike [isDeviceRooted] — see
     * [RaspEmulatorAnalysis.isEmulator].
     */
    fun isEmulator(): Boolean = RaspEmulatorAnalysis.isEmulator(emulatorSignals())
}
