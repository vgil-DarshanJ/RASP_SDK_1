package com.shieldsdk.rasp

/**
 * Classification logic and signal data for emulator detection.
 *
 * ## Extraction, not redesign
 *
 * Every predicate, list and threshold is a **verbatim move** from
 * `MainActivity.emulatorSignals()` / `isEmulator()`. Nothing was loosened to
 * make a test pass — in particular the broad [buildProductIndicatesEmulator]
 * substring `"sdk"` is preserved exactly, and remains a *soft* signal so it
 * cannot convict a real device on its own.
 *
 * ## The BuildProfile seam
 *
 * `android.os.Build` is a static Android class: unreadable from a JVM unit
 * test, and constant within a process on a device. Taking the seven fields as
 * a [BuildProfile] is what makes the interesting question testable —
 * *"would a real Samsung/Pixel/Xiaomi be misclassified?"* — without hardcoding
 * anything about the emulator this happens to run on.
 *
 * ## Verdict model
 *
 * One **hard** signal, or two **soft** ones. Build fields are cheap to spoof on
 * a rooted guest and some budget OEM handsets genuinely ship
 * `Build.MANUFACTURER` as `"unknown"`, so no single Build field is allowed to
 * convict. Files, packages, props, a missing accelerometer and the emulated
 * carrier are hard: awkward to fake and absent from real hardware.
 */
object RaspEmulatorAnalysis {

    /**
     * The `android.os.Build` fields the detector reads, already lowercased.
     *
     * Construct with [fromRaw] so normalisation happens in exactly one place.
     */
    data class BuildProfile(
        val fingerprint: String,
        val model: String,
        val product: String,
        val hardware: String,
        val manufacturer: String,
        val brand: String,
        val device: String,
    ) {
        companion object {
            fun fromRaw(
                fingerprint: String?, model: String?, product: String?,
                hardware: String?, manufacturer: String?, brand: String?, device: String?,
            ) = BuildProfile(
                fingerprint = (fingerprint ?: "").lowercase(),
                model = (model ?: "").lowercase(),
                product = (product ?: "").lowercase(),
                hardware = (hardware ?: "").lowercase(),
                manufacturer = (manufacturer ?: "").lowercase(),
                brand = (brand ?: "").lowercase(),
                device = (device ?: "").lowercase(),
            )
        }
    }

    /** Files that only exist inside an emulated device. */
    val emulatorFiles: List<String> = listOf(
        // QEMU / AOSP goldfish + ranchu
        "/dev/socket/qemud", "/dev/qemu_pipe", "/sys/qemu_trace",
        "/system/bin/qemu-props", "/system/lib/libc_malloc_debug_qemu.so",
        // Genymotion
        "/dev/socket/genyd", "/dev/socket/baseband_genyd",
        // Nox / MEmu / LDPlayer ship their own daemons
        "/system/bin/nox-prop", "/system/bin/ldinit", "/system/bin/microvirt-prop",
    )

    /** Emulator-host control apps, present inside the guest image. */
    val emulatorPackages: List<String> = listOf(
        "com.genymotion.superuser", "com.genymotion.tools",
        "com.bluestacks.appmart", "com.bluestacks.home",
        "com.bignox.app", "com.microvirt.launcher", "com.vphone.launcher",
    )

    /**
     * Signals an attacker cannot trivially spoof, each sufficient alone.
     *
     * `build_hardware` is here despite being a Build field because it names the
     * emulated SoC (`goldfish`/`ranchu`/`cutf`/…), which no retail device
     * reports.
     */
    val hardSignals: Set<String> = setOf(
        "emulator_file", "emulator_package", "qemu_prop", "qemu_boot_prop",
        "virtual_device_prop", "no_accelerometer", "emulator_carrier",
        "build_hardware",
    )

    fun buildFingerprintIndicatesEmulator(p: BuildProfile): Boolean =
        p.fingerprint.startsWith("generic") || p.fingerprint.contains("vbox") ||
            p.fingerprint.contains("emulator") || p.fingerprint.contains("sdk_gphone") ||
            p.fingerprint.contains("unknown")

    fun buildModelIndicatesEmulator(p: BuildProfile): Boolean =
        p.model.contains("google_sdk") || p.model.contains("emulator") ||
            p.model.contains("android sdk built for") || p.model.contains("sdk_gphone")

    fun buildProductIndicatesEmulator(p: BuildProfile): Boolean =
        p.product.contains("sdk") || p.product.contains("vbox86") ||
            p.product.contains("emulator") || p.product.contains("simulator") ||
            p.product.contains("cuttlefish")

    /**
     * The most reliable Build field: the emulated SoC name. `goldfish` and
     * `ranchu` are the AOSP emulator kernels, `cutf` is Cuttlefish (used by CI
     * farms), the rest are the commercial Android-on-PC products.
     */
    fun buildHardwareIndicatesEmulator(p: BuildProfile): Boolean =
        p.hardware.contains("goldfish") || p.hardware.contains("ranchu") ||
            p.hardware.contains("vbox86") || p.hardware.contains("ttvm") ||
            p.hardware.contains("cutf") || p.hardware.contains("nox") ||
            p.hardware.contains("ldplayer")

    fun buildManufacturerIndicatesEmulator(p: BuildProfile): Boolean =
        p.manufacturer.contains("genymotion") || p.manufacturer.contains("unknown")

    fun buildBrandDeviceIndicatesEmulator(p: BuildProfile): Boolean =
        p.brand.startsWith("generic") && p.device.startsWith("generic")

    /** Build-field signals, in the order the probe emits them. */
    fun buildFieldSignals(p: BuildProfile): List<String> {
        val hits = mutableListOf<String>()
        if (buildFingerprintIndicatesEmulator(p)) hits.add("build_fingerprint")
        if (buildModelIndicatesEmulator(p)) hits.add("build_model")
        if (buildProductIndicatesEmulator(p)) hits.add("build_product")
        if (buildHardwareIndicatesEmulator(p)) hits.add("build_hardware")
        if (buildManufacturerIndicatesEmulator(p)) hits.add("build_manufacturer")
        if (buildBrandDeviceIndicatesEmulator(p)) hits.add("build_brand_device")
        return hits
    }

    /** Set by the AOSP emulator. */
    fun propIndicatesQemu(value: String): Boolean = value == "1"

    /** Covers newer images that no longer set `ro.kernel.qemu`. */
    fun propIndicatesVirtualDevice(value: String): Boolean = value.isNotBlank()

    /** The AOSP emulator's fake carrier is literally "Android". */
    fun carrierIndicatesEmulator(networkOperatorName: String?): Boolean =
        networkOperatorName.equals("android", ignoreCase = true)

    /**
     * True when the emulator evidence is strong enough to act on:
     * one hard signal, or two of any kind.
     */
    fun isEmulator(signals: List<String>): Boolean =
        signals.any { it in hardSignals } || signals.size >= 2

    /** Every signal id this detector can emit, in probe order. */
    val allSignalIds: List<String> = listOf(
        "build_fingerprint", "build_model", "build_product", "build_hardware",
        "build_manufacturer", "build_brand_device", "emulator_file",
        "emulator_package", "qemu_prop", "qemu_boot_prop",
        "virtual_device_prop", "no_accelerometer", "emulator_carrier",
    )
}
