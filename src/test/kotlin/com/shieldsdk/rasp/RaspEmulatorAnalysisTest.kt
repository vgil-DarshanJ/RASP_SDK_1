package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * # UNIT TESTS — emulator-detection classification logic
 *
 * Executes the real production classifier in [RaspEmulatorAnalysis] on the JVM.
 * The device-I/O half is covered by
 * `src/androidTest/.../RaspDeviceIntegrityProbesInstrumentedTest`.
 *
 * ## Why real-device profiles are the important half
 *
 * A false positive here blocks a paying customer's phone. These fixtures are
 * realistic `android.os.Build` field sets for retail handsets — including the
 * awkward ones that genuinely ship `Build.MANUFACTURER` as `"unknown"` — so the
 * question *"would this block a real Samsung?"* is answered by a test rather
 * than by inspection.
 *
 * Nothing here references the AVD this project happens to use; no
 * `if emulator == rasp_verify` shortcuts.
 */
class RaspEmulatorAnalysisTest {

    // ── Real retail device profiles ───────────────────────────────────────

    private val pixel8 = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "google/shiba/shiba:14/UQ1A.240205.004/11269751:user/release-keys",
        model = "Pixel 8", product = "shiba", hardware = "shiba",
        manufacturer = "Google", brand = "google", device = "shiba",
    )

    private val galaxyS23 = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "samsung/dm1qxxx/dm1q:14/UP1A.231005.007/S911BXXU5CXAA:user/release-keys",
        model = "SM-S911B", product = "dm1qxxx", hardware = "qcom",
        manufacturer = "samsung", brand = "samsung", device = "dm1q",
    )

    private val xiaomiRedmi = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "Redmi/sunstone/sunstone:13/TKQ1.221114.001/V14.0.4.0:user/release-keys",
        model = "22101316C", product = "sunstone", hardware = "qcom",
        manufacturer = "Xiaomi", brand = "Redmi", device = "sunstone",
    )

    /**
     * A budget handset that ships `Build.MANUFACTURER` as `"unknown"`.
     *
     * This is the case the hard/soft threshold exists for: it fires
     * `build_manufacturer`, and that single soft signal must not convict.
     */
    private val budgetUnknownManufacturer = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "alps/full_k62v1_64/k62v1_64:11/RP1A.200720.011/1620:user/release-keys",
        model = "M2006C3MG", product = "full_k62v1_64", hardware = "mt6765",
        manufacturer = "unknown", brand = "alps", device = "k62v1_64",
    )

    // ── Emulator profiles ─────────────────────────────────────────────────

    private val aospEmulator = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "google/sdk_gphone64_x86_64/emu64xa:14/UE1A.230829.050/12077443:userdebug/dev-keys",
        model = "sdk_gphone64_x86_64", product = "sdk_gphone64_x86_64",
        hardware = "ranchu", manufacturer = "Google", brand = "google", device = "emu64xa",
    )

    private val genymotion = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "generic/vbox86p/vbox86p:9/PI/genymotion:userdebug/test-keys",
        model = "Custom Phone", product = "vbox86p", hardware = "vbox86",
        manufacturer = "Genymotion", brand = "generic", device = "vbox86p",
    )

    private val cuttlefish = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "google/cf_x86_64_phone/vsoc_x86_64:14/UPB4/9999:userdebug/dev-keys",
        model = "Cuttlefish x86_64", product = "cf_x86_64_phone", hardware = "cutf_cvm",
        manufacturer = "Google", brand = "google", device = "vsoc_x86_64",
    )

    private val ldPlayer = RaspEmulatorAnalysis.BuildProfile.fromRaw(
        fingerprint = "generic/ldplayer/ldplayer:9/PI/1:user/release-keys",
        model = "ASUS_Z01QD", product = "ldplayer", hardware = "ldplayer",
        manufacturer = "asus", brand = "generic", device = "generic",
    )

    // ══════════════════════════════════════════════════════════════════════
    // FALSE POSITIVES — the commercially critical half
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `a Pixel 8 is not classified as an emulator`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(pixel8)
        assertTrue("Pixel 8 produced signals: $signals", signals.isEmpty())
        assertFalse(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `a Galaxy S23 is not classified as an emulator`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(galaxyS23)
        assertTrue("Galaxy S23 produced signals: $signals", signals.isEmpty())
        assertFalse(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `a Xiaomi Redmi is not classified as an emulator`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(xiaomiRedmi)
        assertTrue("Redmi produced signals: $signals", signals.isEmpty())
        assertFalse(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `a budget handset reporting manufacturer 'unknown' is NOT blocked`() {
        // The exact false positive the hard/soft split exists to prevent.
        val signals = RaspEmulatorAnalysis.buildFieldSignals(budgetUnknownManufacturer)
        assertEquals("only the manufacturer signal should fire",
            listOf("build_manufacturer"), signals)
        assertFalse(
            "one soft Build field must never convict a real device",
            RaspEmulatorAnalysis.isEmulator(signals),
        )
    }

    @Test
    fun `no single soft signal ever convicts on its own`() {
        RaspEmulatorAnalysis.allSignalIds
            .filterNot { it in RaspEmulatorAnalysis.hardSignals }
            .forEach {
                assertFalse("soft signal '$it' must not convict alone",
                    RaspEmulatorAnalysis.isEmulator(listOf(it)))
            }
    }

    @Test
    fun `a retail carrier name is not the emulator carrier`() {
        listOf("Vodafone IN", "Jio", "T-Mobile", "Airtel", null, "")
            .forEach {
                assertFalse("'$it' must not look like the emulator carrier",
                    RaspEmulatorAnalysis.carrierIndicatesEmulator(it))
            }
    }

    // ══════════════════════════════════════════════════════════════════════
    // POSITIVE — emulator profiles
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `the AOSP emulator is detected`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(aospEmulator)
        assertTrue("expected build_hardware (ranchu)", signals.contains("build_hardware"))
        assertTrue(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `Genymotion is detected`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(genymotion)
        assertTrue(signals.contains("build_hardware"))
        assertTrue(signals.contains("build_manufacturer"))
        assertTrue(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `Cuttlefish is detected via its SoC name`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(cuttlefish)
        assertTrue("cutf must be recognised", signals.contains("build_hardware"))
        assertTrue(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `LDPlayer is detected`() {
        val signals = RaspEmulatorAnalysis.buildFieldSignals(ldPlayer)
        assertTrue(signals.contains("build_hardware"))
        assertTrue(RaspEmulatorAnalysis.isEmulator(signals))
    }

    @Test
    fun `the emulated SoC name is a hard signal`() {
        // build_hardware is the one Build field strong enough to convict alone:
        // no retail device reports goldfish/ranchu/cutf/vbox86.
        assertTrue(RaspEmulatorAnalysis.hardSignals.contains("build_hardware"))
        assertTrue(RaspEmulatorAnalysis.isEmulator(listOf("build_hardware")))
    }

    // ── Individual predicates ─────────────────────────────────────────────

    @Test
    fun `fingerprint predicate covers the known emulator shapes`() {
        listOf("generic/x", "vbox", "emulator", "sdk_gphone", "unknown").forEach { frag ->
            val p = RaspEmulatorAnalysis.BuildProfile.fromRaw(
                frag, "", "", "", "", "", "")
            assertTrue("'$frag' should trip the fingerprint check",
                RaspEmulatorAnalysis.buildFingerprintIndicatesEmulator(p))
        }
    }

    @Test
    fun `hardware predicate covers goldfish ranchu vbox ttvm cutf nox ldplayer`() {
        listOf("goldfish", "ranchu", "vbox86", "ttvm", "cutf", "nox", "ldplayer").forEach { hw ->
            val p = RaspEmulatorAnalysis.BuildProfile.fromRaw("", "", "", hw, "", "", "")
            assertTrue("'$hw' should trip the hardware check",
                RaspEmulatorAnalysis.buildHardwareIndicatesEmulator(p))
        }
    }

    @Test
    fun `real SoC names do not trip the hardware check`() {
        listOf("qcom", "exynos9820", "mt6765", "kirin990", "shiba", "tensor").forEach { hw ->
            val p = RaspEmulatorAnalysis.BuildProfile.fromRaw("", "", "", hw, "", "", "")
            assertFalse("'$hw' is a real SoC and must not trip the check",
                RaspEmulatorAnalysis.buildHardwareIndicatesEmulator(p))
        }
    }

    @Test
    fun `brand and device must BOTH be generic to fire`() {
        val onlyBrand = RaspEmulatorAnalysis.BuildProfile.fromRaw(
            "", "", "", "", "", "generic", "shiba")
        assertFalse(RaspEmulatorAnalysis.buildBrandDeviceIndicatesEmulator(onlyBrand))

        val both = RaspEmulatorAnalysis.BuildProfile.fromRaw(
            "", "", "", "", "", "generic", "generic_x86")
        assertTrue(RaspEmulatorAnalysis.buildBrandDeviceIndicatesEmulator(both))
    }

    @Test
    fun `field matching is case-insensitive via fromRaw`() {
        val p = RaspEmulatorAnalysis.BuildProfile.fromRaw(
            "", "", "", "RANCHU", "GENYMOTION", "", "")
        assertTrue(RaspEmulatorAnalysis.buildHardwareIndicatesEmulator(p))
        assertTrue(RaspEmulatorAnalysis.buildManufacturerIndicatesEmulator(p))
    }

    // ── Unknown / unavailable states ──────────────────────────────────────

    @Test
    fun `null Build fields do not throw and do not convict`() {
        val p = RaspEmulatorAnalysis.BuildProfile.fromRaw(
            null, null, null, null, null, null, null)
        assertTrue(RaspEmulatorAnalysis.buildFieldSignals(p).isEmpty())
        assertFalse(RaspEmulatorAnalysis.isEmulator(RaspEmulatorAnalysis.buildFieldSignals(p)))
    }

    @Test
    fun `an unreadable prop is not an emulator signal`() {
        // readProp returns "" when getprop fails.
        assertFalse(RaspEmulatorAnalysis.propIndicatesQemu(""))
        assertFalse(RaspEmulatorAnalysis.propIndicatesVirtualDevice(""))
        assertFalse(RaspEmulatorAnalysis.propIndicatesVirtualDevice("   "))
    }

    @Test
    fun `no signals means not an emulator`() {
        assertFalse(RaspEmulatorAnalysis.isEmulator(emptyList()))
    }

    // ── Combinations / threshold ──────────────────────────────────────────

    @Test
    fun `every hard signal convicts on its own`() {
        RaspEmulatorAnalysis.hardSignals.forEach {
            assertTrue("'$it' is hard and must convict alone",
                RaspEmulatorAnalysis.isEmulator(listOf(it)))
        }
    }

    @Test
    fun `two soft signals together do convict`() {
        assertTrue(RaspEmulatorAnalysis.isEmulator(
            listOf("build_manufacturer", "build_fingerprint")))
    }

    @Test
    fun `a hard signal convicts even when mixed with soft ones`() {
        assertTrue(RaspEmulatorAnalysis.isEmulator(
            listOf("build_manufacturer", "qemu_prop")))
    }

    // ── Signal data integrity ─────────────────────────────────────────────

    @Test
    fun `emulator file and package lists are preserved`() {
        assertEquals(10, RaspEmulatorAnalysis.emulatorFiles.size)
        assertEquals(7, RaspEmulatorAnalysis.emulatorPackages.size)
        assertTrue(RaspEmulatorAnalysis.emulatorFiles.contains("/dev/qemu_pipe"))
        assertTrue(RaspEmulatorAnalysis.emulatorPackages.contains("com.genymotion.superuser"))
    }

    @Test
    fun `the signal id set is exactly the thirteen documented ids`() {
        assertEquals(13, RaspEmulatorAnalysis.allSignalIds.size)
        assertEquals(
            RaspEmulatorAnalysis.allSignalIds.size,
            RaspEmulatorAnalysis.allSignalIds.toSet().size,
        )
        // Every hard signal must be a real signal id.
        RaspEmulatorAnalysis.hardSignals.forEach {
            assertTrue("hard signal '$it' is not a known id",
                RaspEmulatorAnalysis.allSignalIds.contains(it))
        }
    }

    @Test
    fun `the hard set is exactly the eight documented signals`() {
        // Promoting a signal to hard invites false positives; demoting one
        // weakens detection. Both should be deliberate, so pin the set.
        assertEquals(8, RaspEmulatorAnalysis.hardSignals.size)
    }
}
