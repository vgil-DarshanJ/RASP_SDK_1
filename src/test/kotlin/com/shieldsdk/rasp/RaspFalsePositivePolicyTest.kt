package com.shieldsdk.rasp

import org.junit.Assert.assertFalse
import org.junit.Test

class RaspFalsePositivePolicyTest {
    @Test fun `ordinary navigation and ad blocking apps are not reverse tool targets`() {
        assertFalse("com.sygic.aura" in RaspReverseEngineeringToolsProbe.reTools)
        assertFalse("org.adaway" in RaspReverseEngineeringToolsProbe.reTools)
    }

    @Test fun `unknown build fields alone are not emulator indicators`() {
        val profile = RaspEmulatorAnalysis.BuildProfile.fromRaw("unknown", "phone", "phone", "qcom", "unknown", "brand", "device")
        assertFalse(RaspEmulatorAnalysis.buildFingerprintIndicatesEmulator(profile))
        assertFalse(RaspEmulatorAnalysis.buildManufacturerIndicatesEmulator(profile))
    }
}
