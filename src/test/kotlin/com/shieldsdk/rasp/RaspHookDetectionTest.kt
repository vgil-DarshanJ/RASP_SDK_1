package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hook detection verdict logic tests.
 *
 * Tests the rule: DETECTED = at least one HARD signal OR at least two SOFT signals.
 * Hard signal: hook_framework_lib (known hooking library in /proc/self/maps)
 * Soft signals: hook_rwx_mapping, hook_suspicious_lib_path, hook_native_method
 */
class RaspHookDetectionTest {

    @Test
    fun `single hard signal framework_lib is DETECTED`() {
        val signals = listOf("hook_framework_lib")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("high", RaspHookAnalysis.severityFor(signals)) // Single hard = high
    }

    @Test
    fun `two soft signals is DETECTED`() {
        val signals = listOf("hook_rwx_mapping", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("medium", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `one soft signal alone is NOT DETECTED`() {
        val signals = listOf("hook_rwx_mapping")
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `one soft signal of other type alone is NOT DETECTED`() {
        val signals = listOf("hook_suspicious_lib_path")
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `single native_method (soft) alone is NOT DETECTED`() {
        val signals = listOf("hook_native_method")
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `empty signals is NOT DETECTED`() {
        val signals = emptyList<String>()
        assertFalse(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("none", RaspHookAnalysis.severityFor(signals))
    }

    @Test
    fun `framework lib + soft is DETECTED`() {
        val signals = listOf("hook_framework_lib", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals)) // Framework + corroboration = critical
    }

    @Test
    fun `framework lib + RWX is DETECTED`() {
        val signals = listOf("hook_framework_lib", "hook_rwx_mapping")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals)) // Framework + corroboration = critical
    }

    @Test
    fun `duplicate hard signal counts once`() {
        // Duplicate same signal counts as 1 for verdict
        val signals = listOf("hook_framework_lib", "hook_framework_lib")
        // Single hard signal IS detected (hard = individually conclusive)
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        // With a second distinct hard signal it also works
        val signals2 = listOf("hook_framework_lib", "hook_framework_lib")
        assertTrue(RaspHookAnalysis.hookVerdict(signals2))
    }

    @Test
    fun `clean device RWX mapping alone does not convict`() {
        // Simulates a clean device where JIT creates >12 RWX regions
        // but no framework lib, no native method, no suspicious path
        val signals = listOf("hook_rwx_mapping")
        assertFalse("RWX alone should not convict on clean device", RaspHookAnalysis.hookVerdict(signals))
    }

    @Test
    fun `clean device reflection false positive on native_method alone does not convict`() {
        // Simulates obfuscation/ART making SDK methods appear native
        // hook_native_method is now soft, so alone it should not convict
        val signals = listOf("hook_native_method")
        assertFalse("Single soft signal (native_method) should not convict on clean device", RaspHookAnalysis.hookVerdict(signals))
    }

    @Test
    fun `attacked device framework lib + RWX convicts`() {
        val signals = listOf("hook_framework_lib", "hook_rwx_mapping")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("critical", RaspHookAnalysis.severityFor(signals)) // Framework + corroboration = critical
    }

    @Test
    fun `attacked device two soft signals convict`() {
        val signals = listOf("hook_native_method", "hook_suspicious_lib_path")
        assertTrue(RaspHookAnalysis.hookVerdict(signals))
        assertEquals("medium", RaspHookAnalysis.severityFor(signals)) // Two soft = medium
    }

    @Test
    fun `confidence scales with unique signal families`() {
        assertEquals(0, RaspHookAnalysis.confidenceFor(emptyList()))
        assertEquals(25, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib")))
        assertEquals(25, RaspHookAnalysis.confidenceFor(listOf("hook_native_method")))
        assertEquals(50, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib", "hook_rwx_mapping")))
        assertEquals(50, RaspHookAnalysis.confidenceFor(listOf("hook_rwx_mapping", "hook_suspicious_lib_path")))
        assertEquals(75, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib", "hook_rwx_mapping", "hook_native_method")))
        assertEquals(100, RaspHookAnalysis.confidenceFor(listOf("hook_framework_lib", "hook_rwx_mapping", "hook_native_method", "hook_suspicious_lib_path")))
    }
}