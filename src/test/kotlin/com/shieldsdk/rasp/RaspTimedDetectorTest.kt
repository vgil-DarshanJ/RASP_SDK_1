package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class RaspTimedDetectorTest {
    @Test fun `timed out detector is unavailable not secure`() {
        val detector = RaspTimedDetector()
        try {
            val result = detector.run("slow", 1) { Thread.sleep(100); RaspCheckResult.secure("slow") }
            assertEquals(RaspCheckStatus.UNAVAILABLE, result.status)
        } finally { detector.shutdown() }
    }

    @Test fun `completed detector keeps its verdict`() {
        val detector = RaspTimedDetector()
        try { assertEquals(RaspCheckStatus.DETECTED, detector.run("x", 1000) { RaspCheckResult.detected("x") }.status) }
        finally { detector.shutdown() }
    }

    @Test fun `tick gate rejects an overlapping tick`() {
        val gate = RaspTickGate()
        var nestedRan = true
        gate.run { nestedRan = gate.run { } }
        assertFalse(nestedRan)
    }
}
