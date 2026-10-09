package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The four basic controls; an unreadable USB or ADB state is UNKNOWN, never SECURE (F-02). */
class RaspLeanControlResultsTest {
    private val config = RaspLeanConfig(usbDetection = true, adbDetection = true)

    private fun results(usb: Boolean?, adb: Boolean?) =
        leanControlResults(config, active = null, usbConnected = usb, count = if (usb == true) 1 else 0, adb = adb, clip = null, clipCount = 0)
            .associateBy { it.detectorId }

    @Test
    fun `connected USB and enabled ADB are DETECTED`() {
        val r = results(usb = true, adb = true)
        assertEquals(RaspCheckStatus.DETECTED, r.getValue("usb_connection").status)
        assertEquals(1, r.getValue("usb_connection").evidence.single { it.key == "device_count" }.value)
        assertEquals(RaspCheckStatus.DETECTED, r.getValue("adb_enabled").status)
    }

    @Test
    fun `no USB and ADB off are SECURE`() {
        val r = results(usb = false, adb = false)
        assertEquals(RaspCheckStatus.SECURE, r.getValue("usb_connection").status)
        assertEquals(RaspCheckStatus.SECURE, r.getValue("adb_enabled").status)
    }

    @Test
    fun `unreadable USB and ADB state are UNKNOWN with a reason, not SECURE`() {
        val r = results(usb = null, adb = null)
        for (id in listOf("usb_connection", "adb_enabled")) {
            assertEquals(id, RaspCheckStatus.UNKNOWN, r.getValue(id).status)
            assertNotNull(id, r.getValue(id).reason)
        }
    }

    @Test
    fun `disabled controls produce no result`() {
        val none = leanControlResults(RaspLeanConfig(), true, true, 1, true, true, 0)
        assertTrue(none.isEmpty())
    }
}
