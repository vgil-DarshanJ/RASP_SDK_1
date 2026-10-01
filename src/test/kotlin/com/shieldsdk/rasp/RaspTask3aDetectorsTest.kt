package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Task 3a detectors — mock_location, time_spoofing, unsafe_wifi,
 * screen_recording — each tested for detected / clean / cannot-decide.
 *
 * Real: every `evaluate` function, [RaspTimeSpoofingProbes.Monitor] (clock
 * arithmetic, server-time anchoring), the Wi-Fi security-type mapping and the
 * screen-recording state mapping.
 * Not exercised (need a device): the `observe` functions that read Android
 * services (AppOps, Settings, ConnectivityManager, WifiInfo, WindowManager).
 * Their output is replaced by hand-built `Observation` values.
 */
class RaspTask3aDetectorsTest {

    // ── mock_location ────────────────────────────────────────────────────

    private fun mock(supplied: Boolean, isMock: Boolean?, apps: List<String>? = emptyList()) =
        RaspMockLocationProbes.evaluate(RaspMockLocationProbes.Observation(supplied, isMock, apps))

    @Test fun `mock_location detected when the supplied fix is mock`() {
        assertEquals(RaspCheckStatus.DETECTED, mock(true, true, listOf("com.fake.gps")).status)
    }

    @Test fun `mock_location clean when the supplied fix is not mock, even with a mock app selected`() {
        val r = mock(true, false, listOf("com.fake.gps"))
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(listOf("com.fake.gps"), r.evidence.first { it.key == "mock_location_apps" }.value)
    }

    @Test fun `mock_location cannot decide without the fix's mock flag`() {
        assertEquals(RaspCheckStatus.UNKNOWN, mock(true, null).status)
    }

    @Test fun `mock_location unavailable when no location was supplied`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE, mock(false, null, null).status)
    }

    // ── time_spoofing ────────────────────────────────────────────────────

    private fun time(jump: Long?, offset: Long?, auto: Boolean?) =
        RaspTimeSpoofingProbes.evaluate(RaspTimeSpoofingProbes.Observation(jump, offset, auto))

    @Test fun `time_spoofing detected on two soft signals`() {
        val r = time(jump = 3_600_000, offset = null, auto = false)
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(setOf("clock_jump", "auto_time_disabled"),
            r.evidence.filter { it.key == "time_signal" }.map { it.value }.toSet())
        assertEquals(RaspCheckStatus.DETECTED, time(jump = 0, offset = 600_000, auto = false).status)
    }

    @Test fun `time_spoofing never detected on one soft signal`() {
        assertEquals(RaspCheckStatus.SECURE, time(jump = 0, offset = null, auto = false).status)
        assertEquals(RaspCheckStatus.SECURE, time(jump = 3_600_000, offset = null, auto = true).status)
        assertEquals(RaspCheckStatus.SECURE, time(jump = 0, offset = 600_000, auto = true).status)
    }

    @Test fun `time_spoofing clean with everything in range`() {
        assertEquals(RaspCheckStatus.SECURE, time(jump = 40, offset = 1_500, auto = true).status)
    }

    @Test fun `time_spoofing cannot decide when an unmeasured signal could still make two`() {
        // First reading (no jump yet) with auto time off: one fired + one unmeasured.
        assertEquals(RaspCheckStatus.UNKNOWN, time(jump = null, offset = null, auto = false).status)
        // Setting unreadable plus a clock jump.
        assertEquals(RaspCheckStatus.UNKNOWN, time(jump = 3_600_000, offset = null, auto = null).status)
        // First reading, auto time on, no server time: nothing can reach two → decided.
        assertEquals(RaspCheckStatus.SECURE, time(jump = null, offset = null, auto = true).status)
    }

    @Test fun `monitor measures clock jumps against elapsed realtime`() {
        val m = RaspTimeSpoofingProbes.Monitor()
        assertNull(m.observe(RaspTimeSpoofingProbes.ClockReading(1_000_000, 10_000), true).clockJumpMs)
        // 4 s passed on both clocks: no jump.
        assertEquals(0L, m.observe(RaspTimeSpoofingProbes.ClockReading(1_004_000, 14_000), true).clockJumpMs)
        // 4 s elapsed but wall clock moved +1 h 4 s.
        assertEquals(3_600_000L, m.observe(RaspTimeSpoofingProbes.ClockReading(4_608_000, 18_000), true).clockJumpMs)
    }

    @Test fun `server time stays anchored as the app keeps running`() {
        val m = RaspTimeSpoofingProbes.Monitor()
        m.setServerTime(serverTimeMillis = 5_000_000, receivedAtElapsedMillis = 100_000)
        // 10 minutes later on a correct clock: offset 0, not 10 minutes.
        assertEquals(0L, m.observe(RaspTimeSpoofingProbes.ClockReading(5_600_000, 700_000), true).serverOffsetMs)
        // Clock 2 h behind.
        assertEquals(-7_200_000L, m.observe(RaspTimeSpoofingProbes.ClockReading(5_600_000 - 7_200_000 + 4_000, 704_000), true).serverOffsetMs)
    }

    // ── unsafe_wifi ──────────────────────────────────────────────────────

    private fun wifi(
        onWifi: Boolean?, security: RaspUnsafeWifiProbes.Security, captive: Boolean?,
        wifiPerm: Boolean = true, netPerm: Boolean = true,
    ) = RaspUnsafeWifiProbes.evaluate(
        RaspUnsafeWifiProbes.Observation(wifiPerm, netPerm, onWifi, security, security.name, captive),
    )

    @Test fun `unsafe_wifi detected on open, WEP or captive portal`() {
        assertEquals(RaspCheckStatus.DETECTED, wifi(true, RaspUnsafeWifiProbes.Security.OPEN, false).status)
        assertEquals(RaspCheckStatus.DETECTED, wifi(true, RaspUnsafeWifiProbes.Security.WEP, false).status)
        assertEquals(RaspCheckStatus.DETECTED, wifi(true, RaspUnsafeWifiProbes.Security.SECURED, true).status)
        // Captive portal is reported even when the security type is unknown.
        assertEquals(RaspCheckStatus.DETECTED, wifi(true, RaspUnsafeWifiProbes.Security.UNKNOWN, true).status)
    }

    @Test fun `unsafe_wifi clean on encrypted Wi-Fi or off Wi-Fi`() {
        assertEquals(RaspCheckStatus.SECURE, wifi(true, RaspUnsafeWifiProbes.Security.SECURED, false).status)
        assertEquals(RaspCheckStatus.SECURE, wifi(false, RaspUnsafeWifiProbes.Security.UNKNOWN, null).status)
    }

    @Test fun `unsafe_wifi cannot decide when security type or network is unreadable`() {
        assertEquals(RaspCheckStatus.UNKNOWN, wifi(true, RaspUnsafeWifiProbes.Security.UNKNOWN, false).status)
        assertEquals(RaspCheckStatus.UNKNOWN, wifi(null, RaspUnsafeWifiProbes.Security.UNKNOWN, null).status)
    }

    @Test fun `unsafe_wifi unavailable without permission`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE, wifi(true, RaspUnsafeWifiProbes.Security.OPEN, false, wifiPerm = false).status)
        assertEquals(RaspCheckStatus.UNAVAILABLE, wifi(true, RaspUnsafeWifiProbes.Security.OPEN, false, netPerm = false).status)
    }

    @Test fun `Wi-Fi security types map correctly, OWE counts as encrypted`() {
        assertEquals(RaspUnsafeWifiProbes.Security.OPEN, RaspUnsafeWifiProbes.securityFromType(0).first)
        assertEquals(RaspUnsafeWifiProbes.Security.WEP, RaspUnsafeWifiProbes.securityFromType(1).first)
        assertEquals(RaspUnsafeWifiProbes.Security.SECURED, RaspUnsafeWifiProbes.securityFromType(2).first)
        assertEquals(RaspUnsafeWifiProbes.Security.SECURED, RaspUnsafeWifiProbes.securityFromType(4).first)
        assertEquals(RaspUnsafeWifiProbes.Security.SECURED, RaspUnsafeWifiProbes.securityFromType(6).first)
        assertEquals(RaspUnsafeWifiProbes.Security.UNKNOWN, RaspUnsafeWifiProbes.securityFromType(-1).first)
    }

    @Test fun `unsafe_wifi evidence never contains SSID or BSSID`() {
        val keys = wifi(true, RaspUnsafeWifiProbes.Security.OPEN, true).evidence.map { it.key }
        assertTrue(keys.none { it.contains("ssid") })
    }

    // ── screen_recording ─────────────────────────────────────────────────

    private fun rec(api: Int, perm: Boolean, state: RaspScreenRecordingProbes.State?, error: String? = null) =
        RaspScreenRecordingProbes.evaluate(RaspScreenRecordingProbes.Observation(api, perm, state, error))

    @Test fun `screen_recording detected while the app is recorded`() {
        assertEquals(RaspCheckStatus.DETECTED, rec(35, true, RaspScreenRecordingProbes.State.RECORDED).status)
        assertEquals(RaspScreenRecordingProbes.State.RECORDED, RaspScreenRecordingProbes.stateFromPlatform(1))
    }

    @Test fun `screen_recording clean when not recorded`() {
        assertEquals(RaspCheckStatus.SECURE, rec(35, true, RaspScreenRecordingProbes.State.NOT_RECORDED).status)
        assertEquals(RaspScreenRecordingProbes.State.NOT_RECORDED, RaspScreenRecordingProbes.stateFromPlatform(0))
    }

    @Test fun `screen_recording cannot decide before a state is reported, error on failed registration`() {
        assertEquals(RaspCheckStatus.UNKNOWN, rec(35, true, null).status)
        assertEquals(RaspCheckStatus.ERROR, rec(35, true, null, "SecurityException").status)
    }

    @Test fun `screen_recording unavailable below API 35 or without permission`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE, rec(34, false, null).status)
        assertEquals(RaspCheckStatus.UNAVAILABLE, rec(35, false, null).status)
    }
}
