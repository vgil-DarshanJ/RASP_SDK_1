package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The legacy shipper's `observedAt` formatter (replaces java.time.Instant,
 * API 26). Real: RaspEventShipper.isoUtc; compared with java.time on the JVM,
 * where java.time is available.
 */
class RaspLegacyShipperTimeTest {
    @Test fun `isoUtc formats UTC with milliseconds`() {
        assertEquals("1970-01-01T00:00:00.000Z", RaspEventShipper.isoUtc(0))
        assertEquals("2026-10-01T12:53:38.144Z", RaspEventShipper.isoUtc(1_790_859_218_144))
    }

    @Test fun `isoUtc denotes the same instant java time would`() {
        for (millis in listOf(1L, 999L, 1_000L, 1_700_000_000_000L, 4_102_444_800_000L)) {
            assertEquals(millis, java.time.Instant.parse(RaspEventShipper.isoUtc(millis)).toEpochMilli())
        }
    }
}
