package com.shieldsdk.rasp

import android.content.pm.ActivityInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Task 3b detectors — vishing_call, sim_change, third_party_keyboard,
 * task_hijack — each tested for detected / clean / cannot-decide.
 *
 * Real: every `evaluate` function, the SIM fingerprint (salted SHA-256), the
 * SIM baseline/acknowledge state machine, keyboard package parsing, task
 * hijack matching and host-config findings.
 * Doubles: [MemorySimStore] instead of the EncryptedSharedPreferences store.
 * Not exercised (need a device): the `observe` functions (TelephonyManager,
 * SubscriptionManager, Settings.Secure, PackageManager scans).
 */
class RaspTask3bDetectorsTest {

    // ── vishing_call ─────────────────────────────────────────────────────

    private fun call(perm: Boolean, state: RaspVishingCallProbes.CallState?, fg: Boolean?) =
        RaspVishingCallProbes.evaluate(RaspVishingCallProbes.Observation(perm, state, fg))

    @Test fun `vishing_call detected when a call is active while the app is in front`() {
        assertEquals(RaspCheckStatus.DETECTED, call(true, RaspVishingCallProbes.CallState.OFFHOOK, true).status)
        assertEquals(RaspCheckStatus.DETECTED, call(true, RaspVishingCallProbes.CallState.RINGING, true).status)
    }

    @Test fun `vishing_call clean with no call, or a call while the app is in the background`() {
        assertEquals(RaspCheckStatus.SECURE, call(true, RaspVishingCallProbes.CallState.IDLE, true).status)
        assertEquals(RaspCheckStatus.SECURE, call(true, RaspVishingCallProbes.CallState.OFFHOOK, false).status)
    }

    @Test fun `vishing_call cannot decide when call or foreground state is unreadable`() {
        assertEquals(RaspCheckStatus.UNKNOWN, call(true, null, true).status)
        assertEquals(RaspCheckStatus.UNKNOWN, call(true, RaspVishingCallProbes.CallState.OFFHOOK, null).status)
    }

    @Test fun `vishing_call unavailable without READ_PHONE_STATE`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE, call(false, null, null).status)
    }

    // ── sim_change ───────────────────────────────────────────────────────

    private class MemorySimStore(var saltValue: ByteArray? = ByteArray(32) { it.toByte() }) : RaspSimChangeProbes.Store {
        var baseline: RaspSimChangeProbes.Baseline? = null
        var failSaves = false
        override fun salt() = saltValue
        override fun load() = baseline
        override fun save(baseline: RaspSimChangeProbes.Baseline): Boolean {
            if (failSaves) return false
            this.baseline = baseline
            return true
        }
    }

    private val simA = RaspSimChangeProbes.SimIdentity(1, 1839, "310260")
    private val simB = RaspSimChangeProbes.SimIdentity(7, 2032, "405857")
    private fun sim(store: MemorySimStore, sims: List<RaspSimChangeProbes.SimIdentity>?, perm: Boolean = true, now: Long = 1_000) =
        RaspSimChangeProbes.evaluate(RaspSimChangeProbes.Observation(perm, sims), store, now)

    @Test fun `sim_change first run stores a baseline and is UNKNOWN never SECURE`() {
        val store = MemorySimStore()
        val r = sim(store, listOf(simA))
        assertEquals(RaspCheckStatus.UNKNOWN, r.status)
        assertTrue(store.baseline != null)
    }

    @Test fun `sim_change clean on the same SIM`() {
        val store = MemorySimStore()
        sim(store, listOf(simA))
        assertEquals(RaspCheckStatus.SECURE, sim(store, listOf(simA)).status)
    }

    @Test fun `sim_change detected on a new SIM and stays detected until acknowledged`() {
        val store = MemorySimStore()
        sim(store, listOf(simA))
        val changed = sim(store, listOf(simB), now = 5_000)
        assertEquals(RaspCheckStatus.DETECTED, changed.status)
        assertEquals(5_000L, changed.evidence.first { it.key == "changed_at_millis" }.value)
        // Next check, same new SIM: still DETECTED (not acknowledged).
        assertEquals(RaspCheckStatus.DETECTED, sim(store, listOf(simB), now = 9_000).status)
        assertTrue(RaspSimChangeProbes.acknowledgeChange(store))
        assertEquals(RaspCheckStatus.SECURE, sim(store, listOf(simB)).status)
        assertFalse("nothing pending any more", RaspSimChangeProbes.acknowledgeChange(store))
    }

    @Test fun `sim_change detects removal and an added second SIM`() {
        val removed = MemorySimStore()
        sim(removed, listOf(simA))
        assertEquals(RaspCheckStatus.DETECTED, sim(removed, emptyList()).status)

        val added = MemorySimStore()
        sim(added, listOf(simA))
        assertEquals(RaspCheckStatus.DETECTED, sim(added, listOf(simA, simB)).status)
    }

    @Test fun `sim_change cannot decide when SIMs are unreadable, error when storage fails`() {
        assertEquals(RaspCheckStatus.UNKNOWN, sim(MemorySimStore(), null).status)
        assertEquals(RaspCheckStatus.ERROR, sim(MemorySimStore(saltValue = null), listOf(simA)).status)
        assertEquals(RaspCheckStatus.ERROR, sim(MemorySimStore().apply { failSaves = true }, listOf(simA)).status)
    }

    @Test fun `sim_change unavailable without READ_PHONE_STATE`() {
        assertEquals(RaspCheckStatus.UNAVAILABLE, sim(MemorySimStore(), null, perm = false).status)
    }

    @Test fun `sim fingerprint is salted, order-independent and carries no raw identifiers`() {
        val salt1 = ByteArray(32) { 1 }
        val salt2 = ByteArray(32) { 2 }
        val f = RaspSimChangeProbes.fingerprint(salt1, listOf(simA, simB))
        assertEquals(f, RaspSimChangeProbes.fingerprint(salt1, listOf(simB, simA)))
        assertNotEquals(f, RaspSimChangeProbes.fingerprint(salt2, listOf(simA, simB)))
        assertEquals(64, f.length)
        assertFalse(f.contains("310260"))
    }

    // ── third_party_keyboard ─────────────────────────────────────────────

    private fun kb(pkg: String?, system: Boolean = false, installer: String? = null, extra: List<String> = emptyList()) =
        RaspThirdPartyKeyboardProbes.evaluate(
            RaspThirdPartyKeyboardProbes.Observation(pkg?.let { RaspThirdPartyKeyboardProbes.KeyboardInfo(it, system, installer) }),
            extra,
        )

    @Test fun `third_party_keyboard detected for a non-system, non-allowlisted keyboard`() {
        assertEquals(RaspCheckStatus.DETECTED, kb("com.evil.keys", installer = "com.android.vending").status)
        // A prefix that looks like a system package does not help.
        assertEquals(RaspCheckStatus.DETECTED, kb("com.android.inputmethod.fake", installer = null).status)
        // Allowlisted name but sideloaded: not trusted.
        assertEquals(RaspCheckStatus.DETECTED, kb(RaspThirdPartyKeyboardProbes.GBOARD, installer = "com.android.packageinstaller").status)
    }

    @Test fun `third_party_keyboard clean for system keyboards, Gboard from Play, host-allowlisted from Play`() {
        assertEquals(RaspCheckStatus.SECURE, kb("com.oem.keyboard", system = true).status)
        assertEquals(RaspCheckStatus.SECURE, kb(RaspThirdPartyKeyboardProbes.GBOARD, installer = "com.android.vending").status)
        assertEquals(RaspCheckStatus.SECURE,
            kb("com.vendor.keyboard", installer = "com.android.vending", extra = listOf("com.vendor.keyboard")).status)
    }

    @Test fun `third_party_keyboard cannot decide when the active keyboard is unreadable`() {
        assertEquals(RaspCheckStatus.UNKNOWN, kb(null).status)
    }

    @Test fun `keyboard package is parsed from DEFAULT_INPUT_METHOD`() {
        assertEquals("com.google.android.inputmethod.latin",
            RaspThirdPartyKeyboardProbes.packageOf("com.google.android.inputmethod.latin/com.android.inputmethod.latin.LatinIME"))
        assertEquals(null, RaspThirdPartyKeyboardProbes.packageOf(""))
        assertEquals(null, RaspThirdPartyKeyboardProbes.packageOf(null))
    }

    // ── task_hijack ──────────────────────────────────────────────────────

    private val host = "com.example.bank"
    private val hostActivities = listOf(
        RaspTaskHijackProbes.ActivityConfig("$host.MainActivity", host, ActivityInfo.LAUNCH_MULTIPLE, false),
    )
    private fun hijack(
        foreign: List<RaspTaskHijackProbes.ForeignActivity>?,
        hostActs: List<RaspTaskHijackProbes.ActivityConfig>? = hostActivities,
    ) = RaspTaskHijackProbes.evaluate(RaspTaskHijackProbes.Observation(host, hostActs, foreign, "launcher_apps", foreign?.size ?: 0))

    @Test fun `task_hijack detected when another app declares the host's affinity`() {
        val r = hijack(listOf(
            RaspTaskHijackProbes.ForeignActivity("com.evil.app", "com.evil.app.FakeLogin", host),
            RaspTaskHijackProbes.ForeignActivity("com.other", "com.other.Main", "com.other"),
        ))
        assertEquals(RaspCheckStatus.DETECTED, r.status)
        assertEquals(listOf("com.evil.app"), r.evidence.filter { it.key == "hijacking_package" }.map { it.value })
    }

    @Test fun `task_hijack clean when no other app shares an affinity - host config risks are evidence only`() {
        val risky = listOf(
            RaspTaskHijackProbes.ActivityConfig("$host.Main", host, ActivityInfo.LAUNCH_SINGLE_TASK, true),
        )
        val r = hijack(listOf(RaspTaskHijackProbes.ForeignActivity("com.other", "com.other.Main", "com.other")), risky)
        assertEquals(RaspCheckStatus.SECURE, r.status)
        assertEquals(2, r.evidence.count { it.key == "host_config_finding" })
        // An app whose activities have no affinity cannot be joined by affinity.
        val noAffinity = listOf(RaspTaskHijackProbes.ActivityConfig("$host.Main", null, ActivityInfo.LAUNCH_MULTIPLE, false))
        assertEquals(RaspCheckStatus.SECURE,
            hijack(listOf(RaspTaskHijackProbes.ForeignActivity("com.evil.app", "X", host)), noAffinity).status)
    }

    @Test fun `task_hijack cannot decide when the scan or host manifest is unreadable`() {
        assertEquals(RaspCheckStatus.UNKNOWN, hijack(null).status)
        assertEquals(RaspCheckStatus.UNKNOWN, hijack(emptyList(), hostActs = null).status)
    }
}
