package com.shieldsdk.rasp

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Local JVM unit test — [RaspNetworkProbes.isSystemProxyConfigured] reads
 * only a JVM system property, no Android framework dependency, so it is
 * directly testable here (unlike [RaspNetworkProbes.isVpnActive], which
 * needs a real `Context`/`ConnectivityManager` and is covered by the
 * Phase 4 instrumented suite instead).
 */
class RaspNetworkProbesTest {

    @After
    fun tearDown() {
        System.clearProperty("http.proxyHost")
    }

    @Test
    fun isSystemProxyConfigured_false_whenNoProxyPropertySet() {
        System.clearProperty("http.proxyHost")
        assertFalse(RaspNetworkProbes.isSystemProxyConfigured())
    }

    @Test
    fun isSystemProxyConfigured_true_whenProxyHostIsSet() {
        System.setProperty("http.proxyHost", "10.0.0.1")
        assertTrue(RaspNetworkProbes.isSystemProxyConfigured())
    }

    @Test
    fun isSystemProxyConfigured_false_whenProxyHostIsEmpty() {
        System.setProperty("http.proxyHost", "")
        assertFalse(RaspNetworkProbes.isSystemProxyConfigured())
    }
}
