package com.shieldsdk.rasp

import org.junit.Assert.assertEquals
import org.junit.Test

class RaspNetworkProbesTest {
    @Test fun `http and https proxy properties are both detected`() {
        assertEquals(setOf("http_proxy", "https_proxy"), RaspNetworkProbes.proxySignals(mapOf(
            "http.proxyHost" to "proxy.local", "https.proxyHost" to "secure-proxy.local", "http.proxySet" to null
        )))
    }

    @Test fun `no proxy property produces no proxy signal`() {
        assertEquals(emptySet<String>(), RaspNetworkProbes.proxySignals(mapOf(
            "http.proxyHost" to null, "https.proxyHost" to "", "http.proxySet" to "false"
        )))
    }
}
