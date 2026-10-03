package com.shieldsdk.rasp

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.net.NetworkInterface
import java.security.KeyStore
import java.util.Collections

/** Network signals used by the VPN and MITM detectors. */
public object RaspNetworkProbes {
    /** `null` means neither platform probe could run; it is not a clean result. */
    fun isVpnActive(context: Context): Boolean? {
        var attempted = false
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            if (caps != null) {
                attempted = true
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return true
            }
        } catch (_: Exception) { }
        try {
            val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            attempted = true
            if (interfaces.any { intf ->
                    intf.isUp && intf.interfaceAddresses.isNotEmpty() &&
                        intf.name.lowercase().let { it.contains("tun") || it.contains("ppp") || it.contains("tap") }
                }) return true
        } catch (_: Exception) { }
        return if (attempted) false else null
    }

    /**
     * What the proxy and user-CA probes saw: [signals] that fired, and
     * [failedProbes] that could not run (a failed probe is not a clean one).
     */
    public data class MitmProbe(val signals: Set<String>, val failedProbes: Set<String>)

    /**
     * Proxy and user-CA interception indicators. A user CA is evidence, not a
     * claim that every enterprise profile is malicious; policy decides action.
     */
    fun mitmProbe(context: Context): MitmProbe {
        val signals = proxySignals().toMutableSet()
        val failed = mutableSetOf<String>()
        when (userInstalledCa()) {
            true -> signals += "user_installed_ca"
            null -> failed += "user_ca_store"
            false -> Unit
        }
        when (platformProxy(context)) {
            true -> signals += "platform_proxy"
            null -> failed += "platform_proxy"
            false -> Unit
        }
        return MitmProbe(signals, failed)
    }

    /** Signals only; see [mitmProbe] for the probes that could not run. */
    fun mitmSignals(context: Context): Set<String> = mitmProbe(context).signals

    @JvmStatic
    fun proxySignals(properties: Map<String, String?> = mapOf(
        "http.proxyHost" to System.getProperty("http.proxyHost"),
        "https.proxyHost" to System.getProperty("https.proxyHost"),
        "http.proxySet" to System.getProperty("http.proxySet"),
    )): Set<String> = buildSet {
        if (!properties["http.proxyHost"].isNullOrBlank()) add("http_proxy")
        if (!properties["https.proxyHost"].isNullOrBlank()) add("https_proxy")
        if (properties["http.proxySet"].equals("true", ignoreCase = true)) add("http_proxy_set")
    }

    /** Retained for source compatibility; new code should consume named signals. */
    fun isSystemProxyConfigured(): Boolean = proxySignals().isNotEmpty()

    /** `null` when the proxy setting could not be read. */
    private fun platformProxy(context: Context): Boolean? = try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cm.defaultProxy != null
        } else {
            @Suppress("DEPRECATION") cm.defaultProxy != null
        }
    } catch (_: Exception) { null }

    /**
     * AndroidCAStore exposes aliases prefixed `user:` for user-added roots.
     * `null` when the store could not be read.
     */
    @JvmStatic
    fun userInstalledCa(): Boolean? = try {
        val store = KeyStore.getInstance("AndroidCAStore")
        store.load(null)
        val aliases = store.aliases()
        generateSequence { if (aliases.hasMoreElements()) aliases.nextElement() else null }
            .any { it.startsWith("user:") }
    } catch (_: Exception) { null }

    /** Retained for source compatibility: `false` also when the store could not be read. */
    @JvmStatic
    fun hasUserInstalledCa(): Boolean = userInstalledCa() == true
}
