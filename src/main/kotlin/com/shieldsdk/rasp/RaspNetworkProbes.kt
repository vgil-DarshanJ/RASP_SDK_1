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
     * Proxy and user-CA interception indicators. A user CA is evidence, not a
     * claim that every enterprise profile is malicious; policy decides action.
     */
    fun mitmSignals(context: Context): Set<String> = buildSet {
        proxySignals().forEach(::add)
        if (hasUserInstalledCa()) add("user_installed_ca")
        if (hasPlatformProxy(context)) add("platform_proxy")
    }

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

    private fun hasPlatformProxy(context: Context): Boolean = try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cm.defaultProxy != null
        } else {
            @Suppress("DEPRECATION") cm.defaultProxy != null
        }
    } catch (_: Exception) { false }

    /** AndroidCAStore exposes aliases prefixed `user:` for user-added roots. */
    @JvmStatic
    fun hasUserInstalledCa(): Boolean = try {
        val store = KeyStore.getInstance("AndroidCAStore")
        store.load(null)
        val aliases = store.aliases()
        generateSequence { if (aliases.hasMoreElements()) aliases.nextElement() else null }
            .any { it.startsWith("user:") }
    } catch (_: Exception) { false }
}
