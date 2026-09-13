package com.shieldsdk.rasp

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.NetworkInterface
import java.util.Collections

/**
 * Network-layer probes: active VPN transport and system-proxy (MITM)
 * indicators. Verbatim port of
 * `RaspSecurityChannelHandler.isVpnActive()`/`isMitmDetected()`.
 *
 * ## Scope note — this is the native-only half of MITM detection
 *
 * The Dart side's `MitmDetector` additionally falls back to
 * `SslPinningService.isMitmDetected()`, a TLS-handshake probe against the
 * SDK's own backend when the native proxy check finds nothing. That
 * requires a live network call to a configured backend host and is
 * deliberately out of scope here (Android Native/Flutter Feature Parity
 * plan, Phase 8) — this native SDK has no backend URL of its own to probe
 * against. [isMitmDetected] here reports only the system-proxy signal,
 * same as [RaspSecurityChannelHandler]'s own native-only half already did
 * before this port.
 */
public object RaspNetworkProbes {

    /**
     * `true` when traffic is routed through a VPN — checked two ways:
     * the platform's own `NetworkCapabilities.TRANSPORT_VPN` flag first
     * (authoritative when available), falling back to scanning for
     * `tun`/`ppp`/`tap`-named interfaces (catches VPN apps that don't
     * register through `ConnectivityManager` in the expected way).
     */
    fun isVpnActive(context: Context): Boolean {
        val viaCapabilities = try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val caps = cm.getNetworkCapabilities(network)
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
        } catch (e: Exception) {
            false
        }
        if (viaCapabilities) return true

        return try {
            val interfaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            interfaces.any { intf ->
                if (!intf.isUp || intf.interfaceAddresses.isEmpty()) return@any false
                val name = intf.name.lowercase()
                name.contains("tun") || name.contains("ppp") || name.contains("tap")
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * `true` when a system-level HTTP proxy is configured — the cheap,
     * always-available half of MITM detection. See the class doc for the
     * TLS-probe half this native SDK does not include.
     */
    fun isSystemProxyConfigured(): Boolean = try {
        !System.getProperty("http.proxyHost").isNullOrEmpty()
    } catch (e: Exception) {
        false
    }
}
