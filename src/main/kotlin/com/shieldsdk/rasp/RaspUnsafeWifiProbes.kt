package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build

/**
 * `unsafe_wifi` — is the device on a Wi-Fi network without encryption, or
 * behind a captive portal?
 *
 * Needs `ACCESS_WIFI_STATE` (and `ACCESS_NETWORK_STATE`, both normal
 * permissions the host declares); no location permission, and SSID/BSSID are
 * never read or reported. Missing permission → UNAVAILABLE.
 *
 * | Signal | Source |
 * |---|---|
 * | `open_network` / `wep_network` | API 31+: `WifiInfo.getCurrentSecurityType()`; API ≤ 30: the connected network's `WifiConfiguration` (readable only up to API 28 for normal apps) |
 * | `captive_portal` | `NET_CAPABILITY_CAPTIVE_PORTAL` on the active network |
 *
 * Any signal → DETECTED. On Wi-Fi with security type undeterminable and no
 * captive portal → UNKNOWN. Not on Wi-Fi → SECURE.
 */
object RaspUnsafeWifiProbes {

    const val DETECTOR_ID = "unsafe_wifi"

    enum class Security { OPEN, WEP, SECURED, UNKNOWN }

    data class Observation(
        val wifiStatePermission: Boolean,
        val networkStatePermission: Boolean,
        /** `null` when the active network could not be read. */
        val onWifi: Boolean?,
        val security: Security,
        /** Security type name for evidence, e.g. "PSK", "SAE", "OWE", "OPEN". */
        val securityLabel: String?,
        /** `null` when it could not be read. */
        val captivePortal: Boolean?,
    )

    /** Maps `WifiInfo.getCurrentSecurityType()` (API 31+) to [Security] and a label. */
    fun securityFromType(type: Int): Pair<Security, String> = when (type) {
        WifiInfo.SECURITY_TYPE_OPEN -> Security.OPEN to "OPEN"
        WifiInfo.SECURITY_TYPE_WEP -> Security.WEP to "WEP"
        WifiInfo.SECURITY_TYPE_PSK -> Security.SECURED to "PSK"
        WifiInfo.SECURITY_TYPE_EAP -> Security.SECURED to "EAP"
        WifiInfo.SECURITY_TYPE_SAE -> Security.SECURED to "SAE"
        WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> Security.SECURED to "EAP_WPA3_192"
        WifiInfo.SECURITY_TYPE_OWE -> Security.SECURED to "OWE" // "enhanced open": encrypted
        WifiInfo.SECURITY_TYPE_WAPI_PSK -> Security.SECURED to "WAPI_PSK"
        WifiInfo.SECURITY_TYPE_WAPI_CERT -> Security.SECURED to "WAPI_CERT"
        WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE -> Security.SECURED to "EAP_WPA3"
        WifiInfo.SECURITY_TYPE_OSEN -> Security.SECURED to "OSEN"
        WifiInfo.SECURITY_TYPE_PASSPOINT_R1_R2 -> Security.SECURED to "PASSPOINT_R1_R2"
        WifiInfo.SECURITY_TYPE_PASSPOINT_R3 -> Security.SECURED to "PASSPOINT_R3"
        WifiInfo.SECURITY_TYPE_DPP -> Security.SECURED to "DPP"
        else -> Security.UNKNOWN to "UNKNOWN($type)"
    }

    fun evaluate(o: Observation): RaspCheckResult {
        if (!o.wifiStatePermission) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "ACCESS_WIFI_STATE not granted to the host app")
        }
        if (!o.networkStatePermission) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "ACCESS_NETWORK_STATE not granted to the host app")
        }
        val evidence = mutableListOf(
            RaspEvidence("on_wifi", o.onWifi),
            RaspEvidence("security_type", o.securityLabel),
            RaspEvidence("captive_portal", o.captivePortal),
        )
        when (o.onWifi) {
            null -> return RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Active network could not be read",
            )
            false -> return RaspCheckResult.secure(DETECTOR_ID, evidence)
            true -> Unit
        }
        val signals = buildList {
            if (o.security == Security.OPEN) add("open_network")
            if (o.security == Security.WEP) add("wep_network")
            if (o.captivePortal == true) add("captive_portal")
        }
        evidence.addAll(0, signals.map { RaspEvidence("wifi_signal", it) })
        return when {
            signals.isNotEmpty() -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            o.security == Security.UNKNOWN || o.captivePortal == null -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Wi-Fi security type or captive-portal state could not be determined",
            )
            else -> RaspCheckResult.secure(DETECTOR_ID, evidence)
        }
    }

    fun observe(context: Context): Observation {
        val wifiPerm = granted(context, "android.permission.ACCESS_WIFI_STATE")
        val netPerm = granted(context, "android.permission.ACCESS_NETWORK_STATE")
        if (!wifiPerm || !netPerm) return Observation(wifiPerm, netPerm, null, Security.UNKNOWN, null, null)

        val caps = try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
                ?: return Observation(true, true, false, Security.UNKNOWN, null, null)
            cm.getNetworkCapabilities(network)
        } catch (e: Exception) {
            return Observation(true, true, null, Security.UNKNOWN, null, null)
        } ?: return Observation(true, true, null, Security.UNKNOWN, null, null)

        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return Observation(true, true, false, Security.UNKNOWN, null, false)
        }
        val captive = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
        val (security, label) = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) securityApi31(context, caps)
            else securityLegacy(context)
        } catch (e: Exception) {
            Security.UNKNOWN to null
        }
        return Observation(true, true, true, security, label, captive)
    }

    @Suppress("DEPRECATION")
    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private fun securityApi31(context: Context, caps: NetworkCapabilities): Pair<Security, String?> {
        val info = (caps.transportInfo as? WifiInfo)
            ?: (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).connectionInfo
        return securityFromType(info.currentSecurityType)
    }

    @Suppress("DEPRECATION")
    private fun securityLegacy(context: Context): Pair<Security, String?> {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val networkId = wifi.connectionInfo?.networkId ?: return Security.UNKNOWN to null
        val config = wifi.configuredNetworks?.firstOrNull { it.networkId == networkId }
            ?: return Security.UNKNOWN to null // API 29+: not visible to normal apps
        val keyMgmt = config.allowedKeyManagement
        return when {
            keyMgmt.get(WifiConfiguration.KeyMgmt.WPA_PSK) || keyMgmt.get(WifiConfiguration.KeyMgmt.WPA_EAP) ||
                keyMgmt.get(WifiConfiguration.KeyMgmt.IEEE8021X) -> Security.SECURED to "WPA"
            config.wepKeys?.any { it != null } == true -> Security.WEP to "WEP"
            keyMgmt.get(WifiConfiguration.KeyMgmt.NONE) -> Security.OPEN to "OPEN"
            else -> Security.UNKNOWN to null
        }
    }

    private fun granted(context: Context, permission: String) =
        context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
}
