package com.shieldsdk.rasp

import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** Result of one high-risk-IP lookup — mirrors the Dart layer's `HighRiskIpResult`. */
public data class HighRiskIpResult(
    val matchedBlockedCountry: Boolean,
    val isProxy: Boolean,
    /** `true` when the lookup itself did not complete — distinct from a
     *  lookup that ran and found nothing. Never treated as a threat. */
    val checkFailed: Boolean,
) {
    val isRisk: Boolean get() = matchedBlockedCountry || isProxy

    companion object {
        val unavailable = HighRiskIpResult(false, false, checkFailed = true)
    }
}

/**
 * Public-IP reputation and geo risk — Phase 8 (deferred network detector).
 * Plain `HttpsURLConnection`, no license/backend dependency, no third-party
 * HTTP library — verbatim port of the Dart layer's `GeoFilterService`,
 * hitting the same free lookup endpoint used there
 * (`https://ipapi.co/json/`; a production deployment should point this at
 * a paid provider — ipstack, Cloudflare, MaxMind — the same disclosure the
 * Dart source itself carries).
 *
 * A failed/timed-out lookup reports [HighRiskIpResult.checkFailed], never a
 * risk — an unreliable network must not itself block a legitimate user.
 */
public object RaspGeoIpProbes {

    private const val ENDPOINT = "https://ipapi.co/json/"
    private val blockedCountries = setOf("KP", "IR", "SY")
    private const val TIMEOUT_MS = 5000

    fun checkHighRiskIp(): HighRiskIpResult {
        var connection: HttpURLConnection? = null
        return try {
            val url = URL(ENDPOINT)
            connection = (url.openConnection() as HttpsURLConnection).apply {
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                requestMethod = "GET"
            }
            if (connection.responseCode != 200) return HighRiskIpResult.unavailable

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val json = org.json.JSONObject(body)
            // org.json.JSONObject has no nullable-default optString overload
            // usable cleanly from Kotlin — `has()` + `getString()` avoids
            // the Java-interop type mismatch a `null` default produces.
            val country = if (json.has("country_code") && !json.isNull("country_code")) {
                json.getString("country_code")
            } else {
                null
            }
            val matchedCountry = country != null && blockedCountries.contains(country)
            val isProxy = json.optBoolean("proxy", false)

            HighRiskIpResult(
                matchedBlockedCountry = matchedCountry,
                isProxy = isProxy,
                checkFailed = false,
            )
        } catch (e: Exception) {
            HighRiskIpResult.unavailable
        } finally {
            connection?.disconnect()
        }
    }
}
