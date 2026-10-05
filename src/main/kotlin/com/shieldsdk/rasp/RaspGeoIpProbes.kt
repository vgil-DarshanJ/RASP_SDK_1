package com.shieldsdk.rasp

import android.content.Context
import android.net.ConnectivityManager
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicReference

/**
 * `high_risk_ip` — asks the RASP Shield backend where the device's public IP
 * is and whether it is risky: `GET /v1/ip-risk`, signed like event ingestion
 * (`X-Api-Key`, `X-Timestamp`, `X-Signature` = hex HMAC-SHA256 of
 * `"<timestamp>."` + the empty body, see [RaspHmacSigner]). The backend uses
 * the request's IP (honoring its TRUST_PROXY setting), its configurable
 * blocked-country list and its own lookup cache. The SDK makes no
 * third-party calls and has no debug-build skip.
 *
 * Verdict:
 * - backend credential not configured ([RaspEventShipper.configure]) → UNAVAILABLE
 * - request failed, non-200 answer, or an answer that cannot be read → UNKNOWN
 * - `risk_level` high, or blocked / not-allowed country, Tor, proxy → DETECTED
 * - country unknown (private address, no geo source, lookup failed) → UNKNOWN
 * - `risk_level` low or medium (medium = soft: hosting IP, country changed
 *   since registration) → SECURE, with country, risk_level and reasons in evidence
 *
 * The URL comes from [RaspBackendUrls.endpoint]; the result carries
 * `endpoint_host` (host:port only) so a wrong backend address is visible.
 *
 * Results are cached per active network for [CACHE_MILLIS] (an UNKNOWN for
 * [RETRY_MILLIS]), so the session's 4 s ticks do not call the backend each
 * time.
 */
public object RaspGeoIpProbes {

    const val DETECTOR_ID = "high_risk_ip"
    const val CACHE_MILLIS = 10 * 60_000L
    const val RETRY_MILLIS = 60_000L
    private const val TIMEOUT_MS = 5_000

    /** An HTTP answer; `null` passed to [evaluate] means the request itself failed. */
    data class Response(val status: Int, val body: String)

    fun interface Transport {
        /** `null` on a network failure (no HTTP answer). */
        fun get(url: String, headers: Map<String, String>): Response?
    }

    /**
     * `https://host/v1/events` → `https://host/v1/ip-risk`, built with
     * [RaspBackendUrls.endpoint] (scheme + host + optional prefix + `/v1/ip-risk`).
     * `null` when the ingestion URL is not an absolute http(s) URL.
     */
    fun ipRiskUrl(ingestionUrl: String): String? = RaspBackendUrls.endpoint(ingestionUrl, "ip-risk")

    /**
     * Builds the signed request and maps the answer. No caching.
     * [deviceKeyId]: this device's registered key id, sent as
     * `X-Device-Key-Id` so the backend can compare with the country seen at
     * registration; omitted when the device is not registered yet.
     */
    fun check(
        credential: RaspEventCredential?,
        transport: Transport = HttpTransport,
        nowMillis: Long = System.currentTimeMillis(),
        deviceKeyId: String? = null,
    ): RaspCheckResult {
        if (credential == null) {
            return RaspCheckResult.unavailable(
                DETECTOR_ID, "Backend credential not configured (high_risk_ip asks the platform's /v1/ip-risk)",
            )
        }
        val url = ipRiskUrl(credential.ingestionUrl)
            ?: return unknown("Credential ingestion_url is not a valid http(s) URL")
        // Host only — never the path, API key or signature.
        val host = RaspBackendUrls.hostOf(url)
        val timestamp = nowMillis.toString()
        val headers = buildMap {
            put("X-Api-Key", credential.apiKey)
            put("X-Timestamp", timestamp)
            put("X-Signature", RaspHmacSigner.sign(credential.apiSecret, timestamp, ByteArray(0)))
            if (!deviceKeyId.isNullOrBlank()) put("X-Device-Key-Id", deviceKeyId)
        }
        val response = try {
            transport.get(url, headers)
        } catch (e: Exception) {
            null
        }
        val result = evaluate(response)
        return if (host == null) result
        else result.copy(evidence = result.evidence + RaspEvidence("endpoint_host", host))
    }

    /** The backend's high-risk reasons; any of these makes the result DETECTED. */
    private val highRiskReasons = setOf("blocked_country", "country_not_allowed", "tor", "proxy")

    /**
     * Maps the backend's answer to a result. Pure.
     * - `risk_level` "high", or a blocked / not-allowed country, Tor or proxy → DETECTED;
     * - "medium" (hosting IP, country changed since registration — soft) → SECURE with the reasons in evidence;
     * - "low" → SECURE; country unknown → UNKNOWN with the backend's reason.
     * Answers from an older backend without `risk_level` are decided from `flags`.
     */
    fun evaluate(response: Response?): RaspCheckResult {
        if (response == null) return unknown("IP risk request failed (no answer from the backend)")
        if (response.status != 200) return unknown("IP risk endpoint answered HTTP ${response.status}")
        val body = try {
            RaspJson.parse(response.body) as? Map<*, *>
        } catch (e: RaspJson.ParseException) {
            null
        } ?: return unknown("IP risk answer is not a JSON object")
        val flags = body["flags"] as? Map<*, *> ?: return unknown("IP risk answer has no flags")
        val country = body["country"] as? String
        val source = body["source"] as? String
        val riskLevel = body["risk_level"] as? String
        val reasons = (body["reasons"] as? List<*>)?.filterIsInstance<String>().orEmpty()
        val blocked = flags["blocked_country"] as? Boolean
        val proxy = (body["is_proxy"] ?: flags["proxy"]) as? Boolean
        val hosting = (body["is_hosting"] ?: flags["hosting"]) as? Boolean

        // Old signal names kept for existing consumers (GeoFilterService).
        val signals = buildList {
            if (blocked == true) add("blocked_country")
            if (proxy == true) add("proxy_flag")
        }
        val high = riskLevel == "high" || signals.isNotEmpty() || reasons.any { it in highRiskReasons }
        val evidence = buildList {
            signals.forEach { add(RaspEvidence("high_risk_ip_signal", it)) }
            if (country != null) add(RaspEvidence("country", country))
            if (riskLevel != null) add(RaspEvidence("risk_level", riskLevel, if (riskLevel == "medium") "soft" else null))
            if (reasons.isNotEmpty()) add(RaspEvidence("reasons", reasons))
            if (source != null) add(RaspEvidence("country_source", source))
            if (hosting == true) add(RaspEvidence("hosting", true, "Datacenter / hosting IP"))
            add(RaspEvidence("proxy_flag_available", proxy != null))
        }
        if (high) return RaspCheckResult.detected(DETECTOR_ID, evidence)
        if (country == null) {
            val reason = when (body["reason"] as? String) {
                "private_address" -> "The backend saw a private address (same local network), so it cannot place the IP"
                "no_geo_source" -> "The backend has no IP geo source configured"
                "lookup_failed" -> "The backend's IP geo lookup failed"
                else -> "The backend could not determine the country"
            }
            return RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = reason)
        }
        return RaspCheckResult.secure(DETECTOR_ID, evidence)
    }

    private data class Cached(val networkKey: String?, val atMillis: Long, val result: RaspCheckResult)

    private val cache = AtomicReference<Cached?>(null)

    /** [check] with the per-network cache; what `checkHighRiskIpBlocking` uses. */
    fun checkCached(context: Context, nowMillis: Long = System.currentTimeMillis()): RaspCheckResult {
        val credential = RaspEventShipper.currentCredential()
        val networkKey = activeNetworkKey(context)
        cache.get()?.let { cached ->
            val ttl = if (cached.result.status == RaspCheckStatus.UNKNOWN) RETRY_MILLIS else CACHE_MILLIS
            if (credential != null && cached.networkKey == networkKey && nowMillis - cached.atMillis in 0L until ttl) {
                return cached.result
            }
        }
        val deviceKeyId = try {
            EncryptedRegistrationStore(context).registeredKeyId()
        } catch (e: Exception) {
            null
        }
        val result = check(credential, HttpTransport, nowMillis, deviceKeyId)
        if (credential != null) cache.set(Cached(networkKey, nowMillis, result)) else cache.set(null)
        return result
    }

    /** Drops the cached answer (tests, or after the credential changes). */
    fun clearCache() = cache.set(null)

    private fun activeNetworkKey(context: Context): String? = try {
        (context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).activeNetwork?.toString()
    } catch (e: Exception) {
        null
    }

    private fun unknown(reason: String) = RaspCheckResult.unknown(DETECTOR_ID, reason)

    /** Plain `HttpURLConnection` GET. */
    object HttpTransport : Transport {
        override fun get(url: String, headers: Map<String, String>): Response? {
            var connection: HttpURLConnection? = null
            return try {
                connection = (URL(url).openConnection() as HttpURLConnection).apply {
                    connectTimeout = TIMEOUT_MS
                    readTimeout = TIMEOUT_MS
                    requestMethod = "GET"
                    instanceFollowRedirects = false
                    headers.forEach { (k, v) -> setRequestProperty(k, v) }
                }
                val status = connection.responseCode
                val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
                Response(status, body)
            } catch (e: Exception) {
                null
            } finally {
                connection?.disconnect()
            }
        }
    }
}
