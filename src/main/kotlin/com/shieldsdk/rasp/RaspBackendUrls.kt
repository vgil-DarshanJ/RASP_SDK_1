package com.shieldsdk.rasp

import java.net.URI

/**
 * Backend endpoint URLs derived from the credential's `ingestion_url`
 * (normally `https://host/v1/events`).
 *
 * The scheme and `host[:port]` are kept; user info, query and fragment are
 * dropped; `/v1/events` (and anything after `/v1`) is stripped from the
 * path, and the endpoint is joined as `/v1/<path>`. A path prefix in front
 * of `/v1` is kept (`https://host/api/v1/events` → `https://host/api/v1/ip-risk`).
 * An ingestion URL without a path (`http://host:4000`) gives
 * `http://host:4000/v1/<path>` — the old string-cutting turned that into
 * `http://ip-risk`.
 */
public object RaspBackendUrls {

    /** `null` when [ingestionUrl] is not an absolute http(s) URL with a host. */
    @JvmStatic
    public fun endpoint(ingestionUrl: String, v1Path: String): String? {
        val uri = try {
            URI(ingestionUrl.trim())
        } catch (e: Exception) {
            return null
        }
        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") return null
        val host = uri.host ?: return null
        val authority = if (uri.port >= 0) "$host:${uri.port}" else host
        val path = (uri.rawPath ?: "").trimEnd('/')
        val prefix = when {
            path.contains("/v1/") -> path.substringBefore("/v1/")
            path.endsWith("/v1") -> path.removeSuffix("/v1")
            else -> path
        }
        return "$scheme://$authority$prefix/v1/${v1Path.trimStart('/')}"
    }

    /** `host[:port]` of [url] for logs and evidence — never the path, key or query. `null` if unparsable. */
    @JvmStatic
    public fun hostOf(url: String): String? = try {
        val uri = URI(url.trim())
        uri.host?.let { if (uri.port >= 0) "$it:${uri.port}" else it }
    } catch (e: Exception) {
        null
    }
}
