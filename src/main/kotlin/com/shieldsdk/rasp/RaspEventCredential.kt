package com.shieldsdk.rasp

import org.json.JSONObject

/**
 * The parsed shape of the JSON credential file issued by the RASP Shield
 * platform's backend (`POST /v1/credentials/applications/:id/credentials`)
 * — see `FROUNTEND_BACKEND_RASPOWN/BE/src/credentials/routes.ts` for the
 * exact fields this mirrors. A host app downloads that JSON once from the
 * platform's web UI and passes its raw text to
 * [RaspEventShipper.configure] — this SDK never fetches or generates a
 * credential itself.
 *
 * [apiSecret] backs the HMAC request signature every ingestion call now
 * carries (see [RaspEventShipper]'s class doc) — without it, a leaked
 * [apiKey] alone used to be sufficient to post events as this
 * application; this closes that gap. Held in memory only, for the
 * process lifetime of whatever configured it — never persisted to disk
 * by this SDK.
 */
public data class RaspEventCredential(
    val organizationId: String,
    val applicationId: String,
    val apiKey: String,
    val apiSecret: String,
    val ingestionUrl: String,
)

public object RaspEventCredentialParser {

    /** `null` on any malformed/incomplete JSON — never throws, matching
     *  every other parsing boundary in this SDK. */
    fun parse(json: String): RaspEventCredential? = try {
        val obj = JSONObject(json)
        val organizationId = obj.getString("organization_id")
        val applicationId = obj.getString("application_id")
        val apiKey = obj.getString("api_key")
        val apiSecret = obj.getString("api_secret")
        val ingestionUrl = obj.getString("ingestion_url")
        if (organizationId.isBlank() || applicationId.isBlank() || apiKey.isBlank() ||
            apiSecret.isBlank() || ingestionUrl.isBlank()
        ) {
            null
        } else {
            RaspEventCredential(organizationId, applicationId, apiKey, apiSecret, ingestionUrl)
        }
    } catch (e: Exception) {
        null
    }
}
