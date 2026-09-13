package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.time.Instant
import java.util.concurrent.Executors

/**
 * Ships [RaspCheckResult]s to the RASP Shield platform's ingestion API
 * (`POST <ingestion_url>`, see `FROUNTEND_BACKEND_RASPOWN/BE/src/ingestion/routes.ts`)
 * — the audit-trail pipeline the platform's dashboard reads from.
 *
 * ## Every request is HMAC-signed, not just key-authenticated
 *
 * Earlier versions of this class sent only `X-Api-Key` — a leaked key
 * alone was then sufficient to post events as this application, forever,
 * until someone noticed and revoked it. Every request now also carries
 * `X-Timestamp` and `X-Signature` (HMAC-SHA256 over
 * `"<timestamp>.<raw body>"`, keyed by the credential's `apiSecret` — see
 * [RaspHmacSigner]). The backend recomputes and compares this, rejects
 * stale timestamps, and rejects a replayed exact signature even within
 * the freshness window (see `middleware/apiKey.ts` +
 * `redis/replayGuard.ts`). A captured `X-Api-Key` alone can no longer
 * forge or replay a request.
 *
 * ## "Never disturb the app" — the actual contract, not just a claim
 *
 * [shipAsync] runs entirely on its own single-thread executor, separate
 * from [RaspShieldCore]'s detector-scan executor so a slow network call
 * here can never delay a security scan or vice versa. It never throws
 * back to the caller — a network failure, a malformed response, a
 * misconfigured credential all resolve to a logged (via
 * [RaspShieldCore.logger]) no-op. There is no retry queue in this version
 * (a dropped batch on a flaky network is simply gone) — see the class doc
 * of `FROUNTEND_BACKEND_RASPOWN`'s ingestion route for why that is an
 * accepted trade-off for v1 rather than an oversight: a banking app's
 * runtime behavior must never depend on telemetry delivery succeeding.
 *
 * ## Usage
 *
 * ```kotlin
 * val credentialJson = File(credentialFilePath).readText() // however your app got it
 * RaspEventShipper.configure(credentialJson)
 *
 * val results = RaspShieldCore.scanAllBlocking(context)
 * RaspEventShipper.shipAsync(context, results)
 * ```
 *
 * Configuration is a plain, explicit method call — this SDK never fetches
 * or generates its own credential, matching the same
 * "explicit-configuration-not-magic" pattern already established by
 * [RaspShieldCore.configureExpectedSigningCertificate]/
 * [RaspShieldCore.configureCertificatePin].
 */
public object RaspEventShipper {

    /** SDK-wide version string, stamped onto every shipped event's
     *  `sdkVersion` field — the platform dashboard's version column reads
     *  this to tell an old integration apart from a current one. */
    public const val SDK_VERSION: String = "1.0.0"

    @Volatile
    private var credential: RaspEventCredential? = null

    /** `true` when the JSON parsed successfully and shipping is possible. */
    public fun configure(credentialJson: String): Boolean {
        val parsed = RaspEventCredentialParser.parse(credentialJson)
        credential = parsed
        return parsed != null
    }

    public fun isConfigured(): Boolean = credential != null

    private const val PREFS_FILE = "rasp_shield_secure_prefs"
    private const val PREFS_KEY = "rasp_shield_ingestion_credential"

    /** Keystore-backed, not a plain XML file — this does not defeat a
     *  rooted device running Frida at runtime (nothing client-side can),
     *  but it stops the credential from sitting in a trivially-grepped
     *  plaintext SharedPreferences file or an adb backup. Built fresh
     *  per-call rather than cached: [MasterKey] is cheap to construct and
     *  this avoids holding a `Context` reference longer than one call. */
    private fun securePrefs(context: Context) = EncryptedSharedPreferences.create(
        context.applicationContext ?: context,
        PREFS_FILE,
        MasterKey.Builder(context.applicationContext ?: context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /** Same as [configure], and also persists [credentialJson] to
     *  encrypted storage (see [securePrefs]'s doc) so a later [restore]
     *  call — e.g. on the next app launch — can recover it without asking
     *  the user to paste it again. Returns `false` (and does not persist
     *  anything) on the same malformed-JSON condition [configure] already
     *  reports `false` for. */
    public fun configureAndPersist(context: Context, credentialJson: String): Boolean {
        val ok = configure(credentialJson)
        if (ok) {
            try {
                securePrefs(context).edit().putString(PREFS_KEY, credentialJson).apply()
            } catch (e: Exception) {
                notifyLoggerOnly(
                    "event_shipper",
                    "Configured, but could not persist credential securely: ${e.message}",
                )
            }
        }
        return ok
    }

    /** Loads a credential previously saved by [configureAndPersist], if
     *  any. Returns `true` only if one was found and parsed successfully
     *  — `false` covers both "nothing was ever persisted" and "what was
     *  persisted no longer parses" equally honestly; either way,
     *  [isConfigured] remains whatever it already was (never downgraded
     *  by a failed restore). */
    public fun restore(context: Context): Boolean {
        return try {
            val stored = securePrefs(context).getString(PREFS_KEY, null)
            if (stored.isNullOrEmpty()) false else configure(stored)
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Could not read persisted credential: ${e.message}")
            false
        }
    }

    /** Deletes any persisted credential (e.g. on user logout/sign-out) and
     *  clears the in-memory one. Idempotent, never throws. */
    public fun clearPersisted(context: Context) {
        credential = null
        try {
            securePrefs(context).edit().remove(PREFS_KEY).apply()
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Could not clear persisted credential: ${e.message}")
        }
    }

    /** Test-only reset — mirrors `RaspKeystoreProbes`/similar test seams
     *  elsewhere in this SDK. */
    public fun resetForTests() {
        credential = null
    }

    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "RaspEventShipper-worker").apply { isDaemon = true }
    }

    private const val CONNECT_TIMEOUT_MS = 8000
    private const val READ_TIMEOUT_MS = 8000
    private const val MAX_BATCH_SIZE = 200 // matches the backend's own batchSchema cap

    /**
     * Fire-and-forget: batches [results] (chunked at [MAX_BATCH_SIZE], the
     * backend's own accepted-batch limit) and POSTs each chunk on the
     * background executor. Returns immediately — never blocks the caller,
     * regardless of network state. A no-op (logged, not thrown) when
     * [configure] was never called or failed to parse.
     */
    public fun shipAsync(context: Context, results: List<RaspCheckResult>) {
        val cred = credential
        if (cred == null) {
            notifyLoggerOnly("event_shipper", "Not configured — call RaspEventShipper.configure() first")
            return
        }
        if (results.isEmpty()) return

        val appContext = context.applicationContext ?: context
        val deviceInfo = collectDeviceInfo(appContext)

        results.chunked(MAX_BATCH_SIZE).forEach { chunk ->
            executor.execute {
                try {
                    postBatch(cred, chunk, deviceInfo)
                } catch (e: Exception) {
                    notifyLoggerOnly("event_shipper", e.message ?: "Unknown shipping failure")
                }
            }
        }
    }

    private fun notifyLoggerOnly(detectorId: String, reason: String) {
        try {
            RaspShieldCore.logger.onDetectorError(detectorId, IllegalStateException(reason))
        } catch (e: Exception) {
            // The logger itself must never propagate a failure — same rule
            // as RaspShieldCore.notifyLogger.
        }
    }

    private data class DeviceInfo(
        val deviceId: String?,
        val deviceModel: String,
        val manufacturer: String,
        val osVersion: String,
        val appVersion: String?,
    )

    private fun collectDeviceInfo(context: Context): DeviceInfo {
        val deviceId = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        } catch (e: Exception) {
            null
        }
        val appVersion = try {
            val pm = context.packageManager
            val info = pm.getPackageInfo(context.packageName, 0)
            info.versionName
        } catch (e: Exception) {
            null
        }
        return DeviceInfo(
            deviceId = deviceId,
            deviceModel = Build.MODEL ?: "unknown",
            manufacturer = Build.MANUFACTURER ?: "unknown",
            osVersion = Build.VERSION.RELEASE ?: "unknown",
            appVersion = appVersion,
        )
    }

    private fun postBatch(
        credential: RaspEventCredential,
        batch: List<RaspCheckResult>,
        device: DeviceInfo,
    ) {
        val eventsArray = JSONArray()
        for (result in batch) {
            val evidenceArray = JSONArray()
            for (e in result.evidence) {
                evidenceArray.put(JSONObject().apply {
                    put("key", e.key)
                    put("value", e.value)
                    if (e.note != null) put("note", e.note)
                })
            }
            eventsArray.put(JSONObject().apply {
                put("detectorId", result.detectorId)
                put("status", result.status.name)
                put("evidence", evidenceArray)
                if (result.reason != null) put("reason", result.reason)
                if (device.deviceId != null) put("deviceId", device.deviceId)
                put("deviceModel", device.deviceModel)
                put("manufacturer", device.manufacturer)
                put("osPlatform", "android")
                put("osVersion", device.osVersion)
                if (device.appVersion != null) put("appVersion", device.appVersion)
                put("sdkVersion", SDK_VERSION)
                put("observedAt", Instant.ofEpochMilli(result.observedAtMillis).toString())
            })
        }
        // The exact bytes below are what gets signed AND what gets sent —
        // never re-serialized in between, since that could produce
        // different bytes (whitespace/key order) than what was signed,
        // which would make the server's independently-recomputed
        // signature fail to match through no fault of an attacker.
        val bodyBytes = JSONObject().apply { put("events", eventsArray) }.toString()
            .toByteArray(Charsets.UTF_8)
        val timestamp = System.currentTimeMillis().toString()
        val signature = RaspHmacSigner.sign(credential.apiSecret, timestamp, bodyBytes)

        var connection: HttpURLConnection? = null
        try {
            val url = URL(credential.ingestionUrl)
            connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("X-Api-Key", credential.apiKey)
                setRequestProperty("X-Timestamp", timestamp)
                setRequestProperty("X-Signature", signature)
            }
            connection.outputStream.use { it.write(bodyBytes) }

            val code = connection.responseCode
            if (code !in 200..299) {
                notifyLoggerOnly("event_shipper", "Ingestion endpoint returned HTTP $code")
            }
        } finally {
            connection?.disconnect()
        }
    }
}
