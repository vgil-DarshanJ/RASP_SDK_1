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
 * Ships [RaspCheckResult]s to the RASP Shield platform's ingestion API.
 *
 * ## Two signing paths (configurable via [useEvidenceEnvelope])
 *
 * ### Legacy HMAC path (default, backward compatible)
 * - Request carries `X-Api-Key`, `X-Timestamp`, `X-Signature` (HMAC-SHA256)
 * - Signature keyed by credential's `apiSecret` — see [RaspHmacSigner]
 * - Backend validates via shared secret
 * - Works with existing backend ingestion endpoint
 *
 * ### New Evidence Envelope path (opt-in via [setUseEvidenceEnvelope(true)])
 * - Each batch wrapped in a [RaspEvidenceEnvelope] signed by the
 *   per-install hardware-backed EC P-256 device key ([RaspDeviceKey])
 * - Envelope includes: eventId, eventTime, monotonicCounter, nonce,
 *   sdkVersion, appId, deviceKeyId, detectorResults, ECDSA signature
 * - Backend validates via registered device public key (no shared secret)
 * - Provides tamper evidence, replay protection, device binding
 *
 * ## Offline durability
 * - When network is unavailable, envelopes are queued in
 *   [RaspOfflineQueue] (AES-256-GCM encrypted, Keystore-wrapped key)
 * - FIFO ordering, size cap (1000), exponential backoff retry
 * - Events persist across process restarts — never lost on crash
 *
 * ## "Never disturb the app"
 * - All I/O on dedicated single-thread executors
 * - Never throws to caller — failures logged via [RaspShieldCore.logger]
 * - Network failures trigger queueing, not data loss
 */
public object RaspEventShipper {

    /** SDK-wide version string from Gradle publication. */
    @JvmField public val SDK_VERSION: String = BuildConfig.RASP_ENGINE_VERSION

    @Volatile
    private var credential: RaspEventCredential? = null

    /** When `true`, use the new Evidence Envelope + device key signing path. */
    @Volatile
    private var useEvidenceEnvelope = false

    /** Per-process device key (lazy, created on first use). */
    @Volatile
    private var deviceKey: RaspDeviceKey? = null

    /** Per-process offline queue (lazy, created on first use). */
    @Volatile
    private var offlineQueue: RaspOfflineQueue? = null

    /** `true` when the JSON parsed successfully and shipping is possible. */
    public fun configure(credentialJson: String): Boolean {
        val parsed = RaspEventCredentialParser.parse(credentialJson)
        credential = parsed
        return parsed != null
    }

    /** Enables the new Evidence Envelope signing path (opt-in). */
    public fun setUseEvidenceEnvelope(enabled: Boolean) {
        useEvidenceEnvelope = enabled
    }

    /** Returns whether the new Evidence Envelope path is active. */
    public fun isUsingEvidenceEnvelope(): Boolean = useEvidenceEnvelope

    public fun isConfigured(): Boolean = credential != null

    private const val PREFS_FILE = "rasp_shield_secure_prefs"
    private const val PREFS_KEY = "rasp_shield_ingestion_credential"

    private fun securePrefs(context: Context) = EncryptedSharedPreferences.create(
        context.applicationContext ?: context,
        PREFS_FILE,
        MasterKey.Builder(context.applicationContext ?: context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

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

    public fun restore(context: Context): Boolean {
        return try {
            val stored = securePrefs(context).getString(PREFS_KEY, null)
            if (stored.isNullOrEmpty()) false else configure(stored)
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Could not read persisted credential: ${e.message}")
            false
        }
    }

    public fun clearPersisted(context: Context) {
        credential = null
        try {
            securePrefs(context).edit().remove(PREFS_KEY).apply()
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Could not clear persisted credential: ${e.message}")
        }
    }

    public fun resetForTests() {
        credential = null
        deviceKey = null
        offlineQueue = null
        useEvidenceEnvelope = false
    }

    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "RaspEventShipper-worker").apply { isDaemon = true }
    }

    private const val CONNECT_TIMEOUT_MS = 8000
    private const val READ_TIMEOUT_MS = 8000
    private const val MAX_BATCH_SIZE = 200

    /**
     * Fire-and-forget: batches [results], builds envelopes (if enabled),
     * and ships or queues them. Returns immediately.
     */
    public fun shipAsync(context: Context, results: List<RaspCheckResult>) {
        val cred = credential
        if (cred == null) {
            notifyLoggerOnly("event_shipper", "Not configured — call RaspEventShipper.configure() first")
            return
        }
        if (results.isEmpty()) return

        val appContext = context.applicationContext ?: context

        if (useEvidenceEnvelope) {
            shipWithEvidenceEnvelopes(appContext, cred, results)
        } else {
            shipLegacyHmac(appContext, cred, results)
        }
    }

    /** New path: Evidence Envelope + device key + offline queue. */
    private fun shipWithEvidenceEnvelopes(
        appContext: Context,
        credential: RaspEventCredential,
        results: List<RaspCheckResult>,
    ) {
        val key = deviceKey ?: RaspDeviceKey(appContext).also { deviceKey = it }
        val queue = offlineQueue ?: RaspOfflineQueue(appContext).also { offlineQueue = it }
        val envelopeBuilder = RaspEvidenceEnvelope()

        // Ensure queue is reloaded from storage on first use
        queue.reloadFromStorage()

        // Start flusher if not already running
        queue.startFlusher { envelopeJson ->
            postEnvelope(credential, envelopeJson)
        }

        results.chunked(MAX_BATCH_SIZE).forEach { chunk ->
            executor.execute {
                try {
                    val envelopeJson = envelopeBuilder.buildEnvelope(appContext, key, chunk)
                    envelopeJson?.let { envelope ->
                        if (!queue.enqueue(envelope)) {
                            notifyLoggerOnly("event_shipper", "Offline queue full, dropping envelope")
                        }
                    }
                } catch (e: Exception) {
                    notifyLoggerOnly("event_shipper", "Envelope build failed: ${e.message}")
                }
            }
        }
    }

    /** Legacy path: HMAC-signed batch POST (unchanged behavior). */
    private fun shipLegacyHmac(
        appContext: Context,
        credential: RaspEventCredential,
        results: List<RaspCheckResult>,
    ) {
        val deviceInfo = collectDeviceInfo(appContext)

        results.chunked(MAX_BATCH_SIZE).forEach { chunk ->
            executor.execute {
                try {
                    postBatch(credential, chunk, deviceInfo)
                } catch (e: Exception) {
                    notifyLoggerOnly("event_shipper", e.message ?: "Unknown shipping failure")
                }
            }
        }
    }

    /** Posts a single Evidence Envelope to the ingestion endpoint. */
    private fun postEnvelope(credential: RaspEventCredential, envelopeJson: String): Boolean {
        val bodyBytes = envelopeJson.toByteArray(Charsets.UTF_8)
        // Evidence Envelope path: no X-Timestamp, no X-Signature (HMAC).
        // The envelope itself carries its own ECDSA signature + monotonic counter + nonce.
        // Backend identifies this path by the presence of "envelopeVersion" in the body.
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
                // No X-Timestamp, no X-Signature — envelope is self-authenticating
            }
            connection.outputStream.use { it.write(bodyBytes) }

            val code = connection.responseCode
            if (code !in 200..299) {
                notifyLoggerOnly("event_shipper", "Envelope ingestion returned HTTP $code")
                return false
            }
            return true
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Envelope post failed: ${e.message}")
            return false
        } finally {
            connection?.disconnect()
        }
    }

    private fun notifyLoggerOnly(detectorId: String, reason: String) {
        try {
            RaspShieldCore.logger.onDetectorError(detectorId, IllegalStateException(reason))
        } catch (e: Exception) {
            // Logger must never propagate
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

    /** Legacy HMAC batch post — unchanged from original implementation. */
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