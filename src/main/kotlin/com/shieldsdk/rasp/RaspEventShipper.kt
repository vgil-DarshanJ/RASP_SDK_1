package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.Executors

/**
 * Ships [RaspCheckResult]s to the RASP Shield platform's ingestion API.
 *
 * ## Two signing paths (configurable via [useEvidenceEnvelope])
 *
 * ### Legacy HMAC path (opt-in via [setUseEvidenceEnvelope(false)], for old backends)
 * - Request carries `X-Api-Key`, `X-Timestamp`, `X-Signature` (HMAC-SHA256)
 * - Signature keyed by credential's `apiSecret` — see [RaspHmacSigner]
 * - Backend validates via shared secret
 * - Works with existing backend ingestion endpoint
 *
 * ### Evidence Envelope path (default)
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

    /**
     * When `true` (the default since 1.2, F-14), results go as signed Evidence
     * Envelopes with the device key; `false` selects the legacy HMAC path,
     * which new backend applications refuse.
     */
    @Volatile
    private var useEvidenceEnvelope = true

    /** Per-process device key (lazy, created on first use). */
    @Volatile
    private var deviceKey: RaspDeviceKey? = null

    /** Per-process offline queue (lazy, created on first use). */
    @Volatile
    private var offlineQueue: RaspOfflineQueue? = null

    /** Per-process envelope builder (lazy) — one counter source for the whole process. */
    @Volatile
    private var envelopeBuilder: RaspEvidenceEnvelope? = null

    /** Per-process delivery (lazy): device registration + response handling for queued envelopes. */
    @Volatile
    private var delivery: RaspEnvelopeDelivery? = null

    @Volatile
    private var registrar: RaspDeviceRegistrar? = null

    @Volatile
    private var riskDelivery: RaspRiskEventDelivery? = null

    private val deliveryStats = RaspDeliveryStats()

    /**
     * Envelopes that left the queue since the process started, by reason:
     * `delivered`, `dropped_invalid` (400/422), `dropped_expired` (older than
     * 7 days), `dropped_unauthorized` (401 again after re-registration),
     * `dropped_rejected` (other 4xx), and `re_registrations`.
     */
    public fun deliveryStats(): Map<String, Long> = deliveryStats.snapshot()

    /** `true` when the JSON parsed successfully and shipping is possible. */
    public fun configure(credentialJson: String): Boolean {
        val parsed = RaspEventCredentialParser.parse(credentialJson)
        credential = parsed
        return parsed != null
    }

    /** Chooses the Evidence Envelope path (`true`, default) or the legacy HMAC path (`false`). */
    public fun setUseEvidenceEnvelope(enabled: Boolean) {
        useEvidenceEnvelope = enabled
    }

    /** Returns whether the new Evidence Envelope path is active. */
    public fun isUsingEvidenceEnvelope(): Boolean = useEvidenceEnvelope

    public fun isConfigured(): Boolean = credential != null

    /** The configured credential, for other signed backend calls (`high_risk_ip`). */
    internal fun currentCredential(): RaspEventCredential? = credential

    private const val PREFS_FILE = "rasp_shield_secure_prefs"
    private const val PREFS_KEY = "rasp_shield_ingestion_credential"

    /** Keystore-encrypted (F-24); migrates the credential from the old EncryptedSharedPreferences file once. */
    private fun securePrefs(context: Context) = RaspSecurePrefs.open(context, PREFS_FILE)

    public fun configureAndPersist(context: Context, credentialJson: String): Boolean {
        val ok = configure(credentialJson)
        if (ok) {
            try {
                if (!securePrefs(context).putString(PREFS_KEY, credentialJson)) {
                    notifyLoggerOnly("event_shipper", "Configured, but the credential was not written to encrypted storage")
                }
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
            val stored = securePrefs(context).getString(PREFS_KEY)
            if (stored.isNullOrEmpty()) false else configure(stored)
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Could not read persisted credential: ${e.message}")
            false
        }
    }

    public fun clearPersisted(context: Context) {
        credential = null
        try {
            securePrefs(context).remove(PREFS_KEY)
        } catch (e: Exception) {
            notifyLoggerOnly("event_shipper", "Could not clear persisted credential: ${e.message}")
        }
    }

    public fun resetForTests() {
        credential = null
        lastLocationHeartbeat = null
        deviceKey = null
        offlineQueue?.stopFlusher()
        offlineQueue = null
        envelopeBuilder = null
        delivery = null
        registrar = null
        riskDelivery = null
        useEvidenceEnvelope = true
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

    /**
     * New path: Evidence Envelope + device key + offline queue.
     *
     * Every envelope is persisted to [RaspOfflineQueue] first and only then
     * sent. The first delivery registers the device key
     * (`POST /v1/devices/register`); what each response does to a queued
     * envelope is [RaspEnvelopeDelivery]'s table.
     */
    private fun shipWithEvidenceEnvelopes(
        appContext: Context,
        @Suppress("UNUSED_PARAMETER") credential: RaspEventCredential,
        results: List<RaspCheckResult>,
    ) {
        val queue = synchronized(this) {
            offlineQueue ?: RaspOfflineQueue(appContext).also { offlineQueue = it }
        }
        // Delivery reads the credential configured at send time.
        queue.startFlusher(delivery(appContext)::deliver)

        results.chunked(MAX_BATCH_SIZE).forEach { chunk ->
            executor.execute {
                try {
                    val envelope = envelopeBuilder(appContext).build(chunk)
                    if (envelope == null) {
                        notifyLoggerOnly(
                            "event_shipper",
                            "Envelope not built (device key, counter persistence or signing unavailable); batch not shipped",
                        )
                        return@execute
                    }
                    if (!queue.enqueue(envelope)) {
                        notifyLoggerOnly("event_shipper", "Envelope queued in memory only; encrypted storage write failed")
                    }
                    queue.flushNow()
                } catch (e: Exception) {
                    notifyLoggerOnly("event_shipper", "Envelope build failed: ${e.message}")
                }
            }
        }
    }

    private fun envelopeBuilder(appContext: Context): RaspEvidenceEnvelope = synchronized(this) {
        envelopeBuilder ?: run {
            val key = deviceKey ?: RaspDeviceKey(appContext).also { deviceKey = it }
            RaspEvidenceEnvelope.forDevice(appContext, key).also { envelopeBuilder = it }
        }
    }

    private fun delivery(appContext: Context): RaspEnvelopeDelivery = synchronized(this) {
        delivery ?: RaspEnvelopeDelivery({ credential }, registrar(appContext), stats = deliveryStats).also { delivery = it }
    }

    /** One registrar per process, shared by envelope and risk-event delivery. */
    private fun registrar(appContext: Context): RaspDeviceRegistrar = synchronized(this) {
        registrar ?: run {
            RaspDeviceRegistrar(
                deviceKey(appContext).asRegistrationKeySource(),
                EncryptedRegistrationStore(appContext),
                appContext.packageName,
                signingCertSha256 = { RaspSigningProbes.signingCertSha256(appContext).ifEmpty { null } },
                deviceId = { credential -> RaspDeviceIdentity.forDevice(appContext, credential.accountHashSalt) },
                exchange = RaspHttpExchange.URL_CONNECTION,
            ).also { registrar = it }
        }
    }

    internal fun deviceKey(appContext: Context): RaspDeviceKey = synchronized(this) {
        deviceKey ?: RaspDeviceKey(appContext).also { deviceKey = it }
    }

    /** Sender for Task 8.1 risk events (`POST /v1/risk/events`). */
    internal fun riskEventDelivery(appContext: Context): RaspRiskEventDelivery = synchronized(this) {
        riskDelivery ?: RaspRiskEventDelivery({ credential }, registrar(appContext)).also { riskDelivery = it }
    }

    /**
     * ISO-8601 UTC with milliseconds (`2026-10-01T12:00:00.000Z`) — what the
     * backend's `observedAt` (zod `datetime()`) accepts. `SimpleDateFormat`
     * rather than `java.time.Instant`, which needs API 26 (minSdk is 23). A
     * new formatter per call: `SimpleDateFormat` is not thread-safe.
     */
    internal fun isoUtc(epochMillis: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(java.util.Date(epochMillis))

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
        // A hash, never the raw ANDROID_ID (F-15); the same id registration sends.
        val deviceId = RaspDeviceIdentity.forDevice(context, credential?.accountHashSalt)
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

    /** Legacy HMAC batch post. Returns the HTTP status (throws when no answer). */
    private fun postBatch(
        credential: RaspEventCredential,
        batch: List<RaspCheckResult>,
        device: DeviceInfo,
    ): Int {
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
                put("observedAt", isoUtc(result.observedAtMillis))
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
            return code
        } finally {
            connection?.disconnect()
        }
    }

    // ── Location heartbeat (Task 9.3) ─────────────────────────────────

    @Volatile
    private var lastLocationHeartbeat: RaspLocationHeartbeatStatus? = null

    /** Delivery result of the last location heartbeat this process sent, or `null`. */
    public fun lastLocationHeartbeat(): RaspLocationHeartbeatStatus? = lastLocationHeartbeat

    /**
     * Sends one location heartbeat (see [RaspLocationHeartbeat]) right away,
     * not through the offline queue — a location is only useful while fresh.
     * Envelope mode: a device-key signed envelope with only this result;
     * legacy mode: an HMAC batch with only this event. The outcome is kept
     * for [lastLocationHeartbeat].
     */
    internal fun sendLocationHeartbeat(context: Context, result: RaspCheckResult, cleared: Boolean) {
        val appContext = context.applicationContext ?: context
        val cred = credential
        if (cred == null) {
            lastLocationHeartbeat = RaspLocationHeartbeatStatus(
                System.currentTimeMillis(), RaspLocationHeartbeatStatus.Outcome.NOT_CONFIGURED, "no backend credential", cleared,
            )
            return
        }
        executor.execute {
            val now = System.currentTimeMillis()
            lastLocationHeartbeat = try {
                if (useEvidenceEnvelope) {
                    val envelope = envelopeBuilder(appContext).build(listOf(result))
                    if (envelope == null) {
                        RaspLocationHeartbeatStatus(now, RaspLocationHeartbeatStatus.Outcome.NOT_DELIVERED, "device key or counter unavailable", cleared)
                    } else {
                        RaspLocationHeartbeatStatus.fromDelivery(delivery(appContext).deliver(envelope), now, cleared)
                    }
                } else {
                    RaspLocationHeartbeatStatus.fromHttpStatus(postBatch(cred, listOf(result), collectDeviceInfo(appContext)), now, cleared)
                }
            } catch (e: Exception) {
                RaspLocationHeartbeatStatus.fromHttpStatus(-1, now, cleared)
            }
        }
    }
}