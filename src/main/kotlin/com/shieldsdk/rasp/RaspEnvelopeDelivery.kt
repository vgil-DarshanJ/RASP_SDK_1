package com.shieldsdk.rasp

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicLong

/** What the offline queue does with one envelope after a delivery attempt. */
public enum class RaspDeliveryOutcome {
    /** Accepted by the backend (2xx): remove from the queue. */
    DELIVERED,

    /** Will never be accepted (invalid, expired, rejected): remove and count. */
    DROPPED,

    /** Network error, 5xx or 429: keep it and retry after the backoff. */
    RETRY_LATER,
}

private const val CONNECT_TIMEOUT_MS = 8000
private const val READ_TIMEOUT_MS = 8000

/** POSTs a body; returns the HTTP status, or -1 when no response was received. */
public fun interface RaspHttpPost {
    public fun post(url: String, headers: Map<String, String>, body: ByteArray): Int

    public companion object {
        /** HttpURLConnection implementation used in production. */
        public val URL_CONNECTION: RaspHttpPost = RaspHttpPost { url, headers, body ->
            var connection: HttpURLConnection? = null
            try {
                connection = (URL(url).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = CONNECT_TIMEOUT_MS
                    readTimeout = READ_TIMEOUT_MS
                    doOutput = true
                    headers.forEach { (name, value) -> setRequestProperty(name, value) }
                }
                connection.outputStream.use { it.write(body) }
                connection.responseCode
            } catch (e: Exception) {
                -1
            } finally {
                connection?.disconnect()
            }
        }
    }
}

/** Counters for envelopes that left the queue, by reason. Process lifetime. */
public class RaspDeliveryStats {
    internal val delivered = AtomicLong()
    internal val droppedInvalid = AtomicLong()
    internal val droppedExpired = AtomicLong()
    internal val droppedUnauthorized = AtomicLong()
    internal val droppedRejected = AtomicLong()
    internal val reRegistrations = AtomicLong()

    public fun snapshot(): Map<String, Long> = linkedMapOf(
        "delivered" to delivered.get(),
        "dropped_invalid" to droppedInvalid.get(),
        "dropped_expired" to droppedExpired.get(),
        "dropped_unauthorized" to droppedUnauthorized.get(),
        "dropped_rejected" to droppedRejected.get(),
        "re_registrations" to reRegistrations.get(),
    )
}

/** The device key as the registrar needs it. Production: [RaspDeviceKey.asRegistrationKeySource]. */
public interface RaspRegistrationKeySource {
    public fun deviceKeyId(): String?
    public fun publicKeyBase64(): String?
    public fun attestationChainBase64(): List<String>?
}

/** Which device key the backend has accepted. Production: [EncryptedRegistrationStore]. */
public interface RaspRegistrationStore {
    public fun registeredKeyId(): String?

    /** `null` clears it. `true` once written. */
    public fun setRegisteredKeyId(keyId: String?): Boolean
}

/**
 * Registers the device key with `POST /v1/devices/register`.
 *
 * The request is authenticated like legacy ingestion — `X-Api-Key`,
 * `X-Timestamp`, and `X-Signature` = HMAC-SHA256 of `"<timestamp>." + body`
 * with the credential's secret — because the backend requires that for
 * registration. Once the backend answers 200/201, the key id is stored
 * (encrypted) and the device is not registered again unless [invalidate] is
 * called after the backend reports an unknown device.
 */
public class RaspDeviceRegistrar(
    private val keySource: RaspRegistrationKeySource,
    private val store: RaspRegistrationStore,
    private val appId: String,
    private val sdkVersion: String = BuildConfig.RASP_ENGINE_VERSION,
    private val http: RaspHttpPost = RaspHttpPost.URL_CONNECTION,
    private val clock: () -> Long = System::currentTimeMillis,
    /** The app's signing certificate SHA-256 (uppercase hex), sent as `signingCertSha256` when known. */
    private val signingCertSha256: () -> String? = { null },
) {
    public enum class Result { REGISTERED, RETRY_LATER, REJECTED }

    /** Registers only when the stored key id is not the current key's id. */
    @Synchronized
    public fun ensureRegistered(credential: RaspEventCredential): Result {
        val keyId = keySource.deviceKeyId() ?: return Result.RETRY_LATER
        if (store.registeredKeyId() == keyId) return Result.REGISTERED
        return register(credential)
    }

    /** Forgets the stored registration (the backend said it does not know this device). */
    @Synchronized
    public fun invalidate() {
        store.setRegisteredKeyId(null)
    }

    @Synchronized
    public fun register(credential: RaspEventCredential): Result {
        val keyId = keySource.deviceKeyId()
        val publicKey = keySource.publicKeyBase64()
        val chain = keySource.attestationChainBase64()
        if (keyId == null || publicKey == null || chain.isNullOrEmpty()) return Result.RETRY_LATER

        val fields = linkedMapOf<String, Any?>(
            "appId" to appId,
            "publicKey" to publicKey,
            "attestationChain" to chain,
            "sdkVersion" to sdkVersion,
        )
        // The backend stores it on the registration and compares later tamper
        // evidence against it (Task 6.0 Part 2.3). Optional: left out when unknown.
        try { signingCertSha256() } catch (e: Exception) { null }
            ?.takeIf { it.isNotBlank() }
            ?.let { fields["signingCertSha256"] = it }
        val body = RaspCanonicalJson.encode(fields).toByteArray(Charsets.UTF_8)
        val timestamp = clock().toString()
        val headers = mapOf(
            "Content-Type" to "application/json",
            "X-Api-Key" to credential.apiKey,
            "X-Timestamp" to timestamp,
            "X-Signature" to RaspHmacSigner.sign(credential.apiSecret, timestamp, body),
        )
        val status = http.post(registrationUrl(credential.ingestionUrl), headers, body)
        return when {
            status == 200 || status == 201 ->
                if (store.setRegisteredKeyId(keyId)) Result.REGISTERED else Result.RETRY_LATER
            status == -1 || status == 429 || status in 500..599 -> Result.RETRY_LATER
            else -> Result.REJECTED
        }
    }

    public companion object {
        /** `https://host/v1/events` → `https://host/v1/devices/register` (see [RaspBackendUrls.endpoint]). */
        @JvmStatic
        public fun registrationUrl(ingestionUrl: String): String =
            RaspBackendUrls.endpoint(ingestionUrl, "devices/register") ?: ingestionUrl
    }
}

/**
 * Sends one queued envelope and decides what the queue does with it.
 *
 * | Situation | Outcome |
 * |---|---|
 * | `eventTimeMillis` older than [MAX_EVENT_AGE_MS] (the backend's limit) | dropped without sending (`dropped_expired`) |
 * | device not registered yet | register first; registration network error/5xx → retry later |
 * | 2xx | delivered |
 * | 400 / 422 | dropped (`dropped_invalid`) |
 * | 401 (unknown device, bad signature) | register again, then retry **once**; a second 401 → dropped (`dropped_unauthorized`) |
 * | network error, 5xx, 429 | retry later with backoff (queue keeps it) |
 * | any other 4xx (403, 409, 413, …) | dropped (`dropped_rejected`) |
 */
public class RaspEnvelopeDelivery(
    private val credentialProvider: () -> RaspEventCredential?,
    private val registrar: RaspDeviceRegistrar,
    private val http: RaspHttpPost = RaspHttpPost.URL_CONNECTION,
    public val stats: RaspDeliveryStats = RaspDeliveryStats(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    internal enum class Classification { DELIVERED, UNAUTHORIZED, DROP_INVALID, RETRY, DROP_REJECTED }

    public fun deliver(envelopeJson: String): RaspDeliveryOutcome {
        val credential = credentialProvider() ?: return RaspDeliveryOutcome.RETRY_LATER

        val eventTime = eventTimeMillis(envelopeJson)
        if (eventTime == null) return dropped(stats.droppedInvalid)
        if (eventTime < clock() - MAX_EVENT_AGE_MS) return dropped(stats.droppedExpired)

        if (registrar.ensureRegistered(credential) != RaspDeviceRegistrar.Result.REGISTERED) {
            return RaspDeliveryOutcome.RETRY_LATER
        }
        val first = classify(post(credential, envelopeJson))
        if (first != Classification.UNAUTHORIZED) return outcomeOf(first)

        // 401: the backend does not accept this device key. Register again, retry once.
        stats.reRegistrations.incrementAndGet()
        registrar.invalidate()
        if (registrar.register(credential) != RaspDeviceRegistrar.Result.REGISTERED) {
            return RaspDeliveryOutcome.RETRY_LATER
        }
        val second = classify(post(credential, envelopeJson))
        return if (second == Classification.UNAUTHORIZED) dropped(stats.droppedUnauthorized) else outcomeOf(second)
    }

    private fun post(credential: RaspEventCredential, envelopeJson: String): Int =
        http.post(
            credential.ingestionUrl,
            // Envelope path: the envelope carries its own device signature; no HMAC headers.
            mapOf("Content-Type" to "application/json", "X-Api-Key" to credential.apiKey),
            envelopeJson.toByteArray(Charsets.UTF_8),
        )

    private fun outcomeOf(c: Classification): RaspDeliveryOutcome = when (c) {
        Classification.DELIVERED -> {
            stats.delivered.incrementAndGet()
            RaspDeliveryOutcome.DELIVERED
        }
        Classification.DROP_INVALID -> dropped(stats.droppedInvalid)
        Classification.DROP_REJECTED -> dropped(stats.droppedRejected)
        Classification.UNAUTHORIZED -> dropped(stats.droppedUnauthorized)
        Classification.RETRY -> RaspDeliveryOutcome.RETRY_LATER
    }

    private fun dropped(counter: AtomicLong): RaspDeliveryOutcome {
        counter.incrementAndGet()
        return RaspDeliveryOutcome.DROPPED
    }

    public companion object {
        /** Same limit as the backend (`ENVELOPE_MAX_AGE_MS`). */
        public const val MAX_EVENT_AGE_MS: Long = 7L * 24 * 60 * 60 * 1000

        internal fun classify(status: Int): Classification = when {
            status in 200..299 -> Classification.DELIVERED
            status == 401 -> Classification.UNAUTHORIZED
            status == 400 || status == 422 -> Classification.DROP_INVALID
            status == -1 || status == 429 || status in 500..599 -> Classification.RETRY
            else -> Classification.DROP_REJECTED
        }

        /** The envelope's `eventTimeMillis`; `null` if the stored text is not a readable envelope. */
        internal fun eventTimeMillis(envelopeJson: String): Long? = try {
            ((RaspJson.parse(envelopeJson) as? Map<*, *>)?.get("eventTimeMillis") as? Long)
        } catch (e: Exception) {
            null
        }
    }
}

/** [RaspRegistrationStore] in EncryptedSharedPreferences; writes use `commit()`. */
public class EncryptedRegistrationStore(context: Context) : RaspRegistrationStore {
    private val appContext = context.applicationContext ?: context
    private val prefs by lazy {
        EncryptedSharedPreferences.create(
            appContext,
            "rasp_device_registration",
            MasterKey.Builder(appContext).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    override fun registeredKeyId(): String? = try {
        prefs.getString("registered_key_id", null)
    } catch (e: Exception) {
        null
    }

    override fun setRegisteredKeyId(keyId: String?): Boolean = try {
        prefs.edit().apply { if (keyId == null) remove("registered_key_id") else putString("registered_key_id", keyId) }.commit()
    } catch (e: Exception) {
        false
    }
}
