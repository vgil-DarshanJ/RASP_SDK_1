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

/** An HTTP answer with its body (at most 16 KB is read), `status` -1 when no response was received. */
public data class RaspHttpResponse(val status: Int, val body: String?)

/** POSTs a body and returns status and body; used where the answer carries data (the registration challenge). */
public fun interface RaspHttpExchange {
    public fun post(url: String, headers: Map<String, String>, body: ByteArray): RaspHttpResponse

    public companion object {
        private const val MAX_BODY_BYTES = 16 * 1024

        /** HttpURLConnection implementation used in production. */
        public val URL_CONNECTION: RaspHttpExchange = RaspHttpExchange { url, headers, body ->
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
                val status = connection.responseCode
                val text = if (status in 200..299) {
                    connection.inputStream.use { stream ->
                        val bytes = stream.readNBytesCompat(MAX_BODY_BYTES)
                        String(bytes, Charsets.UTF_8)
                    }
                } else null
                RaspHttpResponse(status, text)
            } catch (e: Exception) {
                RaspHttpResponse(-1, null)
            } finally {
                connection?.disconnect()
            }
        }

        private fun java.io.InputStream.readNBytesCompat(max: Int): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (out.size() < max) {
                val n = read(buffer, 0, minOf(buffer.size, max - out.size()))
                if (n < 0) break
                out.write(buffer, 0, n)
            }
            return out.toByteArray()
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

    /** ECDSA (DER) signature with the device key, for the registration challenge; `null` when unavailable. */
    public fun signDer(payload: ByteArray): ByteArray? = null
}

/** Which device key the backend has accepted. Production: [EncryptedRegistrationStore]. */
public interface RaspRegistrationStore {
    public fun registeredKeyId(): String?

    /** `null` clears it. `true` once written. */
    public fun setRegisteredKeyId(keyId: String?): Boolean

    /**
     * Format of the registration the stored key was registered with
     * ([RaspDeviceRegistrar.REGISTRATION_VERSION]); an older one makes the
     * registrar register once more. Stores that do not keep it count as current.
     */
    public fun registrationVersion(): Int = RaspDeviceRegistrar.REGISTRATION_VERSION

    public fun setRegistrationVersion(version: Int): Boolean = true
}

/**
 * Registers the device key with `POST /v1/devices/register`.
 *
 * The request is authenticated like legacy ingestion — `X-Api-Key`,
 * `X-Timestamp`, and `X-Signature` = HMAC-SHA256 of `"<timestamp>." + body`
 * with the credential's secret — because the backend requires that for
 * registration. Once the backend answers 200/201, the key id is stored
 * (encrypted) and the device is not registered again unless [invalidate] is
 * called after the backend reports an unknown (or not attested) device, or
 * the stored registration is from an older [REGISTRATION_VERSION].
 *
 * ## Proof of possession (F-13)
 * With [exchange], each registration first asks `POST /v1/devices/challenge`
 * for a one-time challenge and signs `rasp-register-v1:<challenge>:<keyId>`
 * with the device key; challenge and signature go with the registration.
 * No challenge endpoint (404/405, older backend) → registration without
 * proof; network error, 429 or 5xx → [Result.RETRY_LATER].
 *
 * ## Stable device id (F-15)
 * [deviceId] (production: [RaspDeviceIdentity.forDevice]) is sent as
 * `deviceId`, so the backend recognises a reinstall of the same phone.
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
    /** Stable device id sent as `deviceId` (see [RaspDeviceIdentity]); `null` → left out. */
    private val deviceId: (RaspEventCredential) -> String? = { null },
    /** For the registration challenge; `null` → registrations carry no proof of possession. */
    private val exchange: RaspHttpExchange? = null,
) {
    public enum class Result { REGISTERED, RETRY_LATER, REJECTED }

    /** Registers only when the stored key id is not the current key's id, or was registered in an older format. */
    @Synchronized
    public fun ensureRegistered(credential: RaspEventCredential): Result {
        val keyId = keySource.deviceKeyId() ?: return Result.RETRY_LATER
        if (store.registeredKeyId() == keyId && store.registrationVersion() >= REGISTRATION_VERSION) return Result.REGISTERED
        return register(credential)
    }

    private sealed class Proof {
        data class Signed(val challenge: String, val signatureBase64: String) : Proof()
        object NotSupported : Proof()
        object Retry : Proof()
    }

    private fun proofOfPossession(credential: RaspEventCredential, keyId: String): Proof {
        val http = exchange ?: return Proof.NotSupported
        val url = RaspBackendUrls.endpoint(credential.ingestionUrl, "devices/challenge") ?: return Proof.NotSupported
        val body = "{}".toByteArray(Charsets.UTF_8)
        val timestamp = clock().toString()
        val response = http.post(
            url,
            mapOf(
                "Content-Type" to "application/json",
                "X-Api-Key" to credential.apiKey,
                "X-Timestamp" to timestamp,
                "X-Signature" to RaspHmacSigner.sign(credential.apiSecret, timestamp, body),
            ),
            body,
        )
        return when {
            response.status == -1 || response.status == 429 || response.status in 500..599 -> Proof.Retry
            response.status != 200 -> Proof.NotSupported
            else -> {
                val challenge = try {
                    ((RaspJson.parse(response.body ?: "") as? Map<*, *>)?.get("challenge") as? String)
                } catch (e: Exception) {
                    null
                }
                val signature = challenge?.let { keySource.signDer(possessionMessage(it, keyId)) }
                if (challenge == null || signature == null) Proof.NotSupported
                else Proof.Signed(challenge, RaspBase64.encode(signature))
            }
        }
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

        val proof = proofOfPossession(credential, keyId)
        if (proof is Proof.Retry) return Result.RETRY_LATER

        val fields = linkedMapOf<String, Any?>(
            "appId" to appId,
            "publicKey" to publicKey,
            "attestationChain" to chain,
            "sdkVersion" to sdkVersion,
        )
        try { deviceId(credential) } catch (e: Exception) { null }
            ?.takeIf { it.isNotBlank() }
            ?.let { fields["deviceId"] = it }
        if (proof is Proof.Signed) {
            fields["challenge"] = proof.challenge
            fields["challengeSignature"] = proof.signatureBase64
        }
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
                if (store.setRegisteredKeyId(keyId) && store.setRegistrationVersion(REGISTRATION_VERSION)) Result.REGISTERED
                else Result.RETRY_LATER
            status == -1 || status == 429 || status in 500..599 -> Result.RETRY_LATER
            else -> Result.REJECTED
        }
    }

    public companion object {
        /**
         * 2: registrations carry `deviceId` and, when the backend offers it, a
         * signed challenge. Keys registered in an older format register once more.
         */
        public const val REGISTRATION_VERSION: Int = 2

        /** The bytes signed for the registration challenge (same as the backend's `possessionMessage`). */
        @JvmStatic
        public fun possessionMessage(challenge: String, deviceKeyId: String): ByteArray =
            "rasp-register-v1:$challenge:$deviceKeyId".toByteArray(Charsets.UTF_8)

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
        prefs.edit().apply {
            if (keyId == null) remove("registered_key_id").remove("registration_version") else putString("registered_key_id", keyId)
        }.commit()
    } catch (e: Exception) {
        false
    }

    /** 0 for keys registered before registration versions existed. */
    override fun registrationVersion(): Int = try {
        prefs.getInt("registration_version", 0)
    } catch (e: Exception) {
        0
    }

    override fun setRegistrationVersion(version: Int): Boolean = try {
        prefs.edit().putInt("registration_version", version).commit()
    } catch (e: Exception) {
        false
    }
}
