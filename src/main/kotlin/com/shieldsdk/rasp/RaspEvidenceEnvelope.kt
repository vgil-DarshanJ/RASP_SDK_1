package com.shieldsdk.rasp

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID

/** Signs envelope bytes. Production: [RaspDeviceKey.asEnvelopeSigner]. */
public interface RaspEnvelopeSigner {
    /** X.509 SubjectPublicKeyInfo (DER) of the signing key, or `null` if there is no key. */
    public fun publicKeySpki(): ByteArray?

    /** SHA256withECDSA over [payload], DER-encoded, or `null` on failure. */
    public fun signDer(payload: ByteArray): ByteArray?
}

/** Source of the per-install monotonic counter. */
public interface RaspEnvelopeCounterStore {
    /**
     * The next counter value, already persisted when this returns, or `null`
     * if it could not be persisted. Must be strictly greater than every value
     * returned before on this install, including before a process restart.
     */
    public fun next(): Long?
}

/**
 * Signed evidence envelope — the wire format for tamper-evident event shipping.
 *
 * ```json
 * {
 *   "appId": "com.example.app",
 *   "detectorResults": [ { "detectorId", "status", "evidence", "reason"?, "observedAtMillis" } ],
 *   "device": { "manufacturer", "model", "osPlatform", "osVersion", "appVersion"? },
 *   "deviceKeyId": "Base64(SHA-256(SPKI))",
 *   "envelopeVersion": 1,
 *   "eventId": "uuid-v4",
 *   "eventTimeMillis": 1699999999999,
 *   "monotonicCounter": 42,
 *   "nonce": "32 hex chars (16 random bytes)",
 *   "sdkVersion": "1.1.0-local",
 *   "signature": "Base64(DER ECDSA P-256 signature)",
 *   "signatureAlgorithm": "ES256"
 * }
 * ```
 *
 * ## What is signed
 * The canonical JSON ([RaspCanonicalJson]) of **every field except
 * `signature`** — including `signatureAlgorithm`, so the algorithm label cannot
 * be swapped either. The backend removes only `signature` before verifying
 * (`BE/src/ingestion/routes.ts`), so both sides sign/verify the same field set.
 *
 * `device` (optional, signed like everything else) names the phone for the
 * dashboard: model, manufacturer, OS and app version. It carries no
 * identifier; the device is still identified by `deviceKeyId`.
 *
 * ## Replay properties
 * - `monotonicCounter` comes from a [RaspEnvelopeCounterStore] that persists
 *   synchronously before the envelope is built, so a crash cannot reissue a
 *   value. Gaps are possible (a failed signature consumes a value); repeats
 *   are not.
 * - `nonce` is 16 bytes from [SecureRandom], fresh per envelope.
 *
 * ## Not provided here
 * The backend can only verify envelopes from a registered device key
 * (`POST /v1/devices/register`); this class does not register the key.
 */
public class RaspEvidenceEnvelope(
    private val signer: RaspEnvelopeSigner,
    private val counterStore: RaspEnvelopeCounterStore,
    private val appId: String,
    private val sdkVersion: String = BuildConfig.RASP_ENGINE_VERSION,
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: SecureRandom = SecureRandom(),
    /** The envelope's `device` object; omitted when `null`. Production: [deviceInfo]. */
    private val device: Map<String, String>? = null,
) {

    /**
     * Builds and signs an envelope as a field map (the exact fields that are
     * serialized). `null` if there is no device key, the counter could not be
     * persisted, or signing failed.
     */
    public fun buildFields(results: List<RaspCheckResult>): Map<String, Any?>? {
        val spki = signer.publicKeySpki() ?: return null
        val counter = counterStore.next() ?: return null
        val unsigned = linkedMapOf<String, Any?>(
            "envelopeVersion" to ENVELOPE_VERSION,
            "eventId" to UUID.randomUUID().toString(),
            "eventTimeMillis" to clock(),
            "monotonicCounter" to counter,
            "nonce" to newNonce(),
            "sdkVersion" to sdkVersion,
            "appId" to appId,
            "deviceKeyId" to deviceKeyId(spki),
            "detectorResults" to results.map(::resultFields),
            "signatureAlgorithm" to SIGNATURE_ALGORITHM,
        )
        if (!device.isNullOrEmpty()) unsigned["device"] = device
        val signature = signer.signDer(signingInput(unsigned)) ?: return null
        return unsigned + ("signature" to RaspBase64.encode(signature))
    }

    /** [buildFields] serialized as the canonical JSON body that is POSTed. */
    public fun build(results: List<RaspCheckResult>): String? =
        buildFields(results)?.let { RaspCanonicalJson.encode(it) }

    private fun newNonce(): String {
        val bytes = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun resultFields(r: RaspCheckResult): Map<String, Any?> = linkedMapOf<String, Any?>(
        "detectorId" to r.detectorId,
        "status" to r.status.name,
        "evidence" to r.evidence.map { e ->
            linkedMapOf<String, Any?>("key" to e.key, "value" to e.value).apply {
                if (e.note != null) put("note", e.note)
            }
        },
        "observedAtMillis" to r.observedAtMillis,
    ).apply { if (r.reason != null) put("reason", r.reason) }

    public companion object {
        public const val ENVELOPE_VERSION: Int = 1
        public const val SIGNATURE_ALGORITHM: String = "ES256"
        public const val NONCE_BYTES: Int = 16

        /** Base64(SHA-256(SPKI)) — the backend's `deviceKeyId` lookup key. */
        @JvmStatic
        public fun deviceKeyId(spki: ByteArray): String =
            RaspBase64.encode(MessageDigest.getInstance("SHA-256").digest(spki))

        /** The bytes that are signed: canonical JSON of every field except `signature`. */
        @JvmStatic
        public fun signingInput(fields: Map<String, Any?>): ByteArray =
            RaspCanonicalJson.encode(fields - "signature").toByteArray(Charsets.UTF_8)

        /**
         * Verifies [fields] against an EC P-256 public key (SPKI DER). Mirrors
         * the backend check; used for self-tests.
         */
        @JvmStatic
        public fun verify(fields: Map<String, Any?>, spki: ByteArray): Boolean = try {
            val sig = (fields["signature"] as? String)?.let { RaspBase64.decode(it) }
            if (sig == null || fields["signatureAlgorithm"] != SIGNATURE_ALGORITHM) {
                false
            } else {
                val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
                Signature.getInstance("SHA256withECDSA").run {
                    initVerify(key)
                    update(signingInput(fields))
                    verify(sig)
                }
            }
        } catch (e: Exception) {
            false
        }

        /** Longest value kept in the `device` object (the backend stores at most 200). */
        internal const val DEVICE_FIELD_MAX = 100

        /**
         * The `device` object: entries with a blank value are left out, the
         * rest trimmed to [DEVICE_FIELD_MAX] characters.
         */
        @JvmStatic
        public fun deviceInfo(
            manufacturer: String?,
            model: String?,
            osVersion: String?,
            appVersion: String?,
            osPlatform: String = "android",
        ): Map<String, String> = linkedMapOf(
            "manufacturer" to manufacturer,
            "model" to model,
            "osPlatform" to osPlatform,
            "osVersion" to osVersion,
            "appVersion" to appVersion,
        ).mapNotNull { (k, v) -> v?.trim()?.takeIf { it.isNotEmpty() }?.let { k to it.take(DEVICE_FIELD_MAX) } }.toMap()

        /** [deviceInfo] for this phone: `Build` values and the host app's versionName. */
        @JvmStatic
        public fun deviceInfo(context: Context): Map<String, String> {
            val appVersion = try {
                context.packageManager.getPackageInfo(context.packageName, 0).versionName
            } catch (e: Exception) {
                null
            }
            return deviceInfo(android.os.Build.MANUFACTURER, android.os.Build.MODEL, android.os.Build.VERSION.RELEASE, appVersion)
        }

        /** Production wiring: hardware device key + encrypted, synchronously persisted counter. */
        @JvmStatic
        public fun forDevice(context: Context, deviceKey: RaspDeviceKey): RaspEvidenceEnvelope {
            val app = context.applicationContext ?: context
            return RaspEvidenceEnvelope(
                deviceKey.asEnvelopeSigner(), RaspEncryptedCounterStore(app), app.packageName, device = deviceInfo(app),
            )
        }
    }
}

/**
 * Counter persisted in EncryptedSharedPreferences with `commit()` (synchronous),
 * so a value is on disk before any envelope carrying it exists. Same file and
 * key as the earlier implementation, so existing installs keep counting up.
 */
internal class RaspEncryptedCounterStore(private val context: Context) : RaspEnvelopeCounterStore {

    private val prefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    override fun next(): Long? = synchronized(LOCK) {
        try {
            val next = prefs.getLong(KEY, 0L) + 1
            if (prefs.edit().putLong(KEY, next).commit()) next else null
        } catch (e: Exception) {
            try {
                RaspShieldCore.logger.onDetectorError("envelope_counter", e)
            } catch (_: Exception) { }
            null
        }
    }

    private companion object {
        const val PREFS_NAME = "rasp_envelope_state"
        const val KEY = "monotonic_counter"
        /** Process-wide: two stores on the same file must not interleave read-increment-write. */
        val LOCK = Any()
    }
}
