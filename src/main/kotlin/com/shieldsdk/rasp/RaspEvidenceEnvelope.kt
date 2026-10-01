package com.shieldsdk.rasp

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicLong

/**
 * Signed evidence envelope — the wire format for tamper-evident event shipping.
 *
 * ## Envelope structure (JSON)
 * ```json
 * {
 *   "envelopeVersion": 1,
 *   "eventId": "uuid-v4",
 *   "eventTimeMillis": 1699999999999,
 *   "monotonicCounter": 42,
 *   "nonce": "base64url-encoded-16-bytes",
 *   "sdkVersion": "1.1.0-local",
 *   "appId": "com.example.app",
 *   "deviceKeyId": "sha256-of-spki",
 *   "detectorResults": [ ... RaspCheckResult JSON ... ],
 *   "signature": "base64-ecdsa-signature",
 *   "signatureAlgorithm": "ES256"
 * }
 * ```
 *
 * ## Security properties
 * - **Tamper evidence**: Any modification to the envelope body invalidates the ECDSA signature.
 * - **Replay protection**: `monotonicCounter` (per-install, never resets) + `nonce` (per-event, random)
 *   allow the backend to detect duplicates and out-of-order delivery.
 * - **Device binding**: Signature is created by the hardware-backed EC P-256 key from [RaspDeviceKey].
 *   The backend can verify the signature against the registered device public key.
 * - **No secrets in envelope**: The envelope carries only public data + signature. The private key
 *   never leaves the Keystore.
 *
 * ## Ordering
 * The envelope is serialized to **canonical JSON** (sorted keys, no whitespace) before signing
 * and before transmission. This ensures the exact bytes signed are the exact bytes the backend
 * will verify — no re-serialization mismatch.
 */
public class RaspEvidenceEnvelope {

    companion object {
        const val ENVELOPE_VERSION = 1
        const val SIGNATURE_ALGORITHM = "ES256"
        const val NONCE_BYTES = 16
    }

    /** Monotonic counter — persists across process restarts via EncryptedSharedPreferences. */
    private var monotonicCounter: Long = 0

    /** App package name (set once at first use). */
    private var appId: String? = null

    /** Device key ID (SHA-256 of SPKI) — set once at first use. */
    private var deviceKeyId: String? = null

    private val prefsName = "rasp_envelope_state"
    private val prefsCounterKey = "monotonic_counter"
    private val prefsAppIdKey = "app_id"
    private val prefsDeviceKeyIdKey = "device_key_id"

    /**
     * Builds and signs an evidence envelope for the given detector results.
     * Returns `null` if the device key is unavailable or signing fails.
     */
    public fun buildEnvelope(
        context: android.content.Context,
        deviceKey: RaspDeviceKey,
        results: List<RaspCheckResult>,
    ): String? {
        // Initialize persistent state on first call
        initState(context, deviceKey)

        val eventId = java.util.UUID.randomUUID().toString()
        val eventTimeMillis = System.currentTimeMillis()
        val counter = nextCounter(context)
        val nonce = generateNonce()
        val sdkVersion = BuildConfig.RASP_ENGINE_VERSION

        val body = JSONObject().apply {
            put("envelopeVersion", ENVELOPE_VERSION)
            put("eventId", eventId)
            put("eventTimeMillis", eventTimeMillis)
            put("monotonicCounter", counter)
            put("nonce", nonce)
            put("sdkVersion", sdkVersion)
            put("appId", appId ?: context.packageName)
            put("deviceKeyId", deviceKeyId ?: "")
            put("detectorResults", resultsToJson(results))
        }

        // Canonical serialization: sorted keys, no whitespace
        val canonicalBody = canonicalize(body).toString().toByteArray(StandardCharsets.UTF_8)

        val signatureB64 = deviceKey.sign(canonicalBody) ?: return null

        val envelope = JSONObject().apply {
            put("envelopeVersion", ENVELOPE_VERSION)
            put("eventId", eventId)
            put("eventTimeMillis", eventTimeMillis)
            put("monotonicCounter", counter)
            put("nonce", nonce)
            put("sdkVersion", sdkVersion)
            put("appId", appId ?: context.packageName)
            put("deviceKeyId", deviceKeyId ?: "")
            put("detectorResults", resultsToJson(results))
            put("signature", signatureB64)
            put("signatureAlgorithm", SIGNATURE_ALGORITHM)
        }

        return canonicalize(envelope).toString()
    }

    /** Initializes persistent state (counter, appId, deviceKeyId) from encrypted prefs. */
    private fun initState(context: android.content.Context, deviceKey: RaspDeviceKey) {
        if (appId != null && deviceKeyId != null && monotonicCounter > 0) return

        val prefs = getEncryptedPrefs(context)
        monotonicCounter = prefs.getLong(prefsCounterKey, 0)
        appId = prefs.getString(prefsAppIdKey, null)
        deviceKeyId = prefs.getString(prefsDeviceKeyIdKey, null)

        if (appId == null) {
            appId = context.packageName
            prefs.edit().putString(prefsAppIdKey, appId).apply()
        }
        if (deviceKeyId == null) {
            deviceKeyId = computeDeviceKeyId(deviceKey)
            if (deviceKeyId != null) {
                prefs.edit().putString(prefsDeviceKeyIdKey, deviceKeyId).apply()
            }
        }
    }

    /** Atomically increments and persists the monotonic counter. */
    private fun nextCounter(context: android.content.Context): Long {
        val prefs = getEncryptedPrefs(context)
        val next = monotonicCounter + 1
        monotonicCounter = next
        prefs.edit().putLong(prefsCounterKey, next).apply()
        return next
    }

    /** Generates a cryptographically random nonce (16 bytes, base64url-encoded). */
    private fun generateNonce(): String {
        val bytes = ByteArray(NONCE_BYTES)
        java.security.SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.URL_SAFE)
    }

    /** Computes device key ID = SHA-256 of SPKI (Base64-encoded). */
    private fun computeDeviceKeyId(deviceKey: RaspDeviceKey): String? {
        val publicKey = deviceKey.getPublicKey() ?: return null
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    private fun resultsToJson(results: List<RaspCheckResult>): JSONArray = JSONArray().apply {
        for (r in results) {
            put(JSONObject().apply {
                put("detectorId", r.detectorId)
                put("status", r.status.name)
                put("evidence", evidenceToJson(r.evidence))
                if (r.reason != null) put("reason", r.reason)
                put("observedAtMillis", r.observedAtMillis)
            })
        }
    }

    private fun evidenceToJson(evidence: List<RaspEvidence>): JSONArray = JSONArray().apply {
        for (e in evidence) {
            put(JSONObject().apply {
                put("key", e.key)
                put("value", e.value)
                if (e.note != null) put("note", e.note)
            })
        }
    }

    /**
     * Canonicalizes JSON: sorts keys recursively, removes whitespace.
     * Uses a deterministic serialization so the exact bytes signed
     * match the exact bytes the backend verifies.
     */
    private fun canonicalize(obj: JSONObject): JSONObject {
        val sorted = JSONObject()
        val keys = mutableListOf<String>()
        val iterator = obj.keys()
        while (iterator.hasNext()) {
            keys.add(iterator.next() as String)
        }
        keys.sort()
        for (key in keys) {
            val value = obj.get(key)
            sorted.put(key, when (value) {
                is JSONObject -> canonicalize(value)
                is JSONArray -> canonicalize(value)
                else -> value
            })
        }
        return sorted
    }

    private fun canonicalize(arr: JSONArray): JSONArray {
        val out = JSONArray()
        for (i in 0 until arr.length()) {
            val value = arr.get(i)
            out.put(when (value) {
                is JSONObject -> canonicalize(value)
                is JSONArray -> canonicalize(value)
                else -> value
            })
        }
        return out
    }

    private fun getEncryptedPrefs(context: android.content.Context) =
        androidx.security.crypto.EncryptedSharedPreferences.create(
            context.applicationContext ?: context,
            prefsName,
            androidx.security.crypto.MasterKey.Builder(context.applicationContext ?: context)
                .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM)
                .build(),
            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )

    /** Test-only reset. */
    public fun resetForTests(context: android.content.Context) {
        monotonicCounter = 0
        appId = null
        deviceKeyId = null
        try {
            getEncryptedPrefs(context).edit().clear().apply()
        } catch (_: Exception) { }
    }
}