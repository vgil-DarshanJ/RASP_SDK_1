package com.shieldsdk.rasp

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.SecureRandom
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Per-install, hardware-backed EC P-256 device identity key.
 *
 * ## Key properties
 * - Algorithm: EC P-256 (secp256r1 / prime256v1)
 * - Storage: Android Keystore — StrongBox (API 28+) preferred, TEE fallback
 * - Exportability: **Never** — private key is non-exportable by construction
 * - Purposes: SIGN only (no encrypt/decrypt/derive)
 * - Alias: `RASP_DEVICE_IDENTITY_KEY` — distinct from the RSA binding key
 *   used by `RaspKeystoreProbes` so the two key hierarchies never collide.
 *
 * ## Lifecycle
 * - First call to [ensureKey] (or any export/sign call) generates the key (may take 100-500ms on
 *   first run — call off the main thread).
 * - Subsequent calls return the existing key instantly.
 * - Key survives app updates/uninstalls **only if** the app is signed with
 *   the same certificate and the user doesn't factory-reset — this is the
 *   Android Keystore contract, not something this SDK can strengthen.
 * - `clear()` exists for test reset and explicit user "forget me" flows.
 *
 * ## Usage
 * ```kotlin
 * val keyManager = RaspDeviceKey(context)
 * val publicKeyB64 = keyManager.exportPublicKeyBase64()          // POST /v1/devices/register
 * val chain = keyManager.exportAttestationChainBase64()            // same request
 * val signature = keyManager.sign(payloadBytes)       // for evidence envelopes
 * ```
 */
public class RaspDeviceKey(private val context: Context) {

    companion object {
        private const val KEY_ALIAS = "RASP_DEVICE_IDENTITY_KEY"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val EC_CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }

    private val keyStore by lazy { KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) } }

    /**
     * Returns the Base64-encoded X.509 (SPKI) public key.
     * Safe to log, safe to send to backend — never reveals private material.
     */
    open fun getPublicKeyBase64(): String? {
        return try {
            val publicKey = getPublicKey() ?: return null
            Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    /**
     * Signs [payload] with the device identity key.
     * Returns `null` if the key is unavailable or signing fails.
     * Never throws — failures are logged via [RaspShieldCore.logger].
     */
    open fun sign(payload: ByteArray): String? =
        signDer(payload)?.let { Base64.encodeToString(it, Base64.NO_WRAP) }

    /** SHA256withECDSA over [payload], DER-encoded. Creates the key if missing. */
    public fun signDer(payload: ByteArray): ByteArray? {
        return try {
            if (!ensureKey()) return null
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? java.security.KeyStore.PrivateKeyEntry
                ?: return null
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(entry.privateKey)
            signature.update(payload)
            signature.sign()
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    /**
     * Creates the key if it does not exist yet. Returns `true` when a key
     * exists afterwards.
     *
     * [attestationChallenge] is embedded in the key's attestation certificate
     * (API 24+). It only affects a key created by this call — an existing key
     * keeps the challenge (or lack of one) it was created with. For the
     * backend to treat the attestation as fresh, pass a challenge it issued;
     * without one, 32 random local bytes are used, which yields an attestation
     * chain but proves nothing about freshness.
     */
    public fun ensureKey(attestationChallenge: ByteArray? = null): Boolean {
        return try {
            if (keyStore.containsAlias(KEY_ALIAS)) return true
            generateKeyPair(attestationChallenge ?: ByteArray(32).also { SecureRandom().nextBytes(it) })
            keyStore.containsAlias(KEY_ALIAS)
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            false
        }
    }

    /**
     * Base64 (standard, no line breaks) X.509 SPKI of the device key, for
     * `POST /v1/devices/register`. Creates the key if missing.
     */
    public fun exportPublicKeyBase64(): String? =
        exportPublicKeySpki()?.let { RaspBase64.encode(it) }

    /** DER X.509 SPKI of the device key. Creates the key if missing. */
    public fun exportPublicKeySpki(): ByteArray? =
        if (ensureKey()) getPublicKey()?.encoded else null

    /**
     * The key's certificate chain, leaf first, each certificate Base64 DER,
     * for `POST /v1/devices/register`. Creates the key if missing.
     *
     * With hardware attestation the leaf carries the Android key-attestation
     * extension and the chain ends at a Google attestation root. A key created
     * without attestation (API 23, or a key made by an earlier SDK build) has
     * a single self-signed certificate; the backend must treat that as
     * "not attested", not as a failure to parse.
     */
    public fun exportAttestationChainBase64(): List<String>? =
        if (ensureKey()) getAttestationCertificateChain()?.let { chain ->
            chain.map { RaspBase64.encode(Base64.decode(it, Base64.NO_WRAP)) }
        } else null

    /** Base64(SHA-256(SPKI)) — the id the backend stores this key under. */
    public fun deviceKeyId(): String? =
        exportPublicKeySpki()?.let { RaspEvidenceEnvelope.deviceKeyId(it) }

    /** This key as the source for [RaspDeviceRegistrar]. */
    public fun asRegistrationKeySource(): RaspRegistrationKeySource = object : RaspRegistrationKeySource {
        override fun deviceKeyId(): String? = this@RaspDeviceKey.deviceKeyId()
        override fun publicKeyBase64(): String? = exportPublicKeyBase64()
        override fun attestationChainBase64(): List<String>? = exportAttestationChainBase64()
        override fun signDer(payload: ByteArray): ByteArray? = this@RaspDeviceKey.signDer(payload)
    }

    /** This key as the signer for [RaspEvidenceEnvelope]. */
    public fun asEnvelopeSigner(): RaspEnvelopeSigner = object : RaspEnvelopeSigner {
        override fun publicKeySpki(): ByteArray? = exportPublicKeySpki()
        override fun signDer(payload: ByteArray): ByteArray? = this@RaspDeviceKey.signDer(payload)
    }

    /**
     * Verifies a signature against this device's public key.
     * Purely for self-test / backend round-trip verification.
     */
    open fun verify(payload: ByteArray, signatureB64: String): Boolean {
        return try {
            val publicKey = getPublicKey() ?: return false
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initVerify(publicKey)
            signature.update(payload)
            signature.verify(Base64.decode(signatureB64, Base64.NO_WRAP))
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            false
        }
    }

    /** Deletes the device identity key. Idempotent, never throws. */
    public fun clear() {
        try {
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
            }
        } catch (e: Exception) {
            notifyLogger("device_key", e)
        }
    }

    /** Checks if a device identity key already exists. */
    public fun hasKey(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    /**
     * Returns the raw [PublicKey] for advanced use cases (e.g. certificate pinning).
     */
    open fun getPublicKey(): PublicKey? {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? java.security.KeyStore.PrivateKeyEntry
                ?: return null
            entry.certificate.publicKey
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    /**
     * Returns the attestation certificate chain as a list of Base64-encoded DER certificates.
     * The first element is the leaf certificate (device's attestation cert),
     * followed by any intermediate CAs, ending with the root.
     * Returns `null` if attestation is not supported or the key doesn't have a certificate chain.
     * This is used by the backend to verify the key's hardware-backed origin.
     */
    public fun getAttestationCertificateChain(): List<String>? {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? java.security.KeyStore.PrivateKeyEntry
                ?: return null
            val chain = entry.certificateChain ?: return null
            if (chain.isEmpty()) return null
            chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }.toList()
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    /**
     * Generates a new EC P-256 key pair in Keystore. Tries, in order:
     * StrongBox + attestation, TEE + attestation, TEE without attestation.
     * Each failed attempt (StrongBox absent, attestation unsupported on some
     * API 24–25 devices) falls through to the next; the last failure is thrown.
     */
    private fun generateKeyPair(attestationChallenge: ByteArray) {
        val attempts = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) add(true to true)
            add(false to true)
            add(false to false)
        }
        var lastError: Exception? = null
        for ((strongBox, attest) in attempts) {
            try {
                val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN).run {
                    setDigests(KeyProperties.DIGEST_SHA256)
                    setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                    if (attest && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        setAttestationChallenge(attestationChallenge)
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(strongBox)
                    build()
                }
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).run {
                    initialize(spec)
                    generateKeyPair()
                }
                return
            } catch (e: Exception) {
                // ProviderException (incl. StrongBoxUnavailableException, API 28+) or
                // InvalidAlgorithmParameterException; caught as Exception so no API-28
                // class is referenced in a catch clause on API 23–27.
                lastError = e
                try { keyStore.deleteEntry(KEY_ALIAS) } catch (_: Exception) { }
            }
        }
        throw lastError ?: IllegalStateException("device key generation failed")
    }

    /** Checks if the existing key is inside StrongBox (API 28+). */
    public fun isInsideStrongBox(): Boolean? {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? java.security.KeyStore.PrivateKeyEntry
                ?: return null
            val privateKey = entry.privateKey as ECPrivateKey
            val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
            // isInsideStrongBox() added in API 28; use reflection to avoid compile-time dependency
            val method = KeyInfo::class.java.getMethod("isInsideStrongBox")
            method.invoke(keyInfo) as Boolean
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    private fun notifyLogger(tag: String, throwable: Throwable) {
        try {
            RaspShieldCore.logger.onDetectorError(tag, throwable)
        } catch (_: Exception) {
            // Logger must never propagate
        }
    }
}