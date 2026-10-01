package com.shieldsdk.rasp

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
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
 * - First call to [getOrCreate] generates the key (may take 100-500ms on
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
 * val publicKeyB64 = keyManager.getPublicKeyBase64() // for backend registration
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
    public fun getPublicKeyBase64(): String? {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null)
                ?: return generateKeyPair().let { getPublicKeyBase64()!! }
            val publicKey = (entry as java.security.KeyStore.PrivateKeyEntry).certificate.publicKey
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
    public fun sign(payload: ByteArray): String? {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? java.security.KeyStore.PrivateKeyEntry
                ?: return generateKeyPair().let { sign(payload) }
            val privateKey = entry.privateKey as ECPrivateKey
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(payload)
            Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    /**
     * Verifies a signature against this device's public key.
     * Purely for self-test / backend round-trip verification.
     */
    public fun verify(payload: ByteArray, signatureB64: String): Boolean {
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

    /** Returns the raw [PublicKey] for advanced use cases (e.g. certificate pinning). */
    public fun getPublicKey(): PublicKey? {
        return try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? java.security.KeyStore.PrivateKeyEntry
                ?: return null
            entry.certificate.publicKey
        } catch (e: Exception) {
            notifyLogger("device_key", e)
            null
        }
    }

    /** Generates a new EC P-256 key pair in Keystore (StrongBox preferred). */
    private fun generateKeyPair(): KeyPairGenerator {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256)
            setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
            // Non-exportable by default — no setUserAuthenticationRequired needed
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // Try StrongBox first; if unavailable, the generateKeyPair() call
                // will throw StrongBoxUnavailableException and we fall back below.
                try {
                    setIsStrongBoxBacked(true)
                } catch (_: StrongBoxUnavailableException) {
                    // Will retry without StrongBox in the catch block below
                }
            }
            build()
        }

        return try {
            kpg.initialize(builder)
            kpg.generateKeyPair()
            kpg
        } catch (e: StrongBoxUnavailableException) {
            // StrongBox not available — retry with TEE
            val fallbackBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
            ).run {
                setDigests(KeyProperties.DIGEST_SHA256)
                setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(false)
                }
                build()
            }
            kpg.initialize(fallbackBuilder)
            kpg.generateKeyPair()
            kpg
        }
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