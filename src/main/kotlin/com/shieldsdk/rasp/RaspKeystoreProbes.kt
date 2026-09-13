package com.shieldsdk.rasp

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.RSAPrivateKey

/**
 * Hardware-backed Android Keystore checks: device binding and
 * TEE/StrongBox availability. Verbatim port of the logic that lived inline
 * in the Flutter plugin's `RaspSecurityChannelHandler.kt`
 * (`verifyDeviceBinding`/`isSecureHardwareUnavailable`/
 * `isInsideSecureHardware`/`generateBindingKey`) — same key alias, same
 * key-generation parameters, same fallback behavior, so a device that has
 * already generated a binding key via one consumption path (Flutter) is
 * read identically via the other (native).
 *
 * Context-free: `AndroidKeyStore` is a JCA provider, not a `Context`-scoped
 * service — every method here needs no `Context` at all.
 */
public object RaspKeystoreProbes {

    private const val KEY_ALIAS = "RASP_DEVICE_BINDING_KEY"

    /**
     * `true` when this install has a working hardware-backed device-binding
     * key. **Historical native polarity note**: the original
     * `verifyDeviceBinding()` this ports returned `true` when binding had
     * *failed* (kept in `MainActivity`/`RaspSecurityChannelHandler` exactly
     * as shipped, per those files' own doc comments). This method inverts
     * that at the boundary — `isDeviceBindingIntact() == true` means
     * binding is genuinely fine — so [RaspShieldCore]'s facade never has to
     * carry that inverted-boolean landmine forward into a new API surface.
     */
    fun isDeviceBindingIntact(): Boolean = try {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            generateBindingKey()
            // First run on this install: the key was just created, so
            // binding is now intact — matches the original's "return
            // false" (= binding not-failed) branch immediately after
            // provisioning, just expressed in the corrected polarity.
            return true
        }
        keyStore.getEntry(KEY_ALIAS, null) != null
    } catch (e: Exception) {
        // Original polarity: any exception here means binding could not be
        // established/verified, i.e. NOT intact.
        false
    }

    private fun generateBindingKey() {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(false)
            }
            build()
        }
        kpg.initialize(parameterSpec)
        kpg.generateKeyPair()
    }

    /**
     * `null` when it could not be determined (matches every other
     * `Boolean?`-returning probe in this SDK — never collapsed to `false`).
     * `true` when NEITHER a TEE nor StrongBox is available.
     */
    fun isSecureHardwareUnavailable(context: android.content.Context): Boolean? = try {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            true
        } else if (Build.VERSION.SDK_INT >= 31) {
            val hasStrongBox =
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                    context.packageManager.hasSystemFeature(
                        android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE
                    )
            val hasTee = context.packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_HARDWARE_KEYSTORE
            )
            (hasStrongBox || hasTee).not()
        } else {
            isInsideSecureHardware(KEY_ALIAS).not()
        }
    } catch (e: Exception) {
        null
    }

    private fun isInsideSecureHardware(alias: String): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(alias)) {
            generateBindingKey()
        }
        val privateKey = keyStore.getKey(alias, null) as RSAPrivateKey
        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
        return keyInfo.isInsideSecureHardware
    }
}
