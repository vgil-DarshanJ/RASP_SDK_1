package com.shieldsdk.rasp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypts and decrypts one value; [aad] binds it to its key name. `null` on any failure. */
internal interface RaspValueCipher {
    fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray?
    fun decrypt(blob: ByteArray, aad: ByteArray): ByteArray?
}

/**
 * AES-256-GCM with a non-exportable key in the Android Keystore
 * ([KEY_ALIAS]); the Keystore picks the 12-byte IV. Blob = IV ‖ ciphertext+tag.
 */
internal class RaspKeystoreValueCipher(private val alias: String = KEY_ALIAS) : RaspValueCipher {
    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    override fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray? = try {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()); updateAAD(aad) }
        cipher.iv + cipher.doFinal(plain)
    } catch (e: Exception) {
        null
    }

    override fun decrypt(blob: ByteArray, aad: ByteArray): ByteArray? = try {
        if (blob.size <= IV_BYTES) null
        else Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, IV_BYTES))
            updateAAD(aad)
            doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
        }
    } catch (e: Exception) {
        null
    }

    companion object {
        const val KEY_ALIAS = "rasp_shield_prefs_key_v2"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}

/**
 * A small encrypted key-value store (F-24), replacing androidx.security's
 * EncryptedSharedPreferences, which is deprecated upstream.
 *
 * - Values are encrypted with [cipher] (production: [RaspKeystoreValueCipher],
 *   AES-256-GCM with a Keystore key) and stored Base64 in an ordinary
 *   app-private SharedPreferences file; the key name is the GCM associated
 *   data, so a value copied to another key does not decrypt. Key names are
 *   not secret and stay readable.
 * - Writes use `commit()`: a counter is on disk before it is used.
 * - A value that does not decrypt (changed file, lost Keystore key) reads as
 *   absent; for the envelope counter the caller treats that as an error.
 * - [legacy]: the store this one replaces. On first use its entries are
 *   copied once, then it is cleared, so existing installs keep their
 *   credential, registration and counter.
 */
internal class RaspSecurePrefs(
    private val prefs: SharedPreferences,
    private val cipher: RaspValueCipher,
    private val legacy: (() -> SharedPreferences?)? = null,
) {
    @Volatile private var migrated = false

    private fun aad(key: String) = "rasp-prefs-v2:$key".toByteArray(Charsets.UTF_8)

    @Synchronized
    private fun migrateOnce() {
        if (migrated) return
        migrated = true
        if (prefs.getBoolean(MIGRATED_FLAG, false) || legacy == null) return
        val old = try { legacy.invoke() } catch (e: Exception) { null }
        val editor = prefs.edit()
        old?.all?.forEach { (key, value) ->
            val text = when (value) {
                is String -> value
                is Long, is Int, is Boolean -> value.toString()
                else -> null
            } ?: return@forEach
            encode(key, text)?.let { editor.putString(key, it) }
        }
        editor.putBoolean(MIGRATED_FLAG, true)
        if (editor.commit()) {
            try { old?.edit()?.clear()?.commit() } catch (e: Exception) { /* best effort */ }
        }
    }

    private fun encode(key: String, value: String): String? =
        cipher.encrypt(value.toByteArray(Charsets.UTF_8), aad(key))?.let { RaspBase64.encode(it) }

    fun getString(key: String): String? {
        migrateOnce()
        val stored = prefs.getString(key, null) ?: return null
        val blob = RaspBase64.decode(stored) ?: return null
        return cipher.decrypt(blob, aad(key))?.toString(Charsets.UTF_8)
    }

    /** `true` once written to disk. */
    fun putString(key: String, value: String): Boolean {
        migrateOnce()
        val encoded = encode(key, value) ?: return false
        return prefs.edit().putString(key, encoded).commit()
    }

    /** Several values in one `commit()`: all or none are written. */
    fun putAll(values: Map<String, String>): Boolean {
        migrateOnce()
        val editor = prefs.edit()
        for ((key, value) in values) editor.putString(key, encode(key, value) ?: return false)
        return editor.commit()
    }

    fun contains(key: String): Boolean {
        migrateOnce()
        return prefs.contains(key)
    }

    /** Every stored key. */
    fun keys(): Set<String> {
        migrateOnce()
        return prefs.all.keys.filterTo(mutableSetOf()) { it != MIGRATED_FLAG }
    }

    /** Removes every value (the migration stays done). */
    fun clear(): Boolean {
        migrateOnce()
        return prefs.edit().clear().putBoolean(MIGRATED_FLAG, true).commit()
    }

    fun remove(vararg keys: String): Boolean {
        migrateOnce()
        val editor = prefs.edit()
        keys.forEach { editor.remove(it) }
        return editor.commit()
    }

    companion object {
        private const val MIGRATED_FLAG = "__migrated_from_encrypted_prefs"

        /**
         * Production store `<name>_v2` for the app, migrating from the
         * EncryptedSharedPreferences file [legacyName] (same name as before).
         */
        @Suppress("DEPRECATION")
        fun open(context: Context, legacyName: String): RaspSecurePrefs {
            val app = context.applicationContext ?: context
            return RaspSecurePrefs(
                app.getSharedPreferences("${legacyName}_v2", Context.MODE_PRIVATE),
                RaspKeystoreValueCipher(),
                legacy = {
                    if (!app.getSharedPreferencesFile(legacyName)) null
                    else EncryptedSharedPreferences.create(
                        app,
                        legacyName,
                        MasterKey.Builder(app).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
                        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
                    )
                },
            )
        }

        private fun Context.getSharedPreferencesFile(name: String): Boolean =
            java.io.File(applicationInfo.dataDir, "shared_prefs/$name.xml").exists()
    }
}
