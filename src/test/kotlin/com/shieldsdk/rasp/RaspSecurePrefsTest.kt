package com.shieldsdk.rasp

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * The Keystore-backed encrypted store that replaces EncryptedSharedPreferences (F-24).
 *
 * Real: RaspSecurePrefs (encoding, key binding, migration, multi-key writes),
 * AES-256-GCM from the JDK.
 * Doubles: [MemoryPrefs] for SharedPreferences and [SoftwareCipher] for the
 * Android Keystore key (same algorithm, key in memory). Not exercised: the
 * Keystore itself and reading an EncryptedSharedPreferences file (device only;
 * phone test plan).
 */
class RaspSecurePrefsTest {

    class MemoryPrefs(initial: Map<String, Any?> = emptyMap()) : SharedPreferences {
        val values = linkedMapOf<String, Any?>().apply { putAll(initial) }
        var commits = 0
        override fun getAll(): MutableMap<String, *> = LinkedHashMap(values)
        override fun getString(key: String?, defValue: String?) = values[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?) = defValues
        override fun getInt(key: String?, defValue: Int) = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long) = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float) = values[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean) = values[key] as? Boolean ?: defValue
        override fun contains(key: String?) = values.containsKey(key)
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            val puts = linkedMapOf<String, Any?>()
            val removes = mutableSetOf<String>()
            var clear = false
            override fun putString(key: String, value: String?) = apply { puts[key] = value }
            override fun putStringSet(key: String, values: MutableSet<String>?) = apply { puts[key] = values }
            override fun putInt(key: String, value: Int) = apply { puts[key] = value }
            override fun putLong(key: String, value: Long) = apply { puts[key] = value }
            override fun putFloat(key: String, value: Float) = apply { puts[key] = value }
            override fun putBoolean(key: String, value: Boolean) = apply { puts[key] = value }
            override fun remove(key: String) = apply { removes += key }
            override fun clear() = apply { clear = true }
            override fun commit(): Boolean {
                if (clear) values.clear()
                removes.forEach { values.remove(it) }
                values.putAll(puts)
                commits++
                return true
            }
            override fun apply() { commit() }
        }
    }

    class SoftwareCipher : RaspValueCipher {
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        override fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray? {
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key); updateAAD(aad) }
            return c.iv + c.doFinal(plain)
        }
        override fun decrypt(blob: ByteArray, aad: ByteArray): ByteArray? = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, 12))
                updateAAD(aad)
                doFinal(blob, 12, blob.size - 12)
            }
        } catch (e: Exception) {
            null
        }
    }

    private val cipher = SoftwareCipher()

    @Test fun `values round-trip and are not stored in clear text`() {
        val file = MemoryPrefs()
        val store = RaspSecurePrefs(file, cipher)
        assertTrue(store.putString("rasp_shield_ingestion_credential", """{"api_secret":"s3cr3t"}"""))
        assertEquals("""{"api_secret":"s3cr3t"}""", store.getString("rasp_shield_ingestion_credential"))
        assertFalse((file.values["rasp_shield_ingestion_credential"] as String).contains("s3cr3t"))
        assertNull(store.getString("missing"))
    }

    @Test fun `a changed value or a value moved to another key does not decrypt`() {
        val file = MemoryPrefs()
        val store = RaspSecurePrefs(file, cipher)
        store.putString("monotonic_counter", "41")
        val blob = file.values["monotonic_counter"] as String
        file.values["registered_key_id"] = blob
        assertNull("bound to its key name", store.getString("registered_key_id"))
        val bytes = RaspBase64.decode(blob)!!.also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        file.values["monotonic_counter"] = RaspBase64.encode(bytes)
        assertNull("tampered", store.getString("monotonic_counter"))
        assertTrue("still present, so callers can tell 'unreadable' from 'absent'", store.contains("monotonic_counter"))
    }

    @Test fun `entries of the old store are migrated once, then the old store is cleared`() {
        val old = MemoryPrefs(mapOf("registered_key_id" to "key-1", "monotonic_counter" to 41L, "registration_version" to 2))
        var opened = 0
        val file = MemoryPrefs()
        val store = RaspSecurePrefs(file, cipher, legacy = { opened++; old })
        assertEquals("key-1", store.getString("registered_key_id"))
        assertEquals("41", store.getString("monotonic_counter"))
        assertEquals("2", store.getString("registration_version"))
        assertTrue("old store cleared", old.values.isEmpty())
        // A new instance on the same file does not migrate again.
        RaspSecurePrefs(file, cipher, legacy = { opened++; old }).getString("registered_key_id")
        assertEquals(1, opened)
    }

    @Test fun `putAll writes every value in one commit, keys and clear`() {
        val file = MemoryPrefs()
        val store = RaspSecurePrefs(file, cipher)
        store.getString("x") // run the (empty) migration first
        val before = file.commits
        assertTrue(store.putAll(mapOf("hash" to "h", "sim_count" to "2", "changed_at" to "-1")))
        assertEquals(before + 1, file.commits)
        assertEquals(setOf("hash", "sim_count", "changed_at"), store.keys())
        assertTrue(store.remove("hash", "sim_count"))
        assertEquals(setOf("changed_at"), store.keys())
        assertTrue(store.clear())
        assertTrue(store.keys().isEmpty())
    }

    @Test fun `a cipher failure is a failed write, never a clear-text fallback`() {
        val failing = object : RaspValueCipher {
            override fun encrypt(plain: ByteArray, aad: ByteArray): ByteArray? = null
            override fun decrypt(blob: ByteArray, aad: ByteArray): ByteArray? = null
        }
        val file = MemoryPrefs()
        val store = RaspSecurePrefs(file, failing)
        assertFalse(store.putString("k", "v"))
        assertFalse(store.putAll(mapOf("a" to "1")))
        assertFalse(file.values.containsKey("k"))
    }
}
