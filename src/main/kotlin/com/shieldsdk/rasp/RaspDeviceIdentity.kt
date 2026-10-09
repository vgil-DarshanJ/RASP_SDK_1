package com.shieldsdk.rasp

import android.content.Context
import android.provider.Settings
import java.security.MessageDigest

/**
 * A stable device id the backend can use to recognise a reinstall (F-15),
 * without receiving ANDROID_ID itself.
 *
 * ANDROID_ID (Android 8+) is per device, per user and per app-signing key,
 * and survives uninstall/reinstall, while the device key in the Keystore
 * does not. The id sent is:
 * - with the credential's account-hash salt: hex(HMAC-SHA256(salt,
 *   "android_id:" + ANDROID_ID)) — the same scheme as account hashes, so
 *   two applications with different salts cannot link their ids;
 * - without a salt (older credentials): hex(SHA-256("rasp-device-id-v1:" +
 *   packageName + ":" + ANDROID_ID)).
 * `null` when ANDROID_ID cannot be read or is the constant some old builds
 * returned for every device.
 *
 * It identifies the phone for grouping and fraud rules; it is not proof of
 * anything (the device key and its attestation are).
 */
public object RaspDeviceIdentity {
    /** The id older Android builds returned on many devices; useless as an identifier. */
    private const val KNOWN_BROKEN_ANDROID_ID = "9774d56d682e549c"

    @JvmStatic
    public fun deviceId(androidId: String?, packageName: String, accountHashSalt: String?): String? {
        val id = androidId?.trim()?.lowercase()?.takeIf { it.isNotEmpty() && it != KNOWN_BROKEN_ANDROID_ID } ?: return null
        if (accountHashSalt != null && RaspAccountHasher.isValidSalt(accountHashSalt)) {
            return RaspAccountHasher.hash(accountHashSalt, "android_id:$id")
        }
        return MessageDigest.getInstance("SHA-256")
            .digest("rasp-device-id-v1:$packageName:$id".toByteArray(Charsets.UTF_8))
            .toHex()
    }

    /** [deviceId] for this app on this phone. */
    @JvmStatic
    public fun forDevice(context: Context, accountHashSalt: String?): String? {
        val androidId = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        } catch (e: Exception) {
            null
        }
        return deviceId(androidId, context.packageName, accountHashSalt)
    }
}
