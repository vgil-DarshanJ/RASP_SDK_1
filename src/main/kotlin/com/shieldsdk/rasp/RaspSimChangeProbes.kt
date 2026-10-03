package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * `sim_change` — has the set of active SIMs changed since the app last saw it?
 * (SIM-swap fraud: an attacker moves the victim's number to a new SIM to
 * receive OTPs.)
 *
 * Reads, per active subscription, only: Android's subscription id (assigned
 * per SIM card and kept for that card), carrier id and MCC+MNC. Never the
 * phone number, IMEI or ICCID (the ICCID is not readable by normal apps on
 * Android 10+ anyway). These are hashed with a random per-install salt
 * (SHA-256); only the hash is stored, in EncryptedSharedPreferences, and
 * nothing SIM-related is uploaded beyond SIM counts and the change time.
 *
 * - No READ_PHONE_STATE → UNAVAILABLE.
 * - First run (no baseline stored yet) → the baseline is stored, UNKNOWN with
 *   reason "baseline stored" (never SECURE).
 * - Fingerprint differs → DETECTED; it stays DETECTED (across restarts) until
 *   the host calls [acknowledgeChange] — e.g. after re-verifying the customer.
 * - Same fingerprint, nothing pending → SECURE.
 * - Stored baseline cannot be read → ERROR (it is not replaced by a new one).
 *
 * [resetBaseline] forgets the baseline, for testing only: it is refused unless
 * the app is a debuggable build.
 */
object RaspSimChangeProbes {

    const val DETECTOR_ID = "sim_change"
    const val PERMISSION = "android.permission.READ_PHONE_STATE"

    /** One active SIM, without personal identifiers. */
    data class SimIdentity(val subscriptionId: Int, val carrierId: Int, val mccMnc: String?)

    data class Baseline(val hash: String, val simCount: Int, val changeDetectedAtMillis: Long?)

    /** Persistent state. Production: [EncryptedStore]. */
    interface Store {
        /** The per-install salt, created on first use; `null` if storage is unavailable. */
        fun salt(): ByteArray?
        /** `null` when no baseline is stored yet; throws when storage cannot be read. */
        fun load(): Baseline?
        /** `true` once written. */
        fun save(baseline: Baseline): Boolean
        /** Removes the baseline (the salt stays). `true` once removed. */
        fun clear(): Boolean
    }

    const val REASON_BASELINE_STORED = "baseline stored"

    data class Observation(
        val permissionGranted: Boolean,
        /** Active SIMs (empty = none); `null` when they could not be read. */
        val sims: List<SimIdentity>?,
    )

    fun fingerprint(salt: ByteArray, sims: List<SimIdentity>): String {
        val canonical = sims.sortedBy { it.subscriptionId }
            .joinToString(";") { "${it.subscriptionId}:${it.carrierId}:${it.mccMnc ?: ""}" }
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(salt)
            update(canonical.toByteArray(Charsets.UTF_8))
        }.digest()
        return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    fun evaluate(o: Observation, store: Store, nowMillis: Long): RaspCheckResult {
        if (!o.permissionGranted) {
            return RaspCheckResult.unavailable(DETECTOR_ID, "$PERMISSION not granted to the host app")
        }
        val sims = o.sims ?: return RaspCheckResult(
            DETECTOR_ID, RaspCheckStatus.UNKNOWN, reason = "Active SIMs could not be read",
        )
        val salt = store.salt() ?: return RaspCheckResult.error(DETECTOR_ID, "Secure storage unavailable")
        val hash = fingerprint(salt, sims)
        val previous = try {
            store.load()
        } catch (e: Exception) {
            // Never treat an unreadable baseline as a first run: storing a new
            // one would hide a SIM change.
            return RaspCheckResult.error(DETECTOR_ID, "Could not read SIM baseline")
        }

        if (previous == null) {
            if (!store.save(Baseline(hash, sims.size, null))) {
                return RaspCheckResult.error(DETECTOR_ID, "Could not store SIM baseline")
            }
            return RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, listOf(RaspEvidence("sim_count", sims.size)),
                reason = REASON_BASELINE_STORED,
            )
        }
        if (previous.hash != hash) {
            store.save(Baseline(hash, sims.size, nowMillis))
            return RaspCheckResult.detected(
                DETECTOR_ID,
                listOf(
                    RaspEvidence("previous_sim_count", previous.simCount),
                    RaspEvidence("sim_count", sims.size),
                    RaspEvidence("changed_at_millis", nowMillis),
                ),
            )
        }
        previous.changeDetectedAtMillis?.let { changedAt ->
            return RaspCheckResult.detected(
                DETECTOR_ID,
                listOf(
                    RaspEvidence("sim_count", sims.size),
                    RaspEvidence("changed_at_millis", changedAt),
                    RaspEvidence("acknowledged", false),
                ),
            )
        }
        return RaspCheckResult.secure(DETECTOR_ID, listOf(RaspEvidence("sim_count", sims.size)))
    }

    /** Accepts the current SIMs as the new baseline. `false` if nothing was pending or storage failed. */
    fun acknowledgeChange(store: Store): Boolean {
        val current = try { store.load() } catch (e: Exception) { null } ?: return false
        if (current.changeDetectedAtMillis == null) return false
        return store.save(current.copy(changeDetectedAtMillis = null))
    }

    /**
     * Forgets the stored baseline, so the next run stores a new one and reports
     * UNKNOWN "baseline stored". For testing only: refused (returns `false`,
     * nothing changed) unless [debuggableBuild]. Production apps accept a new
     * SIM with [acknowledgeChange] instead.
     */
    fun resetBaseline(store: Store, debuggableBuild: Boolean): Boolean =
        debuggableBuild && store.clear()

    fun observe(context: Context): Observation {
        if (context.checkSelfPermission(PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            return Observation(false, null)
        }
        return Observation(true, readSims(context))
    }

    @Suppress("DEPRECATION")
    private fun readSims(context: Context): List<SimIdentity>? = try {
        val manager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
        (manager.activeSubscriptionInfoList ?: emptyList()).map { info ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                SimIdentity(info.subscriptionId, info.carrierId, "${info.mccString ?: ""}${info.mncString ?: ""}")
            } else {
                SimIdentity(info.subscriptionId, -1, "${info.mcc}${info.mnc}")
            }
        }
    } catch (e: Exception) {
        null
    }

    /** EncryptedSharedPreferences-backed [Store]; writes use `commit()`. */
    class EncryptedStore(context: Context) : Store {
        private val appContext = context.applicationContext ?: context
        private val prefs by lazy {
            EncryptedSharedPreferences.create(
                appContext,
                "rasp_sim_state",
                MasterKey.Builder(appContext).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        }

        override fun salt(): ByteArray? = try {
            synchronized(LOCK) {
                prefs.getString("salt", null)?.let { RaspBase64.decode(it) } ?: run {
                    val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
                    if (prefs.edit().putString("salt", RaspBase64.encode(salt)).commit()) salt else null
                }
            }
        } catch (e: Exception) {
            null
        }

        /** Throws when the encrypted preferences cannot be read (see [Store.load]). */
        override fun load(): Baseline? =
            prefs.getString("hash", null)?.let { hash ->
                Baseline(
                    hash,
                    prefs.getInt("sim_count", 0),
                    prefs.getLong("changed_at", -1L).takeIf { it >= 0 },
                )
            }

        override fun clear(): Boolean = try {
            prefs.edit().remove("hash").remove("sim_count").remove("changed_at").commit()
        } catch (e: Exception) {
            false
        }

        override fun save(baseline: Baseline): Boolean = try {
            prefs.edit()
                .putString("hash", baseline.hash)
                .putInt("sim_count", baseline.simCount)
                .putLong("changed_at", baseline.changeDetectedAtMillis ?: -1L)
                .commit()
        } catch (e: Exception) {
            false
        }

        private companion object { val LOCK = Any() }
    }
}
