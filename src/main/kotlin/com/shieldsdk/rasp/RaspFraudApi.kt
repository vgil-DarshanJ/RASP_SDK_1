package com.shieldsdk.rasp

import java.math.BigDecimal
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.Executors
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Session lifecycle event reported by the host app. */
public enum class RaspSessionEvent {
    LOGIN, RESUME, LOGOUT;

    public val wire: String get() = name.lowercase()

    public companion object {
        @JvmStatic
        public fun fromWire(value: String): RaspSessionEvent? = entries.firstOrNull { it.wire == value }
    }
}

/**
 * Pseudonymous ids → HMAC-SHA256 hashes, keyed with the per-application salt
 * (`account_hash_salt` in the issued credential, or config). Raw ids are
 * hashed immediately and never stored or sent. Same salt and id give the same
 * hash on the device and in the backend; another application's salt gives a
 * different hash, so hashes cannot be joined across applications.
 */
public object RaspAccountHasher {
    public const val MAX_ID_LENGTH: Int = 256
    private val SALT = Regex("^[0-9a-fA-F]{32,128}$")

    @JvmStatic
    public fun isValidSalt(saltHex: String?): Boolean = saltHex != null && saltHex.length % 2 == 0 && SALT.matches(saltHex)

    /** Lowercase hex HMAC-SHA256(key = salt bytes, message = UTF-8 id). */
    @JvmStatic
    public fun hash(saltHex: String, id: String): String {
        require(isValidSalt(saltHex)) { "account hash salt must be 32-128 hex characters" }
        requireValidId(id, "id")
        val key = saltHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
        return mac.doFinal(id.toByteArray(Charsets.UTF_8)).toHex()
    }

    internal fun requireValidId(id: String, name: String) {
        require(id.isNotEmpty() && id.length <= MAX_ID_LENGTH) { "$name must be 1-$MAX_ID_LENGTH characters" }
        require(id.none { it.isISOControl() }) { "$name must not contain control characters" }
    }
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

/**
 * Transaction context binding. [canonical] is
 * `rasp-txn-v1|<amount>|<currency>|<beneficiaryHash>|<nonce>|<timestampMillis>|<counter>`,
 * signed with the device key (SHA256withECDSA, DER, Base64 in
 * [signatureBase64]). The host's server can verify it with the public key
 * registered for [deviceKeyId]. [bindingSha256] (hex SHA-256 of
 * [canonical]) is what goes to the RASP backend — the amount does not.
 */
public data class RaspSignedTransaction(
    val canonical: String,
    val signatureBase64: String,
    val counter: Long,
    val nonce: String,
    val timestampMillis: Long,
    val beneficiaryHash: String,
    val bindingSha256: String,
    val deviceKeyId: String,
    val risk: RaspRiskAssessment,
)

public data class RaspSessionReport(
    val accountHash: String,
    val sessionHash: String,
    val event: RaspSessionEvent,
    val risk: RaspRiskAssessment,
    /** `true` when a signed event was handed to the sender (backend configured). */
    val sentToBackend: Boolean,
)

public data class RaspTransactionReport(
    val transaction: RaspSignedTransaction,
    val channel: String,
    val sentToBackend: Boolean,
)

/**
 * Host-facing session and transaction API (Task 8.1). Opt-in: created only
 * when `RaspLeanConfig.sessionRiskScoring` is on. The SDK recommends
 * ([RaspRiskAssessment.verdict], [RaspRiskAssessment.stepUpRecommended]);
 * the host app decides. Invalid input throws [IllegalArgumentException];
 * a missing salt, missing session or signing failure throws
 * [IllegalStateException].
 */
public class RaspFraudApi internal constructor(
    private val signer: RaspEnvelopeSigner,
    private val counterStore: RaspEnvelopeCounterStore,
    private val appId: String,
    private val saltProvider: () -> String?,
    private val riskProvider: () -> RaspRiskAssessment,
    /** Receives the canonical JSON of a signed risk event; `false` when not sent (no backend configured). */
    private val sender: (String) -> Boolean,
    private val locationProvider: () -> RaspLocationSnapshot? = { null },
    private val sdkVersion: String = BuildConfig.RASP_ENGINE_VERSION,
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: SecureRandom = SecureRandom(),
) {
    @Volatile private var accountHash: String? = null
    @Volatile private var sessionHash: String? = null

    /** The hashed account of the active session, or `null` (never the raw id). */
    public fun currentAccountHash(): String? = accountHash

    @Synchronized
    public fun reportSession(accountId: String, sessionId: String, event: RaspSessionEvent): RaspSessionReport {
        val salt = salt()
        val account = RaspAccountHasher.hash(salt, accountId.also { RaspAccountHasher.requireValidId(it, "accountId") })
        val session = RaspAccountHasher.hash(salt, sessionId.also { RaspAccountHasher.requireValidId(it, "sessionId") })
        val risk = riskProvider()
        val fields = baseFields("session", account, session, risk).apply { put("sessionEvent", event.wire) }
        val sent = sign(fields)?.let(sender) ?: false
        if (event == RaspSessionEvent.LOGOUT) {
            accountHash = null
            sessionHash = null
        } else {
            accountHash = account
            sessionHash = session
        }
        return RaspSessionReport(account, session, event, risk, sent)
    }

    /** Signs the transaction binding only (nothing is sent). Needs an active session. */
    @Synchronized
    public fun signTransaction(amount: String, currency: String, beneficiaryId: String): RaspSignedTransaction {
        val canonicalAmount = canonicalAmount(amount)
        require(CURRENCY.matches(currency)) { "currency must be 3 uppercase letters (ISO 4217)" }
        RaspAccountHasher.requireValidId(beneficiaryId, "beneficiaryId")
        check(accountHash != null) { "no active session: call reportSession(login) first" }
        val beneficiaryHash = RaspAccountHasher.hash(salt(), beneficiaryId)
        val spki = signer.publicKeySpki() ?: throw IllegalStateException("device key unavailable")
        val counter = counterStore.next() ?: throw IllegalStateException("counter could not be persisted")
        val nonce = newNonce()
        val timestamp = clock()
        val canonical = listOf("rasp-txn-v1", canonicalAmount, currency, beneficiaryHash, nonce, timestamp.toString(), counter.toString())
            .joinToString("|")
        val signature = signer.signDer(canonical.toByteArray(Charsets.UTF_8))
            ?: throw IllegalStateException("device key signing failed")
        return RaspSignedTransaction(
            canonical, RaspBase64.encode(signature), counter, nonce, timestamp, beneficiaryHash,
            sha256Hex(canonical), RaspEvidenceEnvelope.deviceKeyId(spki), riskProvider(),
        )
    }

    /** Signs the binding and sends a transaction event (hashes and binding digest, no amount). */
    @Synchronized
    public fun reportTransaction(amount: String, currency: String, beneficiaryId: String, channel: String): RaspTransactionReport {
        require(CHANNEL.matches(channel)) { "channel must match [a-z0-9_-]{1,32}" }
        val signed = signTransaction(amount, currency, beneficiaryId)
        val fields = baseFields("transaction", accountHash!!, sessionHash!!, signed.risk).apply {
            put("beneficiaryHash", signed.beneficiaryHash)
            put("currency", currency)
            put("channel", channel)
            put("bindingSha256", signed.bindingSha256)
        }
        val sent = sign(fields)?.let(sender) ?: false
        return RaspTransactionReport(signed, channel, sent)
    }

    private fun salt(): String = saltProvider()?.takeIf(RaspAccountHasher::isValidSalt)
        ?: throw IllegalStateException("no account hash salt: use a credential with account_hash_salt or set accountHashSalt")

    private fun baseFields(type: String, account: String, session: String, risk: RaspRiskAssessment) = linkedMapOf<String, Any?>(
        "riskEnvelopeVersion" to RISK_ENVELOPE_VERSION,
        "type" to type,
        "eventId" to UUID.randomUUID().toString(),
        "eventTimeMillis" to clock(),
        "nonce" to newNonce(),
        "appId" to appId,
        "sdkVersion" to sdkVersion,
        "accountHash" to account,
        "sessionHash" to session,
        "riskScore" to risk.score,
        "riskVerdict" to risk.verdict.name,
        "location" to locationProvider()?.takeIf { it.shareWithBackend }?.let {
            // Rounded to 3 decimals (~100 m) before it leaves the phone (F-16).
            linkedMapOf<String, Any?>("latitude" to coarseCoordinate(it.latitude), "longitude" to coarseCoordinate(it.longitude), "capturedAtMillis" to it.capturedAtMillis)
        },
        "signatureAlgorithm" to RaspEvidenceEnvelope.SIGNATURE_ALGORITHM,
    )

    /** Adds counter and device key id, signs; `null` when the key, counter or signature is unavailable. */
    private fun sign(fields: MutableMap<String, Any?>): String? {
        val spki = signer.publicKeySpki() ?: return null
        val counter = counterStore.next() ?: return null
        fields["monotonicCounter"] = counter
        fields["deviceKeyId"] = RaspEvidenceEnvelope.deviceKeyId(spki)
        val signature = signer.signDer(RaspEvidenceEnvelope.signingInput(fields)) ?: return null
        return RaspCanonicalJson.encode(fields + ("signature" to RaspBase64.encode(signature)))
    }

    private fun newNonce(): String = ByteArray(16).also { random.nextBytes(it) }.toHex()

    public companion object {
        public const val RISK_ENVELOPE_VERSION: Int = 1
        private val CURRENCY = Regex("^[A-Z]{3}$")
        private val CHANNEL = Regex("^[a-z0-9_-]{1,32}$")
        private val AMOUNT = Regex("^[0-9]{1,15}(\\.[0-9]{1,6})?$")

        /** `"0100.50"` → `"100.5"`; positive plain decimals only. */
        @JvmStatic
        public fun canonicalAmount(amount: String): String {
            require(AMOUNT.matches(amount)) { "amount must be a plain positive decimal (up to 15 digits, 6 decimals)" }
            val value = BigDecimal(amount)
            require(value.signum() > 0) { "amount must be positive" }
            return value.stripTrailingZeros().toPlainString()
        }

        @JvmStatic
        public fun sha256Hex(text: String): String =
            MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).toHex()
    }
}

/**
 * Sends signed risk events to `POST /v1/risk/events` (same host as the
 * ingestion URL) with `X-Api-Key`; the event carries its own device
 * signature. Registers the device key first. Best effort: up to
 * [MAX_ATTEMPTS] tries on network errors, 5xx and 429; a 401 registers again
 * and retries once; other answers drop the event. No offline queue — a risk
 * event is about the moment it was raised.
 */
public class RaspRiskEventDelivery(
    private val credentialProvider: () -> RaspEventCredential?,
    private val registrar: RaspDeviceRegistrar,
    private val http: RaspHttpPost = RaspHttpPost.URL_CONNECTION,
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
) {
    public enum class Outcome { DELIVERED, DROPPED, NOT_CONFIGURED, FAILED }

    @Volatile public var lastOutcome: Outcome? = null
        private set

    private val executor = Executors.newSingleThreadExecutor { Thread(it, "RaspRiskEvents").apply { isDaemon = true } }

    /** `false` when no backend is configured (nothing will be sent). */
    public fun sendAsync(eventJson: String): Boolean {
        if (credentialProvider() == null) return false
        executor.execute { lastOutcome = deliver(eventJson) }
        return true
    }

    public fun deliver(eventJson: String): Outcome {
        val credential = credentialProvider() ?: return Outcome.NOT_CONFIGURED
        val url = RaspBackendUrls.endpoint(credential.ingestionUrl, "risk/events") ?: return Outcome.DROPPED
        var reRegistered = false
        var attempt = 0
        while (attempt < MAX_ATTEMPTS) {
            attempt++
            if (registrar.ensureRegistered(credential) != RaspDeviceRegistrar.Result.REGISTERED) {
                sleep(BACKOFF_MS * attempt)
                continue
            }
            val status = http.post(
                url,
                mapOf("Content-Type" to "application/json", "X-Api-Key" to credential.apiKey),
                eventJson.toByteArray(Charsets.UTF_8),
            )
            when {
                status in 200..299 -> return Outcome.DELIVERED
                status == 401 && !reRegistered -> {
                    reRegistered = true
                    registrar.invalidate()
                    attempt--
                }
                status == -1 || status == 429 || status in 500..599 -> sleep(BACKOFF_MS * attempt)
                else -> return Outcome.DROPPED
            }
        }
        return Outcome.FAILED
    }

    public companion object {
        public const val MAX_ATTEMPTS: Int = 3
        public const val BACKOFF_MS: Long = 2_000
    }
}
