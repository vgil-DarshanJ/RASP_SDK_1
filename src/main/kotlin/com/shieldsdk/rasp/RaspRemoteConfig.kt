package com.shieldsdk.rasp

import java.net.HttpURLConnection
import java.net.URL
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * Signed remote configuration (Task 10.0): the backend can change a few
 * settings of a running app (detector switches inside the app's own ceiling,
 * intervals within hard bounds, risk thresholds, the high-risk mode, the
 * reputation-list refresh interval) without a new release.
 *
 * ## Trust
 * The config comes from `GET /v1/config` as
 * `{ "payload": "<JSON text>", "signature": "<Base64 Ed25519>", "keyId": "..." }`,
 * the same envelope as the malware reputation list. It is accepted only when:
 * 1. the Ed25519 signature over the exact payload bytes verifies with the
 *    app-pinned [RaspLeanConfig.remoteConfigPublicKey], else the credential's
 *    `config_public_key` ([RaspEventCredential.configPublicKey]);
 * 2. `applicationId` is this credential's application (a config of another
 *    app, signed by the same server, is refused);
 * 3. `expiresAt` is in the future;
 * 4. `version` is higher than the last accepted one (rollback protection;
 *    the same version with the same payload is "unchanged", not an attack);
 * 5. every field is known and inside the bounds below (checked again here,
 *    whatever the server did). Unknown fields are refused, not ignored.
 *
 * A refused config is reported as the result `remote_config_rejected`
 * (DETECTED, reason `bad_signature` | `rollback` | `expired` | `invalid`) and
 * changes nothing: the last good config stays, or, without one, the app's own
 * [RaspLeanConfig].
 *
 * ## What it can never change
 * The ingestion URL, the credential, device-key and envelope settings, TLS
 * pins and their enforcement, request signing, screenshot/clipboard
 * protection, and any detector outside [RaspLeanConfig.remoteManagedDetectors]
 * (default: none). Those fields do not exist in the payload format.
 */
public object RaspRemoteConfig {
    public const val DETECTOR_ID: String = "remote_config_rejected"
    public const val SCHEMA: Long = 1

    /** Detector ids a remote config may switch; the app's ceiling narrows it further. Same list as the backend. */
    public val MANAGEABLE_DETECTORS: Set<String> = linkedSetOf(
        "usb_connection", "adb_enabled", "screenshot_event",
        "root_jailbreak", "emulator", "device_binding", "clone", "developer_mode", "device_lock_missing",
        "secure_hardware_unavailable", "device_fingerprint",
        "frida", "debugger", "re_tools", "hook_detection", "risky_app",
        "tamper", "untrusted_install_source", "repackage",
        "vpn", "mitm", "high_risk_ip",
        "overlay", "accessibility", "external_display",
        "mock_location", "time_spoofing", "unsafe_wifi", "screen_recording",
        "vishing_call", "sim_change", "third_party_keyboard", "task_hijack",
        "device_state_attestation", "malware_reputation",
        "otp_interception_risk", "sms_reader_abuse", "otp_forwarding_risk", "remote_control_app", "screen_sharing_risk",
    )

    /** Hard bounds, inclusive (same as the backend's REMOTE_CONFIG_BOUNDS). */
    public val POLL_SECONDS: IntRange = 2..60
    public val HEARTBEAT_SECONDS: IntRange = 10..300
    public val LOCATION_HEARTBEAT_SECONDS: IntRange = 30..600
    public val RISK_THRESHOLD: IntRange = 1..100
    public val REPUTATION_REFRESH_HOURS: IntRange = 1..168
    public const val MAX_COUNTRIES: Int = 250
    /** Bounds of [RaspLeanConfig.remoteConfigPollMinutes]. */
    public val POLL_MINUTES: IntRange = 5..1440

    private val TOP_LEVEL = setOf("schema", "applicationId", "version", "issuedAt", "expiresAt", "settings")

    public enum class Reason(public val wire: String) {
        BAD_SIGNATURE("bad_signature"), ROLLBACK("rollback"), EXPIRED("expired"), INVALID("invalid"),
    }

    /** The settings a config carries; `null` = keep the app's own value. */
    public data class Settings(
        val detectors: Map<String, Boolean> = emptyMap(),
        val pollIntervalSeconds: Int? = null,
        val heartbeatIntervalSeconds: Int? = null,
        val locationHeartbeatIntervalSeconds: Int? = null,
        val riskMediumThreshold: Int? = null,
        val riskHighThreshold: Int? = null,
        /** `true` when the config sets [stepUpThreshold] (which may be null = only at HIGH). */
        val stepUpThresholdSet: Boolean = false,
        val stepUpThreshold: Int? = null,
        val highRiskTransactionMode: Boolean? = null,
        /** Applied by the backend's IP-risk check; kept here as evidence only. */
        val allowedCountries: List<String>? = null,
        val blockedCountries: List<String>? = null,
        val reputationRefreshHours: Int? = null,
    )

    public data class Accepted(
        val version: Long,
        val applicationId: String,
        val expiresAtMillis: Long,
        val settings: Settings,
        /** The signed JSON exactly as received (what is stored). */
        val signedJson: String,
        val payload: String,
        /** Detectors the config wanted to switch but the app's ceiling does not allow. */
        val ignoredDetectors: List<String>,
        /** The app's config with these settings applied. */
        val effective: RaspLeanConfig,
    )

    public sealed class Verdict {
        public data class Ok(val config: Accepted) : Verdict()
        /** Same version and payload as the last accepted config. */
        public object Unchanged : Verdict()
        public data class Rejected(val reason: Reason, val detail: String, val version: Long? = null) : Verdict()
    }

    /**
     * Checks [signedJson] (see the class doc for the rules). Pure: no
     * Android, network or disk. [local] is the app's own config, which the
     * settings are applied to; [lastVersion]/[lastPayload] describe the last
     * accepted config (null when none).
     */
    public fun verify(
        signedJson: String,
        publicKeyBase64: String,
        applicationId: String,
        local: RaspLeanConfig,
        lastVersion: Long?,
        lastPayload: String?,
        nowMillis: Long,
    ): Verdict {
        val key = RaspBase64.decode(publicKeyBase64.trim())?.let { RaspEd25519.rawPublicKey(it) }
            ?: return Verdict.Rejected(Reason.INVALID, "Config public key is not a Base64 Ed25519 key")
        val outer = parseObject(signedJson) ?: return Verdict.Rejected(Reason.INVALID, "Config is not a JSON object")
        val payload = outer["payload"] as? String ?: return Verdict.Rejected(Reason.INVALID, "Config has no payload")
        val signature = (outer["signature"] as? String)?.let { RaspBase64.decode(it) }
            ?: return Verdict.Rejected(Reason.BAD_SIGNATURE, "Config has no valid signature field")
        if (!RaspEd25519.verify(key, payload.toByteArray(Charsets.UTF_8), signature)) {
            return Verdict.Rejected(Reason.BAD_SIGNATURE, "Config signature does not verify")
        }

        val body = parseObject(payload) ?: return Verdict.Rejected(Reason.INVALID, "Payload is not a JSON object")
        val version = (body["version"] as? Long)?.takeIf { it >= 1 }
        val unknown = body.keys.filterNot { it in TOP_LEVEL }
        if (unknown.isNotEmpty()) return Verdict.Rejected(Reason.INVALID, "Unknown payload fields: ${unknown.sorted()}", version)
        if (body["schema"] != SCHEMA) return Verdict.Rejected(Reason.INVALID, "Unsupported config schema", version)
        if (version == null) return Verdict.Rejected(Reason.INVALID, "Config has no valid version")
        if (body["applicationId"] != applicationId) return Verdict.Rejected(Reason.INVALID, "Config is for another application", version)
        val expiresAt = (body["expiresAt"] as? String)?.let(::parseIso)
            ?: return Verdict.Rejected(Reason.INVALID, "Config has no valid expiresAt", version)
        if ((body["issuedAt"] as? String)?.let(::parseIso) == null) return Verdict.Rejected(Reason.INVALID, "Config has no valid issuedAt", version)
        if (expiresAt <= nowMillis) return Verdict.Rejected(Reason.EXPIRED, "Config expired", version)
        if (lastVersion != null) {
            if (version == lastVersion && payload == lastPayload) return Verdict.Unchanged
            if (version <= lastVersion) return Verdict.Rejected(Reason.ROLLBACK, "Version $version is not above $lastVersion", version)
        }

        val settings = when (val s = parseSettings(body["settings"])) {
            is SettingsParse.Ok -> s.settings
            is SettingsParse.Bad -> return Verdict.Rejected(Reason.INVALID, s.detail, version)
        }
        val ignored = settings.detectors.keys.filterNot { it in local.remoteManagedDetectors }.sorted()
        val effective = apply(local, settings)
        try {
            RaspRiskPolicy(effective.riskMediumThreshold, effective.riskHighThreshold, effective.stepUpThreshold)
        } catch (e: IllegalArgumentException) {
            return Verdict.Rejected(Reason.INVALID, "Risk thresholds would be inconsistent with the app's own", version)
        }
        return Verdict.Ok(Accepted(version, applicationId, expiresAt, settings, signedJson, payload, ignored, effective))
    }

    /**
     * [local] with [settings] applied. Detectors only inside
     * [RaspLeanConfig.remoteManagedDetectors]; everything else the payload
     * cannot express stays as the app set it.
     */
    public fun apply(local: RaspLeanConfig, settings: Settings): RaspLeanConfig {
        var c = local
        for ((id, on) in settings.detectors) {
            if (id in local.remoteManagedDetectors) c = withDetector(c, id, on)
        }
        settings.pollIntervalSeconds?.let { c = c.copy(pollIntervalMillis = it * 1000L) }
        settings.heartbeatIntervalSeconds?.let { c = c.copy(heartbeatIntervalMillis = it * 1000L) }
        settings.locationHeartbeatIntervalSeconds?.let { c = c.copy(locationHeartbeatIntervalMillis = it * 1000L) }
        settings.riskMediumThreshold?.let { c = c.copy(riskMediumThreshold = it) }
        settings.riskHighThreshold?.let { c = c.copy(riskHighThreshold = it) }
        if (settings.stepUpThresholdSet) c = c.copy(stepUpThreshold = settings.stepUpThreshold)
        settings.highRiskTransactionMode?.let { c = c.copy(highRiskTransactionMode = it) }
        settings.reputationRefreshHours?.let { c = c.copy(malwareReputationRefreshHours = it) }
        return c
    }

    /** One detector switch; ids outside [MANAGEABLE_DETECTORS] change nothing. */
    internal fun withDetector(c: RaspLeanConfig, id: String, on: Boolean): RaspLeanConfig = when (id) {
        "usb_connection" -> c.copy(usbDetection = on)
        "adb_enabled" -> c.copy(adbDetection = on)
        "screenshot_event" -> c.copy(screenshotEventDetection = on)
        "root_jailbreak" -> c.copy(rootDetection = on)
        "emulator" -> c.copy(emulatorDetection = on)
        "device_binding" -> c.copy(deviceBindingCheck = on)
        "clone" -> c.copy(cloneDetection = on)
        "developer_mode" -> c.copy(developerModeDetection = on)
        "device_lock_missing" -> c.copy(deviceLockCheck = on)
        "secure_hardware_unavailable" -> c.copy(secureHardwareCheck = on)
        "device_fingerprint" -> c.copy(deviceFingerprintCheck = on)
        "frida" -> c.copy(fridaDetection = on)
        "debugger" -> c.copy(debuggerDetection = on)
        "re_tools" -> c.copy(reverseEngineeringToolsDetection = on)
        "hook_detection" -> c.copy(hookDetection = on)
        "risky_app" -> c.copy(riskyAppDetection = on)
        "tamper" -> c.copy(tamperDetection = on)
        "untrusted_install_source" -> c.copy(untrustedInstallSourceDetection = on)
        "repackage" -> c.copy(repackagingDetection = on)
        "vpn" -> c.copy(vpnDetection = on)
        "mitm" -> c.copy(mitmDetection = on)
        "high_risk_ip" -> c.copy(highRiskIpDetection = on)
        "overlay" -> c.copy(overlayDetection = on)
        "accessibility" -> c.copy(accessibilityDetection = on)
        "external_display" -> c.copy(externalDisplayDetection = on)
        "mock_location" -> c.copy(mockLocationDetection = on)
        "time_spoofing" -> c.copy(timeSpoofingDetection = on)
        "unsafe_wifi" -> c.copy(unsafeWifiDetection = on)
        "screen_recording" -> c.copy(screenRecordingDetection = on)
        "vishing_call" -> c.copy(vishingCallDetection = on)
        "sim_change" -> c.copy(simChangeDetection = on)
        "third_party_keyboard" -> c.copy(thirdPartyKeyboardDetection = on)
        "task_hijack" -> c.copy(taskHijackDetection = on)
        "device_state_attestation" -> c.copy(deviceStateAttestationDetection = on)
        "malware_reputation" -> c.copy(malwareReputationDetection = on)
        "otp_interception_risk" -> c.copy(otpInterceptionDetection = on)
        "sms_reader_abuse" -> c.copy(smsReaderAbuseDetection = on)
        "otp_forwarding_risk" -> c.copy(otpForwardingDetection = on)
        "remote_control_app" -> c.copy(remoteControlAppDetection = on)
        "screen_sharing_risk" -> c.copy(screenSharingDetection = on)
        else -> c
    }

    private sealed class SettingsParse {
        data class Ok(val settings: Settings) : SettingsParse()
        data class Bad(val detail: String) : SettingsParse()
    }

    private val SETTING_KEYS = setOf(
        "detectors", "pollIntervalSeconds", "heartbeatIntervalSeconds", "locationHeartbeatIntervalSeconds",
        "riskMediumThreshold", "riskHighThreshold", "stepUpThreshold", "highRiskTransactionMode",
        "allowedCountries", "blockedCountries", "reputationRefreshHours",
    )
    private val COUNTRY = Regex("^[A-Z]{2}$")

    private fun parseSettings(value: Any?): SettingsParse {
        val map = value as? Map<*, *> ?: return SettingsParse.Bad("Config has no settings object")
        val unknown = map.keys.map { it.toString() }.filterNot { it in SETTING_KEYS }
        if (unknown.isNotEmpty()) return SettingsParse.Bad("Unknown settings: ${unknown.sorted()}")

        fun int(name: String, range: IntRange): Pair<Int?, String?> {
            if (!map.containsKey(name)) return null to null
            val n = map[name] as? Long ?: return null to "$name must be an integer"
            if (n !in range.first.toLong()..range.last.toLong()) return null to "$name must be within ${range.first}..${range.last}"
            return n.toInt() to null
        }
        fun countries(name: String): Pair<List<String>?, String?> {
            if (!map.containsKey(name)) return null to null
            val list = map[name] as? List<*> ?: return null to "$name must be a list"
            if (list.size > MAX_COUNTRIES) return null to "$name has more than $MAX_COUNTRIES entries"
            val codes = list.map { it as? String }
            if (codes.any { it == null || !COUNTRY.matches(it) }) return null to "$name must hold ISO 3166-1 alpha-2 codes"
            return codes.filterNotNull() to null
        }

        val detectors = linkedMapOf<String, Boolean>()
        if (map.containsKey("detectors")) {
            val d = map["detectors"] as? Map<*, *> ?: return SettingsParse.Bad("detectors must be an object")
            for ((k, v) in d) {
                val id = k.toString()
                if (id !in MANAGEABLE_DETECTORS) return SettingsParse.Bad("Detector $id cannot be managed remotely")
                detectors[id] = v as? Boolean ?: return SettingsParse.Bad("detectors.$id must be true or false")
            }
        }
        val (poll, e1) = int("pollIntervalSeconds", POLL_SECONDS)
        val (heartbeat, e2) = int("heartbeatIntervalSeconds", HEARTBEAT_SECONDS)
        val (location, e3) = int("locationHeartbeatIntervalSeconds", LOCATION_HEARTBEAT_SECONDS)
        val (medium, e4) = int("riskMediumThreshold", RISK_THRESHOLD)
        val (high, e5) = int("riskHighThreshold", RISK_THRESHOLD)
        val stepUpSet = map.containsKey("stepUpThreshold")
        val (stepUp, e6) = if (stepUpSet && map["stepUpThreshold"] == null) null to null else int("stepUpThreshold", RISK_THRESHOLD)
        val (reputation, e7) = int("reputationRefreshHours", REPUTATION_REFRESH_HOURS)
        val (allowed, e8) = countries("allowedCountries")
        val (blocked, e9) = countries("blockedCountries")
        listOf(e1, e2, e3, e4, e5, e6, e7, e8, e9).firstOrNull { it != null }?.let { return SettingsParse.Bad(it) }
        val highRisk = if (map.containsKey("highRiskTransactionMode")) {
            map["highRiskTransactionMode"] as? Boolean ?: return SettingsParse.Bad("highRiskTransactionMode must be true or false")
        } else null
        return SettingsParse.Ok(Settings(detectors, poll, heartbeat, location, medium, high, stepUpSet, stepUp, highRisk, allowed, blocked, reputation))
    }

    private fun parseObject(text: String): Map<String, Any?>? = try {
        @Suppress("UNCHECKED_CAST")
        RaspJson.parse(text) as? Map<String, Any?>
    } catch (e: RaspJson.ParseException) {
        null
    }

    /** The backend's `Date.toISOString()` format only; strict. */
    internal fun parseIso(text: String): Long? = try {
        if (!Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$").matches(text)) null
        else SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
            isLenient = false
        }.parse(text)?.time
    } catch (e: ParseException) {
        null
    }
}

/** Where the remote config stands, as shown in [RaspLeanState.remoteConfigStatus]. */
public enum class RaspRemoteConfigStatus {
    /** `remoteConfigEnabled` is off. */
    OFF,
    /** No credential or no config public key: nothing can be verified. */
    UNAVAILABLE,
    /** Nothing received yet (or nothing published); the app's own config applies. */
    WAITING,
    /** A verified config is applied. */
    APPLIED,
    /** The last config received was refused; the last good one (or the app's own) still applies. */
    REJECTED,
    /** The stored config expired; the app's own config applies again. */
    EXPIRED,
}

/**
 * Fetches, verifies, stores and reports the remote config for one session.
 * Network and disk work run on its own daemon thread; [onApplied] receives
 * each new effective config (the session applies it without a restart).
 */
internal class RaspRemoteConfigClient(
    private val local: RaspLeanConfig,
    private val store: Store,
    private val credential: () -> RaspEventCredential?,
    private val deviceKeyId: () -> String?,
    private val onApplied: (RaspLeanConfig) -> Unit,
    private val clock: () -> Long = System::currentTimeMillis,
    private val fetch: (url: String, headers: Map<String, String>) -> RaspHttpResponse = ::httpGet,
) {
    /** The encrypted store for the last accepted signed config. */
    interface Store {
        fun load(): String?
        fun save(signedJson: String): Boolean
        fun clear()
    }

    @Volatile private var accepted: RaspRemoteConfig.Accepted? = null
    @Volatile private var rejection: RaspRemoteConfig.Verdict.Rejected? = null
    @Volatile private var expired = false
    @Volatile private var fetchedOnce = false
    private var executor: ScheduledExecutorService? = null
    private var next: ScheduledFuture<*>? = null

    val status: RaspRemoteConfigStatus
        get() = when {
            !local.remoteConfigEnabled -> RaspRemoteConfigStatus.OFF
            publicKey() == null -> RaspRemoteConfigStatus.UNAVAILABLE
            rejection != null -> RaspRemoteConfigStatus.REJECTED
            accepted != null -> RaspRemoteConfigStatus.APPLIED
            expired -> RaspRemoteConfigStatus.EXPIRED
            else -> RaspRemoteConfigStatus.WAITING
        }

    val version: Long? get() = accepted?.version

    private fun publicKey(): String? =
        local.remoteConfigPublicKey?.takeIf { it.isNotBlank() } ?: credential()?.configPublicKey?.takeIf { it.isNotBlank() }

    /** The last good config from the store, checked again (signature, application, expiry). */
    fun loadCached() {
        val signed = store.load() ?: return
        val key = publicKey() ?: return
        val app = credential()?.applicationId ?: return
        when (val v = RaspRemoteConfig.verify(signed, key, app, local, null, null, clock())) {
            is RaspRemoteConfig.Verdict.Ok -> use(v.config)
            is RaspRemoteConfig.Verdict.Rejected -> {
                // An expired or no-longer-valid stored config is dropped quietly: it was ours.
                store.clear()
                if (v.reason == RaspRemoteConfig.Reason.EXPIRED) expired = true
            }
            RaspRemoteConfig.Verdict.Unchanged -> Unit
        }
    }

    /** Also drops an accepted config once it expires (checked on every fetch and every result). */
    private fun expireIfDue() {
        val current = accepted ?: return
        if (current.expiresAtMillis > clock()) return
        accepted = null
        expired = true
        store.clear()
        onApplied(local)
    }

    /** One fetch and check, on the calling thread. */
    fun refreshNow() {
        expireIfDue()
        val cred = credential() ?: return
        val key = publicKey() ?: return
        val url = RaspBackendUrls.endpoint(cred.ingestionUrl, "config") ?: return
        val headers = linkedMapOf("X-Api-Key" to cred.apiKey, "Accept" to "application/json")
        deviceKeyId()?.let { headers["X-Device-Key-Id"] = it }
        accepted?.let { headers["If-None-Match"] = "\"${it.version}\"" }
        val response = fetch(url, headers)
        fetchedOnce = true
        if (response.status != 200) return // 304 unchanged; 404 none/expired; network or server error: keep what we have
        val body = response.body ?: return
        val current = accepted
        when (val v = RaspRemoteConfig.verify(body, key, cred.applicationId, local, current?.version, current?.payload, clock())) {
            is RaspRemoteConfig.Verdict.Ok -> {
                if (store.save(v.config.signedJson)) use(v.config)
            }
            is RaspRemoteConfig.Verdict.Rejected -> rejection = v
            RaspRemoteConfig.Verdict.Unchanged -> rejection = null
        }
    }

    private fun use(config: RaspRemoteConfig.Accepted) {
        accepted = config
        rejection = null
        expired = false
        onApplied(config.effective)
    }

    /**
     * The `remote_config_rejected` result:
     * - DETECTED: the last config received was refused (reason in evidence);
     * - SECURE: a verified config is applied;
     * - UNAVAILABLE: no credential or no config public key;
     * - UNKNOWN: nothing received yet, nothing published, or the stored one expired.
     */
    fun result(): RaspCheckResult {
        expireIfDue()
        val id = RaspRemoteConfig.DETECTOR_ID
        if (credential() == null) return RaspCheckResult.unavailable(id, "Remote config needs a configured credential")
        if (publicKey() == null) return RaspCheckResult.unavailable(id, "No config public key (credential has no config_public_key)")
        val evidence = mutableListOf(RaspEvidence("remote_config_status", status.name))
        accepted?.let {
            evidence += RaspEvidence("remote_config_version", it.version)
            if (it.ignoredDetectors.isNotEmpty()) evidence += RaspEvidence("ignored_detectors", it.ignoredDetectors.joinToString(","))
        }
        rejection?.let { r ->
            evidence += RaspEvidence("reason", r.reason.wire)
            evidence += RaspEvidence("detail", r.detail)
            r.version?.let { evidence += RaspEvidence("rejected_version", it) }
            return RaspCheckResult.detected(id, evidence)
        }
        if (accepted != null) return RaspCheckResult.secure(id, evidence)
        return RaspCheckResult.unknown(
            id,
            if (expired) "The stored remote config expired; the app's own config applies"
            else if (fetchedOnce) "No remote config published for this app" else "No remote config received yet",
        )
    }

    /** Loads the stored config, fetches now, then every `remoteConfigPollMinutes` (±20 % jitter). */
    fun start() {
        val minutes = local.remoteConfigPollMinutes.coerceIn(RaspRemoteConfig.POLL_MINUTES)
        val ex = Executors.newSingleThreadScheduledExecutor { Thread(it, "RaspRemoteConfig").apply { isDaemon = true } }
        executor = ex
        fun schedule(delayMillis: Long) {
            next = try {
                ex.schedule({
                    runCatching { refreshNow() }
                    schedule((minutes * 60_000L * (0.8 + 0.4 * Random.nextDouble())).toLong())
                }, delayMillis, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                null
            }
        }
        ex.execute { runCatching { loadCached() } }
        schedule(0)
    }

    fun refreshAsync() {
        try {
            executor?.execute { runCatching { refreshNow() } }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            // stopped
        }
    }

    fun stop() {
        next?.cancel(false)
        executor?.shutdownNow()
    }

    companion object {
        private const val TIMEOUT_MS = 8000
        private const val MAX_BYTES = 64 * 1024

        /** GET with [headers]: status and body (≤ 64 KB, only for 200). */
        fun httpGet(url: String, headers: Map<String, String>): RaspHttpResponse {
            var connection: HttpURLConnection? = null
            return try {
                connection = (URL(url).openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = TIMEOUT_MS
                    readTimeout = TIMEOUT_MS
                    useCaches = false
                    headers.forEach { (name, value) -> setRequestProperty(name, value) }
                }
                val status = connection.responseCode
                val body = if (status == 200) connection.inputStream.use { stream ->
                    val bytes = stream.readBytesLimited(MAX_BYTES) ?: return RaspHttpResponse(-1, null)
                    String(bytes, Charsets.UTF_8)
                } else null
                RaspHttpResponse(status, body)
            } catch (e: Exception) {
                RaspHttpResponse(-1, null)
            } finally {
                connection?.disconnect()
            }
        }

        private fun java.io.InputStream.readBytesLimited(max: Int): ByteArray? {
            val out = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val n = read(buffer)
                if (n < 0) break
                out.write(buffer, 0, n)
                if (out.size() > max) return null
            }
            return out.toByteArray()
        }

        /** Production store: the engine's encrypted preferences (Android Keystore AES-GCM). */
        fun securePrefsStore(context: android.content.Context): Store = object : Store {
            private val prefs by lazy { RaspSecurePrefs.open(context, "rasp_remote_config") }
            override fun load(): String? = try { prefs.getString(KEY) } catch (e: Exception) { null }
            override fun save(signedJson: String): Boolean = try { prefs.putString(KEY, signedJson) } catch (e: Exception) { false }
            override fun clear() { try { prefs.remove(KEY) } catch (e: Exception) { /* best effort */ } }
        }

        private const val KEY = "signed_config"
    }
}
