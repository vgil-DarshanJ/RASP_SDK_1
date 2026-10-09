package com.shieldsdk.rasp

import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Keeps the `malware_reputation` list current from the backend
 * (`GET /v1/reputation/list`, see the backend's reputation routes).
 *
 * - The list is the same signed format as a bundled one
 *   ([RaspMalwareReputationProbes]); it is accepted only when its Ed25519
 *   signature verifies with the public key the app was configured with (or
 *   that came in the credential), and only when its version is not older
 *   than the list in use. A network attacker can therefore neither change
 *   it nor roll it back.
 * - Checked at most once per [REFRESH_INTERVAL_MILLIS] per process, on its
 *   own thread; detector ticks never wait for the network.
 * - The last accepted list is kept in app-private storage ([dir], production:
 *   `Context.filesDir`), so it survives restarts and works offline.
 * - [listFor] returns the newer of the downloaded and the bundled list.
 */
internal object RaspReputationListUpdater {
    const val REFRESH_INTERVAL_MILLIS: Long = 24L * 60 * 60 * 1000
    const val FILE_NAME = "rasp_reputation_list.json"
    private const val MAX_BYTES = 1024 * 1024
    private const val TIMEOUT_MS = 8000

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "RaspReputationList").apply { isDaemon = true } }
    private val running = AtomicBoolean(false)
    @Volatile private var lastAttemptMillis = 0L
    private val loaded = AtomicReference<Pair<File, String>?>(null)

    /** GET [url] with [headers]; status and body (≤ 1 MB). Tests replace it. */
    @Volatile
    var fetch: (url: String, headers: Map<String, String>) -> RaspHttpResponse = { url, headers ->
        var connection: HttpURLConnection? = null
        try {
            connection = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                headers.forEach { (name, value) -> setRequestProperty(name, value) }
            }
            val status = connection.responseCode
            val body = if (status == 200) connection.inputStream.use { String(it.readBytesLimited(MAX_BYTES), Charsets.UTF_8) } else null
            RaspHttpResponse(status, body)
        } catch (e: Exception) {
            RaspHttpResponse(-1, null)
        } finally {
            connection?.disconnect()
        }
    }

    private fun java.io.InputStream.readBytesLimited(max: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (out.size() <= max) {
            val n = read(buffer)
            if (n < 0) break
            out.write(buffer, 0, n)
        }
        if (out.size() > max) throw IllegalStateException("reputation list larger than $max bytes")
        return out.toByteArray()
    }

    private fun version(listJson: String?, publicKey: String?): Long? =
        (RaspMalwareReputationProbes.loadList(listJson, publicKey) as? RaspMalwareReputationProbes.Load.Ok)?.list?.version

    /** The stored downloaded list (kept in memory after the first read), or null. */
    private fun stored(dir: File): String? {
        loaded.get()?.takeIf { it.first == dir }?.let { return it.second }
        return try {
            File(dir, FILE_NAME).takeIf { it.exists() }?.readText(Charsets.UTF_8)?.also { loaded.set(dir to it) }
        } catch (e: Exception) {
            null
        }
    }

    /** The list to evaluate: the downloaded one when it verifies and is at least as new as [bundled]. */
    fun listFor(dir: File, bundled: String?, publicKey: String?): String? {
        val downloaded = stored(dir) ?: return bundled
        val downloadedVersion = version(downloaded, publicKey) ?: return bundled
        val bundledVersion = version(bundled, publicKey)
        return if (bundledVersion == null || downloadedVersion >= bundledVersion) downloaded else bundled
    }

    /**
     * Starts a background check when one is due. [publicKey] must be the
     * key the app trusts; without it, or without a credential, nothing happens.
     */
    fun refreshIfDue(dir: File, credential: RaspEventCredential?, publicKey: String?, bundled: String?, nowMillis: Long = System.currentTimeMillis()) {
        if (credential == null || publicKey.isNullOrBlank()) return
        if (nowMillis - lastAttemptMillis < REFRESH_INTERVAL_MILLIS) return
        if (!running.compareAndSet(false, true)) return
        lastAttemptMillis = nowMillis
        executor.execute {
            try {
                refreshNow(dir, credential, publicKey, bundled)
            } finally {
                running.set(false)
            }
        }
    }

    /** One check, on the calling thread. `true` when a newer (or equal) verified list was stored. */
    fun refreshNow(dir: File, credential: RaspEventCredential, publicKey: String, bundled: String?): Boolean {
        val url = RaspBackendUrls.endpoint(credential.ingestionUrl, "reputation/list") ?: return false
        val response = fetch(url, mapOf("X-Api-Key" to credential.apiKey, "Accept" to "application/json"))
        val body = response.body?.takeIf { response.status == 200 } ?: return false
        val newVersion = version(body, publicKey) ?: return false
        val current = version(listFor(dir, bundled, publicKey), publicKey)
        if (current != null && newVersion < current) return false
        return try {
            dir.mkdirs()
            val target = File(dir, FILE_NAME)
            val tmp = File(dir, "$FILE_NAME.tmp")
            tmp.writeText(body, Charsets.UTF_8)
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) return false
            }
            loaded.set(dir to body)
            true
        } catch (e: Exception) {
            false
        }
    }

    /** For tests. */
    fun resetForTests() {
        lastAttemptMillis = 0L
        running.set(false)
        loaded.set(null)
    }
}
