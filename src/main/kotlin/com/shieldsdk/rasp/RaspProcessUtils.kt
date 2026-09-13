package com.shieldsdk.rasp

/**
 * Bounded `Runtime.exec` waiting, shared by every detector that shells out
 * (`getprop`, `which su`, `getenforce`).
 *
 * `Process.waitFor()` with no arguments blocks **indefinitely** — a hung or
 * wedged shell on a misbehaving device/OEM image would hang the calling
 * thread forever, which is unacceptable for a control a banking app calls
 * on every scan. `Process.waitFor(timeout, unit)` (the bounded overload) is
 * only available API 26+; this object provides one bounded-wait path that
 * works from this SDK's `minSdk = 23` up, using a watcher thread + `join`
 * on the older API levels instead.
 *
 * Never throws: an exceeded timeout, an interrupted wait, or an exec
 * failure all resolve to `false` (process did not finish in time / could
 * not be started) — the caller already treats "did not complete" as
 * "signal unavailable," exactly like every other I/O failure in this class
 * of detector.
 */
internal object RaspProcessUtils {

    private const val DEFAULT_TIMEOUT_MS = 1500L

    /**
     * Runs [command], returning its first stdout line, or `null` if it
     * could not be started, did not finish within [timeoutMs], or produced
     * no output. Always destroys the process afterward — never leaks a
     * lingering shell process across calls.
     */
    fun firstLineOf(command: Array<String>, timeoutMs: Long = DEFAULT_TIMEOUT_MS): String? {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(command)
            val finished = waitBounded(process, timeoutMs)
            if (!finished) return null
            process.inputStream.bufferedReader().use { it.readLine() }
        } catch (e: Exception) {
            null
        } finally {
            try {
                process?.destroy()
            } catch (e: Exception) {
                // Best-effort cleanup only.
            }
        }
    }

    /**
     * `true` once [process] exits within [timeoutMs]; `false` on timeout —
     * never blocks past that bound. Uses the direct timed overload on
     * API 26+; a watcher-thread `join` below that, since `minSdk` is 23.
     */
    private fun waitBounded(process: Process, timeoutMs: Long): Boolean {
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            try {
                process.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            }
        } else {
            val watcher = Thread {
                try {
                    process.waitFor()
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            watcher.isDaemon = true
            watcher.start()
            try {
                watcher.join(timeoutMs)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            val exited = !watcher.isAlive
            if (!exited) {
                watcher.interrupt()
            }
            exited
        }
    }
}
