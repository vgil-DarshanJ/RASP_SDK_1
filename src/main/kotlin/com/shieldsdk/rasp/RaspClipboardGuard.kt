package com.shieldsdk.rasp

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context

/**
 * Clipboard protection.
 *
 * ## What this deliberately does NOT do
 *
 * Since Android 10 (API 29), the platform itself already prevents a
 * background app from *reading* another app's clipboard content — and even
 * for this app's own copies, reading arbitrary clipboard content back is a
 * sensitive-data liability an SDK has no legitimate reason to take on. This
 * class never inspects, stores, or reports *what* was copied — the one
 * exception is checking whether the current clip's length is exactly zero
 * (see [isClipCurrentlyEmpty]), which is how a real copy is told apart from
 * this guard's own clear() reporting itself back; that check never sees,
 * keeps, or exposes the actual text when it's non-empty.
 *
 * ## What it does
 *
 * 1. [enable] registers a [ClipboardManager.OnPrimaryClipChangedListener]
 *    and counts primary-clip changes while this app is attached — evidence
 *    that "something was copied", never what.
 * 2. With `autoClearOnCopy = true`, every detected change is immediately
 *    overwritten with an empty clip — the actual enforcement primitive for
 *    "nothing copied inside this app should be pastable elsewhere". This is
 *    a best-effort, Android-version-dependent control: on API 29+ a
 *    background app cannot even observe `onPrimaryClipChanged` unless it is
 *    the default IME or has focus, and no Android API can prevent a *third*
 *    app from having already read a clip in the instant before this listener
 *    fires. Treat this as raising the bar, not an absolute guarantee — the
 *    same honest framing this SDK already uses for screenshot protection
 *    (`FLAG_SECURE` blocks the OS-level screenshot path; it does not, and
 *    cannot, prevent a second physical camera pointed at the screen).
 * 3. [clear] is exposed standalone so a host app can wipe the clipboard
 *    immediately after intentionally copying something sensitive (e.g. a
 *    one-time code), without leaving protection enabled at all times.
 *
 * Context-only (applicationContext), same testability convention as
 * [RaspUsbAnalysis] and the other probe classes.
 *
 * Public (not `internal`) so a consumer that only wants this one check —
 * including a pure Kotlin/Java Android app with no Flutter engine on its
 * classpath — can depend on this Gradle module directly and call it without
 * going through [RaspShieldPlugin]'s MethodChannel at all. See
 * `docs/LEAN_SECURITY_INTEGRATION_GUIDE.md`.
 */
class RaspClipboardGuard(
    context: Context,
) : ClipboardManager.OnPrimaryClipChangedListener {

    private val clipboardManager: ClipboardManager? = try {
        context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    } catch (e: Exception) {
        null
    }

    @Volatile
    private var listening = false

    @Volatile
    private var autoClearOnCopy = false

    @Volatile
    private var changeCount = 0

    @Volatile
    private var lastChangeAtMillis: Long? = null

    /**
     * Starts monitoring (and, if [autoClearOnCopy], enforcing). Returns
     * `false` only when this device/build has no [ClipboardManager] at all —
     * never throws.
     */
    fun enable(autoClearOnCopy: Boolean): Boolean {
        val manager = clipboardManager ?: return false
        this.autoClearOnCopy = autoClearOnCopy
        if (!listening) {
            try {
                manager.addPrimaryClipChangedListener(this)
                listening = true
            } catch (e: Exception) {
                return false
            }
        }
        return true
    }

    /** Idempotent — safe to call when never enabled or already disabled. */
    fun disable() {
        val manager = clipboardManager
        if (manager != null && listening) {
            try {
                manager.removePrimaryClipChangedListener(this)
            } catch (e: Exception) {
                // Listener already detached (e.g. engine tearing down); the
                // state flag below is still the source of truth for `active`.
            }
        }
        listening = false
        autoClearOnCopy = false
    }

    fun isActive(): Boolean = listening

    /** Overwrites the primary clip with an empty one. `false` if it could not. */
    fun clear(): Boolean {
        val manager = clipboardManager ?: return false
        return try {
            manager.setPrimaryClip(ClipData.newPlainText("", ""))
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * `true` when the current primary clip has no text in it. Used only to
     * tell "this change was our own clear (or something else already
     * emptied it)" apart from "this is a real copy" — a direct reality
     * check, not a guess based on call timing/ordering. Deliberately does
     * NOT distinguish or log *what* non-empty text is present — only
     * whether the length is zero, which carries no user data.
     */
    private fun isClipCurrentlyEmpty(): Boolean {
        val manager = clipboardManager ?: return true
        return try {
            val clip = manager.primaryClip
            val text = if (clip != null && clip.itemCount > 0) {
                clip.getItemAt(0).coerceToText(null)?.toString()
            } else {
                null
            }
            text.isNullOrEmpty()
        } catch (e: Exception) {
            // Could not read it either way — treat as "not our concern",
            // never as a reason to skip clearing a real copy.
            false
        }
    }

    /**
     * Read-and-clear evidence, same convention as
     * [RaspSecurityChannelHandler.drainScreenshotEventEvidence]: the count
     * reported is exactly how many primary-clip changes fired since the last
     * read, then resets — a scan never double-reports the same change.
     *
     * **This is destructive, single-consumer state — [RaspLeanSession]'s own
     * poll tick is the one intended caller.** A second, independent caller
     * (e.g. a host app's own UI polling this on its own timer to show a live
     * "changes so far" readout) draining the same counter corrupts what the
     * lean session sees: every tick's read comes back inconsistent, which
     * looks like — and produces — a constantly-changing signature, so the
     * lean session ships this detector's "still SECURE" result on nearly
     * every poll instead of the intended once-as-baseline behavior. A host
     * app that wants to show live evidence in its own UI should call
     * [peekEvidence] instead, which never resets anything.
     */
    fun drainEvidence(): Map<String, Any?> {
        val count = changeCount
        val lastAt = lastChangeAtMillis
        changeCount = 0
        return mapOf(
            "supported" to (clipboardManager != null),
            "active" to listening,
            "auto_clear_enabled" to autoClearOnCopy,
            "change_count" to count,
            "last_change_at_millis" to lastAt,
        )
    }

    /**
     * Same shape as [drainEvidence], but read-only — never resets
     * [changeCount]. Safe to call from a host app's own UI on any timer of
     * its choosing, as many times as it wants, with zero effect on what
     * [RaspLeanSession] (which calls [drainEvidence]) sees or ships. Use
     * this for a live on-screen "changes so far" display; use [drainEvidence]
     * only if you are implementing your own event-shipping loop instead of
     * using [RaspLeanSession].
     */
    fun peekEvidence(): Map<String, Any?> {
        return mapOf(
            "supported" to (clipboardManager != null),
            "active" to listening,
            "auto_clear_enabled" to autoClearOnCopy,
            "change_count" to changeCount,
            "last_change_at_millis" to lastChangeAtMillis,
        )
    }

    override fun onPrimaryClipChanged() {
        // A change that leaves the clip empty is either our own clear()
        // reporting itself back, or something else emptying it — either
        // way, not a real copy to react to. Checking the actual current
        // state (instead of a "was I mid-clear a moment ago" flag) is what
        // makes this correct under rapid, overlapping copies: each callback
        // judges reality at the instant it fires, with nothing left over
        // from an earlier call that may not have finished yet.
        if (isClipCurrentlyEmpty()) {
            return
        }
        changeCount += 1
        lastChangeAtMillis = System.currentTimeMillis()
        if (autoClearOnCopy) {
            clear()
        }
    }
}
