package com.shieldsdk.rasp

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityServiceException
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.model.IntegrityErrorCode

/**
 * Google Play Integrity native boundary — the production implementation
 * behind `MainActivity`'s `playIntegrityIsAvailable`/
 * `requestPlayIntegrityToken` channel methods.
 *
 * Pulled into its own class taking a [Context] rather than an Activity, for
 * the same reason `RaspDeviceIntegrityProbes`/`RaspHookProbes` are: it lets
 * an instrumentation test call the real production implementation directly —
 * no Activity, no Flutter engine, nothing mocked. See
 * `docs/PLAY_INTEGRITY_NATIVE_AUDIT.md` for the full architecture this
 * backs.
 *
 * Two rules enforced throughout: the raw token is only ever handed to the
 * [requestToken] caller (never logged, never persisted here or anywhere
 * downstream in this class), and the nonce a request binds to is always the
 * caller's own — nothing here mints or trusts a locally-generated nonce as
 * authoritative.
 */
class RaspPlayIntegrityBridge(
    private val context: Context,
    private val integrityManager: IntegrityManager =
        IntegrityManagerFactory.create(context.applicationContext),
) {
    /**
     * Heuristic-only "does Play Integrity look reachable" probe — presence
     * of the Play Store package. This is NOT a promise the API will
     * actually work (Play Services can be installed but stale/broken, or
     * the device can lack a Play Store account); it exists only so a caller
     * can short-circuit an attestation attempt that is obviously hopeless.
     * The authoritative signal is always [requestToken]'s own outcome.
     */
    fun isAvailable(): Boolean = try {
        context.packageManager.getPackageInfo("com.android.vending", 0)
        true
    } catch (e: Exception) {
        false
    }

    /**
     * Requests a real Play Integrity token bound to [nonce] — the SERVER-
     * issued challenge nonce; this method never generates or trusts a
     * locally-minted nonce as authoritative.
     *
     * [onResult] is invoked exactly once: with the raw token on success, or
     * with an [IntegrityRequestException] carrying [mapIntegrityErrorCode]'s
     * stable code on any failure. Google's Task API resolves asynchronously
     * on its own callback thread, so [onResult] may run after this function
     * returns.
     */
    fun requestToken(nonce: String, onResult: (Result<String>) -> Unit) {
        if (!isAvailable()) {
            onResult(Result.failure(IntegrityRequestException("PLAY_STORE_NOT_FOUND")))
            return
        }
        try {
            val request = IntegrityTokenRequest.builder().setNonce(nonce).build()
            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    onResult(Result.success(response.token()))
                }
                .addOnFailureListener { exception ->
                    onResult(
                        Result.failure(
                            IntegrityRequestException(mapIntegrityErrorCode(exception), exception)
                        )
                    )
                }
        } catch (e: Exception) {
            onResult(Result.failure(IntegrityRequestException("INTEGRITY_REQUEST_FAILED", e)))
        }
    }
}

/** Carries a stable [code] (see [mapIntegrityErrorCode]) alongside the real cause. */
class IntegrityRequestException(val code: String, cause: Throwable? = null) :
    Exception(code, cause)

/**
 * Maps a Play Integrity failure to an explicit, stable error code the Dart
 * side can branch on — never a silent swallow or a generic bucket when
 * Google gives a real reason. [IntegrityServiceException.errorCode] is the
 * documented enum from
 * `com.google.android.play.core.integrity.model.IntegrityErrorCode`; any
 * other exception type (e.g. a failure surfaced before Google assigns its
 * own code) falls through to a generic bucket rather than throwing.
 *
 * Pure and side-effect-free — no Context, no Android runtime dependency —
 * so it is directly unit-testable on a plain JVM
 * (`RaspPlayIntegrityErrorMappingTest`, `src/test/kotlin`).
 */
fun mapIntegrityErrorCode(exception: Exception): String {
    val cause = exception as? IntegrityServiceException
        ?: return "INTEGRITY_UNKNOWN_ERROR"
    return when (cause.errorCode) {
        IntegrityErrorCode.API_NOT_AVAILABLE -> "API_NOT_AVAILABLE"
        IntegrityErrorCode.PLAY_STORE_NOT_FOUND -> "PLAY_STORE_NOT_FOUND"
        IntegrityErrorCode.NETWORK_ERROR -> "NETWORK_ERROR"
        IntegrityErrorCode.PLAY_STORE_ACCOUNT_NOT_FOUND -> "PLAY_STORE_ACCOUNT_NOT_FOUND"
        IntegrityErrorCode.APP_NOT_INSTALLED -> "APP_NOT_INSTALLED"
        IntegrityErrorCode.PLAY_SERVICES_NOT_FOUND -> "PLAY_SERVICES_NOT_FOUND"
        IntegrityErrorCode.APP_UID_MISMATCH -> "APP_UID_MISMATCH"
        IntegrityErrorCode.TOO_MANY_REQUESTS -> "TOO_MANY_REQUESTS"
        IntegrityErrorCode.CANNOT_BIND_TO_SERVICE -> "CANNOT_BIND_TO_SERVICE"
        IntegrityErrorCode.NONCE_TOO_SHORT -> "NONCE_TOO_SHORT"
        IntegrityErrorCode.NONCE_TOO_LONG -> "NONCE_TOO_LONG"
        IntegrityErrorCode.GOOGLE_SERVER_UNAVAILABLE -> "GOOGLE_SERVER_UNAVAILABLE"
        IntegrityErrorCode.NONCE_IS_NOT_BASE64 -> "NONCE_IS_NOT_BASE64"
        IntegrityErrorCode.INTERNAL_ERROR -> "INTERNAL_ERROR"
        IntegrityErrorCode.PLAY_STORE_VERSION_OUTDATED -> "PLAY_STORE_VERSION_OUTDATED"
        IntegrityErrorCode.PLAY_SERVICES_VERSION_OUTDATED -> "PLAY_SERVICES_VERSION_OUTDATED"
        IntegrityErrorCode.CLOUD_PROJECT_NUMBER_IS_INVALID -> "CLOUD_PROJECT_NUMBER_IS_INVALID"
        IntegrityErrorCode.CLIENT_TRANSIENT_ERROR -> "CLIENT_TRANSIENT_ERROR"
        else -> "INTEGRITY_UNKNOWN_ERROR"
    }
}
