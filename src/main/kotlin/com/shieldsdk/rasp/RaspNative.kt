package com.shieldsdk.rasp

/**
 * Loader and bindings for `libraspshield.so` (src/main/cpp).
 *
 * The library registers its methods itself (RegisterNatives in JNI_OnLoad).
 * If it cannot be loaded — missing ABI, a hooked loader, a JVM unit test —
 * [available] is `false` and every caller uses its Kotlin fallback; nothing
 * here throws.
 */
internal object RaspNative {

    /** Must match kNativeApiVersion in jni_entry.cpp. */
    const val API_VERSION = 1

    /** Why loading failed, for evidence; `null` when [available]. */
    @Volatile var loadError: String? = null
        private set

    val available: Boolean by lazy {
        try {
            System.loadLibrary("raspshield")
            val version = nativeApiVersion()
            if (version != API_VERSION) loadError = "native API version $version, expected $API_VERSION"
            version == API_VERSION
        } catch (t: Throwable) {
            loadError = t.javaClass.simpleName + (t.message?.let { ": $it" } ?: "")
            false
        }
    }

    @JvmStatic external fun nativeApiVersion(): Int
}
