package com.shieldsdk.rasp

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbManager

/**
 * Physical USB connection state.
 *
 * Distinct from [RaspSecurityChannelHandler.isAdbEnabled] /
 * `isDeveloperModeEnabled` (already shipped, `Settings.Global` reads): those
 * report whether ADB debugging is *permitted*, not whether a cable is
 * actually plugged in right now. This class answers the physical-layer
 * question — "is this device connected to a host over USB at all" — which
 * matters even when USB debugging itself is off (e.g. USB Mass Storage /
 * MTP / PTP, or a charge-only cable that still enumerates as a USB device).
 *
 * Takes a [Context], not an [android.app.Activity] — every method here works
 * from `applicationContext` alone, same convention as [RaspDeviceProbes] and
 * [RaspDeviceIntegrityProbes], so it is trivially unit/instrumentation
 * testable without a live Activity.
 *
 * Public (not `internal`) so a consumer that only wants this one check —
 * including a pure Kotlin/Java Android app with no Flutter engine on its
 * classpath — can depend on this Gradle module directly and call it without
 * going through [RaspShieldPlugin]'s MethodChannel at all. See
 * `docs/LEAN_SECURITY_INTEGRATION_GUIDE.md`.
 */
class RaspUsbAnalysis(private val context: Context) {

    /**
     * `true`/`false` when the check could run, `null` when it could not
     * (no [UsbManager] on this device/build — never collapsed into `false`,
     * see [RaspSecurityChannelHandler]'s class doc on that convention).
     */
    fun isUsbConnected(): Boolean? {
        val usbManager = usbManagerOrNull() ?: return null
        return try {
            if (usbManager.deviceList.isNotEmpty()) return true
            if (usbManager.accessoryList?.isNotEmpty() == true) return true
            stickyUsbStateConnected()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Reads the most recently broadcast `UsbManager.ACTION_USB_STATE` sticky
     * intent without registering a live [android.content.BroadcastReceiver].
     * `registerReceiver(null, filter)` is the documented Android idiom for
     * *querying* the current value of a sticky broadcast on demand — it
     * returns immediately with the last-broadcast intent (or null if none has
     * ever fired) and, passed a null receiver, registers nothing that needs
     * unregistering. This keeps USB state a poll-per-scan check, matching
     * every other detector in this SDK (no persistent receivers, no leaks to
     * manage across Activity/Engine lifecycle).
     */
    private fun stickyUsbStateConnected(): Boolean {
        return try {
            // UsbManager.ACTION_USB_STATE / USB_CONNECTED / USB_CONFIGURED are
            // real AOSP fields but are annotated @hide — present in the
            // framework at runtime, absent from the public `android.jar`
            // this module compiles against, so referencing them as
            // UsbManager.* fails with "Unresolved reference" at compile
            // time. Their string values are stable, documented ABI (the
            // broadcast action/extra names a receiver must match to work at
            // all), so inlining them here is safe and is the standard
            // workaround for this exact hidden-API situation.
            val filter = IntentFilter("android.hardware.usb.action.USB_STATE")
            val sticky: Intent? = context.registerReceiver(null, filter)
            sticky?.getBooleanExtra("connected", false) == true ||
                sticky?.getBooleanExtra("configured", false) == true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Structured evidence for the Dart-side detector, mirroring the
     * `supported`/`…_detected`/counts shape [RaspSecurityChannelHandler]
     * already uses for `getScreenshotEventEvidence`/`getExternalDisplayState`.
     * Device *names* only (`UsbDevice.deviceName`, a kernel path like
     * `/dev/bus/usb/001/002`) — never vendor/product identifiers that could
     * fingerprint a specific accessory, which this SDK has no legitimate use
     * for.
     */
    fun usbConnectionEvidence(): Map<String, Any?> {
        val usbManager = usbManagerOrNull() ?: return mapOf("supported" to false)
        return try {
            val devices = usbManager.deviceList
            mapOf(
                "supported" to true,
                "connected" to (isUsbConnected() == true),
                "device_count" to devices.size,
                "device_names" to devices.values.map { it.deviceName },
            )
        } catch (e: Exception) {
            mapOf("supported" to false)
        }
    }

    private fun usbManagerOrNull(): UsbManager? = try {
        context.getSystemService(Context.USB_SERVICE) as? UsbManager
    } catch (e: Exception) {
        null
    }
}
