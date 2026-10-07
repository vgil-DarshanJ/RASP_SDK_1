package com.shieldsdk.rasp

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.provider.Telephony

/**
 * `sms_reader_abuse` — visible apps that hold a granted SMS permission
 * (READ_SMS, RECEIVE_SMS, RECEIVE_MMS, RECEIVE_WAP_PUSH) or notification-
 * listener access, excluding this app, system apps, the default SMS app and
 * the configured allowlist. Reads only package metadata; never message
 * content. Clean but with limited package visibility (Android 11+ without
 * QUERY_ALL_PACKAGES, which this SDK does not request) → UNKNOWN with the
 * reason, never SECURE.
 */
public object RaspSmsReaderProbes {
    const val DETECTOR_ID = "sms_reader_abuse"

    @JvmField
    public val SMS_PERMISSIONS: List<String> = listOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
    )

    public data class AppSms(val packageName: String, val system: Boolean, val grantedSmsPermissions: List<String>)

    public data class Observation(
        val hostPackage: String,
        /** Visible packages; `null` when they could not be listed. */
        val packages: List<AppSms>?,
        val notificationListeners: List<RaspAppFacts>?,
        val defaultSmsPackage: String?,
        val allowlist: List<String>,
        val visibilityComplete: Boolean,
    )

    public fun evaluate(o: Observation): RaspCheckResult {
        val packages = o.packages ?: return RaspCheckResult.unknown(DETECTOR_ID, "Installed packages could not be listed")
        fun excluded(pkg: String) = pkg == o.hostPackage || pkg == o.defaultSmsPackage || pkg in o.allowlist
        val smsApps = packages.filter { !it.system && !excluded(it.packageName) && it.grantedSmsPermissions.isNotEmpty() }
        val listenerClasses = o.notificationListeners?.filterNot { excluded(it.packageName) }?.map {
            it.packageName to RaspFraudEnvironment.classifyListener(it, o.hostPackage, o.allowlist)
        }
        val listenerApps = listenerClasses?.filter { it.second == RaspFraudEnvironment.ListenerClass.UNKNOWN_APP }?.map { it.first }
        val unverified = listenerClasses?.filter { it.second == RaspFraudEnvironment.ListenerClass.UNVERIFIED }?.map { it.first }
        val evidence = smsApps.map { RaspEvidence("sms_permission_app", it.packageName, it.grantedSmsPermissions.joinToString()) } +
            listenerApps.orEmpty().map { RaspEvidence("notification_listener_app", it) } +
            unverified.orEmpty().map { RaspEvidence("unverified_notification_listener", it, "package not visible") } +
            listOf(
                RaspEvidence("packages_checked", packages.size),
                RaspEvidence("visibility", RaspFraudEnvironment.visibilityLabel(o.visibilityComplete)),
                RaspEvidence("message_content_read", false),
            )
        return when {
            smsApps.isNotEmpty() || !listenerApps.isNullOrEmpty() -> RaspCheckResult.detected(DETECTOR_ID, evidence)
            listenerApps == null -> RaspCheckResult(DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "Notification listeners could not be read")
            !unverified.isNullOrEmpty() -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence, reason = "A notification listener is not visible to this app",
            )
            !o.visibilityComplete -> RaspCheckResult(
                DETECTOR_ID, RaspCheckStatus.UNKNOWN, evidence,
                reason = "Package visibility is limited: only launcher apps and declared packages were checked",
            )
            else -> RaspCheckResult.secure(DETECTOR_ID, evidence)
        }
    }

    /** Granted SMS permissions of one package, from its requested-permission flags. Pure. */
    public fun grantedSms(requested: Array<String>?, flags: IntArray?): List<String> {
        if (requested == null || flags == null) return emptyList()
        return requested.indices.filter { i ->
            requested[i] in SMS_PERMISSIONS && i < flags.size && flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
        }.map { requested[it] }
    }

    public fun observe(context: Context, allowlist: List<String>): Observation {
        val packages = try {
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS).map { info ->
                val flags = info.applicationInfo?.flags ?: 0
                AppSms(
                    info.packageName,
                    system = flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                    grantedSmsPermissions = grantedSms(info.requestedPermissions, info.requestedPermissionsFlags),
                )
            }
        } catch (e: Exception) {
            null
        }
        val defaultSms = try { Telephony.Sms.getDefaultSmsPackage(context) } catch (e: Exception) { null }
        return Observation(
            hostPackage = context.packageName,
            packages = packages,
            notificationListeners = RaspFraudEnvironment.notificationListenerPackages(context)
                ?.map { RaspFraudEnvironment.appFacts(context, it) },
            defaultSmsPackage = defaultSms,
            allowlist = allowlist,
            visibilityComplete = RaspFraudEnvironment.visibilityComplete(context),
        )
    }
}
