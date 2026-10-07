package com.shieldsdk.rasp

/** Session risk verdict. The SDK only recommends; the host app decides what to do. */
public enum class RaspRiskVerdict { LOW, MEDIUM, HIGH, UNKNOWN }

/**
 * Thresholds for [RaspRiskScore]. [stepUpThreshold]: also recommend step-up
 * at or above this score (`null` = only at HIGH). [highRiskTransactionMode]:
 * a stricter profile for sensitive actions — step-up is also recommended at
 * MEDIUM and when the verdict is UNKNOWN. The SDK exposes the flag; the host
 * enforces it.
 */
public data class RaspRiskPolicy(
    val mediumThreshold: Int = 30,
    val highThreshold: Int = 60,
    val stepUpThreshold: Int? = null,
    val highRiskTransactionMode: Boolean = false,
) {
    init {
        require(mediumThreshold in 1..100 && highThreshold in 1..100 && mediumThreshold < highThreshold) {
            "thresholds must satisfy 0 < medium < high <= 100"
        }
        require(stepUpThreshold == null || stepUpThreshold in 1..100) { "stepUpThreshold must be 1..100" }
    }
}

/**
 * The session risk at one tick.
 * [score]: 0-100 from groups with a detection; `null` when nothing was scored.
 * [maxPossibleScore]: the score if every undecided group were a detection.
 */
public data class RaspRiskAssessment(
    val score: Int?,
    val maxPossibleScore: Int?,
    val verdict: RaspRiskVerdict,
    val stepUpRecommended: Boolean,
    val firedGroups: List<String>,
    val undecidedGroups: List<String>,
    /** Detector ids that caused [firedGroups]. */
    val contributingDetectors: List<String>,
    val highRiskTransactionMode: Boolean,
    val evaluatedAtMillis: Long,
) {
    public companion object {
        @JvmField
        public val NOT_EVALUATED: RaspRiskAssessment = RaspRiskAssessment(
            null, null, RaspRiskVerdict.UNKNOWN, false, emptyList(), emptyList(), emptyList(), false, 0L,
        )
    }
}

/**
 * Session risk score (0-100), grouped by independence: correlated detectors
 * share a group and a group counts once however many of its detectors fire
 * (root plus hooking traces are one "device compromise", not two).
 *
 * | Group | Weight | Detectors |
 * |---|---|---|
 * | device_compromise | 40 | root_jailbreak, hook_detection, frida, re_tools, emulator, device_state_attestation |
 * | app_integrity | 30 | tamper, repackage, debugger, untrusted_install_source, clone |
 * | remote_access_overlay | 35 | remote_control_app, screen_sharing_risk, otp_interception_risk, otp_forwarding_risk, accessibility, overlay, external_display, screen_recording, task_hijack, risky_app |
 * | sms_access | 25 | sms_reader_abuse |
 * | malware | 35 | malware_reputation |
 * | social_engineering | 30 | vishing_call |
 * | identity_change | 25 | sim_change, device_binding, mock_location, time_spoofing |
 * | network | 15 | mitm, high_risk_ip, vpn, unsafe_wifi |
 *
 * Not scored: screenshot/clipboard/USB/ADB/developer-mode/device-lock/keyboard
 * and other hygiene detectors.
 *
 * Group state: fired (any DETECTED), clean (no DETECTED, ≥1 SECURE and none
 * UNKNOWN/ERROR), undecided (otherwise). UNAVAILABLE results (the check does
 * not run on this device or is not configured) are not inputs; a group with
 * no other results is not scored. Verdict: LOW below [RaspRiskPolicy.mediumThreshold], MEDIUM below
 * [RaspRiskPolicy.highThreshold], HIGH at or above it. LOW is never given
 * when the undecided groups could raise it — that is UNKNOWN; MEDIUM with
 * undecided groups is a lower bound (see [RaspRiskAssessment.undecidedGroups]
 * and [RaspRiskAssessment.maxPossibleScore]). No scored groups → UNKNOWN.
 */
public object RaspRiskScore {

    public data class Group(val id: String, val weight: Int, val detectors: Set<String>)

    @JvmField
    public val GROUPS: List<Group> = listOf(
        Group("device_compromise", 40, setOf("root_jailbreak", "hook_detection", "frida", "re_tools", "emulator", "device_state_attestation")),
        Group("app_integrity", 30, setOf("tamper", "repackage", "debugger", "untrusted_install_source", "clone")),
        Group(
            "remote_access_overlay", 35,
            setOf(
                "remote_control_app", "screen_sharing_risk", "otp_interception_risk", "otp_forwarding_risk",
                "accessibility", "overlay", "external_display", "screen_recording", "task_hijack", "risky_app",
            ),
        ),
        Group("sms_access", 25, setOf("sms_reader_abuse")),
        Group("malware", 35, setOf("malware_reputation")),
        Group("social_engineering", 30, setOf("vishing_call")),
        Group("identity_change", 25, setOf("sim_change", "device_binding", "mock_location", "time_spoofing")),
        Group("network", 15, setOf("mitm", "high_risk_ip", "vpn", "unsafe_wifi")),
    )

    private fun verdictFor(score: Int, policy: RaspRiskPolicy) = when {
        score >= policy.highThreshold -> RaspRiskVerdict.HIGH
        score >= policy.mediumThreshold -> RaspRiskVerdict.MEDIUM
        else -> RaspRiskVerdict.LOW
    }

    @JvmStatic
    @JvmOverloads
    public fun assess(
        results: Collection<RaspCheckResult>,
        policy: RaspRiskPolicy = RaspRiskPolicy(),
        nowMillis: Long = System.currentTimeMillis(),
    ): RaspRiskAssessment {
        val byId = results.associateBy { it.detectorId }
        val fired = mutableListOf<Group>()
        val undecided = mutableListOf<Group>()
        val contributing = mutableListOf<String>()
        var scored = 0
        for (group in GROUPS) {
            val inGroup = group.detectors.mapNotNull { byId[it] }.filter { it.status != RaspCheckStatus.UNAVAILABLE }
            if (inGroup.isEmpty()) continue
            scored++
            val detected = inGroup.filter { it.status == RaspCheckStatus.DETECTED }
            when {
                detected.isNotEmpty() -> { fired += group; contributing += detected.map { it.detectorId } }
                inGroup.none { it.status == RaspCheckStatus.UNKNOWN || it.status == RaspCheckStatus.ERROR } -> Unit
                else -> undecided += group
            }
        }
        if (scored == 0) {
            return RaspRiskAssessment(
                null, null, RaspRiskVerdict.UNKNOWN, policy.highRiskTransactionMode, emptyList(), emptyList(), emptyList(),
                policy.highRiskTransactionMode, nowMillis,
            )
        }
        val score = fired.sumOf { it.weight }.coerceAtMost(100)
        val maxScore = (score + undecided.sumOf { it.weight }).coerceAtMost(100)
        val decided = verdictFor(score, policy)
        // LOW only when the undecided groups could not raise it; MEDIUM is a lower bound.
        val verdict = if (decided == RaspRiskVerdict.LOW && verdictFor(maxScore, policy) != decided) RaspRiskVerdict.UNKNOWN else decided
        val stepUp = verdict == RaspRiskVerdict.HIGH ||
            (policy.stepUpThreshold != null && score >= policy.stepUpThreshold) ||
            (policy.highRiskTransactionMode && verdict != RaspRiskVerdict.LOW)
        return RaspRiskAssessment(
            score, maxScore, verdict, stepUp,
            fired.map { it.id }, undecided.map { it.id }, contributing.distinct(),
            policy.highRiskTransactionMode, nowMillis,
        )
    }
}
