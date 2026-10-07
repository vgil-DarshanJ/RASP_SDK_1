# New detectors (Tasks 3a–3c)

All ten are off by default (`RaspLeanConfig` flag, same name in Kotlin and
Dart). Each reports one of SECURE / DETECTED / UNAVAILABLE / UNKNOWN / ERROR;
a check that cannot decide is never SECURE.

Severity is the backend's (`BE/src/detectors/severity.ts`, which drives risk
score and webhook thresholds); title and category are the dashboard's
(`FE/lib/alertCatalog.ts`). The Flutter facade (`lean_session.dart`) uses the
same titles and severities.

| Detector id | Task | Backend severity | Dashboard title / category | Config flag (+ options) | Host requirements | DETECTED when | UNAVAILABLE / UNKNOWN when |
|---|---|---|---|---|---|---|---|
| `mock_location` | 3a | high | Mock Location / Device Integrity | `mockLocationDetection` | Supplies a location with its mock flag (`RaspLocationSnapshot.fromLocation`, Flutter `isMock`) | the supplied fix's mock flag is true | UNAVAILABLE: no location supplied. UNKNOWN: location without mock flag |
| `time_spoofing` | 3a | medium | Time Spoofing / Device Integrity | `timeSpoofingDetection` (+ `serverTimeMillis`, `setServerTime()`) | — | two of: wall-clock jump vs monotonic clock, offset from server time, auto time off | UNKNOWN: an unmeasured signal could still make two (first reading, setting unreadable) |
| `unsafe_wifi` | 3a | medium | Unsafe Wi-Fi / Network Security | `unsafeWifiDetection` | `ACCESS_WIFI_STATE`, `ACCESS_NETWORK_STATE` | open or WEP network, or captive portal | UNAVAILABLE: permission missing. UNKNOWN: security type unreadable (API 29–30) |
| `screen_recording` | 3a | high | Screen Recording / Privacy & Screen | `screenRecordingDetection` | Android 15+, `DETECT_SCREEN_RECORDING` | app windows visible in an active recording | UNAVAILABLE: below API 35 or permission missing. UNKNOWN: no state reported yet |
| `vishing_call` | 3b | high | Call During App Use / Privacy & Screen | `vishingCallDetection` (+ `isCallActive()`) | `READ_PHONE_STATE` (runtime) | telephony call ringing/active while the app is in the foreground | UNAVAILABLE: permission missing. UNKNOWN: state unreadable |
| `sim_change` | 3b | high | SIM Change / Device Integrity | `simChangeDetection` (+ `acknowledgeSimChange()`) | `READ_PHONE_STATE` (runtime) | salted SIM fingerprint differs from the stored one; stays until acknowledged | UNAVAILABLE: permission missing. UNKNOWN: first run (baseline stored) or SIMs unreadable |
| `third_party_keyboard` | 3b | medium | Third-party Keyboard / Privacy & Screen | `thirdPartyKeyboardDetection` (+ `trustedKeyboardPackages`) | — | active keyboard is not a system app and not (allowlisted and from Play) | UNKNOWN: active keyboard unreadable |
| `task_hijack` | 3b | high | Task Hijacking / App Integrity | `taskHijackDetection` | — (engine `<queries>` launcher intent) | another visible app declares the host's task affinity | UNKNOWN: package scan or own manifest unreadable |
| `device_state_attestation` | 3c | high | Device State Attestation / Device Integrity | `deviceStateAttestationDetection` (+ `maxSecurityPatchAgeDays`) | Hardware key attestation (API 24+) | bootloader unlocked, verified boot unverified/failed, or (if set) patch older than the limit | UNAVAILABLE: no device key/chain. UNKNOWN: no attestation extension, software-level attestation, no root of trust |
| `malware_reputation` | 3c | critical | Known Malware Installed / Device Integrity | `malwareReputationDetection` (+ `malwareReputationListJson`, `malwareReputationPublicKey`) | Signed list + Ed25519 key; list packages visible (`<queries>`) | a listed package is installed | UNAVAILABLE: list/key missing, malformed, or signature invalid. UNKNOWN: package scan failed |

## Notes per detector

- **mock_location** — the selected mock-location app (AppOps, API 23+) is
  reported as evidence but does not decide: it shows a mock provider is
  allowed, not that this fix came from it.
- **time_spoofing** — a server time is anchored to `elapsedRealtime` when it
  is received, so it stays valid while the app runs. Without one, DETECTED
  needs both the clock jump and auto time being off.
- **unsafe_wifi** — no SSID/BSSID is read or shipped. OWE ("enhanced open")
  counts as encrypted.
- **screen_recording** — Android exposes no API that shows another app's
  MediaProjection session below API 35; mirroring to a display is covered
  by `external_display`.
- **vishing_call** — VoIP calls do not change the telephony call state and
  are not seen.
- **sim_change** — reads only Android's subscription id, carrier id and
  MCC+MNC per active SIM; never IMEI, phone number or ICCID. Hashed with a
  per-install random salt; only the hash is stored (EncryptedSharedPreferences).
- **third_party_keyboard** — a package name alone is never trusted (a
  sideloaded app can reuse Gboard's name), so allowlisted keyboards must come
  from Google Play; system keyboards (OEM defaults) are always trusted.
- **task_hijack** — the host's own risky manifest settings (singleTask with
  an affinity, allowTaskReparenting, custom affinities) are reported as
  `host_config_finding` evidence only: they are a build finding, the same on
  every device.
- **device_state_attestation** — decoded on the device from the device key's
  attestation certificate; not verified against the Google attestation roots
  there, so a compromised OS could present a forged chain. The authoritative
  check belongs on the backend (chain is sent to `POST /v1/devices/register`).
- **malware_reputation** — list format and signing: see
  `RaspMalwareReputationProbes` and `tools/sign-reputation-list.js`. The
  signature covers the payload text byte-for-byte. Ed25519 is verified by
  `RaspEd25519` (pure Kotlin) because the platform provider has it only
  from API 33.

## Package visibility

The engine manifest adds a `<queries>` intent for launcher activities so
`task_hijack` and `malware_reputation` (both off by default) can see apps
with a launcher icon on Android 11+. It merges into every host app; a host
can remove it with `tools:node="remove"`. Apps without a launcher icon stay
invisible unless the host declares them as `<package>` entries. The SDK does
not use `QUERY_ALL_PACKAGES`. Both detectors report the scope as
`visibility` evidence. Details: [PACKAGE_VISIBILITY.md](PACKAGE_VISIBILITY.md).

## Task 8.1 fraud signals

All five are off by default and need no new permission. They never read
SMS content, contacts, phone numbers, IMEI or account names, and the SDK
does not request READ_SMS, RECEIVE_SMS or QUERY_ALL_PACKAGES. They are risk
signals, not proof of fraud. Design, privacy, the session risk score and the
transaction API: `docs/FRAUD_RISK_DESIGN.md` in the workspace root.

| Detector id | Backend severity | Dashboard title / category | Config flag (+ options) | DETECTED when | UNKNOWN when |
|---|---|---|---|---|---|
| `otp_interception_risk` | high | OTP Interception Risk / Privacy & Screen | `otpInterceptionDetection` (+ `notificationListenerAllowlist`) | 1 hard signal (accessibility abuse; a visible non-system, non-allowlisted notification listener) or 2 soft signals (overlay; remote-control app). Evidence names each `contributing_signal` | an undecided input could still reach the threshold (listeners or services unreadable, a listener package not visible) |
| `sms_reader_abuse` | high | SMS Reader Apps / Privacy & Screen | `smsReaderAbuseDetection` (+ `smsAppAllowlist`) | a visible non-system app (not the default SMS app, not allowlisted) holds a granted SMS permission or notification-listener access | nothing found but package visibility is limited (Android 11+ without QUERY_ALL_PACKAGES), packages or listeners unreadable |
| `otp_forwarding_risk` | medium | OTP Forwarding Risk (hint) / Privacy & Screen | `otpForwardingDetection` (+ `autoForwardPackages`) | a known SMS auto-forward app, a non-allowlisted accessibility service that can perform gestures, or a remote-control app. Always `risk_hint = true`; call forwarding is `not_checked` | one of the three inputs unreadable |
| `remote_control_app` | high | Remote Control App / Privacy & Screen | `remoteControlAppDetection` (+ `remoteControlListJson`, `remoteControlListPublicKey`) | a built-in or signed-list remote-control package is installed, or a cast/external display or (Android 15+) a screen recording is active | package check failed, configured list rejected (signature), displays unreadable |
| `screen_sharing_risk` | high | Screen Sharing During App Use / Privacy & Screen | `screenSharingDetection` | the app is in the foreground and its screen is recorded (Android 15+) or a cast/external display is attached | foreground state unreadable, or screen capture not observable (below Android 15, or no DETECT_SCREEN_RECORDING) with no display attached |

The built-in package lists (`RaspRemoteControlProbes.builtInPackages`,
`RaspOtpForwardingProbes.builtInAutoForwardPackages`) are a starting point
and are declared in the engine `<queries>`; extend them with the signed list
or config (and declare extra packages in the host manifest).
