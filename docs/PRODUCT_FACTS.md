# RASP Shield — product facts (one source)

The numbers and claims every README, guide, dashboard page and document
uses (F-25). Change them here first, then where they are repeated.
The detector tables below are generated from the code (ids from the Flutter
plugin's descriptors, which cover every id the engine reports; titles and
categories from `FE/lib/alertCatalog.ts`; severities from
`BE/src/detectors/severity.ts`).

| Fact | Value |
|---|---|
| On-device detectors | **42** (including the 4 basic controls: screenshot block, USB, ADB, clipboard). Every one is off until the host app turns it on. |
| Alerts raised by the backend | **7** (signing-certificate mismatch and 6 fraud-risk rules) |
| Result states | **5**: SECURE, DETECTED, UNAVAILABLE, UNKNOWN, ERROR. Only DETECTED is a threat; a check that cannot decide is never SECURE. |
| Platforms available | **Android** — native (Kotlin/Java, engine AAR + `sdk_rasp/android_native`) and **Flutter on Android** (`rasp_shield` plugin) |
| Not available | iOS, web. React Native: a partial package (`sdk_rasp/react_native`), not released |
| Minimum Android | Engine AAR: Android 6.0 (API 23). Flutter apps: Flutter's own minimum, Android 7.0 (API 24) with Flutter 3.47 |
| Versions (2026-10-09) | Engine `com.shieldsdk.rasp:android-core` 1.1.0 (`1.1.0-local` in development builds; releases from `v*` tags), Flutter plugin `rasp_shield` 1.1.0, trial app 1.1.0 (versionCode 2) |
| Event delivery | Signed evidence envelopes (device key in the Keystore) by default; legacy HMAC batches only for applications that keep them on |
| Wording | No absolute security claims and no other products' names anywhere |

## Detectors

<!-- generated: 42 on-device, 7 backend -->
### On the device (42)

| Category | Detector | Id | Severity |
|---|---|---|---|
| Privacy & Screen | Accessibility Abuse | `accessibility` | medium |
| Privacy & Screen | Clipboard Protection | `clipboard_protection` | low |
| Privacy & Screen | External Display / Mirroring | `external_display` | medium |
| Privacy & Screen | OTP Forwarding Risk (hint) | `otp_forwarding_risk` | medium |
| Privacy & Screen | OTP Interception Risk | `otp_interception_risk` | high |
| Privacy & Screen | Overlay Attack | `overlay` | medium |
| Privacy & Screen | Remote Control App | `remote_control_app` | high |
| Privacy & Screen | Screen Recording | `screen_recording` | high |
| Privacy & Screen | Screen Sharing During App Use | `screen_sharing_risk` | high |
| Privacy & Screen | Screenshot Taken | `screenshot_event` | medium |
| Privacy & Screen | Screenshot & Video Block | `screenshot_protection` | medium |
| Privacy & Screen | SMS Reader Apps | `sms_reader_abuse` | high |
| Privacy & Screen | Third-party Keyboard | `third_party_keyboard` | medium |
| Privacy & Screen | Call During App Use | `vishing_call` | high |
| Device Integrity | USB Debugging (ADB) | `adb_enabled` | medium |
| Device Integrity | App Clone / Dual Space | `clone` | high |
| Device Integrity | Developer Mode | `developer_mode` | low |
| Device Integrity | Device Binding | `device_binding` | high |
| Device Integrity | Device Fingerprint | `device_fingerprint` | medium |
| Device Integrity | Device Lock | `device_lock_missing` | medium |
| Device Integrity | Device State Attestation | `device_state_attestation` | high |
| Device Integrity | Emulator Detection | `emulator` | medium |
| Device Integrity | Known Malware Installed | `malware_reputation` | critical |
| Device Integrity | Mock Location | `mock_location` | high |
| Device Integrity | Root / Jailbreak | `root_jailbreak` | critical |
| Device Integrity | Hardware-Backed Keystore | `secure_hardware_unavailable` | low |
| Device Integrity | SIM Change | `sim_change` | high |
| Device Integrity | Time Spoofing | `time_spoofing` | medium |
| Device Integrity | USB Connection | `usb_connection` | low |
| Runtime Protection | Debugger Attached | `debugger` | medium |
| Runtime Protection | Frida / Instrumentation | `frida` | critical |
| Runtime Protection | Hooking / Method Interception | `hook_detection` | critical |
| Runtime Protection | Reverse-Engineering Tools | `re_tools` | high |
| App Integrity | Signature / Repackaging | `repackage` | high |
| App Integrity | App Tampering | `tamper` | high |
| App Integrity | Task Hijacking | `task_hijack` | high |
| App Integrity | Installation Source | `untrusted_install_source` | high |
| Network Security | IP Reputation | `high_risk_ip` | medium |
| Network Security | SSL / MITM Detection | `mitm` | high |
| Network Security | Unsafe Wi-Fi | `unsafe_wifi` | medium |
| Network Security | VPN Connection | `vpn` | low |
| Other | Risky Application / Environment | `risky_app` | high |

### Raised by the backend (7)

| Category | Detector | Id | Severity |
|---|---|---|---|
| App Integrity | Signing Certificate Mismatch | `tamper_signing_mismatch` | high |
| Fraud Risk | Concurrent Sessions | `concurrent_sessions` | medium |
| Fraud Risk | Device Change Velocity | `device_change_velocity` | high |
| Fraud Risk | Impossible Travel | `impossible_travel` | high |
| Fraud Risk | New Beneficiary | `new_beneficiary` | low |
| Fraud Risk | New Device for Account | `new_device_for_account` | medium |
| Fraud Risk | Transaction Velocity | `transaction_velocity` | high |
