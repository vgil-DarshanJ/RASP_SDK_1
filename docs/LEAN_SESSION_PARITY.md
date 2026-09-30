# Flutter lean-session parity

The Dart lean-session implementation was replaced by a Flutter facade over
`RaspLeanSession` in the Kotlin engine. The facade owns only configuration,
state decoding, and the EventChannel subscription; ticking, deadline handling,
detector execution, change detection, and native audit shipping are Kotlin-only.

| Former Dart behavior | Kotlin coverage |
|---|---|
| Debug build is a debugger finding, combined with an attached-debugger check | `RaspLeanSession.runExtended()` enables `RaspShieldCore.checkDebuggerBlocking()` for `debuggerDetection`; that method combines `FLAG_DEBUGGABLE` with JDWP/`TracerPid` signals. |
| Device fingerprint posture check | `RaspLeanSession.runExtended()` enables `RaspShieldCore.checkDeviceFingerprintBlocking()` for `deviceFingerprintCheck`; `RaspDeviceFingerprintProbes` supplies lock, ADB, SELinux, and install-source state. |
| MITM/proxy check | `RaspLeanSession.runExtended()` enables `RaspShieldCore.checkMitmBlocking()` for `mitmDetection`; it uses proxy/user-CA signals and configured SPKI pinning. |
| High-risk IP lookup | `RaspLeanSession.runExtended()` enables `RaspShieldCore.checkHighRiskIpBlocking()` for `highRiskIpDetection`; `RaspGeoIpProbes` performs the bounded lookup. |
| Repackage expected-certificate configuration | `RaspSecurityChannelHandler.leanConfig()` maps `expectedSigningCertSha256`; `RaspLeanSession.applyConfig()` passes it to `RaspShieldCore.configureExpectedSigningCertificate()` before `checkRepackagingBlocking()` runs. |

No behavior gap was found in this review. The Flutter facade maps the same
configuration keys in `lib/sdk/lean_session.dart` and starts the Kotlin session
through `startLeanSession`.
