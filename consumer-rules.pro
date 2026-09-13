# Play Integrity's response models are deserialized reflectively by
# Google's own client library — required wherever the Phase 7 attestation
# surface is included in a consuming app's release/R8-minified build.
-keep class com.google.android.play.core.integrity.** { *; }

# RaspHookProbes.criticalMethods resolves six specific methods reflectively
# by hardcoded class+method name string, as its own integrity check (a
# Java-level hooking framework replaces a method's entry point, after
# which ART reports it as `native` — see RaspHookProbes' class doc). A
# real, pre-existing gap this port found: with NO keep rule, R8
# minification/obfuscation on a consuming app's release build silently
# renames these methods, the reflection permanently resolves to
# MethodIntegrity.UNAVAILABLE for every one of them, and hook_native_method
# can never fire again — not a crash, just a detector quietly gone blind.
# RaspShieldCore.selfTest() (Phase 9) checks this exact condition at
# runtime so a release-build QA pass catches it if this rule is ever
# accidentally dropped.
-keep class com.shieldsdk.rasp.RaspDeviceProbes {
    boolean isFridaDetected();
    boolean isDebuggerAttached();
}
-keep class com.shieldsdk.rasp.RaspHookProbes {
    boolean isHookingDetected();
}
-keep class com.shieldsdk.rasp.RaspSignalAnalysis {
    boolean fridaVerdict(java.util.List);
    boolean debuggerVerdict(java.util.List);
}
-keep class com.shieldsdk.rasp.RaspHookAnalysis {
    boolean hookVerdict(java.util.List);
}
