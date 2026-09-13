# RaShield android-core

The shared Android detection engine behind RaShield's Flutter plugin and
native Android SDK — root/jailbreak, Frida, hooking, tamper, MITM, overlay,
and every other detector, implemented once here so both integration paths
report identically.

Published via [JitPack](https://jitpack.io) on every tagged release. Add it
to a Gradle project with:

```kotlin
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.Vedant0Nisar:RaShield-SDK:v1.0.0")
}
```

This repository is not meant to be used standalone by application
developers — it's a dependency of the Flutter and Android Native RaShield
SDKs, which wire up detector configuration, event shipping, and the
lean-session polling loop on top of it.
