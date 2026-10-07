# RaShield android-core

The shared Android detection engine behind RaShield's Flutter plugin and
native Android SDK — root/jailbreak, Frida, hooking, tamper, MITM, overlay,
and every other detector, implemented once here so both integration paths
report identically.

The AAR includes a Rust native library (`native/`). Releases are built by
GitHub Actions on each `v<version>` tag and published to **GitHub Packages**
as `com.shieldsdk.rasp:android-core:<version>`, plus the AAR as a GitHub
Release asset. Repository block, local build (needs Rust, cargo-ndk and the
NDK) and release steps: [docs/PUBLISHING.md](docs/PUBLISHING.md). JitPack
is best effort and not verified.

This repository is not meant to be used standalone by application
developers — it's a dependency of the Flutter and Android Native RaShield
SDKs, which wire up detector configuration, event shipping, and the
lean-session polling loop on top of it.
