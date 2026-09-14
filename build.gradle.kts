// android_core — the single source of truth for every RASP Shield detection
// class. Published to JitPack from this standalone repo (see jitpack.yml)
// so the Flutter plugin and the native Android SDK both depend on it as a
// normal Maven coordinate (`implementation("com.github.<owner>:<repo>:<tag>")`)
// instead of a `project(":android_core")` source-folder reference — that
// source-folder wiring required every consumer to manually clone this
// module and edit their own settings.gradle.kts, which is not how any
// other RASP vendor's SDK integrates. This repo IS the root project (no
// parent monorepo needed) precisely so it can be built and published
// standalone by JitPack on every tagged release.
//
// Pinned to AGP 8.7.2 / Kotlin 2.0.21 / Gradle 8.10.2 — deliberately
// NOT the bleeding-edge AGP 9.1.0/Gradle 9.3.1 combo the rest of this
// SDK's monorepo uses. AGP 9's restructured "Unified Test Platform" and
// new variant-builder internals repeatedly crashed JitPack's own
// dependency-scanning script (listDeps) with a
// ConcurrentModificationException — first on the androidTest classpath,
// then, even after disabling that variant, on the unitTest classpath via
// an API (HasUnitTestBuilder.enableUnitTest) that should have resolved
// per AGP's own bytecode but didn't compile in this build script. Rather
// than keep patching around individual AGP-9-specific config quirks
// JitPack's tooling hasn't caught up to, this repo targets the same
// well-proven AGP/Gradle line the vast majority of JitPack-published
// Android libraries already build against successfully today. Only
// affects THIS standalone publish target. (The monorepo used to keep a
// separate copy of this source on the newer toolchain for local dev —
// that copy was removed once every consumer switched to the JitPack
// coordinate this repo publishes, so this is now the only copy.)
//
// Every SDK/version value below is a literal, not sourced from any
// `flutter.*` Gradle property — this module must compile with no Flutter
// tooling present at all.
//
// No `src/test`/`src/androidTest` here either (unlike the monorepo
// copy) — this repo's only job is to build+publish the release AAR,
// which needs neither.

plugins {
    id("com.android.library") version "8.7.2"
    id("org.jetbrains.kotlin.android") version "2.0.21"
    `maven-publish`
}

android {
    namespace = "com.shieldsdk.rasp"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    // Publishes the "release" AAR variant as a Maven publication — this is
    // what JitPack picks up and republishes under the
    // com.github.<owner>:<repo>:<tag> coordinate consumers actually use.
    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Play Integrity attestation (Phase 7) — the only external runtime
    // dependency any detector in this module needs.
    implementation("com.google.android.play:integrity:1.4.0")

    // Keystore-backed EncryptedSharedPreferences for RaspEventShipper's
    // configureAndPersist/restore — the native-Kotlin equivalent of the
    // Flutter SDK's flutter_secure_storage-backed persistence. Same
    // security property: a credential surviving app restart is stored
    // encrypted, tied to the device Keystore, not in a plain XML file.
    implementation("androidx.security:security-crypto:1.1.0")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.shieldsdk.rasp"
                artifactId = "android-core"
                // The actual version consumers use is the Git tag, via the
                // com.github.<owner>:<repo>:<tag> coordinate — JitPack maps
                // the requested tag onto whatever this builds regardless of
                // the literal string here.
                version = "1.0.0"
            }
        }
    }
}
