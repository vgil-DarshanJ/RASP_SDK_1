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
// Every SDK/version value below is a literal, not sourced from any
// `flutter.*` Gradle property — this module must compile with no Flutter
// tooling present at all.
//
// Deliberately has no `src/test` or `src/androidTest` here (unlike the
// sdk_rasp/android_core monorepo copy, which keeps both for local dev
// QA). JitPack's own dependency-scanning step (listDeps) chokes with a
// ConcurrentModificationException enumerating AGP's "Unified Test
// Platform" configurations (_internal-unified-test-platform-*) — and, it
// turns out, AGP 9 creates that whole configuration set unconditionally
// for every library module's androidTest variant, REGARDLESS of whether
// any androidTest dependency is declared (confirmed: removing them alone
// didn't change anything). `enableAndroidTest = false` below is what
// actually stops AGP from creating that variant at all. This repo's only
// job is to build+publish the release AAR, which never needed an
// androidTest variant in the first place.

plugins {
    id("com.android.library") version "9.1.0"
    id("org.jetbrains.kotlin.android") version "2.4.0"
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
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

androidComponents {
    beforeVariants {
        it.enableAndroidTest = false
    }
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
