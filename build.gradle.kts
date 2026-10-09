import java.security.MessageDigest

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

group = "com.shieldsdk.rasp"
// Override for a local integration build: -PraspEngineVersion=1.1.0-local
version = providers.gradleProperty("raspEngineVersion").orElse("1.1.0-local").get()

android {
    namespace = "com.shieldsdk.rasp"
    compileSdk = 35

    // Native library (native/, Rust, built by cargo-ndk — see the tasks at
    // the end of this file): pinned NDK; ABIs per Task 4 (no 32-bit x86).
    ndkVersion = "27.1.12297006"

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
        buildConfigField("String", "RASP_ENGINE_VERSION", "\"${project.version}\"")
    }

    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("rustJniLibs"))
    sourceSets["main"].kotlin.srcDir(layout.buildDirectory.dir("generated/raspNativeHashes/kotlin"))

    packaging {
        jniLibs {
            // Already stripped by cargo (profile.release strip = true).
            keepDebugSymbols += "**/libraspshield.so"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            // This is an SDK AAR with a public Kotlin/Java API. Library-side
            // shrinking removed public entry points that no engine source
            // referenced directly (including RaspLeanSession and
            // RaspShieldCore), leaving consumers with unresolved references.
            // Consumer R8 still applies consumer-rules.pro when an app builds
            // a release; do not shrink or rename this published API here.
            isMinifyEnabled = false
        }
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

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.24.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
    testImplementation("androidx.test:core:1.5.0")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.shieldsdk.rasp"
                artifactId = "android-core"
                // Release builds pass the tag without its "v":
                // -PraspEngineVersion=1.1.0 (see .github/workflows/release.yml
                // and docs/PUBLISHING.md).
                version = project.version.toString()
            }
        }
        repositories {
            // GitHub Packages, used by the release workflow only: it exists
            // only when GITHUB_REPOSITORY and GITHUB_TOKEN are set (Actions
            // sets both; the token is the built-in GITHUB_TOKEN).
            val githubRepository = System.getenv("GITHUB_REPOSITORY")
            val githubToken = System.getenv("GITHUB_TOKEN")
            if (!githubRepository.isNullOrBlank() && !githubToken.isNullOrBlank()) {
                maven {
                    name = "GitHubPackages"
                    url = uri("https://maven.pkg.github.com/${githubRepository.lowercase()}")
                    credentials {
                        username = System.getenv("GITHUB_ACTOR")
                        password = githubToken
                    }
                }
            }
        }
    }
}

// ── Native core (Task 9.0): Rust crate in native/, built with cargo-ndk ────
//
// Needs cargo (rustup) with the targets aarch64-linux-android,
// armv7-linux-androideabi, x86_64-linux-android, cargo-ndk, and the NDK
// pinned above. checkNativeToolchain stops the build with install steps
// when one is missing (docs/PUBLISHING.md).
val rustAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")
val rustTargets = listOf("aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android")
val rustJniLibsDir = layout.buildDirectory.dir("rustJniLibs")
val nativeHashesDir = layout.buildDirectory.dir("generated/raspNativeHashes/kotlin")
val pinnedNdkVersion = android.ndkVersion

/** Output of a command, or `null` when it cannot be started or exits non-zero. */
fun commandOutput(vararg command: String): String? = try {
    val process = ProcessBuilder(*command).redirectErrorStream(true).start()
    val text = process.inputStream.bufferedReader().readText()
    if (process.waitFor() == 0) text else null
} catch (e: Exception) {
    null
}

/** The pinned NDK's directory, or `null` when it is not installed. */
fun installedNdkDirectory(): File? = try {
    android.ndkDirectory.takeIf { File(it, "source.properties").isFile }
} catch (e: Exception) {
    null
}

val checkNativeToolchain = tasks.register("checkNativeToolchain") {
    group = "build"
    description = "Fails with install instructions when Rust, the Android targets, cargo-ndk or the NDK is missing."
    doLast {
        val problems = mutableListOf<String>()
        val installedTargets = commandOutput("rustup", "target", "list", "--installed")
        if (commandOutput("cargo", "--version") == null || installedTargets == null) {
            problems += "Rust is not installed (cargo / rustup not on PATH). Install rustup from https://rustup.rs, open a new terminal, then run:\n" +
                "      rustup target add ${rustTargets.joinToString(" ")}\n" +
                "      cargo install cargo-ndk --version 4.1.2 --locked"
        } else {
            val missing = rustTargets.filter { it !in installedTargets.lines().map(String::trim) }
            if (missing.isNotEmpty()) problems += "Missing Rust targets: ${missing.joinToString()}. Run: rustup target add ${rustTargets.joinToString(" ")}"
            if (commandOutput("cargo", "ndk", "--version") == null) {
                problems += "cargo-ndk is not installed. Run: cargo install cargo-ndk --version 4.1.2 --locked"
            }
        }
        if (installedNdkDirectory() == null) {
            problems += "Android NDK $pinnedNdkVersion is not installed. Run: sdkmanager --install \"ndk;$pinnedNdkVersion\" (or Android Studio > SDK Manager > SDK Tools > NDK (Side by side), version $pinnedNdkVersion)"
        }
        if (problems.isNotEmpty()) {
            throw GradleException(
                "The engine includes a Rust native library (native/) and cannot be built without its toolchain:\n" +
                    problems.joinToString("\n") { "  - $it" } +
                    "\nSee docs/PUBLISHING.md, section \"Build locally\".",
            )
        }
    }
}

val cargoNdkBuild = tasks.register<Exec>("cargoNdkBuild") {
    group = "build"
    description = "Builds libraspshield.so for ${rustAbis.joinToString()} with cargo-ndk (release profile)."
    dependsOn(checkNativeToolchain)
    workingDir = file("native")
    inputs.dir("native/src")
    inputs.files("native/Cargo.toml", "native/Cargo.lock", "native/.cargo/config.toml")
    outputs.dir(rustJniLibsDir)
    val outDir = rustJniLibsDir.get().asFile
    doFirst {
        // Resolved here, not while configuring, so a missing NDK is reported
        // by checkNativeToolchain instead of failing every Gradle command.
        environment("ANDROID_NDK_HOME", installedNdkDirectory()!!.absolutePath)
    }
    commandLine(
        listOf("cargo", "ndk") + rustAbis.flatMap { listOf("-t", it) } +
            listOf("--platform", "23", "-o", outDir.absolutePath, "build", "--release", "--locked"),
    )
}

/**
 * The integrity hash RaspNative checks before loading (same algorithm as
 * RaspNativeIntegrity.loadSegmentsSha256): SHA-256 over every PT_LOAD
 * segment's file bytes, with the ELF header's section-table fields zeroed,
 * so an app build that strips the library again does not change it.
 */
fun loadSegmentsSha256(file: File): String {
    val data = file.readBytes()
    require(data.size >= 0x40 && data[0] == 0x7f.toByte() && data[5] == 1.toByte()) { "not a little-endian ELF: $file" }
    val is64 = data[4].toInt() == 2
    val fields = if (is64) listOf(0x28 to 8, 0x3A to 2, 0x3C to 2, 0x3E to 2) else listOf(0x20 to 4, 0x2E to 2, 0x30 to 2, 0x32 to 2)
    fields.forEach { (offset, length) -> data.fill(0.toByte(), offset, offset + length) }
    fun le(at: Int, n: Int): Long = (0 until n).fold(0L) { acc, i -> acc or ((data[at + i].toLong() and 0xff) shl (8 * i)) }
    val phoff = (if (is64) le(0x20, 8) else le(0x1C, 4)).toInt()
    val phentsize = le(if (is64) 0x36 else 0x2A, 2).toInt()
    val phnum = le(if (is64) 0x38 else 0x2C, 2).toInt()
    val md = MessageDigest.getInstance("SHA-256")
    for (i in 0 until phnum) {
        val base = phoff + i * phentsize
        if (le(base, 4) != 1L) continue
        val offset = (if (is64) le(base + 8, 8) else le(base + 4, 4)).toInt()
        val size = (if (is64) le(base + 32, 8) else le(base + 16, 4)).toInt()
        md.update(data, offset, size)
    }
    return md.digest().joinToString("") { "%02X".format(it) }
}

val generateRaspNativeHashes = tasks.register("generateRaspNativeHashes") {
    group = "build"
    description = "Writes the expected integrity hash of each libraspshield.so into RaspNativeHashes.kt."
    dependsOn(cargoNdkBuild)
    val libsDir = rustJniLibsDir
    val outDir = nativeHashesDir
    inputs.dir(libsDir)
    outputs.dir(outDir)
    doLast {
        val entries = rustAbis.map { abi ->
            val so = libsDir.get().file("$abi/libraspshield.so").asFile
            check(so.isFile) { "missing $so — did cargoNdkBuild run?" }
            "        \"$abi\" to \"${loadSegmentsSha256(so)}\","
        }
        val target = outDir.get().file("com/shieldsdk/rasp/RaspNativeHashes.kt").asFile
        target.parentFile.mkdirs()
        target.writeText(
            """
            |// Generated by the generateRaspNativeHashes Gradle task - do not edit.
            |package com.shieldsdk.rasp
            |
            |/** Expected RaspNativeIntegrity.loadSegmentsSha256 of libraspshield.so per ABI, from this build. */
            |internal object RaspNativeHashes {
            |    val EXPECTED: Map<String, String> = mapOf(
            |${entries.joinToString("\n")}
            |    )
            |}
            |""".trimMargin(),
        )
    }
}

tasks.named("preBuild") { dependsOn(cargoNdkBuild, generateRaspNativeHashes) }
tasks.configureEach {
    if (name.endsWith("SourcesJar") || name.startsWith("sourceRelease") || name.startsWith("sourceDebug")) {
        dependsOn(generateRaspNativeHashes)
    }
}
