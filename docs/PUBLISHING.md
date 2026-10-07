# Publishing and consuming android-core

The engine AAR contains Kotlin code and a Rust native library
(`libraspshield.so` for arm64-v8a, armeabi-v7a, x86_64; `native/`). Building
it needs a Rust toolchain, so releases are built by GitHub Actions.

## Where releases are published

| Channel | Coordinate / location | Status |
|---|---|---|
| **GitHub Packages (Maven) — primary** | `com.shieldsdk.rasp:android-core:<version>` from `https://maven.pkg.github.com/vgil-darshanj/rasp_sdk_1` | built by `.github/workflows/release.yml` on each `v<version>` tag |
| GitHub Release asset | `android-core-<version>.aar` + `.sha256` on the release page of the tag | same workflow |
| mavenLocal (development) | `com.shieldsdk.rasp:android-core:1.1.0-local` | `./gradlew publishToMavenLocal "-PraspEngineVersion=1.1.0-local"` |
| JitPack | `com.github.vgil-DarshanJ:RASP_SDK_1:<tag>` | **best effort, not verified** (see below) |

`<version>` is the tag without its `v`: tag `v1.1.0` publishes `1.1.0`.

## Consuming from GitHub Packages

GitHub Packages asks for a token even for public packages. Each developer
(or CI) needs a GitHub personal access token (classic) with the
`read:packages` scope. Keep it out of the repository: put it in
`~/.gradle/gradle.properties` (user home, not the project):

```properties
gpr.user=<your GitHub user name>
gpr.key=<token with read:packages>
```

`settings.gradle.kts` of the consuming app:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            name = "RaspShieldEngine"
            url = uri("https://maven.pkg.github.com/vgil-darshanj/rasp_sdk_1")
            credentials {
                username = providers.gradleProperty("gpr.user").orNull ?: System.getenv("GITHUB_ACTOR")
                password = providers.gradleProperty("gpr.key").orNull ?: System.getenv("GITHUB_TOKEN")
            }
            content { includeGroup("com.shieldsdk.rasp") }
        }
    }
}
```

(An app that declares repositories in the root `build.gradle.kts`
`allprojects { repositories { … } }` instead puts the same `maven { … }`
block there.) Then:

```kotlin
dependencies {
    implementation("com.shieldsdk.rasp:android-core:1.1.0")
}
```

In GitHub Actions of the consuming repository, `GITHUB_TOKEN` works if that
repository was given read access to the package (package settings →
Manage Actions access).

### Through the Flutter plugin or the native wrapper

`rasp_shield` (Flutter) and `rasp_shield_native` already depend on
`com.shieldsdk.rasp:android-core:$raspEngineVersion` (default
`1.1.0-local`, from mavenLocal). An app that uses a published engine:

1. adds the repository block above to its Android build
   (`android/settings.gradle.kts` for a Flutter app);
2. sets the version in `android/gradle.properties`:
   `raspEngineVersion=1.1.0`.

### Using the release AAR file directly

Download `android-core-<version>.aar`, check it with
`sha256sum -c android-core-<version>.aar.sha256`, copy it to `app/libs/` and
add `implementation(files("libs/android-core-<version>.aar"))`. A file
dependency carries no POM, so also add the engine's own dependencies:
`com.google.android.play:integrity:1.4.0` and
`androidx.security:security-crypto:1.1.0`.

## Build locally

Prerequisites:

| Tool | Version | Install |
|---|---|---|
| JDK | 17 | Android Studio's JBR or Temurin 17 |
| Android SDK | compileSdk 35 | Android Studio |
| Android NDK | 27.1.12297006 (pinned in `build.gradle.kts`) | `sdkmanager --install "ndk;27.1.12297006"`, or Android Studio → SDK Manager → SDK Tools → NDK (Side by side) |
| Rust | stable (CI pins 1.99.0) | https://rustup.rs |
| Rust Android targets | — | `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` |
| cargo-ndk | 4.1.2 | `cargo install cargo-ndk --version 4.1.2 --locked` |

Commands (from this directory; on Windows use `.\gradlew.bat`):

```
./gradlew testDebugUnitTest assembleRelease publishToMavenLocal "-PraspEngineVersion=1.1.0-local"
cd native && cargo test && cargo clippy --all-targets -- -D warnings
```

Every build first runs `checkNativeToolchain`. When Rust, a target,
cargo-ndk or the NDK is missing, the build stops with a message that lists
what is missing and the exact install command, for example:

```
Execution failed for task ':checkNativeToolchain'.
> The engine includes a Rust native library (native/) and cannot be built without its toolchain:
    - Rust is not installed (cargo / rustup not on PATH). Install rustup from https://rustup.rs, open a new terminal, then run:
        rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
        cargo install cargo-ndk --version 4.1.2 --locked
  See docs/PUBLISHING.md, section "Build locally".
```

Outputs: `build/outputs/aar/android-core-release.aar`; the native libraries
alone in `build/rustJniLibs/<abi>/libraspshield.so`.

## Releasing

1. Make sure `main` builds locally (commands above) and is committed.
2. Push and tag (the tag starts the release workflow):

   ```
   git push origin main
   git tag -a v1.1.0 -m "android-core 1.1.0"
   git push origin v1.1.0
   ```

   Existing tags go up to `v1.0.5`; the first engine with the Rust core
   should be `v1.1.0` or later.
3. Watch the run under the repository's **Actions** tab. When it is green:
   the package appears under **Packages**, and the release page of the tag
   has `android-core-1.1.0.aar` and its `.sha256`.

The workflow uses only the built-in `GITHUB_TOKEN` with `contents: write`
and `packages: write`. If the organization restricts workflow permissions
to read-only (Settings → Actions → General → Workflow permissions), the
publish and release steps fail with 403; allow read and write there.

A tag that already has a release, or a version already in GitHub Packages,
makes the run fail (versions are immutable): bump the version and tag again.

## JitPack

`jitpack.yml` installs rustup (Rust 1.99.0), the three targets, cargo-ndk
4.1.2 and NDK 27.1.12297006 before building. This has **not been
verified**: JitPack's container must allow the downloads (the NDK alone is
about 1 GB) within its build time limit. Treat JitPack as unsupported until
a build at https://jitpack.io/#vgil-DarshanJ/RASP_SDK_1 succeeds; use GitHub
Packages or the release AAR.
