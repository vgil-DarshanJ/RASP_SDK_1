// Standalone root project for JitPack — this repo publishes exactly one
// module (itself), so there is no include(":...") for a subproject here,
// unlike the monorepo copy of this same source at sdk_rasp/android_core.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "android-core"
