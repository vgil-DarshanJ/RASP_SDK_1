// Standalone root project for JitPack — this repo publishes exactly one
// module (itself), so there is no include(":...") for a subproject here.
// This is now the ONLY copy of this source (the old monorepo copy at
// sdk_rasp/android_core was removed once every consumer switched to the
// JitPack coordinate below).

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
