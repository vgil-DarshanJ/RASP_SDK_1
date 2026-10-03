# Package visibility (`<queries>`) in the engine manifest

Android 11 (API 30) and later only let an app see the installed packages it
declares in its manifest `<queries>` element. The engine
(`src/main/AndroidManifest.xml`) declares two kinds of entries, and Android's
manifest merger copies them into every app that includes the SDK.

## What is declared

| Entry | Used by | Why |
|---|---|---|
| `<package android:name="…"/>` for 13 named packages (remote-access tools, Xposed/Magisk-related apps, Lucky Patcher, …) | `risky_app`, `re_tools` | each is checked only for presence with `PackageManager.getPackageInfo()` |
| `<intent>` for `ACTION_MAIN` + `CATEGORY_LAUNCHER` | `task_hijack`, `malware_reputation` | makes every app that has a **launcher icon** visible, so other apps' activities and the reputation list's packages can be checked |

The launcher intent does **not** make apps without a launcher activity
visible (some background-only apps); those are only visible if the host app
lists them as `<package>` entries itself.

## What is not used

The SDK never declares, requests or checks `android.permission.QUERY_ALL_PACKAGES`
(the broad visibility permission Google Play restricts). A search of the
engine, the Flutter plugin, the native module and the trial app finds it only
in comments that say it is not requested.

## The detectors are off by default

`taskHijackDetection` and `malwareReputationDetection` default to `false` in
`RaspLeanConfig` (Kotlin and Dart). The `<queries>` entries are merged into
the host app whether or not those detectors are turned on, because a
manifest cannot depend on runtime configuration.

## Removing the launcher entry from a host app

A host app that does not want the broader visibility can remove the merged
intent in its own `AndroidManifest.xml`:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
    <queries>
        <intent tools:node="remove">
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent>
    </queries>
</manifest>
```

Effect: `task_hijack` and `malware_reputation` still run (if enabled) but see
fewer packages; both report the scope as `visibility` evidence and the number
of packages they could see (`visible_packages` for `task_hijack`). For
`malware_reputation`, the host can instead declare the list's packages as
`<package>` entries.

## Google Play

Declaring `<queries>` entries does not need a Play Console declaration (only
`QUERY_ALL_PACKAGES` does), but Play reviews package-visibility use against
its policy. The bank publishing the app should confirm the launcher intent
is acceptable for its listing, or remove it as shown above.
