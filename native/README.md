# libraspshield.so — native core (Rust)

Replaces the earlier C++ shell (`src/main/cpp`, Task 4 step 1). It ports
**existing, already-tested** Kotlin checks; nothing new is detected. Every
function keeps its Kotlin implementation as the fallback.

| Module | Port of | Used by |
|---|---|---|
| `maps.rs` | `/proc/self/maps` rules in `RaspHookAnalysis.kt` (framework libraries, executable mappings from writable places, RWX count without `[anon:dart-code]`, evidence lines) | `hook_detection` (`RaspHookProbes.observe`) |
| `hashing.rs` | `RaspTamperAnalysis.sha256Hex` / `dexSha256` / `normalizeHex`, the signing-certificate digest, `RaspCertificatePinProbes.spkiPin` / `isPin`, constant-time hash comparison | `tamper`, `repackage`, `mitm` pins |
| `root.rs` | file and mount-table checks of `RaspRootAnalysis.kt` / `RaspDeviceIntegrityProbes.kt` (`su`, Magisk/KernelSU paths, busybox, writable protected partitions, mount-table traces) | `root_jailbreak` (`rootAssessment`) |
| `io.rs` | bounded reads (`std::fs`: `openat`/`read` through bionic, no Java I/O) | maps / mounts |
| `jni_entry.rs` | `JNI_OnLoad` + RegisterNatives; the only module allowed `unsafe_code` | — |

**Not ported: the APK signing-block parser** (Task 9.0 item 3d). The engine
has no such parser in Kotlin to port, and this task ports existing checks
only; writing a new one is a separate decision.

## Build

`./gradlew assembleRelease` runs `cargoNdkBuild` (cargo-ndk, NDK
27.1.12297006, `--platform 23`, release profile) for `arm64-v8a`,
`armeabi-v7a` and `x86_64` into `build/rustJniLibs`, then
`generateRaspNativeHashes`, which bakes each library's integrity hash into
`RaspNativeHashes.kt`. Needs: rustup with the three Android targets, and
`cargo install cargo-ndk`.

Release profile: `panic = "abort"`, `lto = true`, `opt-level = "z"`,
`strip = true`, `codegen-units = 1`. Link flags (`.cargo/config.toml`):
`-z max-page-size=16384` (16 KB pages), `-z relro`, `-z now`. Exported
symbols: `JNI_OnLoad` only (a Rust cdylib exports only `#[no_mangle]`
items; methods are registered with RegisterNatives, so no `Java_*` names).

## Safety rules

- No panics on any input: no unchecked indexing or panicking casts; every
  JNI entry runs inside `catch_unwind` (returns `null`/`false`/`-1`). In
  release builds `panic = "abort"`, so a panic would end the process rather
  than unwind into the JVM.
- `unsafe`: `#![deny(unsafe_code)]` crate-wide (`[lints.rust]`). The only
  item the lint covers is `#[no_mangle]` on `JNI_OnLoad` in `jni_entry.rs`.
  There is no `unsafe` block: the `jni` crate (0.21) wraps the raw calls,
  and `register_native_methods` is a safe call whose contract (each
  function pointer matches its signature string) is documented there.
- Bounded reads: maps ≤ 16 MiB, mounts ≤ 4 MiB, lines cut at 8192
  characters. A file larger than its cap is not judged: the call returns
  `null` and Kotlin reads it instead.
- Hashes are compared in constant time (no early exit for equal lengths).
- No logging at all (no paths in any build). Kotlin reasons for an unused
  native core contain no paths.
- Reads use `std::fs` (bionic `openat`/`read`), not raw `syscall`
  instructions: those would need `unsafe` outside the JNI boundary.

## Integrity check at load

`RaspNative.ensureLoaded(context)` reads the library the system loads for
this app's ABI (extracted in `nativeLibraryDir`, or the `lib/<abi>/` entry
of the base or split APK), computes the integrity hash and compares it with
`RaspNativeHashes` (constant time) before `System.loadLibrary`. The hash is
SHA-256 over every PT_LOAD segment with the ELF header's section-table
fields zeroed: an app build strips libraries again (the trial APK's copy is
8 bytes smaller than the AAR's), which rewrites only the section table, so
the hash still matches; any change to loaded code or data does not. On any
failure the detectors run Kotlin and add `native_core_unavailable`
evidence with the reason; a failed load never makes a result SECURE. The
file is hashed and then loaded by name, so a swap between the two calls is
not excluded (this catches a library replaced at rest).

## Tests

- `cargo test`: unit tests per module (including malformed input) and
  `tests/parity.rs`.
- Parity: `fixtures/` holds maps and mount-table inputs, hash vectors and the
  root path lists; the expected files are written by the Kotlin test
  `RaspNativeParityTest` (`RASP_UPDATE_PARITY=1 ./gradlew testDebugUnitTest
  --tests '*RaspNativeParityTest'`), which also checks them on every run.
  `cargo test` checks the Rust side against the same files. A rule changed
  on one side fails the other side's test.
- `RaspNativeFallbackTest` (JVM): the not-loaded path, and the integrity
  hash of the built libraries against the baked values.
- `cargo clippy --all-targets -- -D warnings` (also with
  `--target aarch64-linux-android`).
- Not run here: on-device loading and native results (phone checklist).

## Fuzzing (cargo-fuzz, not run in this repo yet)

```
rustup toolchain install nightly
cargo install cargo-fuzz
cd native
cargo +nightly fuzz run maps_parser -- -max_total_time=600
cargo +nightly fuzz run mounts_parser -- -max_total_time=600
```

Use a Linux or macOS host. Crashes land in `fuzz/artifacts/`.

## Dependency audit

`cargo install cargo-audit && cargo audit` (in `native/`). Direct
dependencies: `jni` 0.21, `sha2` 0.10.

## Known limits

- Releases are built by `.github/workflows/release.yml` (GitHub Packages and
  a release asset); `jitpack.yml` installs the toolchain but is not
  verified. See `docs/PUBLISHING.md`.
- Kotlin and Rust agree on the fixtures (ASCII and common non-ASCII text);
  for maps lines longer than 8192 characters the native core looks at the
  first 8192 only.
