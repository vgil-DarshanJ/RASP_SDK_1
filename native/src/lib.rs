//! Native core of the RASP Shield Android engine (`libraspshield.so`).
//!
//! Ports of existing, already-tested Kotlin checks — same inputs, same
//! verdicts (see the parity fixtures in `fixtures/`):
//! - [maps]: `/proc/self/maps` parsing and the hook signal rules
//!   (`RaspHookAnalysis.kt`);
//! - [hashing]: SHA-256 and the certificate / SPKI / dex hashing helpers
//!   (`RaspTamperAnalysis.kt`, `RaspCertificatePinProbes.kt`,
//!   `RaspSigningProbes.kt`), with constant-time comparison;
//! - [root]: the root file and mount-table signal checks
//!   (`RaspRootAnalysis.kt`, `RaspDeviceIntegrityProbes.kt`).
//!
//! Rules: no panics on any input (bounded reads, no unchecked indexing);
//! no logging at all (so no paths in logs); `unsafe` only in [jni_entry].
//! The Kotlin implementation stays as the fallback for every function.

pub mod hashing;
pub mod io;
pub mod json;
pub mod maps;
pub mod root;
pub mod text;

mod jni_entry;

/// Bumped whenever the registered JNI methods change; `RaspNative.kt`
/// refuses a library that reports another value.
pub const NATIVE_API_VERSION: i32 = 2;
