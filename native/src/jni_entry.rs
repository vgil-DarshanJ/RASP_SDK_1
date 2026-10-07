//! The JNI boundary — the only module where `unsafe_code` is allowed. The
//! one item the lint covers is `#[no_mangle]` on `JNI_OnLoad`; there is no
//! `unsafe` block (the `jni` crate wraps the raw JNI calls).
//!
//! `JNI_OnLoad` registers the methods on `com.shieldsdk.rasp.RaspNative`
//! with RegisterNatives, so the library exports only `JNI_OnLoad` (no
//! `Java_*` symbols). Every entry runs its body inside `catch_unwind`: a
//! panic becomes a `null`/`false`/`-1` result, never an unwind into the JVM
//! (release builds use `panic = "abort"`, so a panic there ends the process
//! instead — the code is written not to panic; see the module tests).
//! Native methods return `null` when they cannot answer; Kotlin then uses
//! its own implementation.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jint, jstring, JNI_ERR, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM, NativeMethod};

use crate::io::{read_bounded, ReadOutcome, MAX_MAPS_BYTES};
use crate::{hashing, maps, root, NATIVE_API_VERSION};

const CLASS: &str = "com/shieldsdk/rasp/RaspNative";

/// Called by `System.loadLibrary`.
///
/// `#[no_mangle]` is the exported entry point the VM looks up by name (the
/// `unsafe_code` lint covers it); `vm` comes from the VM and is valid for the
/// whole call.
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> jint {
    catch_unwind(AssertUnwindSafe(|| register(&vm).unwrap_or(JNI_ERR))).unwrap_or(JNI_ERR)
}

fn register(vm: &JavaVM) -> Option<jint> {
    let mut env = vm.get_env().ok()?;
    let class = env.find_class(CLASS).ok()?;
    let methods = [
        method("nativeApiVersion", "()I", native_api_version as *mut c_void),
        method("nativeHookMapsScan", "(Ljava/lang/String;)Ljava/lang/String;", native_hook_maps_scan as *mut c_void),
        method("nativeRootScan", "()Ljava/lang/String;", native_root_scan as *mut c_void),
        method("nativeSha256Hex", "([B)Ljava/lang/String;", native_sha256_hex as *mut c_void),
        method("nativeDexSha256", "([Ljava/lang/String;[[B)Ljava/lang/String;", native_dex_sha256 as *mut c_void),
        method("nativeSpkiPin", "([B)Ljava/lang/String;", native_spki_pin as *mut c_void),
        method("nativeHashEquals", "(Ljava/lang/String;Ljava/lang/String;)Z", native_hash_equals as *mut c_void),
    ];
    // Not an `unsafe` call in jni 0.21, but the same contract holds: every
    // fn_ptr above is an `extern "system"` function whose parameters and
    // return type match its JNI signature string exactly (checked against the
    // `external fun` declarations in RaspNative.kt and by the phone check).
    env.register_native_methods(&class, &methods).ok()?;
    Some(JNI_VERSION_1_6)
}

fn method(name: &str, sig: &str, fn_ptr: *mut c_void) -> NativeMethod {
    NativeMethod { name: name.into(), sig: sig.into(), fn_ptr }
}

fn new_string(env: &mut JNIEnv, value: Option<String>) -> jstring {
    match value {
        Some(s) => env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    if value.is_null() {
        return None;
    }
    env.get_string(value).ok().map(Into::into)
}

extern "system" fn native_api_version(_env: JNIEnv, _class: JClass) -> jint {
    catch_unwind(|| NATIVE_API_VERSION).unwrap_or(-1)
}

/// The maps summary as JSON. With `null` the library reads `/proc/self/maps`
/// itself; `null` result when that read fails or exceeds the cap.
extern "system" fn native_hook_maps_scan(mut env: JNIEnv, _class: JClass, content: JString) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let text = match read_string(&mut env, &content) {
            Some(text) if text.len() <= MAX_MAPS_BYTES => Some(text),
            Some(_) => None,
            None => match read_bounded(Path::new("/proc/self/maps"), MAX_MAPS_BYTES) {
                ReadOutcome::Complete(text) => Some(text),
                ReadOutcome::Truncated | ReadOutcome::Unreadable => None,
            },
        };
        let json = text.map(|t| maps::summarize(&t).to_json());
        new_string(&mut env, json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

extern "system" fn native_root_scan(mut env: JNIEnv, _class: JClass) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = root::scan();
        new_string(&mut env, json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

extern "system" fn native_sha256_hex(mut env: JNIEnv, _class: JClass, bytes: JByteArray) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        if bytes.is_null() {
            return std::ptr::null_mut();
        }
        let digest = env.convert_byte_array(&bytes).ok().map(|b| hashing::sha256_hex(&b));
        new_string(&mut env, digest)
    }))
    .unwrap_or(std::ptr::null_mut())
}

extern "system" fn native_spki_pin(mut env: JNIEnv, _class: JClass, spki: JByteArray) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        if spki.is_null() {
            return std::ptr::null_mut();
        }
        let pin = env.convert_byte_array(&spki).ok().map(|b| hashing::spki_pin(&b));
        new_string(&mut env, pin)
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// `null` when there is no entry, the arrays differ in length, or Kotlin's
/// `dexSha256` would throw.
extern "system" fn native_dex_sha256(
    mut env: JNIEnv,
    _class: JClass,
    names: JObjectArray,
    contents: JObjectArray,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let digest = dex_entries(&mut env, &names, &contents).and_then(|entries| {
            let refs: Vec<(&str, &[u8])> = entries.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
            hashing::dex_sha256(&refs).ok().flatten()
        });
        new_string(&mut env, digest)
    }))
    .unwrap_or(std::ptr::null_mut())
}

fn dex_entries(env: &mut JNIEnv, names: &JObjectArray, contents: &JObjectArray) -> Option<Vec<(String, Vec<u8>)>> {
    if names.is_null() || contents.is_null() {
        return None;
    }
    let count = env.get_array_length(names).ok()?;
    if env.get_array_length(contents).ok()? != count {
        return None;
    }
    let mut entries = Vec::new();
    for i in 0..count {
        let name: JString = env.get_object_array_element(names, i).ok()?.into();
        let name = read_string(env, &name)?;
        let bytes: JObject = env.get_object_array_element(contents, i).ok()?;
        if bytes.is_null() {
            return None;
        }
        let bytes = env.convert_byte_array(JByteArray::from(bytes)).ok()?;
        entries.push((name, bytes));
    }
    Some(entries)
}

extern "system" fn native_hash_equals(mut env: JNIEnv, _class: JClass, a: JString, b: JString) -> jboolean {
    catch_unwind(AssertUnwindSafe(|| {
        match (read_string(&mut env, &a), read_string(&mut env, &b)) {
            (Some(a), Some(b)) if hashing::constant_time_eq(a.as_bytes(), b.as_bytes()) => JNI_TRUE,
            _ => JNI_FALSE,
        }
    }))
    .unwrap_or(JNI_FALSE)
}
