// JNI entry point for libraspshield.so.
//
// Methods are registered in JNI_OnLoad with RegisterNatives (on
// com.shieldsdk.rasp.RaspNative), so the library exports only JNI_OnLoad.
#include <jni.h>

namespace {

// Bumped whenever the set or signature of registered methods changes;
// RaspNative.kt refuses to use a library reporting a different value.
constexpr jint kNativeApiVersion = 1;

jint NativeApiVersion(JNIEnv*, jclass) { return kNativeApiVersion; }

const JNINativeMethod kMethods[] = {
    {"nativeApiVersion", "()I", reinterpret_cast<void*>(NativeApiVersion)},
};

}  // namespace

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  JNIEnv* env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
  jclass cls = env->FindClass("com/shieldsdk/rasp/RaspNative");
  if (cls == nullptr) return JNI_ERR;
  const jint count = static_cast<jint>(sizeof(kMethods) / sizeof(kMethods[0]));
  const bool ok = env->RegisterNatives(cls, kMethods, count) == JNI_OK;
  env->DeleteLocalRef(cls);
  return ok ? JNI_VERSION_1_6 : JNI_ERR;
}
