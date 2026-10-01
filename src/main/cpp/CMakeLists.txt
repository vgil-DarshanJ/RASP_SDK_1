# libraspshield.so — native half of the RASP engine.
#
# Hardening / packaging choices:
# - 16 KB page alignment (-z max-page-size=16384) so the library loads on
#   Android 15+ devices with 16 KB pages.
# - Hidden visibility: the only exported symbol is JNI_OnLoad; JNI methods
#   are registered with RegisterNatives, so no Java_* names appear in the
#   dynamic symbol table.
# - Stripped at link time (-s); AGP also strips release libraries.
# - No exceptions/RTTI, static libc++ (no libc++_shared.so to ship).
cmake_minimum_required(VERSION 3.22.1)
project(raspshield CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(raspshield SHARED
    jni_entry.cpp
)

target_compile_options(raspshield PRIVATE
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -fno-exceptions
    -fno-rtti
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -O2
    -Wall -Wextra -Werror
)

target_link_options(raspshield PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,--exclude-libs,ALL"
    "-Wl,--gc-sections"
    "-Wl,-z,relro"
    "-Wl,-z,now"
    "-s"
)
