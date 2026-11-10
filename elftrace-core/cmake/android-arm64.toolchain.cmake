
# Force a 64-bit ARM Android target for dependencies whose C code is built via
# CMake (currently: unicorn-engine-sys -> the Unicorn C library).
#
# Why this wrapper exists:
#   The Rust `cmake` crate loads whatever CMAKE_TOOLCHAIN_FILE points at, but it
#   does NOT forward the caller's environment (ANDROID_ABI, etc.) into CMake
#   cache variables. The NDK's android.toolchain.cmake then falls back to its
#   default ABI, armeabi-v7a, which modern clang rejects with
#   `unsupported argument 'armv7-a' to option '-march='`.
#
#   This file seeds the cache variables the NDK toolchain reads *before*
#   including it, guaranteeing an aarch64 (arm64-v8a) build.

if(NOT DEFINED ENV{ANDROID_NDK})
  message(FATAL_ERROR "ANDROID_NDK env var must point at the NDK root")
endif()

set(ANDROID_ABI      "arm64-v8a"  CACHE STRING "Android ABI"       FORCE)
set(ANDROID_PLATFORM "android-24" CACHE STRING "Android API level" FORCE)
set(ANDROID_NDK      "$ENV{ANDROID_NDK}" CACHE PATH "Android NDK root" FORCE)

include("$ENV{ANDROID_NDK}/build/cmake/android.toolchain.cmake")

# Unicorn builds every CPU it supports by default (x86, mips, ppc, ...). For an
# Android ARM64 tool that is pure dead weight. Restrict it to aarch64 only.
# Unicorn 2.x uses the name `aarch64` (1.x used `arm64`). This is a CACHE var,
# so it persists into unicorn's CMakeLists even though we set it here first.
set(UNICORN_ARCHS "aarch64" CACHE STRING "Unicorn target architectures" FORCE)

