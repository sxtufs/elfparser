# ==============================================================================
# ELFTrace ProGuard & R8 Optimization Rules
# ==============================================================================

# 1. Native JNI Bridge Protection
# JNI method names in libelftrace.so map to exact Java class and method names
-keep class io.elftrace.app.core.JNIBridge { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# 2. JSON Data Models Protection (Gson Deserialization)
# Field names must match JSON keys from native Rust engine exactly.
# `-keep class ... { *; }` already covers fields+methods, so the separate
# -keepclassmembers block was redundant and has been removed.
-keep class io.elftrace.app.core.models.** { *; }
# NARROWER ALTERNATIVE (test on device before enabling): lets R8 obfuscate /
# merge the model classes while still preserving field names for Gson:
#   -keepclassmembers,allowobfuscation class io.elftrace.app.core.models.** { <fields>; }

# 3. Gson Configuration
-keepattributes Signature
-keepattributes *Annotation*
# `EnclosingMethod` is only needed for reflection that inspects enclosing
# methods; not used here. Dropped to shrink the attribute table.
# -keepattributes EnclosingMethod
# Gson 2.10.1 ships consumer ProGuard rules in its AAR, so the library-wide
# keep below is usually unnecessary and blocks R8 from optimizing Gson itself.
# ENABLE THIS ONLY IF a device test shows Gson reflection breaking:
#   -keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**

# 4. ViewModels
# The `by viewModels()` delegate resolves the type at compile time, so the
# class name does not need to be preserved. The no-arg constructor is already
# kept by rule 5. The blanket keep below is therefore usually unnecessary —
# ENABLE THIS ONLY IF a device test shows ViewModel instantiation failing:
#   -keep class io.elftrace.app.viewmodel.** { *; }

# 5. Jetpack Compose & Kotlin Coroutines
-dontwarn kotlinx.coroutines.**
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# 6. Optimization and Obfuscation
-repackageclasses 'io.elftrace.app.internal'
-allowaccessmodification
-dontusemixedcaseclassnames
