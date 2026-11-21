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
# Gson maps JSON keys -> field names by reflection, so field names and the
# no-arg constructor MUST be preserved. The class NAMES may be obfuscated:
# every model is referenced via `SomeClass::class.java` (a compile-time
# reference), so R8 renames the class and its references together.
#
# NOTE: deliberately NOT using `allowobfuscation` here. That variant lets R8
# merge/remove model classes, which previously produced default-valued fields
# (Gson resolved a merged/inlined type). Keeping members without the
# allowobfuscation flag preserves class identity while still renaming it.
-keepclassmembers class io.elftrace.app.core.models.** {
    <fields>;
    <init>(...);
}
-keepattributes *Annotation*

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
