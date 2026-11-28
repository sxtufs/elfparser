# ELFTrace ProGuard & R8 rules.

# Native JNI bridge: JNI method names in libelftrace.so map to exact Java class
# and method names, so they must not be renamed.
-keep class io.elftrace.app.core.JNIBridge { *; }

# MCP export sink: libelftrace.so looks the class and `publish` up by name from
# the MCP server thread, so neither may be renamed or removed.
-keep class io.elftrace.app.core.McpExport { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# JSON data models (Gson deserialization).
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

# Gson configuration.
-keepattributes Signature
# `EnclosingMethod` is only needed for reflection that inspects enclosing
# methods; not used here. Dropped to shrink the attribute table.
# -keepattributes EnclosingMethod
# Gson 2.10.1 ships consumer ProGuard rules in its AAR, so the library-wide
# keep below is usually unnecessary and blocks R8 from optimizing Gson itself.
# ENABLE THIS ONLY IF a device test shows Gson reflection breaking:
#   -keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**

# ViewModels.
# The `by viewModels()` delegate resolves the type at compile time, so the
# class name does not need to be preserved. The no-arg constructor is already
# kept by the ViewModel keepclassmembers rule below. The blanket keep is
# therefore usually unnecessary —
# ENABLE THIS ONLY IF a device test shows ViewModel instantiation failing:
#   -keep class io.elftrace.app.viewmodel.** { *; }

# Jetpack Compose & Kotlin coroutines.
-dontwarn kotlinx.coroutines.**
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# Optimization and obfuscation.
-repackageclasses 'io.elftrace.app.internal'
-allowaccessmodification
-dontusemixedcaseclassnames
