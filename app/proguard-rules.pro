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
# Field names must match JSON keys from native Rust engine exactly
-keep class io.elftrace.app.core.models.** { *; }
-keepclassmembers class io.elftrace.app.core.models.** {
    <fields>;
    <methods>;
}

# 3. Gson Configuration
-keepattributes Signature
-keepattributes *Annotation*
-keepattributes EnclosingMethod
-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**

# 4. ViewModels
-keep class io.elftrace.app.viewmodel.** { *; }

# 5. Jetpack Compose & Kotlin Coroutines
-dontwarn kotlinx.coroutines.**
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# 6. Optimization and Obfuscation
-repackageclasses 'io.elftrace.app.internal'
-allowaccessmodification
-dontusemixedcaseclassnames
