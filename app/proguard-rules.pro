# ==============================================================================
# DisElf ProGuard & R8 Optimization Rules
# ==============================================================================

# 1. Native JNI Bridge Protection
# JNI method names in libdiself.so map to exact Java class and method names
-keep class com.diself.app.core.JNIBridge { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# 2. JSON Data Models Protection (Gson Deserialization)
# Field names must match JSON keys from native Rust engine exactly
-keep class com.diself.app.core.models.** { *; }
-keepclassmembers class com.diself.app.core.models.** {
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
-keep class com.diself.app.viewmodel.** { *; }

# 5. Jetpack Compose & Kotlin Coroutines
-dontwarn kotlinx.coroutines.**
-keepclassmembers class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# 6. Optimization and Obfuscation
-repackageclasses 'com.diself.app.internal'
-allowaccessmodification
-dontusemixedcaseclassnames
