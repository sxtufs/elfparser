package com.diself.app.ui.theme

import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.graphics.Color

data class DisElfColors(
    val bg: Color,
    val surface: Color,
    val card: Color,
    val border: Color,
    val primary: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val address: Color,
    val hexBytes: Color,
    val mnemonic: Color,
    val operands: Color,
    val register: Color,
    val changedReg: Color,
    val changedRegBg: Color,
    val isDark: Boolean
)

// Softer, eye-friendly dark mode (Atom / GitHub Dark charcoal, not harsh pitch black)
val DarkThemeColors = DisElfColors(
    bg = Color(0xFF181A1F),
    surface = Color(0xFF21252B),
    card = Color(0xFF282C34),
    border = Color(0xFF3E4451),
    primary = Color(0xFF00ACC1),     // Calm, comfortable teal-cyan (zero neon glare)
    textPrimary = Color(0xFFECEFF1),
    textSecondary = Color(0xFF90A4AE),
    address = Color(0xFF81C784),     // Soft pastel green
    hexBytes = Color(0xFF78909C),
    mnemonic = Color(0xFF80D8FF),    // Sky blue
    operands = Color(0xFFCFD8DC),
    register = Color(0xFFFFD54F),    // Soft amber
    changedReg = Color(0xFFFF5252),
    changedRegBg = Color(0x33FF5252),
    isDark = true
)

// Calibrated Eye-Comfort Light Mode (Soft, blended, zero eye strain)
val LightThemeColors = DisElfColors(
    bg = Color(0xFFF8F9FA),          // Soft off-white paper canvas
    surface = Color(0xFFFFFFFF),     // Pure surface
    card = Color(0xFFFFFFFF),
    border = Color(0xFFE2E8F0),      // Gentle border
    primary = Color(0xFF0284C7),     // Clean, modern sky-blue (blends seamlessly)
    textPrimary = Color(0xFF1E293B), // Deep readable charcoal
    textSecondary = Color(0xFF64748B),
    address = Color(0xFF16A34A),     // Crisp readable forest green
    hexBytes = Color(0xFF64748B),    // Muted slate grey
    mnemonic = Color(0xFF0284C7),    // Keyword blue
    operands = Color(0xFF1E293B),    // High-contrast charcoal
    register = Color(0xFFD97706),    // Warm deep amber/brown
    changedReg = Color(0xFFDC2626),  // Crimson red
    changedRegBg = Color(0xFFFFEBE9),// Soft pink-red highlight
    isDark = false
)

val LocalDisElfColors = compositionLocalOf { DarkThemeColors }

// Global fallback accessors
val BgDark get() = Color(0xFF181A1F)
val SurfaceDark get() = Color(0xFF21252B)
val CardDark get() = Color(0xFF282C34)
val CyanAccent get() = Color(0xFF00ACC1)
val GreenAccent get() = Color(0xFF4CAF50)
val AmberAccent get() = Color(0xFFFFA000)
val RedAccent get() = Color(0xFFE53935)
val ColorAddress get() = Color(0xFF81C784)
val ColorHexBytes get() = Color(0xFF78909C)
val ColorMnemonic get() = Color(0xFF80D8FF)
val ColorOperands get() = Color(0xFFCFD8DC)
val ColorRegister get() = Color(0xFFFFD54F)
val ColorChangedReg get() = Color(0xFFFF5252)
