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

// Softer, eye-friendly dark mode (One Dark / GitHub style, not harsh pitch black)
val DarkThemeColors = DisElfColors(
    bg = Color(0xFF181A1F),
    surface = Color(0xFF21252B),
    card = Color(0xFF282C34),
    border = Color(0xFF3E4451),
    primary = Color(0xFF00E5FF),
    textPrimary = Color(0xFFECEFF1),
    textSecondary = Color(0xFF90A4AE),
    address = Color(0xFF81C784),
    hexBytes = Color(0xFF78909C),
    mnemonic = Color(0xFF80D8FF),
    operands = Color(0xFFCFD8DC),
    register = Color(0xFFFFD54F),
    changedReg = Color(0xFFFF5252),
    changedRegBg = Color(0x33FF5252),
    isDark = true
)

// Soft paper / IDE Light mode (comfortable for long reading, zero eye strain)
val LightThemeColors = DisElfColors(
    bg = Color(0xFFF3F4F6),
    surface = Color(0xFFFFFFFF),
    card = Color(0xFFFFFFFF),
    border = Color(0xFFE5E7EB),
    primary = Color(0xFF00838F),
    textPrimary = Color(0xFF1E293B),
    textSecondary = Color(0xFF64748B),
    address = Color(0xFF2E7D32),
    hexBytes = Color(0xFF94A3B8),
    mnemonic = Color(0xFF0284C7),
    operands = Color(0xFF334155),
    register = Color(0xFFB45309),
    changedReg = Color(0xFFDC2626),
    changedRegBg = Color(0xFFFEE2E2),
    isDark = false
)

val LocalDisElfColors = compositionLocalOf { DarkThemeColors }

// Global fallback accessors
val BgDark get() = Color(0xFF181A1F)
val SurfaceDark get() = Color(0xFF21252B)
val CardDark get() = Color(0xFF282C34)
val CyanAccent get() = Color(0xFF00E5FF)
val GreenAccent get() = Color(0xFF4CAF50)
val AmberAccent get() = Color(0xFFFFA000)
val RedAccent get() = Color(0xFFE53935)
val ColorAddress get() = Color(0xFF81C784)
val ColorHexBytes get() = Color(0xFF90A4AE)
val ColorMnemonic get() = Color(0xFF80D8FF)
val ColorOperands get() = Color(0xFFCFD8DC)
val ColorRegister get() = Color(0xFFFFD54F)
val ColorChangedReg get() = Color(0xFFFF5252)
