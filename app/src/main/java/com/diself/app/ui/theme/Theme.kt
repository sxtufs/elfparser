package com.diself.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider

private val DarkScheme = darkColorScheme(
    primary = DarkThemeColors.primary,
    background = DarkThemeColors.bg,
    surface = DarkThemeColors.surface,
    onBackground = DarkThemeColors.textPrimary,
    onSurface = DarkThemeColors.textPrimary,
)

private val LightScheme = lightColorScheme(
    primary = LightThemeColors.primary,
    background = LightThemeColors.bg,
    surface = LightThemeColors.surface,
    onBackground = LightThemeColors.textPrimary,
    onSurface = LightThemeColors.textPrimary,
)

@Composable
fun DisElfTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colors = if (darkTheme) DarkThemeColors else LightThemeColors
    val scheme = if (darkTheme) DarkScheme else LightScheme

    CompositionLocalProvider(LocalDisElfColors provides colors) {
        MaterialTheme(
            colorScheme = scheme,
            typography = Typography,
            content = content
        )
    }
}
