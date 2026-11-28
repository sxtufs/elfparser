package io.elftrace.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/** Sun in dark mode, moon in light mode — the glyph the toolbar toggle used. */
@Composable
fun ThemeToggleIcon(isDark: Boolean, tint: Color) {
    if (isDark) {
        Canvas(modifier = Modifier.size(20.dp)) {
            val r = size.minDimension / 2f
            val center = Offset(r, r)
            drawCircle(color = tint, radius = r * 0.42f, center = center)
            for (i in 0 until 8) {
                val angle = i * Math.PI / 4.0
                val start = Offset(
                    (center.x + Math.cos(angle) * r * 0.62).toFloat(),
                    (center.y + Math.sin(angle) * r * 0.62).toFloat()
                )
                val end = Offset(
                    (center.x + Math.cos(angle) * r * 0.95).toFloat(),
                    (center.y + Math.sin(angle) * r * 0.95).toFloat()
                )
                drawLine(color = tint, start = start, end = end, strokeWidth = 2.2f)
            }
        }
    } else {
        Canvas(modifier = Modifier.size(20.dp)) {
            val r = size.minDimension / 2f
            drawCircle(color = tint, radius = r * 0.75f, center = Offset(r * 0.9f, r * 1.1f))
            drawCircle(color = Color.White, radius = r * 0.62f, center = Offset(r * 0.65f, r * 0.85f))
        }
    }
}
