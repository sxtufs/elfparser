package io.elftrace.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

/** Outlined server stack — the menu glyph for the MCP server row. */
@Composable
fun McpServerIcon(tint: Color) {
    Canvas(modifier = Modifier.size(20.dp)) {
        val w = size.width
        val h = size.height
        val barH = h * 0.28f
        val gap = h * 0.08f
        val radius = CornerRadius(barH * 0.28f, barH * 0.28f)
        val stroke = w * 0.09f
        for (i in 0 until 2) {
            val top = h * 0.14f + i * (barH + gap)
            drawRoundRect(
                color = tint,
                topLeft = Offset(w * 0.1f, top),
                size = Size(w * 0.8f, barH),
                cornerRadius = radius,
                style = Stroke(width = stroke)
            )
            drawCircle(
                color = tint,
                radius = barH * 0.14f,
                center = Offset(w * 0.26f, top + barH / 2f)
            )
        }
    }
}
