package io.elftrace.app.ui.theme

import androidx.compose.foundation.gestures.FlingBehavior
import androidx.compose.foundation.gestures.ScrollableDefaults
import androidx.compose.runtime.Composable

/**
 * Returns Android's native spline-based fling behavior so scrolling feels
 * light, responsive, and free of mid-list stops or artificial bounce.
 */
@Composable
fun rememberMomentumFlingBehavior(
    @Suppress("UNUSED_PARAMETER") frictionMultiplier: Float = 0.38f
): FlingBehavior {
    return ScrollableDefaults.flingBehavior()
}
