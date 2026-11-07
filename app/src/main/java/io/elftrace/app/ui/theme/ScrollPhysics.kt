package io.elftrace.app.ui.theme

import androidx.compose.animation.core.AnimationState
import androidx.compose.animation.core.DecayAnimationSpec
import androidx.compose.animation.core.animateDecay
import androidx.compose.animation.core.exponentialDecay
import androidx.compose.foundation.gestures.FlingBehavior
import androidx.compose.foundation.gestures.ScrollScope
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import kotlin.math.abs

/**
 * Custom momentum fling behavior for ELFTrace.
 * Provides a natural, extended glide on fast swipes with smooth deceleration,
 * while maintaining pixel-perfect precision on slow drags.
 */
class MomentumFlingBehavior(
    private val decay: DecayAnimationSpec<Float>
) : FlingBehavior {
    override suspend fun ScrollScope.performFling(initialVelocity: Float): Float {
        // Ignore tiny accidental micro-flings
        if (abs(initialVelocity) < 1f) return 0f

        var lastValue = 0f
        var velocityLeft = 0f

        AnimationState(
            initialValue = 0f,
            initialVelocity = initialVelocity
        ).animateDecay(decay) {
            val delta = value - lastValue
            val consumed = scrollBy(delta)
            lastValue = value

            // A boundary is reached only when the scroll requested actual movement (abs(delta) > 0.5f)
            // but the scrollable container could not consume movement in that direction.
            // When actively scrolling through content, consumed moves in the same direction as delta.
            val isBoundaryHit = abs(delta) > 0.5f && !(
                (delta > 0f && consumed > 0.2f) || (delta < 0f && consumed < -0.2f)
            )

            if (isBoundaryHit) {
                cancelAnimation()
                // Consume remaining velocity so it doesn't slam into unwanted overscroll elastic bounce
                velocityLeft = 0f
            }
        }
        return velocityLeft
    }
}

/**
 * Creates and remembers a calibrated MomentumFlingBehavior.
 *
 * @param frictionMultiplier Calibrated friction for natural momentum gliding.
 *        A friction of 0.38f provides an extended, satisfying glide through extensive
 *        disassembly and symbol lists (approx 2x travel distance compared to standard
 *        friction) without artificial acceleration or endless drifting.
 */
@Composable
fun rememberMomentumFlingBehavior(
    frictionMultiplier: Float = 0.38f
): FlingBehavior {
    val decay = remember(frictionMultiplier) {
        exponentialDecay<Float>(
            frictionMultiplier = frictionMultiplier,
            absVelocityThreshold = 0.5f
        )
    }
    return remember(decay) {
        MomentumFlingBehavior(decay)
    }
}
