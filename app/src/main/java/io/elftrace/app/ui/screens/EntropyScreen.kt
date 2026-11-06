package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Equalizer
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.SectionEntropy
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel

@Composable
fun EntropyScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val entropyReport by viewModel.entropyReport.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        // Overall Entropy Summary Card
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Equalizer, contentDescription = null, tint = colors.primary)
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "Entropy Radar & Packer Detector",
                            style = MaterialTheme.typography.titleMedium,
                            color = colors.textPrimary,
                            fontWeight = FontWeight.Bold
                        )
                        val report = entropyReport
                        val scoreText = if (report != null) "${report.overall_entropy} / 8.0" else "Calculating..."
                        val verdictText = report?.overall_verdict ?: "Scan pending"

                        val verdictColor = when {
                            report?.is_likely_packed == true -> RedAccent
                            (report?.overall_entropy ?: 0.0) > 6.4 -> AmberAccent
                            else -> Color(0xFF4CAF50)
                        }

                        Text(
                            text = "$scoreText  •  $verdictText",
                            style = MaterialTheme.typography.bodySmall,
                            color = verdictColor,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                IconButton(onClick = { viewModel.refreshEntropyReport() }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Rescan", tint = colors.primary)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        if (entropyReport != null) {
            val sections = entropyReport!!.sections
            if (sections.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No section entropy records available.", color = colors.textSecondary)
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    flingBehavior = rememberMomentumFlingBehavior(),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(
                        items = sections,
                        key = { "${it.address}_${it.name}" },
                        contentType = { "entropy_item" }
                    ) { sec ->
                        SectionEntropyCard(sec, colors)
                    }
                }
            }
        } else {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("Load a binary to calculate Shannon entropy.", color = colors.textSecondary)
            }
        }
    }
}

@Composable
private fun SectionEntropyCard(sec: SectionEntropy, colors: ELFTraceColors) {
    val progress = (sec.entropy / 8.0).toFloat().coerceIn(0f, 1f)
    val barColor = when {
        sec.is_high_entropy -> RedAccent
        sec.entropy > 6.5 -> AmberAccent
        else -> colors.primary
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = colors.card),
        shape = RoundedCornerShape(8.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = sec.name,
                        color = colors.textPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "0x${"%08X".format(sec.address)}  |  ${formatSize(sec.size)}",
                        color = colors.address,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                }

                Text(
                    text = "${"%.2f".format(sec.entropy)} / 8.0",
                    color = barColor,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(Modifier.height(6.dp))

            // Linear Entropy Bar
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp),
                color = barColor,
                trackColor = colors.surface,
                strokeCap = androidx.compose.ui.graphics.StrokeCap.Round
            )

            Spacer(Modifier.height(4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = sec.status,
                    color = if (sec.is_high_entropy) RedAccent else colors.textSecondary,
                    fontSize = 10.5.sp,
                    fontWeight = if (sec.is_high_entropy) FontWeight.Bold else FontWeight.Normal
                )

                if (sec.is_high_entropy) {
                    Text(
                        text = "HIGH ENTROPY",
                        color = RedAccent,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

private fun formatSize(bytes: Long): String {
    return when {
        bytes >= 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
        bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }
}
