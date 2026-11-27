package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.TriageItem
import io.elftrace.app.core.models.TriageReport
import io.elftrace.app.ui.theme.LocalELFTraceColors
import io.elftrace.app.viewmodel.ELFTraceViewModel

@Composable
fun TriageScreen(viewModel: ELFTraceViewModel) {
    val report by viewModel.triageReport.collectAsState()
    val colors = LocalELFTraceColors.current

    LaunchedEffectOnShow(viewModel)

    when {
        report == null -> Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) { CircularProgressIndicator() }

        report != null && report!!.items.isEmpty() -> Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) { Text("No triage data", color = colors.textSecondary, fontSize = 14.sp) }

        else -> TriageReportView(report!!)
    }
}

@Composable
private fun LaunchedEffectOnShow(viewModel: ELFTraceViewModel) {
    androidx.compose.runtime.LaunchedEffect(Unit) {
        if (viewModel.triageReport.value == null) viewModel.refreshTriageReport()
    }
}

@Composable
private fun TriageReportView(report: TriageReport) {
    val colors = LocalELFTraceColors.current
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        contentPadding = PaddingValues(vertical = 12.dp)
    ) {
        items(report.items.size) { idx ->
            TriageCard(report.items[idx])
        }
        if (report.needed_libs.isNotEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = colors.card)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            "Linked Libraries (${report.needed_libs.size})",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.textPrimary
                        )
                        Spacer(Modifier.height(6.dp))
                        report.needed_libs.forEach { lib ->
                            Text(
                                lib,
                                fontSize = 12.sp,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                color = colors.textSecondary
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun TriageCard(item: TriageItem) {
    val colors = LocalELFTraceColors.current
    val (accent, label) = when (item.status) {
        "Good" -> Color(0xFF4CAF50) to "OK"
        "Weak" -> Color(0xFFF44336) to "MISSING"
        "Warn" -> Color(0xFFFFC107) to "CHECK"
        else -> colors.primary to "INFO"
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = colors.card)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(item.name, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = colors.textPrimary)
                Spacer(Modifier.height(2.dp))
                Text(item.detail, fontSize = 12.sp, color = colors.textSecondary)
            }
            Spacer(Modifier.width(10.dp))
            Surface(shape = RoundedCornerShape(6.dp), color = accent.copy(alpha = 0.15f)) {
                Text(
                    label,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = accent
                )
            }
        }
    }
}
