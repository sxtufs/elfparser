package com.diself.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel
import com.diself.app.viewmodel.Screen

@Composable
fun SecurityScreen(viewModel: DisElfViewModel) {
    val colors = LocalDisElfColors.current
    val scanReport by viewModel.scanReport.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(12.dp)
    ) {
        // Toolbar
        Card(
            colors = CardDefaults.cardColors(containerColor = colors.surface),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = colors.primary)
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text("Security & Crypto Scanner", style = MaterialTheme.typography.titleMedium, color = colors.textPrimary)
                        val count = scanReport?.total_findings ?: 0
                        val statusText = when (count) {
                            0 -> "No detections found"
                            1 -> "1 detection found"
                            else -> "$count detections found"
                        }
                        Text(
                            statusText,
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.textSecondary
                        )
                    }
                }
                IconButton(onClick = { viewModel.runSecurityScan() }) {
                    Icon(Icons.Default.Refresh, contentDescription = "Rescan", tint = colors.primary)
                }
            }
        }

        Spacer(Modifier.height(12.dp))

        if (scanReport != null) {
            val findings = scanReport!!.findings
            if (findings.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No known crypto or root/debug signatures detected.", color = colors.textSecondary)
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(findings) { item ->
                        val sevColor = when (item.severity.lowercase()) {
                            "high" -> RedAccent
                            "medium" -> AmberAccent
                            else -> GreenAccent
                        }

                        Card(
                            colors = CardDefaults.cardColors(containerColor = colors.card),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (item.address != 0L) {
                                        viewModel.selectFunction(item.address, item.name)
                                        viewModel.codeSubTab.value = 0
                                        viewModel.navigateTo(Screen.Code)
                                    }
                                }
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(item.name, color = colors.textPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                    Text(
                                        item.severity.uppercase(),
                                        color = sevColor,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    )
                                }

                                Spacer(Modifier.height(4.dp))
                                Text(item.description, color = colors.textSecondary, fontSize = 12.sp)

                                Spacer(Modifier.height(6.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        "Category: ${item.category}",
                                        color = colors.primary,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    if (item.address != 0L) {
                                        Text(
                                            "0x${"%08X".format(item.address)} (tap to jump)",
                                            color = colors.address,
                                            fontSize = 11.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
