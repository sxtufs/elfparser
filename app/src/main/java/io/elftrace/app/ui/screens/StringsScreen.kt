package io.elftrace.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.core.models.StringItem
import io.elftrace.app.core.models.XRefItem
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StringsScreen(viewModel: ELFTraceViewModel) {
    val colors = LocalELFTraceColors.current
    val stringsList by viewModel.stringsList.collectAsState()
    var search by remember { mutableStateOf("") }
    var selectedString by remember { mutableStateOf<StringItem?>(null) }
    var xrefsList by remember { mutableStateOf<List<XRefItem>>(emptyList()) }

    val cleanHex = search.trim().removePrefix("0x").removePrefix("0X")
    val filtered = remember(search, stringsList) {
        if (search.isBlank()) stringsList
        else {
            stringsList.filter { item ->
                item.string.contains(search, ignoreCase = true) ||
                (cleanHex.isNotEmpty() && "%08X".format(item.vaddr).contains(cleanHex, ignoreCase = true))
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            label = { Text("Filter String or Address") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = colors.primary) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = colors.primary,
                unfocusedBorderColor = colors.border,
                focusedTextColor = colors.textPrimary,
                unfocusedTextColor = colors.textPrimary,
                focusedLabelColor = colors.primary,
                unfocusedLabelColor = colors.textSecondary,
                cursorColor = colors.primary
            )
        )

        Spacer(Modifier.height(6.dp))

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            flingBehavior = rememberMomentumFlingBehavior(),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            items(
                items = filtered,
                key = { "${it.vaddr}_${it.paddr}" },
                contentType = { "string" }
            ) { item ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.card),
                    shape = RoundedCornerShape(6.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            selectedString = item
                            xrefsList = viewModel.getXrefsFor(item.vaddr)
                        }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "0x${"%08X".format(item.vaddr)}",
                            color = colors.address,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            modifier = Modifier.width(90.dp)
                        )
                        Text(
                            text = item.string,
                            color = colors.textPrimary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        // XREF Dialog when tapping a string
        if (selectedString != null) {
            val str = selectedString!!
            val count = xrefsList.size
            val titleText = when (count) {
                0 -> "No Cross-References"
                1 -> "1 Cross-Reference"
                else -> "$count Cross-References"
            }
            AlertDialog(onDismissRequest = { selectedString = null }) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = colors.surface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                        Text(titleText, color = colors.primary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(4.dp))
                        Text("\"${str.string}\"", color = AmberAccent, fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 2)
                        Spacer(Modifier.height(8.dp))
                        if (xrefsList.isEmpty()) {
                            Text("No direct instruction references found.", color = colors.textSecondary, fontSize = 12.sp)
                        } else {
                            LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                items(xrefsList) { ref ->
                                    Card(
                                        colors = CardDefaults.cardColors(containerColor = colors.card),
                                        shape = RoundedCornerShape(8.dp),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, colors.border),
                                        modifier = Modifier.fillMaxWidth().clickable {
                                            viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                            viewModel.codeSubTab.value = 0
                                            viewModel.navigateTo(Screen.Code)
                                            selectedString = null
                                        }
                                    ) {
                                        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
                                            Text("In: ${ref.caller_func ?: "unknown"}", color = colors.primary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                            Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = colors.textPrimary, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                                        }
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                            TextButton(onClick = { selectedString = null }) {
                                Text("Close", color = colors.primary)
                            }
                        }
                    }
                }
            }
        }
    }
}
