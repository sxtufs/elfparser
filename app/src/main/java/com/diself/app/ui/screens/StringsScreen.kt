package com.diself.app.ui.screens

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
import com.diself.app.core.models.StringItem
import com.diself.app.core.models.XRefItem
import com.diself.app.ui.theme.*
import com.diself.app.viewmodel.DisElfViewModel
import com.diself.app.viewmodel.Screen

@Composable
fun StringsScreen(viewModel: DisElfViewModel) {
    val colors = LocalDisElfColors.current
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
            .padding(12.dp)
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
                unfocusedTextColor = colors.textPrimary
            )
        )

        Spacer(Modifier.height(8.dp))

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            items(filtered) { item ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = colors.card),
                    shape = RoundedCornerShape(6.dp),
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
                            .padding(10.dp),
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
                            fontSize = 12.sp
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
            AlertDialog(
                onDismissRequest = { selectedString = null },
                containerColor = colors.surface,
                title = { Text(titleText, color = colors.primary) },
                text = {
                    Column {
                        Text("\"${str.string}\"", color = AmberAccent, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                        Spacer(Modifier.height(8.dp))
                        if (xrefsList.isEmpty()) {
                            Text("No direct instruction references found.", color = colors.textSecondary, fontSize = 12.sp)
                        } else {
                            LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp)) {
                                items(xrefsList) { ref ->
                                    Card(
                                        colors = CardDefaults.cardColors(containerColor = colors.card),
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable {
                                            viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                            viewModel.codeSubTab.value = 0
                                            viewModel.navigateTo(Screen.Code)
                                            selectedString = null
                                        }
                                    ) {
                                        Column(modifier = Modifier.padding(8.dp)) {
                                            Text("In: ${ref.caller_func ?: "unknown"}", color = colors.primary, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                            Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = colors.textPrimary, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { selectedString = null }) {
                        Text("Close", color = colors.primary)
                    }
                }
            )
        }
    }
}
