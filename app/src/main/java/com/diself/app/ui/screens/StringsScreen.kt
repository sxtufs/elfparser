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
    val stringsList by viewModel.stringsList.collectAsState()
    var search by remember { mutableStateOf("") }
    var selectedString by remember { mutableStateOf<StringItem?>(null) }
    var xrefsList by remember { mutableStateOf<List<XRefItem>>(emptyList()) }

    val filtered = remember(search, stringsList) {
        if (search.isBlank()) stringsList
        else stringsList.filter { it.string.contains(search, ignoreCase = true) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .padding(12.dp)
    ) {
        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            label = { Text("Filter Strings (${stringsList.size})") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = CyanAccent) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = CyanAccent,
                unfocusedBorderColor = ColorHexBytes,
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White
            )
        )

        Spacer(Modifier.height(8.dp))

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            items(filtered) { item ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = CardDark),
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
                            color = ColorAddress,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            modifier = Modifier.width(90.dp)
                        )
                        Text(
                            text = item.string,
                            color = Color.White,
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
            AlertDialog(
                onDismissRequest = { selectedString = null },
                containerColor = SurfaceDark,
                title = { Text("String XREFs (${xrefsList.size})", color = CyanAccent) },
                text = {
                    Column {
                        Text("\"${str.string}\"", color = AmberAccent, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                        Spacer(Modifier.height(8.dp))
                        if (xrefsList.isEmpty()) {
                            Text("No direct instruction references found.", color = ColorHexBytes, fontSize = 12.sp)
                        } else {
                            LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp)) {
                                items(xrefsList) { ref ->
                                    Card(
                                        colors = CardDefaults.cardColors(containerColor = CardDark),
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable {
                                            viewModel.selectFunction(ref.from_address, ref.caller_func ?: "caller")
                                            viewModel.codeSubTab.value = 0
                                            viewModel.navigateTo(Screen.Code)
                                            selectedString = null
                                        }
                                    ) {
                                        Column(modifier = Modifier.padding(8.dp)) {
                                            Text("In: ${ref.caller_func ?: "unknown"}", color = CyanAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                            Text("0x${"%08X".format(ref.from_address)}: ${ref.instruction}", color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { selectedString = null }) {
                        Text("Close", color = CyanAccent)
                    }
                }
            )
        }
    }
}
