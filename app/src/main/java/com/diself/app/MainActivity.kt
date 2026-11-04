package com.diself.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.diself.app.ui.screens.*
import com.diself.app.ui.theme.BgDark
import com.diself.app.ui.theme.CyanAccent
import com.diself.app.ui.theme.DisElfTheme
import com.diself.app.ui.theme.SurfaceDark
import com.diself.app.viewmodel.DisElfViewModel
import com.diself.app.viewmodel.Screen

class MainActivity : ComponentActivity() {

    private val viewModel: DisElfViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DisElfTheme {
                val currentScreen by viewModel.currentScreen.collectAsState()

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = BgDark,
                    bottomBar = {
                        NavigationBar(containerColor = SurfaceDark) {
                            NavigationBarItem(
                                selected = currentScreen == Screen.Home,
                                onClick = { viewModel.navigateTo(Screen.Home) },
                                icon = { Icon(Icons.Default.Folder, contentDescription = "Files") },
                                label = { Text("ELF") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Disassembly,
                                onClick = { viewModel.navigateTo(Screen.Disassembly) },
                                icon = { Icon(Icons.Default.Code, contentDescription = "Disasm") },
                                label = { Text("Disasm") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Decompile,
                                onClick = { viewModel.navigateTo(Screen.Decompile) },
                                icon = { Icon(Icons.Default.DataObject, contentDescription = "Decompile") },
                                label = { Text("Decompile") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Flowchart,
                                onClick = { viewModel.navigateTo(Screen.Flowchart) },
                                icon = { Icon(Icons.Default.AccountTree, contentDescription = "Flowchart") },
                                label = { Text("Flowchart") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Trace,
                                onClick = { viewModel.navigateTo(Screen.Trace) },
                                icon = { Icon(Icons.Default.PlayArrow, contentDescription = "Tracer") },
                                label = { Text("Tracer") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Strings,
                                onClick = { viewModel.navigateTo(Screen.Strings) },
                                icon = { Icon(Icons.Default.TextFields, contentDescription = "Strings") },
                                label = { Text("Strings") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                        }
                    }
                ) { innerPadding ->
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        color = BgDark
                    ) {
                        when (currentScreen) {
                            Screen.Home -> HomeScreen(viewModel)
                            Screen.Disassembly -> DisasmScreen(viewModel)
                            Screen.Decompile -> DecompileScreen(viewModel)
                            Screen.Flowchart -> FlowchartScreen(viewModel)
                            Screen.Trace -> TraceScreen(viewModel)
                            Screen.Strings -> StringsScreen(viewModel)
                        }
                    }
                }
            }
        }
    }
}
