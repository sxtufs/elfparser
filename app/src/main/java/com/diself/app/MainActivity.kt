package com.diself.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
                val codeTab by viewModel.codeSubTab.collectAsState()
                val analysisTab by viewModel.analysisSubTab.collectAsState()

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = BgDark,
                    bottomBar = {
                        NavigationBar(containerColor = SurfaceDark) {
                            NavigationBarItem(
                                selected = currentScreen == Screen.Files,
                                onClick = { viewModel.navigateTo(Screen.Files) },
                                icon = { Icon(Icons.Default.Folder, contentDescription = "Files") },
                                label = { Text("Files", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Code,
                                onClick = { viewModel.navigateTo(Screen.Code) },
                                icon = { Icon(Icons.Default.Code, contentDescription = "Code") },
                                label = { Text("Code", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Tracer,
                                onClick = { viewModel.navigateTo(Screen.Tracer) },
                                icon = { Icon(Icons.Default.PlayArrow, contentDescription = "Tracer") },
                                label = { Text("Tracer", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyanAccent,
                                    selectedTextColor = CyanAccent,
                                    unselectedIconColor = Color.Gray,
                                    unselectedTextColor = Color.Gray
                                )
                            )
                            NavigationBarItem(
                                selected = currentScreen == Screen.Analysis,
                                onClick = { viewModel.navigateTo(Screen.Analysis) },
                                icon = { Icon(Icons.Default.Search, contentDescription = "Analysis") },
                                label = { Text("Analysis", fontSize = 11.sp, maxLines = 1, softWrap = false) },
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
                            Screen.Files -> HomeScreen(viewModel)

                            Screen.Code -> {
                                Column(modifier = Modifier.fillMaxSize()) {
                                    TabRow(
                                        selectedTabIndex = codeTab,
                                        containerColor = SurfaceDark,
                                        contentColor = CyanAccent
                                    ) {
                                        Tab(
                                            selected = codeTab == 0,
                                            onClick = { viewModel.codeSubTab.value = 0 },
                                            text = { Text("Disassembly", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                                        )
                                        Tab(
                                            selected = codeTab == 1,
                                            onClick = { viewModel.codeSubTab.value = 1 },
                                            text = { Text("Decompile", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                                        )
                                        Tab(
                                            selected = codeTab == 2,
                                            onClick = { viewModel.codeSubTab.value = 2 },
                                            text = { Text("Flowchart", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                                        )
                                    }
                                    when (codeTab) {
                                        0 -> DisasmScreen(viewModel)
                                        1 -> DecompileScreen(viewModel)
                                        2 -> FlowchartScreen(viewModel)
                                    }
                                }
                            }

                            Screen.Tracer -> TraceScreen(viewModel)

                            Screen.Analysis -> {
                                Column(modifier = Modifier.fillMaxSize()) {
                                    TabRow(
                                        selectedTabIndex = analysisTab,
                                        containerColor = SurfaceDark,
                                        contentColor = CyanAccent
                                    ) {
                                        Tab(
                                            selected = analysisTab == 0,
                                            onClick = { viewModel.analysisSubTab.value = 0 },
                                            text = { Text("Strings", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                                        )
                                        Tab(
                                            selected = analysisTab == 1,
                                            onClick = { viewModel.analysisSubTab.value = 1 },
                                            text = { Text("Security Scanner", fontWeight = FontWeight.Bold, fontSize = 12.sp) }
                                        )
                                    }
                                    when (analysisTab) {
                                        0 -> StringsScreen(viewModel)
                                        1 -> SecurityScreen(viewModel)
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
