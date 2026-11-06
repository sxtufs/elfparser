package io.elftrace.app

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import io.elftrace.app.R
import io.elftrace.app.ui.screens.*
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel
import io.elftrace.app.viewmodel.Screen

class MainActivity : ComponentActivity() {

    private val viewModel: ELFTraceViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val isDark by viewModel.isDarkMode.collectAsState()

            val view = LocalView.current
            if (!view.isInEditMode) {
                SideEffect {
                    val window = (view.context as Activity).window
                    val statusBarColor = if (isDark) Color(0xFF181A1F).toArgb() else Color(0xFFF8F9FA).toArgb()
                    val navBarColor = if (isDark) Color(0xFF181A1F).toArgb() else Color(0xFFF8F9FA).toArgb()
                    window.statusBarColor = statusBarColor
                    window.navigationBarColor = navBarColor

                    val insetsController = WindowCompat.getInsetsController(window, view)
                    insetsController.isAppearanceLightStatusBars = !isDark
                    insetsController.isAppearanceLightNavigationBars = !isDark
                }
            }

            ELFTraceTheme(darkTheme = isDark) {
                val colors = LocalELFTraceColors.current
                val currentScreen by viewModel.currentScreen.collectAsState()
                val codeTab by viewModel.codeSubTab.collectAsState()
                val analysisTab by viewModel.analysisSubTab.collectAsState()

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    containerColor = colors.bg,
                    bottomBar = {
                        // Floating Rounded-Card Bottom Navigation Bar
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .navigationBarsPadding()
                                .padding(horizontal = 12.dp, vertical = 6.dp),
                            shape = RoundedCornerShape(24.dp),
                            color = colors.surface,
                            border = BorderStroke(1.dp, colors.border),
                            shadowElevation = 3.dp
                        ) {
                            NavigationBar(
                                containerColor = Color.Transparent,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(68.dp)
                            ) {
                                NavigationBarItem(
                                    selected = currentScreen == Screen.Files,
                                    onClick = { viewModel.navigateTo(Screen.Files) },
                                    icon = { Icon(Icons.Default.Folder, contentDescription = "Files") },
                                    label = { Text("Files", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = colors.primary,
                                        selectedTextColor = colors.primary,
                                        unselectedIconColor = colors.textSecondary,
                                        unselectedTextColor = colors.textSecondary,
                                        indicatorColor = colors.primary.copy(alpha = 0.18f)
                                    )
                                )
                                NavigationBarItem(
                                    selected = currentScreen == Screen.Code,
                                    onClick = { viewModel.navigateTo(Screen.Code) },
                                    icon = { Icon(Icons.Default.Code, contentDescription = "Code") },
                                    label = { Text("Code", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = colors.primary,
                                        selectedTextColor = colors.primary,
                                        unselectedIconColor = colors.textSecondary,
                                        unselectedTextColor = colors.textSecondary,
                                        indicatorColor = colors.primary.copy(alpha = 0.18f)
                                    )
                                )
                                NavigationBarItem(
                                    selected = currentScreen == Screen.Tracer,
                                    onClick = { viewModel.navigateTo(Screen.Tracer) },
                                    icon = { Icon(Icons.Default.PlayArrow, contentDescription = "Tracer") },
                                    label = { Text("Tracer", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = colors.primary,
                                        selectedTextColor = colors.primary,
                                        unselectedIconColor = colors.textSecondary,
                                        unselectedTextColor = colors.textSecondary,
                                        indicatorColor = colors.primary.copy(alpha = 0.18f)
                                    )
                                )
                                NavigationBarItem(
                                    selected = currentScreen == Screen.Analysis,
                                    onClick = { viewModel.navigateTo(Screen.Analysis) },
                                    icon = { Icon(Icons.Default.Search, contentDescription = "Analysis") },
                                    label = { Text("Analysis", fontSize = 11.sp, maxLines = 1, softWrap = false) },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = colors.primary,
                                        selectedTextColor = colors.primary,
                                        unselectedIconColor = colors.textSecondary,
                                        unselectedTextColor = colors.textSecondary,
                                        indicatorColor = colors.primary.copy(alpha = 0.18f)
                                    )
                                )
                            }
                        }
                    }
                ) { innerPadding ->
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        color = colors.bg
                    ) {
                        when (currentScreen) {
                            Screen.Files -> HomeScreen(viewModel)

                            Screen.Code -> {
                                Column(modifier = Modifier.fillMaxSize()) {
                                    // Standardized Floating Rounded-Card Top Navigation Bar
                                    ELFTraceTopTabBar(
                                        selectedTabIndex = codeTab,
                                        tabs = listOf("Disassembly", "Decompile", "Flowchart"),
                                        onTabSelected = { viewModel.codeSubTab.value = it }
                                    )

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
                                    // Standardized Floating Rounded-Card Top Navigation Bar
                                    ELFTraceTopTabBar(
                                        selectedTabIndex = analysisTab,
                                        tabs = listOf("Strings", "Security Scanner"),
                                        onTabSelected = { viewModel.analysisSubTab.value = it }
                                    )

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

/**
 * Standardized Floating Rounded-Card Top Navigation Container for ELFTrace.
 * Applies uniform horizontal insets, rounded corners, surface background, and clipped active indicator.
 */
@Composable
fun ELFTraceTopTabBar(
    selectedTabIndex: Int,
    tabs: List<String>,
    onTabSelected: (Int) -> Unit
) {
    val colors = LocalELFTraceColors.current
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp),
        shape = RoundedCornerShape(16.dp),
        color = colors.surface,
        border = BorderStroke(1.dp, colors.border),
        shadowElevation = 2.dp
    ) {
        TabRow(
            selectedTabIndex = selectedTabIndex,
            containerColor = Color.Transparent,
            contentColor = colors.primary,
            indicator = { tabPositions ->
                if (selectedTabIndex < tabPositions.size) {
                    TabRowDefaults.SecondaryIndicator(
                        modifier = Modifier.tabIndicatorOffset(tabPositions[selectedTabIndex]),
                        color = colors.primary,
                        height = 3.dp
                    )
                }
            },
            divider = {}
        ) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTabIndex == index,
                    onClick = { onTabSelected(index) },
                    text = {
                        Text(
                            text = title,
                            fontWeight = if (selectedTabIndex == index) FontWeight.Bold else FontWeight.Medium,
                            fontSize = 12.sp,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                )
            }
        }
    }
}
