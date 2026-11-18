package io.elftrace.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CenterFocusStrong
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.elftrace.app.ui.theme.*
import io.elftrace.app.viewmodel.ELFTraceViewModel
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.roundToInt
import kotlin.math.sin

private enum class CfgEdgeKind { TRUE, FALSE, JUMP, FALLTHROUGH }

private data class CfgEdge(
    val fromId: Int,
    val toId: Int,
    val kind: CfgEdgeKind
)

private data class CfgInsn(
    val addr: String,
    val mnemonic: String,
    val operands: String
)

private data class CfgBlock(
    val id: Int,
    val rangeLabel: String,
    val instructions: List<CfgInsn>,
    val isExit: Boolean = false
)

private data class CfgGraph(
    val summary: String,
    val blocks: List<CfgBlock>,
    val edges: List<CfgEdge>
)

private data class NodeLayout(
    val block: CfgBlock,
    val x: Float,
    val y: Float,
    val width: Float,
    val height: Float
)

private fun parseCfgText(text: String): CfgGraph {
    if (text.isBlank()) return CfgGraph("", emptyList(), emptyList())

    val lines = text.lines()
    val summaryLines = mutableListOf<String>()
    val blocks = mutableListOf<CfgBlock>()
    val edges = mutableListOf<CfgEdge>()

    var curId: Int? = null
    var curRange = ""
    var curInsns = mutableListOf<CfgInsn>()
    var curExit = false

    val blockHeaderRegex = Regex("""^Block\s+(\d+)\s*\(([^)]+)\)""")
    val insnRegex = Regex("""^\s*(0x[0-9a-fA-F]+):\s+(\S+)(?:\s+(.*))?$""")
    val trueRegex = Regex("""\[TRUE\]\s+branch\s*->\s*Block\s+(\d+)""")
    val falseRegex = Regex("""\[FALSE\]\s+fallthrough\s+to\s+Block\s+(\d+)""")
    val jumpRegex = Regex("""\(jump\s*->\s*Block\s+(\d+)\)""")
    val fallRegex = Regex("""\(fallthrough\s+to\s+Block\s+(\d+)\)""")

    fun flushBlock() {
        val id = curId ?: return
        blocks.add(CfgBlock(id, curRange, curInsns.toList(), curExit))
        curId = null
        curRange = ""
        curInsns = mutableListOf()
        curExit = false
    }

    for (line in lines) {
        val trimmed = line.trim()
        if (trimmed.startsWith("//") && curId == null) {
            summaryLines.add(trimmed.removePrefix("//").trim())
            continue
        }

        val bh = blockHeaderRegex.find(trimmed)
        if (bh != null) {
            flushBlock()
            curId = bh.groupValues[1].toIntOrNull()
            curRange = bh.groupValues[2]
            continue
        }

        val id = curId ?: continue

        val insnMatch = insnRegex.find(line)
        if (insnMatch != null) {
            curInsns.add(
                CfgInsn(
                    addr = insnMatch.groupValues[1],
                    mnemonic = insnMatch.groupValues[2],
                    operands = insnMatch.groupValues[3].trim()
                )
            )
            continue
        }

        val trueMatch = trueRegex.find(trimmed)
        if (trueMatch != null) {
            trueMatch.groupValues[1].toIntOrNull()?.let { to ->
                edges.add(CfgEdge(id, to, CfgEdgeKind.TRUE))
            }
            continue
        }
        val falseMatch = falseRegex.find(trimmed)
        if (falseMatch != null) {
            falseMatch.groupValues[1].toIntOrNull()?.let { to ->
                edges.add(CfgEdge(id, to, CfgEdgeKind.FALSE))
            }
            continue
        }
        val jumpMatch = jumpRegex.find(trimmed)
        if (jumpMatch != null) {
            jumpMatch.groupValues[1].toIntOrNull()?.let { to ->
                edges.add(CfgEdge(id, to, CfgEdgeKind.JUMP))
            }
            continue
        }
        val fallMatch = fallRegex.find(trimmed)
        if (fallMatch != null) {
            fallMatch.groupValues[1].toIntOrNull()?.let { to ->
                edges.add(CfgEdge(id, to, CfgEdgeKind.FALLTHROUGH))
            }
            continue
        }
        if (trimmed.contains("[EXIT / RETURN]")) {
            curExit = true
        }
    }
    flushBlock()

    val cleanSummary = summaryLines
        .filterNot { it.startsWith("CONTROL FLOW GRAPH:", ignoreCase = true) }
        .joinToString(" • ")
    return CfgGraph(
        summary = cleanSummary,
        blocks = blocks,
        edges = edges
    )
}

private fun layoutCfgGraph(
    graph: CfgGraph,
    nodeWidthPx: Float,
    hGapPx: Float,
    vGapPx: Float,
    headerHeightPx: Float,
    lineHeightPx: Float,
    footerHeightPx: Float
): Map<Int, NodeLayout> {
    if (graph.blocks.isEmpty()) return emptyMap()

    val blockMap = graph.blocks.associateBy { it.id }
    val adj = mutableMapOf<Int, MutableList<Int>>()
    for (e in graph.edges) {
        adj.getOrPut(e.fromId) { mutableListOf() }.add(e.toId)
    }

    // BFS level assignment from Block 0 (or first block)
    val startId = if (blockMap.containsKey(0)) 0 else graph.blocks.first().id
    val level = mutableMapOf<Int, Int>()
    val queue = ArrayDeque<Int>()
    level[startId] = 0
    queue.add(startId)

    while (queue.isNotEmpty()) {
        val u = queue.removeFirst()
        val uLvl = level[u] ?: 0
        for (v in adj[u].orEmpty()) {
            if (blockMap.containsKey(v) && !level.containsKey(v)) {
                level[v] = uLvl + 1
                queue.add(v)
            }
        }
    }

    // Any disconnected blocks
    var maxLvl = level.values.maxOrNull() ?: 0
    for (b in graph.blocks) {
        if (!level.containsKey(b.id)) {
            maxLvl += 1
            level[b.id] = maxLvl
        }
    }

    val byLevel = graph.blocks.groupBy { level[it.id] ?: 0 }.toSortedMap()

    fun estimateHeight(b: CfgBlock): Float {
        val insnCount = max(1, b.instructions.size)
        return headerHeightPx + insnCount * lineHeightPx + footerHeightPx
    }

    val result = mutableMapOf<Int, NodeLayout>()
    var curY = 40f

    for ((_, rowBlocks) in byLevel) {
        val sortedRow = rowBlocks.sortedBy { it.id }
        val totalRowWidth = sortedRow.size * nodeWidthPx + (sortedRow.size - 1) * hGapPx
        var curX = -totalRowWidth / 2f
        var rowMaxH = 0f

        for (b in sortedRow) {
            val h = estimateHeight(b)
            result[b.id] = NodeLayout(b, curX, curY, nodeWidthPx, h)
            curX += nodeWidthPx + hGapPx
            if (h > rowMaxH) rowMaxH = h
        }
        curY += rowMaxH + vGapPx
    }

    return result
}

@Composable
fun FlowchartScreen(viewModel: ELFTraceViewModel) {
    val context = LocalContext.current
    val colors = LocalELFTraceColors.current
    val clipboardManager = LocalClipboardManager.current
    val flowchartText by viewModel.flowchartText.collectAsState()
    val symbolName by viewModel.selectedSymbolName.collectAsState()
    val currentAddr by viewModel.currentAddress.collectAsState()

    val displayTitle = remember(symbolName, currentAddr) {
        symbolName.ifEmpty { "sub_%08X".format(currentAddr) }
    }

    val graph = remember(flowchartText) { parseCfgText(flowchartText) }
    val density = LocalDensity.current

    val nodeWidthDp = 250.dp
    val nodeWidthPx = with(density) { nodeWidthDp.toPx() }
    val hGapPx = with(density) { 44.dp.toPx() }
    val vGapPx = with(density) { 64.dp.toPx() }
    val headerHeightPx = with(density) { 34.dp.toPx() }
    val lineHeightPx = with(density) { 16.dp.toPx() }
    val footerHeightPx = with(density) { 28.dp.toPx() }

    val layouts = remember(graph, nodeWidthPx) {
        layoutCfgGraph(
            graph = graph,
            nodeWidthPx = nodeWidthPx,
            hGapPx = hGapPx,
            vGapPx = vGapPx,
            headerHeightPx = headerHeightPx,
            lineHeightPx = lineHeightPx,
            footerHeightPx = footerHeightPx
        )
    }

    var viewportSize by remember { mutableStateOf(IntSize.Zero) }
    var scale by remember(flowchartText) { mutableStateOf(0.85f) }
    var pan by remember(flowchartText) { mutableStateOf(Offset.Zero) }
    var selectedBlockId by remember(flowchartText) { mutableStateOf<Int?>(null) }

    fun centerOnBlock(blockId: Int) {
        val node = layouts[blockId] ?: return
        if (viewportSize.width == 0 || viewportSize.height == 0) return
        val cx = node.x + node.width / 2f
        val cy = node.y + node.height / 2f
        pan = Offset(
            x = viewportSize.width / 2f - cx * scale,
            y = viewportSize.height / 3f - cy * scale
        )
        selectedBlockId = blockId
    }

    LaunchedEffect(layouts, viewportSize) {
        if (layouts.isNotEmpty() && viewportSize.width > 0 && pan == Offset.Zero) {
            val firstId = if (layouts.containsKey(0)) 0 else layouts.keys.minOrNull() ?: 0
            centerOnBlock(firstId)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bg)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        // Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                Text(
                    text = displayTitle,
                    color = colors.primary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (graph.summary.isNotEmpty()) {
                    Text(
                        text = graph.summary,
                        color = colors.textSecondary,
                        fontSize = 10.5.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(
                    onClick = {
                        scale = 0.85f
                        val firstId = if (layouts.containsKey(0)) 0 else layouts.keys.minOrNull() ?: 0
                        centerOnBlock(firstId)
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        Icons.Default.CenterFocusStrong,
                        contentDescription = "Reset View",
                        tint = colors.primary,
                        modifier = Modifier.size(18.dp)
                    )
                }
                IconButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(flowchartText))
                        Toast.makeText(context, "Copied Flowchart to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Copy",
                        tint = colors.textPrimary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        Spacer(Modifier.height(4.dp))

        if (graph.blocks.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(colors.card, RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = flowchartText.ifEmpty { "// Select a function to view its control flow graph" },
                    color = colors.textSecondary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
            }
        } else {
            // Interactive 2D Pan & Zoom Graph Canvas
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(colors.card, RoundedCornerShape(8.dp))
                    .clipToBounds()
                    .onSizeChanged { viewportSize = it }
                    .pointerInput(Unit) {
                        detectTransformGestures { centroid, panChange, zoomChange, _ ->
                            val oldScale = scale
                            val newScale = (oldScale * zoomChange).coerceIn(0.25f, 2.2f)
                            val factor = newScale / oldScale
                            pan = (pan - centroid) * factor + centroid + panChange
                            scale = newScale
                        }
                    }
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .graphicsLayer {
                            translationX = pan.x
                            translationY = pan.y
                            scaleX = scale
                            scaleY = scale
                            transformOrigin = androidx.compose.ui.graphics.TransformOrigin(0f, 0f)
                        }
                ) {
                    // Edges Layer
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        for (edge in graph.edges) {
                            val from = layouts[edge.fromId] ?: continue
                            val to = layouts[edge.toId] ?: continue

                            val isBackEdge = to.y <= from.y
                            val isHighlighted = selectedBlockId == edge.fromId || selectedBlockId == edge.toId

                            val baseColor = when {
                                isBackEdge -> AmberAccent
                                edge.kind == CfgEdgeKind.TRUE -> GreenAccent
                                edge.kind == CfgEdgeKind.FALSE -> RedAccent
                                else -> colors.primary
                            }
                            val edgeColor = if (selectedBlockId == null || isHighlighted) {
                                baseColor
                            } else {
                                baseColor.copy(alpha = 0.28f)
                            }
                            val strokeWidth = if (isHighlighted) 4f else 2.5f

                            val startX = when (edge.kind) {
                                CfgEdgeKind.TRUE, CfgEdgeKind.FALSE -> {
                                    val fromCenter = from.x + from.width * 0.5f
                                    val toCenter = to.x + to.width * 0.5f
                                    if (toCenter < fromCenter) from.x + from.width * 0.3f
                                    else if (toCenter > fromCenter) from.x + from.width * 0.7f
                                    else fromCenter
                                }
                                else -> from.x + from.width * 0.5f
                            }
                            val startY = from.y + from.height
                            val endX = to.x + to.width * 0.5f
                            val endY = to.y

                            val path = Path()
                            if (isBackEdge) {
                                // Route loop back-edge around the right side
                                val sideX = max(from.x + from.width, to.x + to.width) + 48f
                                path.moveTo(startX, startY)
                                path.cubicTo(
                                    sideX, startY + 40f,
                                    sideX, endY - 40f,
                                    endX, endY
                                )
                            } else {
                                val midY = (startY + endY) / 2f
                                path.moveTo(startX, startY)
                                path.cubicTo(
                                    startX, midY,
                                    endX, midY,
                                    endX, endY
                                )
                            }

                            drawPath(
                                path = path,
                                color = edgeColor,
                                style = Stroke(
                                    width = strokeWidth,
                                    cap = StrokeCap.Round,
                                    pathEffect = if (isBackEdge) PathEffect.dashPathEffect(floatArrayOf(12f, 8f)) else null
                                )
                            )

                            // Arrowhead at (endX, endY)
                            val angle = if (isBackEdge) {
                                atan2(endY - (endY - 40f), endX - (max(from.x + from.width, to.x + to.width) + 48f))
                            } else {
                                Math.PI.toFloat() / 2f
                            }
                            val arrowLen = 12f
                            val a1 = angle - 0.45f
                            val a2 = angle + 0.45f
                            val arrowPath = Path().apply {
                                moveTo(endX, endY)
                                lineTo(endX - arrowLen * cos(a1), endY - arrowLen * sin(a1))
                                moveTo(endX, endY)
                                lineTo(endX - arrowLen * cos(a2), endY - arrowLen * sin(a2))
                            }
                            drawPath(
                                path = arrowPath,
                                color = edgeColor,
                                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                            )
                        }
                    }

                    // Nodes Layer
                    for ((id, node) in layouts) {
                        val isSelected = selectedBlockId == id
                        val outEdges = graph.edges.filter { it.fromId == id }

                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = colors.surface,
                            border = BorderStroke(
                                width = if (isSelected) 2.dp else 1.dp,
                                color = if (isSelected) colors.primary else colors.border
                            ),
                            shadowElevation = if (isSelected) 6.dp else 2.dp,
                            modifier = Modifier
                                .offset { IntOffset(node.x.roundToInt(), node.y.roundToInt()) }
                                .width(nodeWidthDp)
                                .clickable { selectedBlockId = if (isSelected) null else id }
                        ) {
                            Column {
                                // Block Header
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(colors.primary.copy(alpha = 0.14f))
                                        .padding(horizontal = 10.dp, vertical = 5.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "Block ${node.block.id}",
                                        color = colors.primary,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    )
                                    Text(
                                        text = node.block.rangeLabel,
                                        color = colors.textSecondary,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 9.5.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }

                                // Instructions
                                Column(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    for (insn in node.block.instructions) {
                                        Row(modifier = Modifier.fillMaxWidth()) {
                                            Text(
                                                text = insn.addr.removePrefix("0x0000"),
                                                color = colors.textSecondary,
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 10.sp,
                                                modifier = Modifier.width(42.dp)
                                            )
                                            Text(
                                                text = insn.mnemonic,
                                                color = colors.mnemonic,
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.SemiBold,
                                                fontSize = 10.sp,
                                                modifier = Modifier.width(54.dp),
                                                maxLines = 1
                                            )
                                            Text(
                                                text = insn.operands,
                                                color = colors.operands,
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 10.sp,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                }

                                // Footer: Exit badge or clickable branch chips
                                if (node.block.isExit || outEdges.isNotEmpty()) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .background(colors.bg.copy(alpha = 0.5f))
                                            .padding(horizontal = 8.dp, vertical = 4.dp),
                                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        if (node.block.isExit) {
                                            Text(
                                                text = "RETURN",
                                                color = RedAccent,
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 9.5.sp
                                            )
                                        }
                                        for (e in outEdges) {
                                            val (label, chipColor) = when (e.kind) {
                                                CfgEdgeKind.TRUE -> "T: B${e.toId}" to GreenAccent
                                                CfgEdgeKind.FALSE -> "F: B${e.toId}" to RedAccent
                                                CfgEdgeKind.JUMP -> "J: B${e.toId}" to colors.primary
                                                CfgEdgeKind.FALLTHROUGH -> "B${e.toId}" to colors.textSecondary
                                            }
                                            Text(
                                                text = label,
                                                color = chipColor,
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 9.5.sp,
                                                modifier = Modifier.clickable { centerOnBlock(e.toId) }
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
}
