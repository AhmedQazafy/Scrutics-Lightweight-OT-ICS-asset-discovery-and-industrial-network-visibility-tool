"""Network topology export for Scrutics sessions."""

from __future__ import annotations

import csv
import html
import json
import logging
import os
import shutil
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, Optional

import scrutics
from scrutics.diagnostics import VERSION
from scrutics.protocol_display import protocol_display_text
from scrutics.vendor_display import display_vendor_name, vendor_note

logger = logging.getLogger(__name__)

_PKG_DIR = os.path.dirname(scrutics.__file__)
XLSX_JS_SRC = os.path.join(_PKG_DIR, "web", "xlsx.full.min.js")
XLSX_JS_DST = "xlsx.full.min.js"

NODE_COLORS = {
    "OT": "#e07b39",
    "IT": "#4a90d9",
    "Unknown": "#8f98a8",
}


def _asset_type(asset: Any) -> str:
    if getattr(asset, "is_ot", None) is True:
        return "OT"
    if getattr(asset, "is_ot", None) is False:
        return "IT"
    return "Unknown"


def _asset_sort_key(asset: Any) -> tuple[int, Any]:
    ip = str(getattr(asset, "ip", ""))
    try:
        return (0, ip_address(ip))
    except ValueError:
        return (1, ip)


def _safe_text(value: Any, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value)
    return text if text else default


def _edge_label(protocols: Any) -> str:
    if isinstance(protocols, str):
        return protocols
    try:
        values = sorted(str(p) for p in protocols if p)
    except TypeError:
        values = []
    useful = [p for p in values if p.upper() not in {"TCP", "UDP"}]
    return ", ".join(useful or values)


# Why an edge is left out of the topology graph (connections.csv still lists every edge)
EDGE_DROP_ENDPOINT = "endpoint not in the inventory"
EDGE_DROP_SAME_DEVICE = "both ends are the same device"
EDGE_DROP_VIEW_LIMIT = "topology view limit ({})"


def build_graph_data(inventory: Any, edges: dict | None = None, max_edges: int = 2000,
                     drops: dict | None = None) -> dict:
    """
    Convert an inventory and edge counter into serializable topology data. When `drops` is a
    dict, the edges left out of the graph are counted in it by reason.
    """
    drops = {} if drops is None else drops
    assets = sorted(inventory.get_all(), key=_asset_sort_key)

    # Index by Asset.primary_key for edge resolution, with IP fallback lookup
    # so edges keyed by either primary_key or IP can be resolved to Assets.
    # Uses Asset.primary_key; Asset.primary_key itself provides MAC identity
    # when known and IP fallback when MAC identity is unavailable.
    # The graph builder must NOT independently implement identity fallback logic.
    asset_by_pk = {asset.primary_key: asset for asset in assets}
    asset_by_ip = {str(asset.ip): asset for asset in assets if asset.ip}

    connected_pks = set()
    if edges:
        for src_k, dst_k in edges.keys():
            s_asset = asset_by_pk.get(str(src_k)) or asset_by_ip.get(str(src_k))
            d_asset = asset_by_pk.get(str(dst_k)) or asset_by_ip.get(str(dst_k))
            if s_asset and d_asset and s_asset.primary_key != d_asset.primary_key:
                connected_pks.add(s_asset.primary_key)
                connected_pks.add(d_asset.primary_key)

    nodes = []
    isolated_nodes = []
    for asset in assets:
        pk = asset.primary_key
        ntype = _asset_type(asset)
        # Evidence-based classification confidence, the value every other screen shows
        confidence = int(getattr(asset, "classification_confidence_pct", 0) or 0)
        node_data = {
            "id": pk,                   # Persistent identity (Asset.primary_key)
            "label": str(asset.ip),     # Human-friendly IP label for display
            "type": ntype,
            "color": NODE_COLORS[ntype],
            "size": max(14, min(36, 14 + confidence // 4)),
            # Stored registry name (exports) and the name shown on the page
            "vendor": _safe_text(getattr(asset, "vendor", None)),
            "vendor_display": _safe_text(display_vendor_name(getattr(asset, "vendor", None))),
            "vendor_note": vendor_note(asset),
            "protocol": protocol_display_text(asset),
            "role": _safe_text(getattr(asset, "role", None), "Unclassified"),
            "confidence": confidence,
            "mac": _safe_text(getattr(asset, "mac", None)),
            "packet_count": int(getattr(asset, "packet_count", 0) or 0),
        }
        if pk in connected_pks:
            nodes.append(node_data)
        else:
            isolated_nodes.append(node_data)

    graph_edges = []
    for (src_k, dst_k), info in (edges or {}).items():
        src_str = str(src_k)
        dst_str = str(dst_k)
        s_asset = asset_by_pk.get(src_str) or asset_by_ip.get(src_str)
        d_asset = asset_by_pk.get(dst_str) or asset_by_ip.get(dst_str)
        if not s_asset or not d_asset:
            drops[EDGE_DROP_ENDPOINT] = drops.get(EDGE_DROP_ENDPOINT, 0) + 1
            continue
        if s_asset.primary_key == d_asset.primary_key:
            drops[EDGE_DROP_SAME_DEVICE] = drops.get(EDGE_DROP_SAME_DEVICE, 0) + 1
            continue
        count = int((info or {}).get("count", 1) or 1)
        graph_edges.append({
            "from": s_asset.primary_key,
            "to": d_asset.primary_key,
            "label": _edge_label((info or {}).get("protocols", [])),
            "count": count,
            "width": max(1, min(8, 1 + int(count ** 0.35))),
        })

    graph_edges.sort(key=lambda edge: edge["count"], reverse=True)
    if max_edges and len(graph_edges) > max_edges:
        logging.warning(
            f"Topology truncated: {len(graph_edges)} edges reduced to {max_edges}. "
            f"Adjust max_edges parameter or increase limit."
        )
        drops[EDGE_DROP_VIEW_LIMIT.format(max_edges)] = len(graph_edges) - max_edges
        graph_edges = graph_edges[:max_edges]

    return {
        "nodes": nodes,
        "isolated_nodes": isolated_nodes,
        "edges": graph_edges,
        "summary": {
            "assets": len(nodes) + len(isolated_nodes),
            "ot": sum(1 for node in nodes if node["type"] == "OT") + sum(1 for node in isolated_nodes if node["type"] == "OT"),
            "it": sum(1 for node in nodes if node["type"] == "IT") + sum(1 for node in isolated_nodes if node["type"] == "IT"),
            "unknown": sum(1 for node in nodes if node["type"] == "Unknown") + sum(1 for node in isolated_nodes if node["type"] == "Unknown"),
            "connections": len(graph_edges),
            "isolated_count": len(isolated_nodes),
        },
    }


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scrutics Topology</title>
<script src="xlsx.full.min.js"></script>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; width: 100%; height: 100%; overflow: hidden; }
body { background: #151820; color: #e9edf5; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
#header { height: 48px; display: flex; align-items: center; gap: 12px; padding: 0 16px; background: #0c0f15; border-bottom: 1px solid #313846; flex-shrink: 0; }
#header h1 { margin: 0; font-size: 16px; color: #f2a400; font-weight: 700; white-space: nowrap; }
#summary { color: #aab3c2; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#controls { display: flex; align-items: center; gap: 6px; margin-left: auto; }
#controls button {
  background: #202531;
  border: 1px solid #3b4354;
  color: #e2e8f0;
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  font-family: inherit;
  transition: background 0.15s, border-color 0.15s;
}
#controls button:hover {
  background: #2d3445;
  border-color: #556077;
}
#fit-btn {
  background: #2b3648 !important;
  font-weight: 600;
  border-color: #4a5568 !important;
}
#export-btn {
  background: #1e5e45 !important;
  border-color: #2a7a5a !important;
  color: #fff !important;
}
#export-btn:hover {
  background: #277958 !important;
}
#ai-cmd-btn {
  background: #4a3a6a !important;
  border-color: #6a5a8a !important;
  color: #e2e8f0 !important;
}
#ai-cmd-btn:hover {
  background: #5a4a7a !important;
}
#ai-cmd-btn.copied {
  border-color: #4ade80 !important;
  background: #2a5a3a !important;
}
#legend { display: flex; gap: 12px; color: #c5ccd8; font-size: 12px; margin-left: 10px; }
.legend-item { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
.swatch { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
#main { display: flex; width: 100vw; height: calc(100vh - 48px); overflow: hidden; position: relative; }
#canvas-container { flex: 1; height: 100%; position: relative; overflow: hidden; }
#topology { width: 100%; height: 100%; display: block; cursor: grab; }
#topology:active { cursor: grabbing; }
#offscreen-alert {
  position: absolute;
  top: 14px;
  left: 14px;
  background: rgba(18, 22, 31, 0.94);
  border: 1px solid #e07b39;
  border-radius: 6px;
  padding: 6px 12px;
  display: none;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  color: #f6ad55;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.45);
  z-index: 4;
  pointer-events: auto;
}
#offscreen-alert button {
  background: #e07b39;
  border: none;
  color: #fff;
  border-radius: 3px;
  padding: 2px 8px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
}
#offscreen-alert button:hover {
  background: #f28b49;
}
#isolated-panel { width: 280px; background: #1a1e28; border-left: 1px solid #313846; overflow-y: auto; padding: 8px 12px; flex-shrink: 0; }
#isolated-panel h3 { margin: 0 0 8px 0; color: #8f98a8; font-size: 12px; font-weight: 400; letter-spacing: 0.5px; text-transform: uppercase; }
#isolated-list { list-style: none; margin: 0; padding: 0; font-size: 11px; }
#isolated-list li { padding: 4px 0; border-bottom: 1px solid #282e3a; display: flex; flex-wrap: wrap; gap: 4px 8px; }
#isolated-list .ip { color: #c5ccd8; font-weight: 500; }
#isolated-list .detail { color: #687285; }
#tooltip { position: fixed; display: none; z-index: 10; max-width: 360px; padding: 10px 12px; border: 1px solid #434b5c; border-radius: 6px; background: rgba(12,15,21,0.95); color: #e9edf5; font-size: 12px; line-height: 1.55; pointer-events: none; box-shadow: 0 8px 26px rgba(0,0,0,0.45); }
#tooltip b { color: #f2a400; font-size: 13px; }
#hint { position: fixed; left: 50%; bottom: 10px; transform: translateX(-50%); color: #687285; font-size: 11px; pointer-events: none; z-index: 3; }
@media (max-width: 820px) {
  #isolated-panel { width: 200px; font-size: 10px; }
  #isolated-panel h3 { font-size: 10px; }
}
@media (max-width: 720px) {
  #main { flex-direction: column; height: calc(100vh - 48px); }
  #canvas-container { height: 60%; }
  #isolated-panel { width: 100%; height: 40%; border-left: none; border-top: 1px solid #313846; }
}
</style>
</head>
<body>
<div id="header">
  <h1>Scrutics Topology</h1>
  <div id="summary"></div>
  <div id="controls">
    <button id="fit-btn" title="Fit all devices into viewport (Hotkey: F)">Fit View</button>
    <button id="zoom-in-btn" title="Zoom in (+)">+</button>
    <button id="zoom-out-btn" title="Zoom out (−)">−</button>
    <button id="relayout-btn" title="Re-settle physics simulation">Re-layout</button>
    <button id="export-btn">Export to .xls</button>
    <button id="ai-unified-btn" title="AI Assistant — ask questions about this topology">✦ AI Assistant</button>
  </div>
  <div id="legend">
    <span class="legend-item"><span class="swatch" style="background:#e07b39"></span>OT</span>
    <span class="legend-item"><span class="swatch" style="background:#4a90d9"></span>IT</span>
    <span class="legend-item"><span class="swatch" style="background:#8f98a8"></span>Unknown</span>
  </div>
</div>
<div id="main">
  <div id="canvas-container">
    <canvas id="topology"></canvas>
    <div id="offscreen-alert"></div>
  </div>
  <div id="isolated-panel">
    <h3>Isolated Assets</h3>
    <ul id="isolated-list"></ul>
  </div>
</div>
<div id="tooltip"></div>
<div id="hint">Scroll to zoom | Drag nodes | Drag canvas to pan | [F] Fit view | Click border arrows for off-screen devices</div>
<script id="graph-data" type="application/json">__GRAPH_JSON__</script>
<script>
(function () {
  const graph = JSON.parse(document.getElementById("graph-data").textContent);
  const nodes = graph.nodes || [];
  const isolatedNodes = graph.isolated_nodes || [];
  const edges = graph.edges || [];
  const canvas = document.getElementById("topology");
  const ctx = canvas.getContext("2d");
  const tooltip = document.getElementById("tooltip");
  const offscreenAlert = document.getElementById("offscreen-alert");
  const summary = graph.summary || {};

  document.getElementById("summary").textContent =
    `${summary.assets || 0} assets | ${summary.ot || 0} OT | ${summary.it || 0} IT | ${summary.unknown || 0} unknown | ${summary.connections || 0} connections | ${summary.isolated_count || 0} isolated`;

  const isolatedList = document.getElementById("isolated-list");
  if (isolatedNodes.length > 0) {
    isolatedNodes.forEach(node => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="ip">${node.label}</span> <span class="detail">${node.vendor_display || 'Unknown'}</span> <span class="detail">${node.protocol || 'Unknown'}</span> <span class="detail">${node.confidence}%</span>`;
      isolatedList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "No isolated assets.";
    li.style.color = "#687285";
    isolatedList.appendChild(li);
  }

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const nodeIndex = new Map(nodes.map((node, i) => [node.id, i]));

  // Adjacency graph for degrees and connected components
  const adj = new Map();
  nodes.forEach(n => adj.set(n.id, []));
  edges.forEach(e => {
    if (adj.has(e.from)) adj.get(e.from).push(e.to);
    if (adj.has(e.to)) adj.get(e.to).push(e.from);
  });
  nodes.forEach(n => {
    n.degree = (adj.get(n.id) || []).length;
  });

  // Connections drawn between two nodes on the page; a link in both directions counts once in
  // `neighbours`
  const drawnEdges = edges.filter(e => byId.has(e.from) && byId.has(e.to) && e.from !== e.to);
  const neighbours = new Map(nodes.map(n => [n.id, new Set()]));
  drawnEdges.forEach(e => {
    neighbours.get(e.from).add(e.to);
    neighbours.get(e.to).add(e.from);
  });

  // Group of every node, found in data order; only its size is used below
  const groupSize = new Map();
  (function () {
    const seen = new Set();
    nodes.forEach(n => {
      if (seen.has(n.id)) return;
      const members = [n.id];
      seen.add(n.id);
      for (let i = 0; i < members.length; i++) {
        neighbours.get(members[i]).forEach(x => { if (!seen.has(x)) { seen.add(x); members.push(x); } });
      }
      members.forEach(id => groupSize.set(id, members.length));
    });
  })();

  // Structural order. Layout decisions never depend on node ids or labels: nodes are ranked by the
  // size of their group, their number of distinct neighbours, their drawn size and the neighbour
  // counts of their neighbours; ties keep the order of the page data.
  const neighbourWeight = new Map(nodes.map(n => {
    let sum = 0;
    neighbours.get(n.id).forEach(x => { sum += neighbours.get(x).size; });
    return [n.id, sum];
  }));
  const nodesByRank = nodes.slice().sort((a, b) =>
    (groupSize.get(b.id) - groupSize.get(a.id)) ||
    (neighbours.get(b.id).size - neighbours.get(a.id).size) ||
    ((b.size || 0) - (a.size || 0)) ||
    (neighbourWeight.get(b.id) - neighbourWeight.get(a.id)) ||
    (nodeIndex.get(a.id) - nodeIndex.get(b.id)));
  const rank = new Map(nodesByRank.map((n, i) => [n.id, i]));
  function byRank(a, b) {
    return rank.get(a.id) - rank.get(b.id);
  }
  function edgeOrder(e, f) {
    const ea = Math.min(rank.get(e.from), rank.get(e.to)), eb = Math.max(rank.get(e.from), rank.get(e.to));
    const fa = Math.min(rank.get(f.from), rank.get(f.to)), fb = Math.max(rank.get(f.from), rank.get(f.to));
    return (ea - fa) || (eb - fb) || (rank.get(e.from) - rank.get(f.from));
  }
  const edgesByRank = drawnEdges.slice().sort(edgeOrder);
  function rankedNeighbours(node) {
    return Array.from(neighbours.get(node.id)).map(id => byId.get(id)).sort(byRank);
  }

  // Groups, each listed breadth first from its highest-ranked node; largest group first
  const components = [];
  (function () {
    const seen = new Set();
    nodesByRank.forEach(n => {
      if (seen.has(n.id)) return;
      const comp = [n];
      seen.add(n.id);
      for (let i = 0; i < comp.length; i++) {
        rankedNeighbours(comp[i]).forEach(x => { if (!seen.has(x.id)) { seen.add(x.id); comp.push(x); } });
      }
      components.push(comp);
    });
  })();

  let width = 0, height = 0, scale = 1, panX = 0, panY = 0;
  let dragNode = null, hoverNode = null, hoverBorderCluster = null;
  let panning = false, startX = 0, startY = 0, startPanX = 0, startPanY = 0;
  let borderIndicators = [];

  // Physics simulation configuration with alpha cooling (stops jitter/infinite floating)
  let alpha = 1.0;
  let isSimulating = true;
  const MIN_ALPHA = 0.003;
  const ALPHA_DECAY = 0.985;
  const DAMPING = 0.84;
  const NODE_COUNT = nodes.length;
  const REPULSION_BASE = NODE_COUNT > 30 ? 7500 : 5000;
  const EDGE_ATTRACTION = 0.032;
  const CENTER_FORCE = 0.012;

  // Seed layout: each group as a radial tree around its highest-ranked node
  const LEVEL_DISTANCE = 200;
  const GROUP_GAP = 120;
  // Space between groups when they are packed after the layout settles, in world units
  const PACK_GAP = 180;

  // Stars: degree-1 neighbours of a node with at least STAR_MIN_LEAVES of them are spread evenly
  // around it; above STAR_WIDE_FROM the ring widens so each gets STAR_SLOT of its circumference
  const STAR_MIN_LEAVES = 3;
  const STAR_WIDE_FROM = 8;
  const STAR_SLOT = 120;
  const STAR_RADIUS = 190;

  // Crossing reduction after the forces settle: groups up to this size only; larger groups keep the
  // force layout
  const SWAP_MAX_NODES = 30;
  const SWAP_MAX_LINKS = 60;
  const SWAP_MAX_ROUNDS = 20;
  const ARC_SAMPLES = 8;

  // Crossing reduction, star spreading and fit view run once the first layout settles and after each
  // Re-layout; settling after a drag keeps the dragged positions
  let layoutPassPending = true;

  // View: the off-screen rule treats node centres within 28 px of the canvas edge as outside
  const OFFSCREEN_MARGIN = 28;
  const VIEW_MARGIN = 34;

  // Label placement
  const LABEL_GAP = 4;
  const LABEL_RINGS = 6;
  const LABEL_DIRECTIONS = 16;
  const LABEL_GRID_CELL = 48;
  // While the simulation moves a larger graph, labels sit under their nodes unchecked until it settles
  const LABEL_LIVE_MAX_NODES = 200;
  const EDGE_LABEL_POSITIONS = [0.5, 0.4, 0.6, 0.3, 0.7];
  const edgeLabelOrder = edgesByRank.slice().sort((e, f) => ((f.count || 0) - (e.count || 0)) || edgeOrder(e, f));

  function resize() {
    const rect = canvas.getBoundingClientRect();
    width = Math.max(320, Math.floor(rect.width));
    height = Math.max(240, Math.floor(rect.height));
    canvas.width = Math.floor(width * window.devicePixelRatio);
    canvas.height = Math.floor(height * window.devicePixelRatio);
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
  }

  // Radial tree of one group around its first (highest-ranked) node: each node gets a share of its
  // parent's angle in proportion to the size of its subtree. Returns positions relative to the centre
  // and the group's radius.
  function radialTree(comp) {
    const root = comp[0];
    const children = new Map(comp.map(n => [n.id, []]));
    const depth = new Map([[root.id, 0]]);
    const order = [root];
    for (let i = 0; i < order.length; i++) {
      rankedNeighbours(order[i]).forEach(nb => {
        if (!depth.has(nb.id)) {
          depth.set(nb.id, depth.get(order[i].id) + 1);
          children.get(order[i].id).push(nb);
          order.push(nb);
        }
      });
    }
    // Siblings linked to each other sit next to each other around their parent, so a triangle on the
    // root does not cross another
    children.forEach((kids, id) => {
      const rest = kids.slice();
      const chained = [];
      while (rest.length) {
        const last = chained[chained.length - 1];
        const k = last ? rest.findIndex(n => neighbours.get(last.id).has(n.id)) : -1;
        chained.push(rest.splice(k >= 0 ? k : 0, 1)[0]);
      }
      children.set(id, chained);
    });
    const weight = new Map();
    for (let i = order.length - 1; i >= 0; i--) {
      let w = 1;
      children.get(order[i].id).forEach(c => { w += weight.get(c.id); });
      weight.set(order[i].id, w);
    }
    const rootChildren = children.get(root.id).length;
    const firstRing = rootChildren > STAR_WIDE_FROM
      ? Math.max(LEVEL_DISTANCE, rootChildren * STAR_SLOT / (2 * Math.PI)) : LEVEL_DISTANCE;
    const ringRadius = d => (d === 0 ? 0 : firstRing + (d - 1) * LEVEL_DISTANCE);
    const place = new Map([[root.id, { x: 0, y: 0 }]]);
    const wedge = new Map([[root.id, [-Math.PI / 2, 1.5 * Math.PI]]]);
    let extent = 0;
    order.forEach(n => {
      const [a0, a1] = wedge.get(n.id);
      const kids = children.get(n.id);
      const total = kids.reduce((s, c) => s + weight.get(c.id), 0);
      let a = a0;
      kids.forEach(c => {
        const span = (a1 - a0) * weight.get(c.id) / total;
        wedge.set(c.id, [a, a + span]);
        const mid = a + span / 2;
        const r = ringRadius(depth.get(c.id));
        place.set(c.id, { x: Math.cos(mid) * r, y: Math.sin(mid) * r });
        extent = Math.max(extent, r + (c.size || 10));
        a += span;
      });
    });
    return { place, radius: Math.max(90, extent) };
  }

  function seedPositions() {
    const numComps = components.length;
    if (numComps === 0) return;
    const trees = components.map(radialTree);
    // Groups packed in rows, largest first, in cells of their diameter plus GROUP_GAP; the rows are
    // as wide as makes the packing about as wide as the canvas is, relative to its height
    const cell = trees.map(t => 2 * t.radius + GROUP_GAP);
    const aspect = width / Math.max(height, 1);
    const rowWidth = Math.max(Math.max(...cell), Math.sqrt(cell.reduce((s, d) => s + d * d, 0) * aspect));
    const centres = [];
    let x = 0, y = 0, rowHeight = 0, totalWidth = 0;
    cell.forEach(d => {
      if (x > 0 && x + d > rowWidth) { y += rowHeight; x = 0; rowHeight = 0; }
      centres.push({ x: x + d / 2, y: y + d / 2 });
      x += d;
      rowHeight = Math.max(rowHeight, d);
      totalWidth = Math.max(totalWidth, x);
    });
    const totalHeight = y + rowHeight;
    centres.forEach(c => { c.x += width / 2 - totalWidth / 2; c.y += height / 2 - totalHeight / 2; });
    components.forEach((comp, idx) => {
      const c = centres[idx];
      comp.forEach(node => {
        const p = trees[idx].place.get(node.id);
        node.x = c.x + p.x;
        node.y = c.y + p.y;
        node.vx = 0;
        node.vy = 0;
        node.fixed = false;
        node.componentId = idx;
        node.clusterCenter = { x: c.x, y: c.y };
      });
    });
  }

  function worldToScreen(x, y) {
    return { x: x * scale + panX, y: y * scale + panY };
  }

  function screenToWorld(x, y) {
    return { x: (x - panX) / scale, y: (y - panY) / scale };
  }

  function tick() {
    if (alpha < MIN_ALPHA) {
      nodes.forEach(n => { n.vx = 0; n.vy = 0; });
      if (isSimulating) {
        isSimulating = false;
        if (layoutPassPending) {
          layoutPassPending = false;
          reduceCrossings();
          spreadStars();
          packGroups();
          fitView();
        }
        draw();
      }
      return;
    }

    const repulsionNodes = nodesByRank.length > 400 ? nodesByRank.slice(0, 400) : nodesByRank;

    // 1. Repulsion force + Hard non-overlap collision resolution
    for (let i = 0; i < repulsionNodes.length; i++) {
      const a = repulsionNodes[i];
      for (let j = i + 1; j < repulsionNodes.length; j++) {
        const b = repulsionNodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.1;

        // Force multiplier: stronger push between different components
        const sameComp = (a.componentId === b.componentId);
        const repForce = sameComp ? REPULSION_BASE : REPULSION_BASE * 1.9;
        const force = Math.min(25, repForce / (d * d)) * alpha;
        const fx = (dx / d) * force;
        const fy = (dy / d) * force;

        if (!a.fixed) { a.vx += fx; a.vy += fy; }
        if (!b.fixed) { b.vx -= fx; b.vy -= fy; }

        // Collision separation: ensure nodes never physically overlap
        const minDist = (a.size || 10) + (b.size || 10) + 42;
        if (d < minDist) {
          const overlap = (minDist - d) * 0.5 * Math.min(1.0, alpha * 2.5);
          const ox = (dx / d) * overlap;
          const oy = (dy / d) * overlap;
          if (!a.fixed) { a.x += ox; a.y += oy; }
          if (!b.fixed) { b.x -= ox; b.y -= oy; }
        }
      }
    }

    // 2. Edge attraction springs
    edgesByRank.forEach((edge) => {
      const a = byId.get(edge.from);
      const b = byId.get(edge.to);
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const restLen = 175 + Math.min(90, ((a.degree || 1) + (b.degree || 1)) * 7);
      const force = (d - restLen) * EDGE_ATTRACTION * alpha;
      const fx = (dx / d) * force;
      const fy = (dy / d) * force;
      if (!a.fixed) { a.vx += fx; a.vy += fy; }
      if (!b.fixed) { b.vx -= fx; b.vy -= fy; }
    });

    // 3. Cluster center gravity & damping
    nodesByRank.forEach((node) => {
      if (node.fixed) return;
      const center = node.clusterCenter || { x: width / 2, y: height / 2 };
      node.vx += (center.x - node.x) * CENTER_FORCE * alpha;
      node.vy += (center.y - node.y) * CENTER_FORCE * alpha;
      node.vx *= DAMPING;
      node.vy *= DAMPING;
      if (Math.abs(node.vx) < 0.01) node.vx = 0;
      if (Math.abs(node.vy) < 0.01) node.vy = 0;
      node.x += node.vx;
      node.y += node.vy;
    });

    alpha *= ALPHA_DECAY;
  }

  // Deterministic hash for stable per-edge curve offsets, taken over the structural ranks of the
  // two ends so that ids and labels never change a curve
  function edgeHash(fromKey, toKey) {
    let h = 0;
    const s = fromKey + ":" + toKey;
    for (let i = 0; i < s.length; i++) {
      h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    }
    return h;
  }

  // Bend of a connection's arc in world units (15 to 30), the same for both directions of a link.
  // Every arc bends to the left of its direction of travel, so the two arcs of a two-way link are
  // mirror images, and the curve keeps its shape at every zoom.
  const arcBend = new Map();
  function arcControl(edge, a, b) {
    let magnitude = arcBend.get(edge);
    if (magnitude === undefined) {
      const ra = rank.get(edge.from), rb = rank.get(edge.to);
      magnitude = 15 + (Math.abs(edgeHash(String(Math.min(ra, rb)), String(Math.max(ra, rb)))) % 16);
      arcBend.set(edge, magnitude);
    }
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    return { x: (a.x + b.x) / 2 - (dy / d) * magnitude, y: (a.y + b.y) / 2 + (dx / d) * magnitude };
  }

  function arcPolyline(edge) {
    const a = byId.get(edge.from);
    const b = byId.get(edge.to);
    const c = arcControl(edge, a, b);
    const points = [];
    for (let i = 0; i <= ARC_SAMPLES; i++) {
      const t = i / ARC_SAMPLES;
      const u = 1 - t;
      points.push({ x: u * u * a.x + 2 * u * t * c.x + t * t * b.x, y: u * u * a.y + 2 * u * t * c.y + t * t * b.y });
    }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    points.forEach(p => {
      minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
    });
    return { points, minX, maxX, minY, maxY };
  }

  function side(a, b, c) {
    return (c.x - a.x) * (b.y - a.y) - (b.x - a.x) * (c.y - a.y);
  }

  function segmentsCross(p1, p2, q1, q2) {
    return side(q1, q2, p1) * side(q1, q2, p2) < 0 && side(p1, p2, q1) * side(p1, p2, q2) < 0;
  }

  function polylinesCross(p, q) {
    if (p.maxX < q.minX || q.maxX < p.minX || p.maxY < q.minY || q.maxY < p.minY) return false;
    const pp = p.points, qp = q.points;
    for (let i = 0; i < pp.length - 1; i++) {
      for (let j = 0; j < qp.length - 1; j++) {
        if (segmentsCross(pp[i], pp[i + 1], qp[j], qp[j + 1])) return true;
      }
    }
    return false;
  }

  function sameLink(e, f) {
    return (e.from === f.from && e.to === f.to) || (e.from === f.to && e.to === f.from);
  }

  function shareNode(e, f) {
    return e.from === f.from || e.from === f.to || e.to === f.from || e.to === f.to;
  }

  function groupMembers() {
    const groups = new Map();
    nodesByRank.forEach(n => {
      if (!groups.has(n.componentId)) groups.set(n.componentId, []);
      groups.get(n.componentId).push(n);
    });
    return groups;
  }

  function groupArcs(members) {
    const ids = new Set(members.map(n => n.id));
    return edgesByRank.filter(e => ids.has(e.from) && ids.has(e.to));
  }

  // Whether an arc passes over a node that is not one of its ends (within the node's size plus 4)
  function arcOverNode(poly, edge, node) {
    if (node.id === edge.from || node.id === edge.to) return false;
    const r = (node.size || 10) + 4;
    if (node.x + r < poly.minX || node.x - r > poly.maxX || node.y + r < poly.minY || node.y - r > poly.maxY) return false;
    const pts = poly.points;
    for (let i = 0; i < pts.length - 1; i++) {
      const p = pts[i], q = pts[i + 1];
      const dx = q.x - p.x, dy = q.y - p.y;
      const len2 = dx * dx + dy * dy || 1;
      const t = Math.max(0, Math.min(1, ((node.x - p.x) * dx + (node.y - p.y) * dy) / len2));
      const ex = p.x + t * dx - node.x, ey = p.y + t * dy - node.y;
      if (ex * ex + ey * ey < r * r) return true;
    }
    return false;
  }

  // Layout conflicts in a group: pairs of crossing arcs plus arcs passing over a node
  function countConflicts(members, arcs) {
    const poly = arcs.map(arcPolyline);
    let count = 0;
    for (let i = 0; i < arcs.length; i++) {
      for (let j = i + 1; j < arcs.length; j++) {
        if (!shareNode(arcs[i], arcs[j]) && polylinesCross(poly[i], poly[j])) count++;
      }
      members.forEach(n => { if (arcOverNode(poly[i], arcs[i], n)) count++; });
    }
    return count;
  }

  // Greedy swaps of node positions within each group, in structural order, kept only when they
  // lower the number of conflicts (crossing arcs, arcs over a node) and put no two nodes on top of
  // each other; repeated until a round changes nothing. Arcs that share a node are not counted as
  // crossing.
  function reduceCrossings() {
    groupMembers().forEach(members => {
      if (members.length < 4 || members.length > SWAP_MAX_NODES) return;
      const arcs = groupArcs(members);
      const links = new Set(arcs.map(e => Math.min(rank.get(e.from), rank.get(e.to)) + ">" + Math.max(rank.get(e.from), rank.get(e.to))));
      if (links.size > SWAP_MAX_LINKS) return;

      const touching = new Map(members.map(n => [n.id, []]));
      arcs.forEach((e, i) => { touching.get(e.from).push(i); touching.get(e.to).push(i); });
      const poly = arcs.map(arcPolyline);
      // crosses[i]: the arcs that arc i crosses, kept current as swaps are accepted
      const crosses = arcs.map(() => new Set());
      for (let i = 0; i < arcs.length; i++) {
        for (let j = i + 1; j < arcs.length; j++) {
          if (!shareNode(arcs[i], arcs[j]) && polylinesCross(poly[i], poly[j])) {
            crosses[i].add(j);
            crosses[j].add(i);
          }
        }
      }

      // over[i]: the nodes arc i passes over, kept current as swaps are accepted
      const over = arcs.map((e, i) => new Set(members.filter(n => arcOverNode(poly[i], e, n)).map(n => n.id)));

      function countPairs(set, lists) {
        let count = 0;
        set.forEach(i => lists[i].forEach(j => { if (!set.has(j) || i < j) count++; }));
        return count;
      }

      // Conflicts that a swap of a and b can change: crossings of the arcs touching them, those
      // arcs over any node, and the other arcs over a or b
      function localScore(set, lists, overLists, a, b) {
        let count = countPairs(set, lists);
        set.forEach(i => { count += overLists[i].size; });
        for (let i = 0; i < arcs.length; i++) {
          if (set.has(i)) continue;
          if (overLists[i].has(a.id)) count++;
          if (overLists[i].has(b.id)) count++;
        }
        return count;
      }

      function overAfterSwap(set, a, b) {
        return arcs.map((e, i) => {
          if (set.has(i)) return new Set(members.filter(n => arcOverNode(poly[i], e, n)).map(n => n.id));
          const now = new Set(over[i]);
          [a, b].forEach(n => { if (arcOverNode(poly[i], e, n)) now.add(n.id); else now.delete(n.id); });
          return now;
        });
      }

      function crossingsAfterSwap(set) {
        const lists = [];
        set.forEach(i => {
          const found = new Set();
          for (let j = 0; j < arcs.length; j++) {
            if (i !== j && !shareNode(arcs[i], arcs[j]) && polylinesCross(poly[i], poly[j])) found.add(j);
          }
          lists[i] = found;
        });
        return lists;
      }

      function acceptCrossings(set, lists) {
        set.forEach(i => {
          crosses[i].forEach(j => crosses[j].delete(i));
          crosses[i] = lists[i];
        });
        set.forEach(i => crosses[i].forEach(j => crosses[j].add(i)));
      }

      function crowded(node) {
        return members.some(o => o !== node &&
          Math.hypot(o.x - node.x, o.y - node.y) < (o.size || 10) + (node.size || 10) + 8);
      }

      function swap(a, b, set) {
        const x = a.x, y = a.y;
        a.x = b.x; a.y = b.y; b.x = x; b.y = y;
        set.forEach(i => { poly[i] = arcPolyline(arcs[i]); });
      }

      for (let round = 0; round < SWAP_MAX_ROUNDS; round++) {
        let improved = false;
        for (let i = 0; i < members.length; i++) {
          for (let j = i + 1; j < members.length; j++) {
            const a = members[i], b = members[j];
            if (a.fixed || b.fixed) continue;
            const set = new Set(touching.get(a.id).concat(touching.get(b.id)));
            const before = localScore(set, crosses, over, a, b);
            if (before === 0) continue;
            swap(a, b, set);
            const lists = crossingsAfterSwap(set);
            const overLists = overAfterSwap(set, a, b);
            if (localScore(set, lists, overLists, a, b) < before && !crowded(a) && !crowded(b)) {
              acceptCrossings(set, lists);
              overLists.forEach((o, i) => { over[i] = o; });
              improved = true;
            } else {
              swap(a, b, set);
            }
          }
        }
        if (!improved) break;
      }
    });
  }

  // Degree-1 neighbours of a hub are spread evenly around it: through the gaps between the hub's
  // other neighbours, each gap getting a share of the leaves in proportion to its angle, keeping
  // the leaves' angular order. A leaf that would sit on another node moves outward. The change is
  // kept only if it adds no crossing and no arc over a node in the group.
  function spreadStars() {
    const groups = groupMembers();
    nodesByRank.forEach(hub => {
      if (hub.fixed) return;
      const nbs = rankedNeighbours(hub);
      const leaves = nbs.filter(n => neighbours.get(n.id).size === 1 && !n.fixed);
      if (leaves.length < STAR_MIN_LEAVES) return;
      const others = nbs.filter(n => neighbours.get(n.id).size !== 1 || n.fixed);
      const angleOf = n => Math.atan2(n.y - hub.y, n.x - hub.x);
      const members = groups.get(hub.componentId);
      const arcs = groupArcs(members);
      const before = countConflicts(members, arcs);
      const saved = leaves.map(n => [n.x, n.y]);

      const radius = leaves.length > STAR_WIDE_FROM
        ? Math.max(STAR_RADIUS, leaves.length * STAR_SLOT / (2 * Math.PI)) : STAR_RADIUS;
      const fixedAngles = others.map(angleOf).sort((a, b) => a - b);
      const base = fixedAngles.length ? fixedAngles[0] : -Math.PI / 2;
      const norm = a => ((a - base) % (2 * Math.PI) + 2 * Math.PI) % (2 * Math.PI);
      const slots = [];
      if (fixedAngles.length === 0) {
        for (let k = 0; k < leaves.length; k++) slots.push(base + (2 * Math.PI * (k + 0.5)) / leaves.length);
      } else {
        const gaps = fixedAngles.map((a, i) => {
          const next = i + 1 < fixedAngles.length ? fixedAngles[i + 1] : fixedAngles[0] + 2 * Math.PI;
          return { start: a, size: next - a };
        });
        const exact = gaps.map(g => leaves.length * g.size / (2 * Math.PI));
        const counts = exact.map(Math.floor);
        let left = leaves.length - counts.reduce((s, c) => s + c, 0);
        exact.map((x, i) => [x - Math.floor(x), i]).sort((p, q) => (q[0] - p[0]) || (p[1] - q[1]))
          .forEach(([, i]) => { if (left > 0) { counts[i]++; left--; } });
        gaps.forEach((g, i) => {
          for (let k = 0; k < counts[i]; k++) slots.push(g.start + g.size * (k + 1) / (counts[i] + 1));
        });
      }
      const ordered = leaves.slice().sort((p, q) => (norm(angleOf(p)) - norm(angleOf(q))) || byRank(p, q));
      slots.sort((p, q) => norm(p) - norm(q));
      ordered.forEach((leaf, k) => {
        let r = radius;
        for (let step = 0; step < 8; step++) {
          leaf.x = hub.x + Math.cos(slots[k]) * r;
          leaf.y = hub.y + Math.sin(slots[k]) * r;
          const blocked = nodes.some(o => o !== leaf && !ordered.slice(0, k).includes(o) && !leaves.includes(o) &&
            Math.hypot(o.x - leaf.x, o.y - leaf.y) < (o.size || 10) + (leaf.size || 10) + 24);
          if (!blocked) break;
          r += 40;
        }
      });
      if (countConflicts(members, arcs) > before) {
        leaves.forEach((n, i) => { n.x = saved[i][0]; n.y = saved[i][1]; });
      }
    });
  }

  // Groups packed in rows by their settled extent, tallest first (ties in structural order), each
  // keeping its shape. The row width is the one, among the widths at which a row would break, that
  // lets the whole packing be drawn largest on this canvas.
  function packGroups() {
    const groups = Array.from(groupMembers().values());
    if (groups.length < 2) return;
    const boxes = groups.map(members => {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      members.forEach(n => {
        const r = n.size || 10;
        x0 = Math.min(x0, n.x - r); y0 = Math.min(y0, n.y - r);
        x1 = Math.max(x1, n.x + r); y1 = Math.max(y1, n.y + r);
      });
      return { members, x0, y0, w: x1 - x0 + PACK_GAP, h: y1 - y0 + PACK_GAP, rank: rank.get(members[0].id) };
    }).sort((a, b) => (b.h - a.h) || (a.rank - b.rank));
    const availW = Math.max(100, width - 2 * VIEW_MARGIN);
    const availH = Math.max(100, height - 2 * VIEW_MARGIN - 30);
    function shelf(rowWidth) {
      const spots = [];
      let x = 0, y = 0, rowH = 0, total = 0;
      boxes.forEach(b => {
        if (x > 0 && x + b.w > rowWidth) { y += rowH; x = 0; rowH = 0; }
        spots.push({ x, y });
        x += b.w;
        rowH = Math.max(rowH, b.h);
        total = Math.max(total, x);
      });
      return { spots, w: total, h: y + rowH };
    }
    const widths = new Set([Math.max(...boxes.map(b => b.w))]);
    let run = 0;
    boxes.forEach(b => { run += b.w; widths.add(run); });
    let best = null;
    Array.from(widths).sort((a, b) => a - b).forEach(rowWidth => {
      const packed = shelf(rowWidth);
      const zoom = Math.min(availW / packed.w, availH / packed.h);
      if (!best || zoom > best.zoom + 1e-9) best = { zoom, packed };
    });
    boxes.forEach((b, i) => {
      const dx = best.packed.spots[i].x - b.x0;
      const dy = best.packed.spots[i].y - b.y0;
      b.members.forEach(n => {
        n.x += dx; n.y += dy;
        if (n.clusterCenter) n.clusterCenter = { x: n.clusterCenter.x + dx, y: n.clusterCenter.y + dy };
      });
    });
  }

  // Overlays drawn over the canvas by the page (the off-screen banner and the hint line), as boxes
  // in canvas coordinates
  function overlayBoxes() {
    const boxes = [];
    if (typeof canvas.getBoundingClientRect !== "function") return boxes;
    const origin = canvas.getBoundingClientRect();
    ["offscreen-alert", "hint"].forEach(id => {
      const el = document.getElementById(id);
      if (!el || typeof el.getBoundingClientRect !== "function") return;
      if (el.style && el.style.display === "none") return;
      const r = el.getBoundingClientRect();
      if (!r || !(r.width > 0) || !(r.height > 0)) return;
      boxes.push({ x0: r.left - origin.left, y0: r.top - origin.top, x1: r.right - origin.left, y1: r.bottom - origin.top });
    });
    return boxes;
  }

  // Fit view: the largest zoom (up to 1.35) at which every node lies inside the canvas, at least
  // VIEW_MARGIN from its edges and clear of the overlays, and every label finds a free place inside
  // the canvas; below the zoom at which labels are drawn, nodes alone decide
  function fitView() {
    if (nodes.length === 0) {
      scale = 1; panX = 0; panY = 0;
      draw();
      return;
    }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity, maxSize = 0;
    nodes.forEach(n => {
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
      maxSize = Math.max(maxSize, n.size || 10);
    });
    const area = { x0: VIEW_MARGIN, y0: VIEW_MARGIN, x1: width - VIEW_MARGIN, y1: height - VIEW_MARGIN };
    overlayBoxes().forEach(b => {
      // An overlay along the bottom edge (the hint line) shortens the area from below
      if (b.y0 > height / 2 && b.x1 > 0 && b.x0 < width) area.y1 = Math.min(area.y1, b.y0 - 4);
    });
    const availW = Math.max(40, area.x1 - area.x0);
    const availH = Math.max(40, area.y1 - area.y0);
    const gw = maxX - minX, gh = maxY - minY;
    let s = Math.min(1.35, (availW - 2 * maxSize) / Math.max(gw, 1), (availH - 2 * maxSize) / Math.max(gh, 1));
    s = Math.max(0.12, s);
    function setView(z) {
      scale = z;
      panX = (area.x0 + area.x1) / 2 - ((minX + maxX) / 2) * scale;
      panY = (area.y0 + area.y1) / 2 - ((minY + maxY) / 2) * scale;
      updateOffscreenIndicators();
    }
    // First the largest zoom at which every node is in view (no off-screen badge)
    for (let attempt = 0; attempt < 80; attempt++) {
      setView(s);
      if (borderIndicators.length === 0 || s <= 0.12) break;
      s = Math.max(0.12, s * 0.96);
    }
    // Then, for graphs up to LABEL_LIVE_MAX_NODES nodes, if a label finds no free place, the largest
    // zoom at which all do, by bisection; zooming out never drops below the zoom at which labels are
    // drawn just to avoid such a label: the zoom with the fewest of them is kept instead
    let failures = nodes.length <= LABEL_LIVE_MAX_NODES ? placeLabels().failures : 0;
    if (failures > 0 && s > 0.36) {
      let best = { scale: s, failures };
      let hi = s, lo = 0.36;
      for (let step = 0; step < 7 && best.failures > 0; step++) {
        const mid = (hi + lo) / 2;
        setView(mid);
        const f = placeLabels().failures;
        if (f < best.failures || (f === best.failures && mid > best.scale)) best = { scale: mid, failures: f };
        if (f === 0) lo = mid; else hi = mid;
      }
      if (best.failures > 0) {
        setView(lo);
        const f = placeLabels().failures;
        if (f < best.failures) best = { scale: lo, failures: f };
      } else {
        // Largest zoom found with every label placed
        let top = best.scale;
        for (let step = 0; step < 4; step++) {
          const mid = (top + hi) / 2;
          setView(mid);
          if (placeLabels().failures === 0) top = mid; else hi = mid;
        }
        best.scale = top;
      }
      setView(best.scale);
    }
    draw();
  }

  function zoom(factor, centerX, centerY) {
    const cx = centerX !== undefined ? centerX : width / 2;
    const cy = centerY !== undefined ? centerY : height / 2;
    const newScale = Math.max(0.08, Math.min(10, scale * factor));
    panX = cx - (cx - panX) * (newScale / scale);
    panY = cy - (cy - panY) * (newScale / scale);
    scale = newScale;
    draw();
  }

  function pillText(cluster) {
    const count = cluster.items.length;
    return count === 1 ? (cluster.items[0].node.label || cluster.items[0].node.id) : `+${count} devices`;
  }

  // Badge of an off-screen cluster, inward from the canvas edge
  function pillBox(cluster) {
    const inward = 24;
    const bx = cluster.x - Math.cos(cluster.angle) * inward;
    const by = cluster.y - Math.sin(cluster.angle) * inward;
    ctx.font = "10px monospace";
    const pw = ctx.measureText(pillText(cluster)).width + 12;
    const ph = 20;
    return { x0: bx - pw / 2, y0: by - ph / 2, x1: bx + pw / 2, y1: by + ph / 2, cx: bx, cy: by };
  }

  function updateOffscreenIndicators() {
    borderIndicators = [];
    const margin = OFFSCREEN_MARGIN;
    const cx = width / 2;
    const cy = height / 2;
    const left = margin;
    const right = width - margin;
    const top = margin;
    const bottom = height - margin;

    const offNodes = [];
    nodesByRank.forEach(n => {
      const sp = worldToScreen(n.x, n.y);
      if (sp.x < margin || sp.x > width - margin || sp.y < margin || sp.y > height - margin) {
        offNodes.push({ node: n, sx: sp.x, sy: sp.y });
      }
    });

    if (offNodes.length > 0) {
      offscreenAlert.style.display = "flex";
      offscreenAlert.innerHTML = `<span>⚠️ ${offNodes.length} device${offNodes.length > 1 ? 's' : ''} outside view</span> <button id="alert-fit-btn">Fit View</button>`;
      const btn = document.getElementById("alert-fit-btn");
      if (btn) btn.onclick = () => fitView();
    } else {
      offscreenAlert.style.display = "none";
    }

    const rawItems = [];
    offNodes.forEach(item => {
      const dx = item.sx - cx;
      const dy = item.sy - cy;
      let t = Infinity;
      if (dx > 0) t = Math.min(t, (right - cx) / dx);
      else if (dx < 0) t = Math.min(t, (left - cx) / dx);
      if (dy > 0) t = Math.min(t, (bottom - cy) / dy);
      else if (dy < 0) t = Math.min(t, (top - cy) / dy);

      if (t > 0 && isFinite(t)) {
        const bx = cx + t * dx;
        const by = cy + t * dy;
        const angle = Math.atan2(dy, dx);
        rawItems.push({ node: item.node, x: bx, y: by, angle, targetX: item.node.x, targetY: item.node.y });
      }
    });

    // Cluster border markers that are close to each other
    rawItems.forEach(item => {
      let merged = false;
      for (const c of borderIndicators) {
        if (Math.hypot(item.x - c.x, item.y - c.y) < 42) {
          c.items.push(item);
          c.x = (c.x * (c.items.length - 1) + item.x) / c.items.length;
          c.y = (c.y * (c.items.length - 1) + item.y) / c.items.length;
          merged = true;
          break;
        }
      }
      if (!merged) {
        borderIndicators.push({ x: item.x, y: item.y, angle: item.angle, items: [item] });
      }
    });

    // Clusters whose badges would overlap are merged into one "+N devices" badge
    let mergedAny = true;
    while (mergedAny) {
      mergedAny = false;
      const boxes = borderIndicators.map(pillBox);
      for (let i = 0; i < borderIndicators.length && !mergedAny; i++) {
        for (let j = i + 1; j < borderIndicators.length && !mergedAny; j++) {
          if (boxesOverlap(boxes[i], boxes[j], 2)) {
            const a = borderIndicators[i], b = borderIndicators[j];
            const n = a.items.length + b.items.length;
            a.x = (a.x * a.items.length + b.x * b.items.length) / n;
            a.y = (a.y * a.items.length + b.y * b.items.length) / n;
            a.angle = Math.atan2(a.y - cy, a.x - cx);
            a.items = a.items.concat(b.items);
            borderIndicators.splice(j, 1);
            mergedAny = true;
          }
        }
      }
    }
    borderIndicators.forEach(c => {
      c.box = pillBox(c);
      c.hitArea = { x: c.box.x0, y: c.box.y0, w: c.box.x1 - c.box.x0, h: c.box.y1 - c.box.y0 };
    });
  }

  function drawBorderIndicators() {
    borderIndicators.forEach(cluster => {
      const first = cluster.items[0].node;
      const x = cluster.x;
      const y = cluster.y;
      const angle = cluster.angle;
      const isHovered = (hoverBorderCluster === cluster);

      // 1. Arrowhead pointing off-screen
      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(angle);
      ctx.beginPath();
      ctx.moveTo(11, 0);
      ctx.lineTo(-7, -6);
      ctx.lineTo(-3, 0);
      ctx.lineTo(-7, 6);
      ctx.closePath();
      ctx.fillStyle = isHovered ? "#ffffff" : (first.color || "#f2a400");
      ctx.shadowColor = "rgba(0,0,0,0.6)";
      ctx.shadowBlur = 5;
      ctx.fill();
      ctx.restore();

      // 2. Device info badge positioned inward from canvas edge
      const box = cluster.box;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(box.x0, box.y0, box.x1 - box.x0, box.y1 - box.y0, 4);
      else ctx.rect(box.x0, box.y0, box.x1 - box.x0, box.y1 - box.y0);
      ctx.fillStyle = isHovered ? "rgba(35, 42, 56, 0.96)" : "rgba(18, 22, 31, 0.92)";
      ctx.fill();
      ctx.strokeStyle = isHovered ? "#ffffff" : (first.color || "#f2a400");
      ctx.lineWidth = isHovered ? 1.5 : 1;
      ctx.stroke();

      ctx.font = "10px monospace";
      ctx.fillStyle = isHovered ? "#ffffff" : "#e2e8f0";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(pillText(cluster), box.cx, box.cy);
    });
  }

  function drawArrow(edge, a, b) {
    const start = worldToScreen(a.x, a.y);
    const end = worldToScreen(b.x, b.y);

    // Bezier control point from the arc's world geometry
    const control = arcControl(edge, a, b);
    const cp = worldToScreen(control.x, control.y);
    const cpX = cp.x;
    const cpY = cp.y;

    // Target point: pull back from the destination node by its radius
    const nodeRadius = Math.max(6, b.size * scale);
    // Tangent at endpoint of quadratic Bezier: direction from control point to end
    const tangentDx = end.x - cpX;
    const tangentDy = end.y - cpY;
    const tangentD = Math.sqrt(tangentDx * tangentDx + tangentDy * tangentDy) || 1;
    const tnx = tangentDx / tangentD;
    const tny = tangentDy / tangentD;
    const tx = end.x - tnx * nodeRadius;
    const ty = end.y - tny * nodeRadius;

    const isConnectedToHover = hoverNode ? (edge.from === hoverNode.id || edge.to === hoverNode.id) : false;
    const isEdgeDimmed = hoverNode && !isConnectedToHover;

    // Draw curved edge
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.quadraticCurveTo(cpX, cpY, tx, ty);
    ctx.strokeStyle = isConnectedToHover ? "#f2a400" : (isEdgeDimmed ? "rgba(67, 75, 92, 0.25)" : "#5a6375");
    ctx.lineWidth = Math.max(1, (isConnectedToHover ? edge.width + 1 : edge.width) * scale);
    ctx.stroke();

    // Arrowhead aligned to curve tangent at the endpoint
    const head = Math.max(7, (8 + edge.width) * scale);
    ctx.beginPath();
    ctx.moveTo(tx, ty);
    ctx.lineTo(tx - tnx * head + (-tny) * head * 0.45, ty - tny * head + tnx * head * 0.45);
    ctx.lineTo(tx - tnx * head - (-tny) * head * 0.45, ty - tny * head - tnx * head * 0.45);
    ctx.closePath();
    ctx.fillStyle = isConnectedToHover ? "#f2a400" : (isEdgeDimmed ? "rgba(67, 75, 92, 0.25)" : "#5a6375");
    ctx.fill();
  }

  function drawEdgeLabel(edge, place) {
    const isConnectedToHover = hoverNode ? (edge.from === hoverNode.id || edge.to === hoverNode.id) : false;
    if (hoverNode && !isConnectedToHover) return;
    ctx.font = `${place.fontSize}px monospace`;
    ctx.fillStyle = "rgba(12, 15, 21, 0.9)";
    ctx.strokeStyle = isConnectedToHover ? "#f2a400" : "rgba(109, 118, 136, 0.45)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    const box = place.box;
    if (ctx.roundRect) ctx.roundRect(box.x0, box.y0, box.x1 - box.x0, box.y1 - box.y0, 3);
    else ctx.rect(box.x0, box.y0, box.x1 - box.x0, box.y1 - box.y0);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = isConnectedToHover ? "#ffffff" : "#c5ccd8";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(edge.label, (box.x0 + box.x1) / 2, (box.y0 + box.y1) / 2);
  }

  // Text widths by font size and text; the font must be set on ctx before the first lookup
  const labelWidths = new Map();
  function labelWidth(text, fontSize) {
    const key = fontSize + "px " + text;
    if (!labelWidths.has(key)) labelWidths.set(key, ctx.measureText(text).width);
    return labelWidths.get(key);
  }

  function boxesOverlap(a, b, margin) {
    const m = margin === undefined ? 1 : margin;
    return a.x0 < b.x1 + m && b.x0 < a.x1 + m && a.y0 < b.y1 + m && b.y0 < a.y1 + m;
  }

  function boxOnCircle(box, c) {
    const nx = Math.min(Math.max(c.x, box.x0), box.x1);
    const ny = Math.min(Math.max(c.y, box.y0), box.y1);
    const r = c.r + 1;
    return (nx - c.x) * (nx - c.x) + (ny - c.y) * (ny - c.y) < r * r;
  }

  // Whether a segment passes through a box grown by one pixel (Liang-Barsky clipping)
  function segmentOnBox(s, box) {
    const x0 = box.x0 - 1, y0 = box.y0 - 1, x1 = box.x1 + 1, y1 = box.y1 + 1;
    const dx = s.x1 - s.x0, dy = s.y1 - s.y0;
    let t0 = 0, t1 = 1;
    const tests = [[-dx, s.x0 - x0], [dx, x1 - s.x0], [-dy, s.y0 - y0], [dy, y1 - s.y0]];
    for (const [p, q] of tests) {
      if (p === 0) {
        if (q < 0) return false;
      } else {
        const t = q / p;
        if (p < 0) { if (t > t1) return false; if (t > t0) t0 = t; }
        else { if (t < t0) return false; if (t < t1) t1 = t; }
      }
    }
    return t1 - t0 > 1e-6;
  }

  function segmentOnCircle(s, c) {
    const dx = s.x1 - s.x0, dy = s.y1 - s.y0;
    const len2 = dx * dx + dy * dy || 1;
    const t = Math.max(0, Math.min(1, ((c.x - s.x0) * dx + (c.y - s.y0) * dy) / len2));
    const px = s.x0 + t * dx - c.x, py = s.y0 + t * dy - c.y;
    return px * px + py * py < (c.r + 1) * (c.r + 1);
  }

  function segmentBounds(s) {
    return { x0: Math.min(s.x0, s.x1), y0: Math.min(s.y0, s.y1), x1: Math.max(s.x0, s.x1), y1: Math.max(s.y0, s.y1) };
  }

  // Grid of everything a label must not touch: node circles, placed labels, leader lines, off-screen
  // badges and page overlays, in screen coordinates
  function makeLabelGrid() {
    const cells = new Map();
    function eachCell(box, fn) {
      const cx0 = Math.floor(box.x0 / LABEL_GRID_CELL), cx1 = Math.floor(box.x1 / LABEL_GRID_CELL);
      const cy0 = Math.floor(box.y0 / LABEL_GRID_CELL), cy1 = Math.floor(box.y1 / LABEL_GRID_CELL);
      for (let cx = cx0; cx <= cx1; cx++) {
        for (let cy = cy0; cy <= cy1; cy++) fn(cx * 1048576 + cy);
      }
    }
    function add(item) {
      eachCell(item.bounds, key => {
        if (!cells.has(key)) cells.set(key, []);
        cells.get(key).push(item);
      });
    }
    function nearby(bounds, fn) {
      const seen = new Set();
      let hit = false;
      eachCell(bounds, key => {
        if (hit) return;
        for (const item of (cells.get(key) || [])) {
          if (seen.has(item)) continue;
          seen.add(item);
          if (fn(item)) { hit = true; return; }
        }
      });
      return hit;
    }
    return {
      addCircle(c, owner) { add({ circle: c, owner, bounds: { x0: c.x - c.r, y0: c.y - c.r, x1: c.x + c.r, y1: c.y + c.r } }); },
      addBox(box) { add({ box, bounds: box }); },
      addSegment(s) { add({ segment: s, bounds: segmentBounds(s) }); },
      boxHits(box) {
        return nearby(box, item => item.circle ? boxOnCircle(box, item.circle)
          : item.box ? boxesOverlap(box, item.box) : segmentOnBox(item.segment, box));
      },
      // Pieces of arcs of another link (the two arcs of a two-way link are one link)
      boxHitsOtherThan(box, edge) {
        return nearby(box, item => item.segment && !sameLink(item.segment.edge, edge) && segmentOnBox(item.segment, box));
      },
      // A leader line may start on its own node's circle and end on its own label
      segmentHits(s, owner) {
        return nearby(segmentBounds(s), item => item.circle ? (item.owner !== owner && segmentOnCircle(s, item.circle))
          : item.box ? segmentOnBox(s, item.box)
          : segmentsCross({ x: s.x0, y: s.y0 }, { x: s.x1, y: s.y1 }, { x: item.segment.x0, y: item.segment.y0 }, { x: item.segment.x1, y: item.segment.y1 }));
      },
    };
  }

  // Direction for a node's first label candidate: away from the mean position of its neighbours (for
  // the leaves of a star, radially outward from the hub); straight down when that is undefined
  function preferredAngle(node) {
    let sx = 0, sy = 0, n = 0;
    neighbours.get(node.id).forEach(id => { const o = byId.get(id); sx += o.x; sy += o.y; n++; });
    if (n === 0) return Math.PI / 2;
    const dx = node.x - sx / n, dy = node.y - sy / n;
    if (Math.hypot(dx, dy) < 1) return Math.PI / 2;
    return Math.atan2(dy, dx);
  }

  // Label box whose nearest side lies at `distance` from the node centre in direction `angle`
  function labelBox(pos, distance, w, h, angle) {
    const ux = Math.cos(angle), uy = Math.sin(angle);
    const cx = pos.x + ux * distance + ux * w / 2;
    const cy = pos.y + uy * distance + uy * h / 2;
    return { x0: cx - w / 2, y0: cy - h / 2, x1: cx + w / 2, y1: cy + h / 2 };
  }

  // A connection's drawn arc in screen coordinates, as n + 1 points (start to the far node centre)
  function screenArc(edge, n) {
    const a = byId.get(edge.from), b = byId.get(edge.to);
    const start = worldToScreen(a.x, a.y);
    const end = worldToScreen(b.x, b.y);
    const control = arcControl(edge, a, b);
    const cp = worldToScreen(control.x, control.y);
    const pts = [];
    for (let i = 0; i <= n; i++) {
      const t = i / n, u = 1 - t;
      pts.push({ x: u * u * start.x + 2 * u * t * cp.x + t * t * end.x, y: u * u * start.y + 2 * u * t * cp.y + t * t * end.y });
    }
    return pts;
  }

  function leaderFor(pos, r, box) {
    const tx = Math.min(Math.max(pos.x, box.x0), box.x1);
    const ty = Math.min(Math.max(pos.y, box.y0), box.y1);
    const d = Math.hypot(tx - pos.x, ty - pos.y) || 1;
    return { x0: pos.x + (tx - pos.x) / d * (r + 1), y0: pos.y + (ty - pos.y) / d * (r + 1), x1: tx, y1: ty };
  }

  // Label placement in screen coordinates, redone on every draw. Node labels come first, in
  // structural order: each takes the first candidate, from its preferred direction outward through
  // 16 directions and 6 rings, that lies inside the canvas and touches nothing already there; a
  // label placed beyond the first ring is joined to its node by a leader line, which must not cross
  // anything either. Edge labels follow, busiest connection first, at points along their arc, also
  // clear of every other link's arcs; one that does not fit is not drawn, and a two-way link whose
  // arcs carry the same text gets one label. `failures` counts node labels left in their first candidate.
  // The last placement, reused while the view, the canvas, the node positions and the overlays are
  // unchanged (a hover only redraws)
  let placementKey = null, placementResult = null;
  function placeLabels() {
    const checked = !isSimulating || nodes.length <= LABEL_LIVE_MAX_NODES;
    let positions = 0;
    nodes.forEach((n, i) => { positions += (i + 1) * (n.x * 7.3 + n.y * 3.1); });
    const key = [scale, panX, panY, width, height, checked, positions, borderIndicators.length,
      offscreenAlert.style.display].join("|");
    if (key === placementKey) return placementResult;
    placementResult = computeLabelPlacement(checked);
    placementKey = key;
    return placementResult;
  }

  function computeLabelPlacement(checked) {
    const result = { nodeLabels: new Map(), edgeLabels: new Map(), failures: 0 };
    if (scale <= 0.35) return result;
    const grid = makeLabelGrid();
    const limit = { x0: 2, y0: 2, x1: width - 2, y1: height - 2 };
    const inside = box => box.x0 >= limit.x0 && box.y0 >= limit.y0 && box.x1 <= limit.x1 && box.y1 <= limit.y1;
    if (checked) {
      nodes.forEach(node => {
        const pos = worldToScreen(node.x, node.y);
        grid.addCircle({ x: pos.x, y: pos.y, r: Math.max(6, node.size * scale) }, node);
      });
      overlayBoxes().forEach(b => grid.addBox(b));
      borderIndicators.forEach(c => grid.addBox(c.box));
    }

    const nodeFont = Math.max(9, Math.min(13, Math.round(11 * scale)));
    ctx.font = `${nodeFont}px monospace`;
    nodesByRank.forEach(node => {
      const pos = worldToScreen(node.x, node.y);
      const r = Math.max(6, node.size * scale);
      const w = labelWidth(node.label, nodeFont);
      const h = nodeFont;
      const preferred = checked ? preferredAngle(node) : Math.PI / 2;
      let chosen = null, leader = null;
      if (checked) {
        search:
        for (let ring = 0; ring < LABEL_RINGS; ring++) {
          for (let k = 0; k < LABEL_DIRECTIONS; k++) {
            const turn = (k % 2 === 1 ? 1 : -1) * Math.ceil(k / 2);
            const angle = preferred + turn * (2 * Math.PI / LABEL_DIRECTIONS);
            const box = labelBox(pos, r + LABEL_GAP + ring * (h + 6), w, h, angle);
            if (!inside(box) || grid.boxHits(box)) continue;
            let line = null;
            if (ring > 0) {
              line = leaderFor(pos, r, box);
              if (grid.segmentHits(line, node)) continue;
            }
            chosen = box;
            leader = line;
            break search;
          }
        }
      }
      if (!chosen) {
        if (checked) result.failures++;
        chosen = labelBox(pos, r + LABEL_GAP, w, h, preferred);
      }
      grid.addBox(chosen);
      if (leader) grid.addSegment(leader);
      result.nodeLabels.set(node.id, { box: chosen, fontSize: nodeFont, leader });
    });

    if (scale > 0.5) {
      const edgeFont = Math.max(9, Math.min(12, Math.round(10 * scale)));
      ctx.font = `${edgeFont}px monospace`;
      // An edge label touches no connection but its own: every drawn arc, as straight pieces
      const curves = makeLabelGrid();
      if (checked) {
        drawnEdges.forEach(edge => {
          const pts = screenArc(edge, 12);
          for (let i = 0; i < pts.length - 1; i++) {
            curves.addSegment({ x0: pts[i].x, y0: pts[i].y, x1: pts[i + 1].x, y1: pts[i + 1].y, edge });
          }
        });
      }
      const placedLinks = [];
      edgeLabelOrder.forEach(edge => {
        if (!edge.label) return;
        // One label for a two-way link whose arcs carry the same text
        if (placedLinks.some(e => sameLink(e, edge) && e.label === edge.label)) return;
        const a = byId.get(edge.from), b = byId.get(edge.to);
        const start = worldToScreen(a.x, a.y);
        const end = worldToScreen(b.x, b.y);
        const control = arcControl(edge, a, b);
        const cp = worldToScreen(control.x, control.y);
        const w = labelWidth(edge.label, edgeFont) + 10;
        const h = edgeFont + 6;
        for (const t of EDGE_LABEL_POSITIONS) {
          const u = 1 - t;
          const x = u * u * start.x + 2 * u * t * cp.x + t * t * end.x;
          const y = u * u * start.y + 2 * u * t * cp.y + t * t * end.y;
          const box = { x0: x - w / 2, y0: y - h / 2, x1: x + w / 2, y1: y + h / 2 };
          if (!checked || (inside(box) && !grid.boxHits(box) && !curves.boxHitsOtherThan(box, edge))) {
            grid.addBox(box);
            result.edgeLabels.set(edge, { box, fontSize: edgeFont });
            placedLinks.push(edge);
            return;
          }
        }
      });
    }
    return result;
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    updateOffscreenIndicators();
    const labels = placeLabels();

    // 1. Draw connections, then the edge labels that have a place
    drawnEdges.forEach((edge) => drawArrow(edge, byId.get(edge.from), byId.get(edge.to)));
    labels.edgeLabels.forEach((place, edge) => drawEdgeLabel(edge, place));

    // 2. Draw nodes
    nodes.forEach((node) => {
      const pos = worldToScreen(node.x, node.y);
      const radius = Math.max(6, node.size * scale);
      const isHovered = (hoverNode === node);
      const isConnectedToHover = hoverNode && (adj.get(hoverNode.id) || []).includes(node.id);
      const isDimmed = hoverNode && !isHovered && !isConnectedToHover;

      // Glow halo on hover
      if (isHovered || isConnectedToHover) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, radius + 5, 0, Math.PI * 2);
        ctx.fillStyle = isHovered ? "rgba(242, 164, 0, 0.28)" : "rgba(255, 255, 255, 0.15)";
        ctx.fill();
        ctx.strokeStyle = isHovered ? "#f2a400" : "rgba(255, 255, 255, 0.4)";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = isDimmed ? "rgba(100, 110, 125, 0.35)" : node.color;
      ctx.fill();
      ctx.strokeStyle = isHovered ? "#ffffff" : "rgba(255,255,255,0.25)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // 3. Node labels with backdrop outline, and leader lines to labels placed away from their node
    nodes.forEach((node) => {
      const place = labels.nodeLabels.get(node.id);
      if (!place) return;
      const isHovered = (hoverNode === node);
      const isConnectedToHover = hoverNode && (adj.get(hoverNode.id) || []).includes(node.id);
      if (hoverNode && !isHovered && !isConnectedToHover) return;
      if (place.leader) {
        ctx.beginPath();
        ctx.moveTo(place.leader.x0, place.leader.y0);
        ctx.lineTo(place.leader.x1, place.leader.y1);
        ctx.strokeStyle = "rgba(233, 237, 245, 0.45)";
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      ctx.font = `${place.fontSize}px monospace`;
      ctx.textAlign = "left";
      ctx.textBaseline = "top";
      ctx.lineWidth = 3;
      ctx.strokeStyle = "rgba(12, 15, 21, 0.9)";
      ctx.strokeText(node.label, place.box.x0, place.box.y0);
      ctx.fillStyle = isHovered ? "#ffffff" : "#e9edf5";
      ctx.fillText(node.label, place.box.x0, place.box.y0);
    });

    // 4. Off-screen navigation indicators
    drawBorderIndicators();
  }

  function hitNode(screenX, screenY) {
    const point = screenToWorld(screenX, screenY);
    for (let i = nodes.length - 1; i >= 0; i--) {
      const node = nodes[i];
      const dx = node.x - point.x;
      const dy = node.y - point.y;
      if (Math.sqrt(dx * dx + dy * dy) <= node.size + 4) return node;
    }
    return null;
  }

  function hitBorderIndicator(screenX, screenY) {
    for (const c of borderIndicators) {
      if (c.hitArea) {
        const h = c.hitArea;
        if (screenX >= h.x && screenX <= h.x + h.w && screenY >= h.y && screenY <= h.y + h.h) {
          return c;
        }
      }
      if (Math.hypot(screenX - c.x, screenY - c.y) <= 18) return c;
    }
    return null;
  }

  function showTooltip(event, node, borderCluster) {
    if (borderCluster) {
      tooltip.style.display = "block";
      tooltip.style.left = `${event.clientX + 14}px`;
      tooltip.style.top = `${event.clientY + 14}px`;
      const count = borderCluster.items.length;
      tooltip.innerHTML =
        `<b>${count} Device${count > 1 ? 's' : ''} Off-Screen</b><br>` +
        `<span style="color:#aab3c2">Click indicator to pan directly here</span><br><br>` +
        borderCluster.items.slice(0, 8).map(i => `<span style="color:${i.node.color}">●</span> ${i.node.label} (${i.node.type})`).join('<br>') +
        (count > 8 ? `<br>...and ${count - 8} more` : '');
      return;
    }

    if (!node) {
      tooltip.style.display = "none";
      return;
    }
    tooltip.style.display = "block";
    tooltip.style.left = `${event.clientX + 14}px`;
    tooltip.style.top = `${event.clientY + 14}px`;
    tooltip.innerHTML =
      `<b>${node.label}</b><br>` +
      `ID: ${node.id}<br>` +
      `Type: ${node.type}<br>` +
      `Vendor: ${node.vendor_display}<br>` +
      (node.vendor_note ? `Vendor note: ${node.vendor_note}<br>` : "") +
      `Protocol: ${node.protocol}<br>` +
      `Role: ${node.role}<br>` +
      `MAC: ${node.mac}<br>` +
      `Confidence: ${node.confidence}%<br>` +
      `Packets: ${node.packet_count}`;
  }

  canvas.addEventListener("mousemove", (event) => {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    if (dragNode) {
      const point = screenToWorld(x, y);
      dragNode.x = point.x;
      dragNode.y = point.y;
      dragNode.vx = 0;
      dragNode.vy = 0;
      tooltip.style.display = "none";
      // Reheat slightly while dragging for responsive movement
      alpha = Math.max(alpha, 0.12);
      if (!isSimulating) {
        isSimulating = true;
        requestAnimationFrame(loop);
      }
      return;
    }

    if (panning) {
      panX = startPanX + event.clientX - startX;
      panY = startPanY + event.clientY - startY;
      draw();
      return;
    }

    const prevHover = hoverNode;
    const prevBorderHover = hoverBorderCluster;
    hoverNode = hitNode(x, y);
    hoverBorderCluster = hitBorderIndicator(x, y);

    if (hoverNode !== prevHover || hoverBorderCluster !== prevBorderHover) {
      draw();
    }

    showTooltip(event, hoverNode, hoverBorderCluster);
  });

  canvas.addEventListener("mousedown", (event) => {
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Check if user clicked a border indicator
    const borderCluster = hitBorderIndicator(x, y);
    if (borderCluster) {
      const avgX = borderCluster.items.reduce((acc, i) => acc + i.targetX, 0) / borderCluster.items.length;
      const avgY = borderCluster.items.reduce((acc, i) => acc + i.targetY, 0) / borderCluster.items.length;
      panX = width / 2 - avgX * scale;
      panY = height / 2 - avgY * scale;
      draw();
      return;
    }

    const node = hitNode(x, y);
    if (node) {
      dragNode = node;
      node.fixed = true;
    } else {
      panning = true;
      startX = event.clientX;
      startY = event.clientY;
      startPanX = panX;
      startPanY = panY;
    }
  });

  window.addEventListener("mouseup", () => {
    if (dragNode) {
      dragNode.fixed = false;
      dragNode = null;
    }
    panning = false;
  });

  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const mx = event.clientX - rect.left;
    const my = event.clientY - rect.top;
    const z = event.deltaY < 0 ? 1.15 : 0.88;
    zoom(z, mx, my);
  }, { passive: false });

  // UI Control Buttons
  document.getElementById("fit-btn").addEventListener("click", fitView);
  document.getElementById("zoom-in-btn").addEventListener("click", () => zoom(1.25));
  document.getElementById("zoom-out-btn").addEventListener("click", () => zoom(0.8));
  document.getElementById("relayout-btn").addEventListener("click", () => {
    alpha = 1.0;
    layoutPassPending = true;
    isSimulating = true;
    loop();
  });

  window.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
    if (e.key === "f" || e.key === "F") fitView();
    if (e.key === "+" || e.key === "=") zoom(1.2);
    if (e.key === "-" || e.key === "_") zoom(0.8);
  });

  document.getElementById("export-btn").addEventListener("click", function() {
    const allNodes = (graph.nodes || []).concat(graph.isolated_nodes || []);
    const assetData = allNodes.map(n => ({
      "IP": n.id,
      "MAC": n.mac || "",
      "Vendor": n.vendor || "",
      "Vendor note": n.vendor_note || "",
      "Protocol": n.protocol || "",
      "Role": n.role || "",
      "Type": n.type,
      "Confidence %": n.confidence,
      "Packets": n.packet_count
    }));

    const connData = (graph.edges || []).map(e => ({
      "Source": e.from,
      "Destination": e.to,
      "Protocol": e.label || "",
      "Count": e.count,
    }));

    const wb = XLSX.utils.book_new();
    const wsAssets = XLSX.utils.json_to_sheet(assetData);
    XLSX.utils.book_append_sheet(wb, wsAssets, "Assets");

    const wsConns = XLSX.utils.json_to_sheet(connData);
    XLSX.utils.book_append_sheet(wb, wsConns, "Connections");

    const summaryData = [
      ["Property", "Value"],
      ["Total Assets", summary.assets || 0],
      ["OT Assets", summary.ot || 0],
      ["IT Assets", summary.it || 0],
      ["Unknown Assets", summary.unknown || 0],
      ["Total Connections", summary.connections || 0],
      ["Isolated Assets", summary.isolated_count || 0],
      ["Exported", new Date().toLocaleString()],
    ];
    const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(wb, wsSummary, "Summary");

    XLSX.writeFile(wb, "scrutics_topology.xlsx");
  });

  function loop() {
    if (isSimulating) {
      tick();
      draw();
      requestAnimationFrame(loop);
    }
  }

  window.addEventListener("resize", () => {
    resize();
    draw();
  });

  resize();
  seedPositions();
  // Warm up initial simulation so layout settles quickly before first render
  for (let k = 0; k < 60; k++) {
    tick();
  }
  fitView();
  loop();
})();
</script>

<!-- ── Unified AI Panel ────────────────────────────────────────────────────── -->
<!-- Runs entirely in the browser. No requests to the Scrutics host.           -->
<!-- API key entered at runtime, stored in JS memory only, never in HTML.      -->
<style>
#ai-unified-btn {
  background: #1e3048; color: #e07b39; border: 1px solid #e07b39;
  padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 13px;
  font-family: monospace;
}
#ai-unified-btn:hover { background: #e07b39; color: #0d1b2e; }

#ai-panel {
  display: none; position: fixed; top: 0; left: 0; width: 400px; height: 100%;
  background: #0d1b2e; border-right: 2px solid #e07b39; z-index: 9999;
  flex-direction: column; font-family: monospace; font-size: 13px; color: #c8d8e8;
}
#ai-panel.open { display: flex; }

#ai-panel-header {
  background: #1e3048; padding: 10px 14px; border-bottom: 1px solid #2a4060;
  display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;
}
#ai-panel-title { color: #e07b39; font-weight: bold; font-size: 14px; }
#ai-panel-close {
  background: none; border: none; color: #8f98a8; font-size: 18px;
  cursor: pointer; padding: 0 4px; line-height: 1;
}
#ai-panel-close:hover { color: #e07b39; }

.ai-tabs { display: flex; border-bottom: 1px solid #2a4060; flex-shrink: 0; }
.ai-tab {
  flex: 1; padding: 7px 0; background: #0d1b2e; border: none; color: #8f98a8;
  font-family: monospace; font-size: 12px; cursor: pointer;
  border-bottom: 2px solid transparent;
}
.ai-tab:hover { color: #c8d8e8; }
.ai-tab.active { color: #e07b39; border-bottom: 2px solid #e07b39; }

.ai-pane { flex: 1; overflow-y: auto; padding: 14px; display: flex; flex-direction: column; }
.ai-pane.hidden { display: none; }

/* Configure tab */
.ai-field-label { color: #8f98a8; font-size: 11px; margin: 10px 0 3px; }
.ai-tips {
  background: #162030; border: 1px solid #2a5040; border-radius: 4px;
  padding: 9px 11px; margin-bottom: 10px; font-size: 11px; line-height: 1.7; color: #9ab8a8;
}
.ai-tips strong { color: #5ac898; }
.ai-tips a { color: #4a90d9; }
#ai-provider-select, #ai-key-input {
  width: 100%; box-sizing: border-box; background: #1e3048; border: 1px solid #2a4060;
  color: #c8d8e8; padding: 6px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;
}
#ai-provider-select:focus, #ai-key-input:focus { border-color: #e07b39; outline: none; }
#ai-connect-btn {
  margin-top: 12px; width: 100%; background: #e07b39; color: #0d1b2e; border: none;
  padding: 8px; border-radius: 4px; font-family: monospace; font-size: 13px;
  font-weight: bold; cursor: pointer;
}
#ai-connect-btn:hover { background: #f08c4a; }
#ai-config-status { margin-top: 7px; font-size: 11px; text-align: center; min-height: 14px; }

/* Chat tab */
#ai-chat-pane { padding: 0; }
#ai-chat-notice {
  flex: 1; display: flex; align-items: center; justify-content: center;
  color: #5a7898; font-size: 12px; text-align: center; padding: 20px;
}
#ai-chat-history {
  flex: 1; overflow-y: auto; padding: 10px 12px; display: flex;
  flex-direction: column; gap: 8px; min-height: 0;
}
.ai-msg { padding: 7px 10px; border-radius: 4px; line-height: 1.5;
  word-wrap: break-word; white-space: pre-wrap; }
.ai-msg.user { background: #1e3048; border-left: 3px solid #4a90d9; }
.ai-msg.assistant { background: #162030; border-left: 3px solid #e07b39; }
.ai-msg.notice { background: #162030; border-left: 3px solid #5a9878;
  font-size: 11px; color: #7a9888; }
.ai-msg.error { background: #1e1010; border-left: 3px solid #c04040; color: #e09898; }
#ai-chat-input-row {
  padding: 8px 12px; border-top: 1px solid #1e3048; display: flex; gap: 6px; flex-shrink: 0;
}
#ai-chat-input {
  flex: 1; background: #1e3048; border: 1px solid #2a4060; color: #c8d8e8;
  padding: 6px 8px; border-radius: 4px; font-family: monospace; font-size: 12px;
  resize: none; min-height: 32px; max-height: 80px;
}
#ai-chat-input:focus { border-color: #e07b39; outline: none; }
#ai-chat-send {
  background: #e07b39; color: #0d1b2e; border: none; padding: 6px 12px;
  border-radius: 4px; font-family: monospace; font-size: 13px; cursor: pointer; align-self: flex-end;
}
#ai-chat-send:hover { background: #f08c4a; }
#ai-chat-send:disabled, #ai-chat-input:disabled { opacity: 0.4; cursor: not-allowed; }

/* Launch tab */
#ai-launch-pane { gap: 12px; }
.ai-launch-section { background: #162030; border: 1px solid #2a4060; border-radius: 4px; padding: 12px; }
.ai-launch-section h4 { color: #e07b39; margin: 0 0 8px; font-size: 12px; }
.ai-launch-cmd {
  background: #0d1b2e; border: 1px solid #2a4060; border-radius: 3px;
  padding: 8px 10px; font-size: 11px; color: #c8d8e8; word-break: break-all;
  margin-bottom: 8px; min-height: 28px;
}
.ai-copy-btn {
  background: #1e3048; color: #e07b39; border: 1px solid #e07b39;
  padding: 4px 10px; border-radius: 4px; font-family: monospace; font-size: 11px; cursor: pointer;
}
.ai-copy-btn:hover { background: #e07b39; color: #0d1b2e; }
.ai-launch-note { font-size: 10px; color: #5a7898; margin-top: 6px; line-height: 1.5; }
</style>

<div id="ai-panel">
  <div id="ai-panel-header">
    <span id="ai-panel-title">✦ Scrutics AI</span>
    <button id="ai-panel-close" title="Close">✕</button>
  </div>

  <div class="ai-tabs">
    <button class="ai-tab active" data-tab="configure">⚙ Configure</button>
    <button class="ai-tab" data-tab="chat">💬 Chat</button>
    <button class="ai-tab" data-tab="launch">▶ Launch</button>
  </div>

  <!-- Configure tab -->
  <div class="ai-pane" id="ai-configure-pane">
    <div class="ai-tips">
      <strong>Quick chat on this page</strong><br>
      Enter a key below to chat about the topology visible here.<br><br>
      <strong>For full Scrutics AI</strong> (evidence store, anomaly detail, baselines):
      run <code style="color:#e07b39">scrutics_ai_setup.sh</code> in the terminal — it handles
      provider selection, key setup, and reconfiguration in one step.
      See the <strong>Launch</strong> tab for commands.<br><br>
      • <a href="https://aistudio.google.com/app/apikey" target="_blank">Google Gemini</a> — free tier, no credit card.<br>
      • OpenAI and Anthropic — paid accounts required.
    </div>

    <div class="ai-field-label">Provider</div>
    <select id="ai-provider-select">
      <option value="gemini">Google Gemini (__GEMINI_MODEL_HTML__) — free tier</option>
      <option value="openai">OpenAI (__OPENAI_MODEL_HTML__)</option>
      <option value="anthropic">Anthropic (__ANTHROPIC_MODEL_HTML__)</option>
    </select>

    <div class="ai-field-label">API Key <span style="color:#5a7898;font-size:10px">(memory only, never saved)</span></div>
    <input type="password" id="ai-key-input" placeholder="Paste your API key…">

    <button id="ai-connect-btn">Connect and start chatting</button>
    <div id="ai-config-status"></div>
  </div>

  <!-- Chat tab -->
  <div class="ai-pane hidden" id="ai-chat-pane">
    <div id="ai-chat-notice">Configure a provider in the ⚙ Configure tab first.</div>
    <div id="ai-chat-history" style="display:none"></div>
    <div id="ai-chat-input-row" style="display:none">
      <textarea id="ai-chat-input" placeholder="Ask about this topology…" rows="1"></textarea>
      <button id="ai-chat-send">Send</button>
    </div>
  </div>

  <!-- Launch tab -->
  <div class="ai-pane hidden" id="ai-launch-pane">
    <div class="ai-launch-section">
      <h4>Full Scrutics AI in terminal</h4>
      <p style="font-size:11px;color:#8f98a8;margin:0 0 8px">
        The terminal AI has access to the full evidence store, behavioral baselines,
        and anomaly detail — not just topology data.
      </p>
      <div class="ai-launch-cmd" id="ai-launch-cmd-text">scrutics ai</div>
      <button class="ai-copy-btn" id="ai-copy-cmd-btn">Copy command</button>
      <div class="ai-launch-note" id="ai-launch-note"></div>
    </div>

    <div class="ai-launch-section">
      <h4>Reconfigure AI provider</h4>
      <p style="font-size:11px;color:#8f98a8;margin:0 0 8px">
        To change provider or model, run the setup wizard:
      </p>
      <div class="ai-launch-cmd">scrutics ai --reconfigure</div>
      <button class="ai-copy-btn" onclick="copyText('scrutics ai --reconfigure', this)">Copy</button>
      <p style="font-size:10px;color:#5a7898;margin:4px 0 0">
        Or run <code>scrutics_ai_setup.sh</code> directly for a guided wizard.
      </p>
    </div>

    <div class="ai-launch-section">
      <h4>Windows — launch via WSL2</h4>
      <p style="font-size:11px;color:#8f98a8;margin:0 0 8px">
        On Windows, run Scrutics through WSL2 (Linux subsystem):
      </p>
      <div class="ai-launch-cmd">wsl bash -c "cd /mnt/c/Users/$USER/Scrutics && scrutics ai"</div>
      <button class="ai-copy-btn" onclick="copyText('wsl bash -c &quot;cd /mnt/c/Users/$USER/Scrutics &amp;&amp; scrutics ai&quot;', this)">Copy</button>
    </div>
  </div>
</div>

<script>
document.addEventListener("DOMContentLoaded", function() {
(function () {
  "use strict";

  // ── AI Button (opens panel) ───────────────────────────────────────────────
  document.getElementById("ai-unified-btn").addEventListener("click", function () {
    document.getElementById("ai-panel").classList.add("open");
  });

  // ── Panel open/close ──────────────────────────────────────────────────────
  document.getElementById("ai-panel-close").addEventListener("click", function () {
    document.getElementById("ai-panel").classList.remove("open");
  });

  // ── Tab switching ─────────────────────────────────────────────────────────
  var tabs = document.querySelectorAll(".ai-tab");
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      tabs.forEach(function (t) { t.classList.remove("active"); });
      tab.classList.add("active");
      var which = tab.getAttribute("data-tab");
      document.getElementById("ai-configure-pane").classList.toggle("hidden", which !== "configure");
      document.getElementById("ai-chat-pane").classList.toggle("hidden", which !== "chat");
      document.getElementById("ai-launch-pane").classList.toggle("hidden", which !== "launch");
    });
  });

  // ── Build launch command using session dir from URL ───────────────────────
  (function () {
    var path = window.location.pathname;
    var match = path.match(/[/]output[/](scrutics_[0-9]{8}_[0-9]{6})[/]topology[.]html$/);
    var sessionDir = match ? ("./output/" + match[1]) : null;
    var cmd = sessionDir ? ('scrutics ai --session "' + sessionDir + '"') : "scrutics ai";
    document.getElementById("ai-launch-cmd-text").textContent = cmd;
    document.getElementById("ai-launch-note").textContent = sessionDir
      ? "Points directly at this session's evidence."
      : "Session directory not detected from URL — command uses most recent session.";
  })();

  // ── Copy helper ───────────────────────────────────────────────────────────
  window.copyText = function (text, btn) {
    var orig = btn.textContent;
    function done(ok) {
      btn.textContent = ok ? "Copied!" : "Failed";
      setTimeout(function () { btn.textContent = orig; }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }).catch(function () { done(false); });
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.left = "-9999px";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(true); } catch (e) { done(false); }
      document.body.removeChild(ta);
    }
  };

  document.getElementById("ai-copy-cmd-btn").addEventListener("click", function () {
    copyText(document.getElementById("ai-launch-cmd-text").textContent, this);
  });

  // ── Graph context summary ─────────────────────────────────────────────────
  function buildGraphSummary() {
    var g = {};
    try { g = JSON.parse(document.getElementById("graph-data").textContent) || {}; } catch (e) { g = {}; }
    var nodes = (g.nodes || []).concat(g.isolated_nodes || []);
    var edges = g.edges || [];
    var ot = nodes.filter(function (n) { return n.type === "OT"; });
    var it = nodes.filter(function (n) { return n.type === "IT"; });
    var lines = [
      "Scrutics passive OT/ICS network topology summary:",
      "Assets: " + nodes.length + " (OT: " + ot.length + ", IT: " + it.length + ", Unknown: " + (nodes.length - ot.length - it.length) + ")",
      "Connections: " + edges.length,
    ];
    if (ot.length > 0) {
      lines.push("\nOT devices:");
      ot.slice(0, 20).forEach(function (n) {
        lines.push("  " + (n.label||n.id||"?") + " | " + (n.vendor_display||"Unknown") + " | " + (n.protocol||"no protocol") + " | conf: " + (n.confidence||0) + "%");
      });
      if (ot.length > 20) lines.push("  ...and " + (ot.length - 20) + " more");
    }
    if (it.length > 0 && it.length <= 10) {
      lines.push("\nIT devices: " + it.map(function (n) { return n.label||n.id; }).join(", "));
    } else if (it.length > 10) {
      lines.push("\nIT devices: " + it.length + " total");
    }
    if (edges.length > 0 && edges.length <= 15) {
      lines.push("\nConnections:");
      var byId = {};
      nodes.forEach(function (n) { byId[n.id] = n.label || n.id; });
      edges.forEach(function (e) { lines.push("  " + (byId[e.from]||e.from) + " -> " + (byId[e.to]||e.to) + " [" + (e.label||"?") + "]"); });
    } else if (edges.length > 15) {
      lines.push("\nConnections: " + edges.length + " total");
    }
    return lines.join("\n");
  }

  // ── State ─────────────────────────────────────────────────────────────────
  var AI_MODELS = __AI_MODELS_JSON__;
  // Request fields each default model accepts, from the same rules as the Python providers
  var AI_REQUEST_OPTIONS = __AI_REQUEST_OPTIONS_JSON__;
  // Sentence telling each provider's model how long an answer can be for its output limit
  var AI_ANSWER_LENGTH = __AI_ANSWER_LENGTH_JSON__;
  // The retry policy of the Python providers (scrutics/ai/retry.py)
  var RETRY_POLICY = __AI_RETRY_POLICY_JSON__;
  var aiHistory = [];
  var aiKey = "";
  var aiProvider = "";
  var aiReady = false;
  var aiPending = false;

  // ── Connect ───────────────────────────────────────────────────────────────
  document.getElementById("ai-connect-btn").addEventListener("click", function () {
    var key = document.getElementById("ai-key-input").value.trim();
    var provider = document.getElementById("ai-provider-select").value;
    var status = document.getElementById("ai-config-status");
    if (!key) { status.style.color = "#c04040"; status.textContent = "Please enter an API key."; return; }

    aiKey = key;
    aiProvider = provider;
    aiReady = true;
    document.getElementById("ai-key-input").value = "";

    var summary = buildGraphSummary();
    aiHistory = [{
      role: "system",
      content: "You are a network analysis assistant for Scrutics OT/ICS topology data. " +
        "Answer questions about this network. Be concise and accurate. " +
        "Do not invent devices or connections not in the data." +
        (AI_ANSWER_LENGTH[provider] ? " " + AI_ANSWER_LENGTH[provider] : "") + "\n\n" + summary
    }];

    var labels = { openai: "OpenAI " + AI_MODELS.openai, anthropic: "Anthropic " + AI_MODELS.anthropic, gemini: "Gemini " + AI_MODELS.gemini };
    document.getElementById("ai-chat-notice").style.display = "none";
    document.getElementById("ai-chat-history").style.display = "flex";
    document.getElementById("ai-chat-input-row").style.display = "flex";
    document.getElementById("ai-chat-history").innerHTML = "";
    appendMsg("notice", "Connected via " + (labels[provider]||provider) + ". Ready.");

    status.style.color = "#5ac898";
    status.textContent = "Connected. Switch to the Chat tab.";

    tabs.forEach(function (t) { t.classList.remove("active"); });
    document.querySelector("[data-tab='chat']").classList.add("active");
    document.getElementById("ai-configure-pane").classList.add("hidden");
    document.getElementById("ai-chat-pane").classList.remove("hidden");
    document.getElementById("ai-launch-pane").classList.add("hidden");
    document.getElementById("ai-chat-input").focus();
  });

  // ── Append message ────────────────────────────────────────────────────────
  function appendMsg(role, text) {
    var hist = document.getElementById("ai-chat-history");
    var div = document.createElement("div");
    div.className = "ai-msg " + role;
    div.textContent = text;
    hist.appendChild(div);
    hist.scrollTop = hist.scrollHeight;
    return div;
  }

  // ── Send ──────────────────────────────────────────────────────────────────
  function sendMessage(text) {
    if (!text.trim() || aiPending || !aiReady) return;
    appendMsg("user", text);
    aiHistory.push({ role: "user", content: text });
    var thinking = appendMsg("assistant", "Thinking...");
    aiPending = true;
    document.getElementById("ai-chat-send").disabled = true;
    document.getElementById("ai-chat-input").disabled = true;

    callProvider(aiProvider, aiKey, aiHistory, function (progress) { thinking.textContent = progress; })
      .then(function (reply) {
        thinking.textContent = reply;
        aiHistory.push({ role: "assistant", content: reply });
      })
      .catch(function (err) {
        thinking.className = "ai-msg error";
        thinking.textContent = err.message;
      })
      .finally(function () {
        aiPending = false;
        document.getElementById("ai-chat-send").disabled = false;
        document.getElementById("ai-chat-input").disabled = false;
        document.getElementById("ai-chat-input").focus();
      });
  }

  document.getElementById("ai-chat-send").addEventListener("click", function () {
    var inp = document.getElementById("ai-chat-input");
    var text = inp.value.trim();
    if (text) { inp.value = ""; sendMessage(text); }
  });
  document.getElementById("ai-chat-input").addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      var text = this.value.trim();
      if (text) { this.value = ""; sendMessage(text); }
    }
  });

  // ── Provider API calls ────────────────────────────────────────────────────
  function callProvider(provider, key, history, onProgress) {
    if (provider === "openai")    return callOpenAI(key, history, onProgress);
    if (provider === "anthropic") return callAnthropic(key, history, onProgress);
    if (provider === "gemini")    return callGemini(key, history, onProgress);
    return Promise.reject(new Error("Unknown provider: " + provider));
  }

  // CUT_OFF_NOTICE follows an answer that stopped at the output token limit
  var TOKEN_LIMIT_MESSAGE = "The model used its token limit before answering, most likely on reasoning. " +
    "Try a shorter or more specific question.",
    CUT_OFF_NOTICE = "[Answer cut off: the model reached its output limit. Ask for a shorter answer.]";

  // Rejects with the provider's own error type and message, so a refused request can be fixed
  function errorDetail(r) {
    return r.json().catch(function () { return null; }).then(function (body) {
      var err = body && body.error;
      var detail = "";
      if (err && typeof err === "object") {
        detail = [err.type || err.status, err.message].filter(function (p) { return p; }).join(": ");
      } else if (typeof err === "string") {
        detail = err;
      }
      return detail.length > 300 ? detail.slice(0, 300) + "..." : detail;
    });
  }

  function providerError(name, r) {
    return errorDetail(r).then(function (detail) {
      var msg = (r.status === 401 || r.status === 403)
        ? "Auth failed: check your " + name + " key"
        : name + " error HTTP " + r.status;
      throw new Error(detail ? msg + " (" + detail + ")." : msg + ".");
    });
  }

  function retryAfterSeconds(r) {
    // Readable only when the provider exposes the header to the page (CORS)
    var value = r.headers && r.headers.get ? r.headers.get("Retry-After") : null;
    if (!value) return null;
    var seconds = Number(value);
    if (!isNaN(seconds)) return Math.max(0, seconds);
    var when = Date.parse(value);
    return isNaN(when) ? null : Math.max(0, (when - Date.now()) / 1000);
  }

  // Sends doFetch() under RETRY_POLICY and resolves with the first response not to be retried.
  // A failed fetch is not retried: the page cannot tell whether the request was sent.
  function withRetry(name, doFetch, onProgress) {
    var attempt = 1;
    var waited = 0;
    function stop(r, message) {
      return errorDetail(r).then(function (detail) {
        throw new Error(detail ? message + " Details: " + detail : message);
      });
    }
    function run() {
      return doFetch().then(function (r) {
        if (RETRY_POLICY.statuses.indexOf(r.status) < 0) return r;
        var text = RETRY_POLICY.statusText[String(r.status)];
        var advice = r.status === 429 ? RETRY_POLICY.adviceRateLimit : RETRY_POLICY.adviceBusy;
        var line = name + " returned HTTP " + r.status + " (" + text + ")";
        if (attempt >= RETRY_POLICY.maxAttempts) {
          return stop(r, name + " still returned HTTP " + r.status + " (" + text + ") after " + attempt +
            " attempts over " + Math.round(waited) + "s. " + advice);
        }
        var delay;
        var requested = retryAfterSeconds(r);
        if (requested !== null) {
          delay = Math.max(RETRY_POLICY.minServerDelay, requested);
          if (delay > RETRY_POLICY.maxWait) {
            return stop(r, line + " and asked to wait " + Math.round(delay) + "s, longer than Scrutics waits (" +
              RETRY_POLICY.maxWait + "s). Try again later. " + advice);
          }
        } else {
          var base = RETRY_POLICY.baseDelay * Math.pow(2, attempt - 1);
          delay = Math.min(RETRY_POLICY.maxWait, base + Math.random() * base / 2);
        }
        if (waited + delay > RETRY_POLICY.maxTotalWait) {
          return stop(r, name + " still returned HTTP " + r.status + " (" + text + ") after " + attempt +
            " attempts; waiting " + Math.round(delay) + "s more would pass Scrutics' " +
            RETRY_POLICY.maxTotalWait + "s limit on retries. " + advice);
        }
        if (onProgress) {
          onProgress(line + "; retrying in " + Math.round(delay) + "s (attempt " + (attempt + 1) +
            " of " + RETRY_POLICY.maxAttempts + ")...");
        }
        return new Promise(function (resolve) { setTimeout(resolve, delay * 1000); }).then(function () {
          waited += delay;
          attempt += 1;
          return run();
        });
      }, function (e) {
        throw new Error(name + " could not be reached (" + e.message + "). Check your connection; " +
          "the request was not retried because it may already have been sent.");
      });
    }
    return run();
  }

  function callOpenAI(key, history, onProgress) {
    var payload = Object.assign({ model: AI_MODELS.openai, messages: history }, AI_REQUEST_OPTIONS.openai);
    return withRetry("OpenAI", function () { return fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Authorization": "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }); }, onProgress)
    .then(function (r) {
      if (!r.ok) return providerError("OpenAI", r);
      return r.json();
    })
    .then(function (d) {
      var choice = d.choices && d.choices[0];
      var text = choice && choice.message && choice.message.content;
      var cutOff = !!(choice && choice.finish_reason === "length");
      if (!text && cutOff) throw new Error(TOKEN_LIMIT_MESSAGE);
      return text ? (cutOff ? text + "\n\n" + CUT_OFF_NOTICE : text) : "(empty response)";
    });
  }

  function callAnthropic(key, history, onProgress) {
    var sys = history.find(function (m) { return m.role === "system"; });
    var msgs = history.filter(function (m) { return m.role !== "system"; });
    var payload = Object.assign({ model: AI_MODELS.anthropic, messages: msgs }, AI_REQUEST_OPTIONS.anthropic);
    if (sys) payload.system = sys.content;
    return withRetry("Anthropic", function () { return fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true", "content-type": "application/json" },
      body: JSON.stringify(payload),
    }); }, onProgress)
    .then(function (r) {
      if (!r.ok) return providerError("Anthropic", r);
      return r.json();
    })
    .then(function (d) {
      var b = (d.content || []).find(function (x) { return x.type === "text"; });
      var cutOff = d.stop_reason === "max_tokens";
      if (!(b && b.text) && cutOff) throw new Error(TOKEN_LIMIT_MESSAGE);
      return (b && b.text) ? (cutOff ? b.text + "\n\n" + CUT_OFF_NOTICE : b.text) : "(empty response)";
    });
  }

  function callGemini(key, history, onProgress) {
    var sys = history.find(function (m) { return m.role === "system"; });
    var contents = history
      .filter(function (m) { return m.role !== "system"; })
      .map(function (m) { return { role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }; });
    // Generation settings from the providers' rules, written in when the page is generated
    var payload = { contents: contents, generationConfig: __GEMINI_GENERATION_CONFIG_JSON__ };
    if (sys) payload.systemInstruction = { parts: [{ text: sys.content }] };
    return withRetry("Gemini", function () { return fetch("https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(AI_MODELS.gemini) + ":generateContent", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": key },
      body: JSON.stringify(payload),
    }); }, onProgress)
    .then(function (r) {
      if (!r.ok) return providerError("Gemini", r);
      return r.json();
    })
    .then(function (d) {
      var candidate = d.candidates && d.candidates[0];
      var parts = (candidate && candidate.content && candidate.content.parts) || [];
      var text = parts.filter(function (p) { return typeof p.text === "string"; })
        .map(function (p) { return p.text; }).join("");
      var cutOff = !!(candidate && candidate.finishReason === "MAX_TOKENS");
      if (!text && cutOff) throw new Error(TOKEN_LIMIT_MESSAGE);
      return text ? (cutOff ? text + "\n\n" + CUT_OFF_NOTICE : text) : "(empty response)";
    });
  }
})();
}); // End DOMContentLoaded
</script>
</body>
</html>
"""


def _browser_chat_models() -> dict:
    """Models the page's browser chat uses: the configuration defaults for each provider."""
    from scrutics.ai.config import (
        DEFAULT_ANTHROPIC_MODEL, DEFAULT_GEMINI_MODEL, DEFAULT_OPENAI_MODEL,
    )
    return {
        "openai": DEFAULT_OPENAI_MODEL,
        "anthropic": DEFAULT_ANTHROPIC_MODEL,
        "gemini": DEFAULT_GEMINI_MODEL,
    }


# Output token limit of the browser chat's OpenAI requests (unchanged; the assistant sends none)
_BROWSER_OPENAI_MAX_TOKENS = 1024


def _browser_chat_limits() -> dict:
    """Output token limit the browser chat sends to each provider."""
    from scrutics.ai.model_rules import DEFAULT_MAX_TOKENS
    return {"openai": _BROWSER_OPENAI_MAX_TOKENS, **DEFAULT_MAX_TOKENS}


def _browser_chat_request_options() -> dict:
    """Optional request fields for the browser chat's OpenAI and Anthropic models, from the
    providers' rules, with the same output limits as the assistant's defaults (OpenAI: the chat's
    own 1024)."""
    from scrutics.ai.model_rules import (
        DEFAULT_ANTHROPIC_MODEL, DEFAULT_OPENAI_MODEL, anthropic_options, openai_options,
    )
    limits = _browser_chat_limits()
    return {
        # max_completion_tokens: max_tokens is deprecated on Chat Completions and rejected by
        # reasoning models
        "openai": {"max_completion_tokens": limits["openai"], **openai_options(DEFAULT_OPENAI_MODEL, 0.3)},
        "anthropic": {"max_tokens": limits["anthropic"], **anthropic_options(DEFAULT_ANTHROPIC_MODEL, 0.3)},
    }


def _browser_chat_gemini_generation_config() -> dict:
    """generationConfig of the browser chat's Gemini requests."""
    from scrutics.ai.config import DEFAULT_GEMINI_MODEL
    from scrutics.ai.model_rules import gemini_options
    return {"temperature": 0.3, "maxOutputTokens": _browser_chat_limits()["gemini"],
            **gemini_options(DEFAULT_GEMINI_MODEL)}


def _browser_chat_answer_length() -> dict:
    """The system prompt sentence on answer length for each provider's output limit."""
    from scrutics.ai.model_rules import answer_length_instruction
    return {provider: answer_length_instruction(limit) for provider, limit in _browser_chat_limits().items()}


def generate_topology_html(graph: dict) -> str:
    graph_json = json.dumps(graph, separators=(",", ":"), ensure_ascii=False)
    models = _browser_chat_models()
    # Graph data is substituted last so text inside it is never taken for a placeholder
    page = HTML_TEMPLATE.replace("__AI_MODELS_JSON__", json.dumps(models).replace("</", "<\\/"))
    from scrutics.ai.retry import policy_for_browser
    page = page.replace("__AI_RETRY_POLICY_JSON__", json.dumps(policy_for_browser()).replace("</", "<\\/"))
    page = page.replace("__AI_REQUEST_OPTIONS_JSON__",
                        json.dumps(_browser_chat_request_options()).replace("</", "<\\/"))
    page = page.replace("__GEMINI_GENERATION_CONFIG_JSON__",
                        json.dumps(_browser_chat_gemini_generation_config()).replace("</", "<\\/"))
    page = page.replace("__AI_ANSWER_LENGTH_JSON__",
                        json.dumps(_browser_chat_answer_length()).replace("</", "<\\/"))
    for provider, model in models.items():
        page = page.replace(f"__{provider.upper()}_MODEL_HTML__", html.escape(model))
    return page.replace("__GRAPH_JSON__", graph_json.replace("</", "<\\/"))


def export_connections_csv(edges: dict, output_path: str) -> int:
    """Export connections to a CSV file at the given path.

    Edge keys are now (src_primary_key, dst_primary_key) but CSV columns
    must remain IP addresses for compatibility with downstream consumers
    (e.g. scrutics/ai/tools.py which reads source/destination as IPs).
    IPs are read from edge metadata (source_ip/destination_ip).
    """
    if not edges:
        return 0
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    rows = 0
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "destination", "protocol", "count",
                         "first_seen", "last_seen", "src_port", "dst_port"])
        for (src_key, dst_key), info in edges.items():
            # Write IPs from edge metadata, not the primary_key edge keys.
            # Falls back to edge key if metadata is missing (defensive).
            writer.writerow([
                info.get("source_ip", src_key),
                info.get("destination_ip", dst_key),
                _edge_label(info.get("protocols", [])),
                info.get("count", 1),
                datetime.fromtimestamp(info.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M:%S") if info.get("first_seen") else "",
                datetime.fromtimestamp(info.get("last_seen", 0)).strftime("%Y-%m-%d %H:%M:%S") if info.get("last_seen") else "",
                info.get("src_port", ""),
                info.get("dst_port", ""),
            ])
            rows += 1
    return rows


def export_topology(inventory: Any, edges: dict | None, session_dir: str, stats: dict | None = None) -> dict:
    """
    Write topology.json, topology.html, connections.csv, and copy SheetJS library. When `stats`
    is a dict it receives "edges_exported", "edge_drops" and "connections_written".
    """
    stats = {} if stats is None else stats
    drops: dict = {}
    graph = build_graph_data(inventory, edges, drops=drops)
    stats.update(edges_exported=len(graph["edges"]), edge_drops=drops, connections_written=0)
    if not graph["nodes"] and not graph["isolated_nodes"]:
        return {}

    os.makedirs(session_dir, exist_ok=True)

    # JSON
    json_path = os.path.join(session_dir, "topology.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # HTML
    html_path = os.path.join(session_dir, "topology.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_topology_html(graph))

    # Copy SheetJS library
    if os.path.exists(XLSX_JS_SRC):
        shutil.copy2(XLSX_JS_SRC, os.path.join(session_dir, XLSX_JS_DST))

    # Connections CSV
    csv_path = os.path.join(session_dir, "connections.csv")
    if edges:
        stats["connections_written"] = export_connections_csv(edges, csv_path)

    # Manifest
    write_manifest(session_dir, metadata={"inventory": inventory, "edges": edges})

    result = {"json": json_path, "html": html_path, "connections_csv": csv_path}
    return result


def write_manifest(session_dir: str, metadata: dict | None = None, errors: list | None = None) -> str:
    """
    Write manifest.json to the session directory.
    Returns the path to the manifest file.
    Never raises on failure; a failure is logged and, when `errors` is a list, appended to it.

    A session export passes "records", "export_complete" and "export_errors" in `metadata`
    (see scrutics.db.session_export); the manifest always carries those keys.
    """
    manifest_path = os.path.join(session_dir, "manifest.json")
    try:
        os.makedirs(session_dir, exist_ok=True)
        meta = metadata or {}

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        created_at = meta.get("created_at") or now_utc
        capture_ended = meta.get("capture_ended") or now_utc

        # Capture started: explicit override -> engine.capture_started -> fallback to capture_ended
        capture_started = meta.get("capture_started")
        if not capture_started and meta.get("engine") is not None:
            capture_started = getattr(meta["engine"], "capture_started", None)
        if not capture_started:
            capture_started = capture_ended

        # Sensor ID
        sensor_id = meta.get("sensor_id")
        if not sensor_id:
            try:
                sensor_id = socket.gethostname() or "default"
            except Exception:
                sensor_id = "default"

        # Scope
        scope = meta.get("scope", "")

        # Files map
        default_files = {
            "assets": "assets.csv",
            "connections": "connections.csv",
            "evidence": "evidence.json",
            "events": "events.csv",
            "anomalies": "anomalies.csv",
            "topology": "topology.json",
            "topology_html": "topology.html",
        }
        files = dict(default_files)
        if isinstance(meta.get("files"), dict):
            files.update(meta["files"])

        # Stats
        stats = {
            "asset_count": 0,
            "ot_count": 0,
            "it_count": 0,
            "unknown_count": 0,
            "connection_count": 0,
            "anomaly_count": 0,
        }

        if isinstance(meta.get("stats"), dict):
            stats.update(meta["stats"])
        else:
            inventory = meta.get("inventory")
            if inventory is not None:
                try:
                    assets = inventory.get_all()
                    stats["asset_count"] = len(assets)
                    for asset in assets:
                        is_ot = getattr(asset, "is_ot", None)
                        if is_ot is True:
                            stats["ot_count"] += 1
                        elif is_ot is False:
                            stats["it_count"] += 1
                        else:
                            stats["unknown_count"] += 1
                except Exception:
                    pass

            edges = meta.get("edges")
            if edges is not None:
                try:
                    stats["connection_count"] = len(edges)
                except Exception:
                    pass

            records = meta.get("records") or {}
            if "anomalies" in records:
                # Anomalies written to anomalies.csv, not the newest ones kept for display
                stats["anomaly_count"] = int(records["anomalies"]["exported"])
            elif "anomaly_count" in meta:
                try:
                    stats["anomaly_count"] = int(meta["anomaly_count"])
                except Exception:
                    pass
            elif meta.get("engine") is not None:
                try:
                    engine = meta["engine"]
                    if getattr(engine, "baseline", None) is not None:
                        stats["anomaly_count"] = len(engine.baseline.get_anomalies())
                except Exception:
                    pass
            else:
                anom_file = os.path.join(session_dir, "anomalies.csv")
                if os.path.exists(anom_file):
                    try:
                        with open(anom_file, "r", encoding="utf-8") as f:
                            lines = [line.strip() for line in f if line.strip()]
                            stats["anomaly_count"] = max(0, len(lines) - 1)
                    except Exception:
                        pass

        manifest_data = {
            "format": "scrutics-evidence",
            "version": 1,
            "scrutics_version": meta.get("scrutics_version", VERSION.removeprefix("v")),
            "created_at": created_at,
            "capture_started": capture_started,
            "capture_ended": capture_ended,
            "sensor_id": sensor_id,
            "scope": scope,
            "files": files,
            "stats": stats,
            "records": meta.get("records") or {},
            "export_complete": meta.get("export_complete"),
            "export_errors": meta.get("export_errors") or [],
        }

        tmp_path = os.path.join(session_dir, f".manifest.json.tmp.{os.getpid()}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp_path, manifest_path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        return manifest_path
    except Exception as e:
        logger.debug("Failed to write manifest: %s", e)
        if errors is not None:
            errors.append(str(e))
        return manifest_path


def read_manifest(session_dir: str) -> dict:
    """
    Read and validate manifest.json from a session directory.
    Returns the manifest dict, or raises a clear error if invalid/missing.
    Called by the AI layer (SessionContext) and by tests.
    """
    manifest_path = os.path.join(session_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"manifest.json not found in {session_dir}")

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"Invalid JSON in manifest.json: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("manifest.json must contain a JSON object")

    required_keys = [
        "format",
        "version",
        "scrutics_version",
        "created_at",
        "capture_started",
        "capture_ended",
        "sensor_id",
        "scope",
        "files",
        "stats",
    ]
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise ValueError(f"Missing required manifest field(s): {', '.join(missing)}")

    if data.get("format") != "scrutics-evidence":
        raise ValueError(f"Invalid manifest format: expected 'scrutics-evidence', got {data.get('format')!r}")

    if data.get("version") != 1:
        raise ValueError(f"Unsupported manifest version: {data.get('version')!r}")

    if not isinstance(data.get("files"), dict):
        raise ValueError("'files' field in manifest.json must be a dictionary")

    if not isinstance(data.get("stats"), dict):
        raise ValueError("'stats' field in manifest.json must be a dictionary")

    required_stats = [
        "asset_count",
        "ot_count",
        "it_count",
        "unknown_count",
        "connection_count",
        "anomaly_count",
    ]
    missing_stats = [k for k in required_stats if k not in data["stats"]]
    if missing_stats:
        raise ValueError(f"Missing required stats field(s): {', '.join(missing_stats)}")

    return data
