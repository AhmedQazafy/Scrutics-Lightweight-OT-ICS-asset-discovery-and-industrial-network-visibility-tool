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


def build_graph_data(inventory: Any, edges: dict | None = None, max_edges: int = 2000) -> dict:
    """Convert an inventory and edge counter into serializable topology data."""
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
        protocols = getattr(asset, "protocols", None) or []
        confidence = int(getattr(asset, "confidence_pct", 0) or 0)
        node_data = {
            "id": pk,                   # Persistent identity (Asset.primary_key)
            "label": str(asset.ip),     # Human-friendly IP label for display
            "type": ntype,
            "color": NODE_COLORS[ntype],
            "size": max(14, min(36, 14 + confidence // 4)),
            "vendor": _safe_text(getattr(asset, "vendor", None)),
            "protocol": ", ".join(str(p) for p in protocols if p) or "Unknown",
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
        if not s_asset or not d_asset or s_asset.primary_key == d_asset.primary_key:
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
    <h3>Isolated Unknown Assets</h3>
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
      li.innerHTML = `<span class="ip">${node.label}</span> <span class="detail">${node.vendor || 'Unknown'}</span> <span class="detail">${node.protocol || 'Unknown'}</span> <span class="detail">${node.confidence}%</span>`;
      isolatedList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "No isolated unknown assets.";
    li.style.color = "#687285";
    isolatedList.appendChild(li);
  }

  const byId = new Map(nodes.map((node) => [node.id, node]));

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

  // Identify connected components to separate disconnected groups
  const visited = new Set();
  const components = [];
  nodes.forEach(n => {
    if (!visited.has(n.id)) {
      const comp = [];
      const queue = [n.id];
      visited.add(n.id);
      while (queue.length > 0) {
        const currId = queue.shift();
        const currNode = byId.get(currId);
        if (currNode) comp.push(currNode);
        for (const neighborId of (adj.get(currId) || [])) {
          if (!visited.has(neighborId)) {
            visited.add(neighborId);
            queue.push(neighborId);
          }
        }
      }
      components.push(comp);
    }
  });
  components.sort((a, b) => b.length - a.length);

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

  function resize() {
    const rect = canvas.getBoundingClientRect();
    width = Math.max(320, Math.floor(rect.width));
    height = Math.max(240, Math.floor(rect.height));
    canvas.width = Math.floor(width * window.devicePixelRatio);
    canvas.height = Math.floor(height * window.devicePixelRatio);
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
  }

  function seedPositions() {
    const numComps = components.length;
    if (numComps === 0) return;

    if (numComps === 1) {
      const comp = components[0];
      const radius = Math.max(120, Math.sqrt(comp.length) * 55);
      comp.forEach((node, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(comp.length, 1);
        node.x = width / 2 + Math.cos(angle) * radius;
        node.y = height / 2 + Math.sin(angle) * radius;
        node.vx = 0;
        node.vy = 0;
        node.fixed = false;
        node.componentId = 0;
        node.clusterCenter = { x: width / 2, y: height / 2 };
      });
    } else {
      // Multiple disconnected groups: assign distinct spatial cluster centers
      const compRadius = c => Math.max(90, Math.sqrt(c.length) * 55);
      const maxCompR = Math.max(...components.map(compRadius));
      const distBetweenCenters = Math.max(380, maxCompR * 2.2);
      const orbitRadius = Math.max(distBetweenCenters, (distBetweenCenters * numComps) / (2 * Math.PI));

      components.forEach((comp, idx) => {
        const angle = (2 * Math.PI * idx) / numComps;
        const cx = width / 2 + Math.cos(angle) * orbitRadius;
        const cy = height / 2 + Math.sin(angle) * orbitRadius;
        const r = compRadius(comp);

        comp.forEach((node, nIdx) => {
          const nAngle = (2 * Math.PI * nIdx) / Math.max(comp.length, 1);
          const jitter = ((nIdx % 3) - 1) * 15;
          node.x = cx + Math.cos(nAngle) * (r + jitter);
          node.y = cy + Math.sin(nAngle) * (r + jitter);
          node.vx = 0;
          node.vy = 0;
          node.fixed = false;
          node.componentId = idx;
          node.clusterCenter = { x: cx, y: cy };
        });
      });
    }
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
        draw();
      }
      return;
    }

    const repulsionNodes = nodes.length > 400 ? nodes.slice(0, 400) : nodes;

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
    edges.forEach((edge) => {
      const a = byId.get(edge.from);
      const b = byId.get(edge.to);
      if (!a || !b) return;
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
    nodes.forEach((node) => {
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

  function fitView() {
    if (nodes.length === 0) {
      scale = 1; panX = 0; panY = 0;
      draw();
      return;
    }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    nodes.forEach(n => {
      const pad = (n.size || 10) + 45;
      minX = Math.min(minX, n.x - pad);
      maxX = Math.max(maxX, n.x + pad);
      minY = Math.min(minY, n.y - pad);
      maxY = Math.max(maxY, n.y + pad);
    });

    const gw = Math.max(120, maxX - minX);
    const gh = Math.max(120, maxY - minY);
    const padding = 65;
    const availW = Math.max(100, width - padding * 2);
    const availH = Math.max(100, height - padding * 2);

    scale = Math.max(0.12, Math.min(1.35, Math.min(availW / gw, availH / gh)));
    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;
    panX = width / 2 - centerX * scale;
    panY = height / 2 - centerY * scale;
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

  function updateOffscreenIndicators() {
    borderIndicators = [];
    const margin = 28;
    const cx = width / 2;
    const cy = height / 2;
    const left = margin;
    const right = width - margin;
    const top = margin;
    const bottom = height - margin;

    const offNodes = [];
    nodes.forEach(n => {
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
  }

  function drawBorderIndicators() {
    borderIndicators.forEach(cluster => {
      const count = cluster.items.length;
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
      const inward = 24;
      const bx = x - Math.cos(angle) * inward;
      const by = y - Math.sin(angle) * inward;
      const label = count === 1 ? first.id : `+${count} devices`;
      ctx.font = "10px monospace";
      const tw = ctx.measureText(label).width;
      const pw = tw + 12;
      const ph = 20;

      ctx.beginPath();
      const rx = bx - pw / 2;
      const ry = by - ph / 2;
      if (ctx.roundRect) ctx.roundRect(rx, ry, pw, ph, 4);
      else ctx.rect(rx, ry, pw, ph);
      ctx.fillStyle = isHovered ? "rgba(35, 42, 56, 0.96)" : "rgba(18, 22, 31, 0.92)";
      ctx.fill();
      ctx.strokeStyle = isHovered ? "#ffffff" : (first.color || "#f2a400");
      ctx.lineWidth = isHovered ? 1.5 : 1;
      ctx.stroke();

      ctx.fillStyle = isHovered ? "#ffffff" : "#e2e8f0";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(label, bx, by);

      cluster.hitArea = { x: rx, y: ry, w: pw, h: ph };
    });
  }

  // Deterministic hash for stable per-edge curve offsets
  function edgeHash(fromId, toId) {
    let h = 0;
    const s = fromId + ":" + toId;
    for (let i = 0; i < s.length; i++) {
      h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    }
    return h;
  }

  function drawArrow(edge, a, b) {
    const start = worldToScreen(a.x, a.y);
    const end = worldToScreen(b.x, b.y);
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const nx = dx / d;
    const ny = dy / d;

    // Perpendicular direction (used for curve offset and arrowhead)
    const perpX = -ny;
    const perpY = nx;

    // Deterministic curve offset from edge hash
    const h = edgeHash(edge.from, edge.to);
    const sign = (h % 2 === 0) ? 1 : -1;
    const magnitude = 15 + (Math.abs(h) % 16);
    const curveOffset = sign * magnitude * scale;

    // Bezier control point: offset perpendicular from straight-line midpoint
    const midX = (start.x + end.x) / 2;
    const midY = (start.y + end.y) / 2;
    const cpX = midX + perpX * curveOffset;
    const cpY = midY + perpY * curveOffset;

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

    // Protocol label at the actual Bezier midpoint (t=0.5)
    if (edge.label && scale > 0.5 && !isEdgeDimmed) {
      const labelX = 0.25 * start.x + 0.5 * cpX + 0.25 * end.x;
      const labelY = 0.25 * start.y + 0.5 * cpY + 0.25 * end.y;
      const fontSize = Math.max(9, Math.min(12, Math.round(10 * scale)));
      ctx.font = `${fontSize}px monospace`;
      const textWidth = ctx.measureText(edge.label).width;
      const padX = 5;
      const padY = 3;

      ctx.fillStyle = "rgba(12, 15, 21, 0.9)";
      ctx.strokeStyle = isConnectedToHover ? "#f2a400" : "rgba(109, 118, 136, 0.45)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      const lx = labelX - textWidth / 2 - padX;
      const ly = labelY - fontSize / 2 - padY;
      const lw = textWidth + padX * 2;
      const lh = fontSize + padY * 2;
      if (ctx.roundRect) ctx.roundRect(lx, ly, lw, lh, 3);
      else ctx.rect(lx, ly, lw, lh);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = isConnectedToHover ? "#ffffff" : "#c5ccd8";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(edge.label, labelX, labelY);
    }
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // 1. Draw connections
    edges.forEach((edge) => {
      const a = byId.get(edge.from);
      const b = byId.get(edge.to);
      if (a && b) drawArrow(edge, a, b);
    });

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

      // Node label with backdrop outline
      if (scale > 0.35 && !isDimmed) {
        const fontSize = Math.max(9, Math.min(13, Math.round(11 * scale)));
        ctx.font = `${fontSize}px monospace`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.lineWidth = 3;
        ctx.strokeStyle = "rgba(12, 15, 21, 0.9)";
        ctx.strokeText(node.label, pos.x, pos.y + radius + 5);
        ctx.fillStyle = isHovered ? "#ffffff" : "#e9edf5";
        ctx.fillText(node.label, pos.x, pos.y + radius + 5);
      }
    });

    // 3. Off-screen navigation indicators
    updateOffscreenIndicators();
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
      `Vendor: ${node.vendor}<br>` +
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
        lines.push("  " + (n.label||n.id||"?") + " | " + (n.vendor||"Unknown") + " | " + (n.protocol||"no protocol") + " | conf: " + (n.confidence||"?") + "%");
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
        "Do not invent devices or connections not in the data.\n\n" + summary
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

    callProvider(aiProvider, aiKey, aiHistory)
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
  function callProvider(provider, key, history) {
    if (provider === "openai")    return callOpenAI(key, history);
    if (provider === "anthropic") return callAnthropic(key, history);
    if (provider === "gemini")    return callGemini(key, history);
    return Promise.reject(new Error("Unknown provider: " + provider));
  }

  function callOpenAI(key, history) {
    return fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Authorization": "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify({ model: AI_MODELS.openai, messages: history, temperature: 0.3, max_tokens: 1024 }),
    })
    .then(function (r) {
      if (r.status === 401 || r.status === 403) throw new Error("Auth failed — check your OpenAI key.");
      if (!r.ok) throw new Error("OpenAI error HTTP " + r.status);
      return r.json();
    })
    .then(function (d) {
      return (d.choices && d.choices[0] && d.choices[0].message && d.choices[0].message.content) || "(empty response)";
    });
  }

  function callAnthropic(key, history) {
    var sys = history.find(function (m) { return m.role === "system"; });
    var msgs = history.filter(function (m) { return m.role !== "system"; });
    var payload = { model: AI_MODELS.anthropic, max_tokens: 1024, messages: msgs, temperature: 0.3 };
    if (sys) payload.system = sys.content;
    return fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true", "content-type": "application/json" },
      body: JSON.stringify(payload),
    })
    .then(function (r) {
      if (r.status === 401 || r.status === 403) throw new Error("Auth failed — check your Anthropic key.");
      if (!r.ok) throw new Error("Anthropic error HTTP " + r.status);
      return r.json();
    })
    .then(function (d) {
      var b = (d.content || []).find(function (x) { return x.type === "text"; });
      return (b && b.text) || "(empty response)";
    });
  }

  function callGemini(key, history) {
    var sys = history.find(function (m) { return m.role === "system"; });
    var contents = history
      .filter(function (m) { return m.role !== "system"; })
      .map(function (m) { return { role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }; });
    var payload = { contents: contents, generationConfig: { temperature: 0.3, maxOutputTokens: 1024 } };
    if (sys) payload.systemInstruction = { parts: [{ text: sys.content }] };
    return fetch("https://generativelanguage.googleapis.com/v1beta/models/" + encodeURIComponent(AI_MODELS.gemini) + ":generateContent?key=" + encodeURIComponent(key), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
    .then(function (r) {
      if (r.status === 400 || r.status === 401 || r.status === 403) throw new Error("Auth or request error — check your Gemini key.");
      if (!r.ok) throw new Error("Gemini error HTTP " + r.status);
      return r.json();
    })
    .then(function (d) {
      try { return d.candidates[0].content.parts[0].text || "(empty response)"; }
      catch (e) { return "(empty response)"; }
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


def generate_topology_html(graph: dict) -> str:
    graph_json = json.dumps(graph, separators=(",", ":"), ensure_ascii=False)
    models = _browser_chat_models()
    # Graph data is substituted last so text inside it is never taken for a placeholder
    page = HTML_TEMPLATE.replace("__AI_MODELS_JSON__", json.dumps(models).replace("</", "<\\/"))
    for provider, model in models.items():
        page = page.replace(f"__{provider.upper()}_MODEL_HTML__", html.escape(model))
    return page.replace("__GRAPH_JSON__", graph_json.replace("</", "<\\/"))


def export_connections_csv(edges: dict, output_path: str) -> None:
    """Export connections to a CSV file at the given path.

    Edge keys are now (src_primary_key, dst_primary_key) but CSV columns
    must remain IP addresses for compatibility with downstream consumers
    (e.g. scrutics/ai/tools.py which reads source/destination as IPs).
    IPs are read from edge metadata (source_ip/destination_ip).
    """
    if not edges:
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
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


def export_topology(inventory: Any, edges: dict | None, session_dir: str) -> dict:
    """Write topology.json, topology.html, connections.csv, and copy SheetJS library."""
    graph = build_graph_data(inventory, edges)
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
        export_connections_csv(edges, csv_path)

    # Manifest
    write_manifest(session_dir, metadata={"inventory": inventory, "edges": edges})

    result = {"json": json_path, "html": html_path, "connections_csv": csv_path}
    return result


def write_manifest(session_dir: str, metadata: dict | None = None) -> str:
    """
    Write manifest.json to the session directory.
    Returns the path to the manifest file.
    Never raises on failure; logs/ignores per existing checkpoint pattern.
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

            if "anomaly_count" in meta:
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
            "scrutics_version": meta.get("scrutics_version", "0.6.1"),
            "created_at": created_at,
            "capture_started": capture_started,
            "capture_ended": capture_ended,
            "sensor_id": sensor_id,
            "scope": scope,
            "files": files,
            "stats": stats,
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
