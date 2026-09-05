"""Network topology export for Scrutics sessions."""

from __future__ import annotations

import csv
import json
import logging
import os
import shutil
from datetime import datetime
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, Optional

import scrutics

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
    asset_by_ip = {str(asset.ip): asset for asset in assets}

    connected_ips = set()
    if edges:
        for src, dst in edges.keys():
            connected_ips.add(str(src))
            connected_ips.add(str(dst))

    nodes = []
    isolated_nodes = []
    for asset in assets:
        ip = str(asset.ip)
        ntype = _asset_type(asset)
        protocols = getattr(asset, "protocols", None) or []
        confidence = int(getattr(asset, "confidence_pct", 0) or 0)
        node_data = {
            "id": ip,
            "label": ip,
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
        if ip in connected_ips:
            nodes.append(node_data)
        else:
            isolated_nodes.append(node_data)

    graph_edges = []
    for (src, dst), info in (edges or {}).items():
        src = str(src)
        dst = str(dst)
        if src not in asset_by_ip or dst not in asset_by_ip or src == dst:
            continue
        count = int((info or {}).get("count", 1) or 1)
        graph_edges.append({
            "from": src,
            "to": dst,
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


HTML_TEMPLATE = """<!doctype html>
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
#header h1 { margin: 0; font-size: 16px; color: #f2a400; font-weight: 700; }
#summary { color: #aab3c2; font-size: 12px; }
#legend { margin-left: auto; display: flex; gap: 14px; color: #c5ccd8; font-size: 12px; }
.legend-item { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
.swatch { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
#export-btn { background: #2a7a5a; border: none; color: #fff; padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-family: inherit; }
#export-btn:hover { background: #3a9a7a; }
#main { display: flex; width: 100vw; height: calc(100vh - 48px); overflow: hidden; }
#topology { flex: 1; cursor: grab; height: 100%; }
#topology:active { cursor: grabbing; }
#isolated-panel { width: 280px; background: #1a1e28; border-left: 1px solid #313846; overflow-y: auto; padding: 8px 12px; flex-shrink: 0; }
#isolated-panel h3 { margin: 0 0 8px 0; color: #8f98a8; font-size: 12px; font-weight: 400; letter-spacing: 0.5px; text-transform: uppercase; }
#isolated-list { list-style: none; margin: 0; padding: 0; font-size: 11px; }
#isolated-list li { padding: 4px 0; border-bottom: 1px solid #282e3a; display: flex; flex-wrap: wrap; gap: 4px 8px; }
#isolated-list .ip { color: #c5ccd8; font-weight: 500; }
#isolated-list .detail { color: #687285; }
#tooltip { position: fixed; display: none; z-index: 5; max-width: 340px; padding: 10px 12px; border: 1px solid #434b5c; border-radius: 6px; background: rgba(12,15,21,0.94); color: #e9edf5; font-size: 12px; line-height: 1.55; pointer-events: none; box-shadow: 0 8px 26px rgba(0,0,0,0.35); }
#tooltip b { color: #f2a400; font-size: 13px; }
#hint { position: fixed; left: 50%; bottom: 10px; transform: translateX(-50%); color: #687285; font-size: 11px; pointer-events: none; }
@media (max-width: 820px) {
  #isolated-panel { width: 200px; font-size: 10px; }
  #isolated-panel h3 { font-size: 10px; }
}
@media (max-width: 720px) {
  #main { flex-direction: column; height: calc(100vh - 48px); }
  #topology { height: 60%; }
  #isolated-panel { width: 100%; height: 40%; border-left: none; border-top: 1px solid #313846; }
}
</style>
</head>
<body>
<div id="header">
  <h1>Scrutics Topology</h1>
  <div id="summary"></div>
  <button id="export-btn">Export to .xls</button>
  <div id="legend">
    <span class="legend-item"><span class="swatch" style="background:#e07b39"></span>OT</span>
    <span class="legend-item"><span class="swatch" style="background:#4a90d9"></span>IT</span>
    <span class="legend-item"><span class="swatch" style="background:#8f98a8"></span>Unknown</span>
  </div>
</div>
<div id="main">
  <canvas id="topology"></canvas>
  <div id="isolated-panel">
    <h3>Isolated Unknown Assets</h3>
    <ul id="isolated-list"></ul>
  </div>
</div>
<div id="tooltip"></div>
<div id="hint">Scroll to zoom | drag nodes | drag background to pan | hover for details</div>
<script id="graph-data" type="application/json">__GRAPH_JSON__</script>
<script>
(function () {
  const graph = JSON.parse(document.getElementById("graph-data").textContent);
  const nodes = graph.nodes;
  const isolatedNodes = graph.isolated_nodes || [];
  const edges = graph.edges;
  const canvas = document.getElementById("topology");
  const ctx = canvas.getContext("2d");
  const tooltip = document.getElementById("tooltip");
  const summary = graph.summary || {};

  document.getElementById("summary").textContent =
    `${summary.assets || 0} assets | ${summary.ot || 0} OT | ${summary.it || 0} IT | ${summary.unknown || 0} unknown | ${summary.connections || 0} connections | ${summary.isolated_count || 0} isolated`;

  const isolatedList = document.getElementById("isolated-list");
  if (isolatedNodes.length > 0) {
    isolatedNodes.forEach(node => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="ip">${node.id}</span> <span class="detail">${node.vendor || 'Unknown'}</span> <span class="detail">${node.protocol || 'Unknown'}</span> <span class="detail">${node.confidence}%</span>`;
      isolatedList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "No isolated unknown assets.";
    li.style.color = "#687285";
    isolatedList.appendChild(li);
  }

  const byId = new Map(nodes.map((node) => [node.id, node]));
  let width = 0, height = 0, scale = 1, panX = 0, panY = 0;
  let dragNode = null, panning = false, startX = 0, startY = 0, startPanX = 0, startPanY = 0;
  const NODE_COUNT = nodes.length;
  const REPULSION_FORCE = NODE_COUNT > 30 ? 6200 : 4200;
  const EDGE_ATTRACTION = 0.035;
  const DAMPING = 0.84;
  const CENTER_FORCE = 0.008;

  function resize() {
    const rect = canvas.getBoundingClientRect();
    width = Math.max(320, Math.floor(rect.width));
    height = Math.max(240, Math.floor(rect.height));
    canvas.width = Math.floor(width * window.devicePixelRatio);
    canvas.height = Math.floor(height * window.devicePixelRatio);
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
  }

  function seedPositions() {
    const radius = Math.max(180, Math.min(width, height) * (NODE_COUNT > 30 ? 0.45 : 0.33));
    nodes.forEach((node, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1);
      node.x = width / 2 + Math.cos(angle) * radius;
      node.y = height / 2 + Math.sin(angle) * radius;
      node.vx = 0;
      node.vy = 0;
      node.fixed = false;
    });
  }

  function worldToScreen(x, y) {
    return { x: x * scale + panX, y: y * scale + panY };
  }

  function screenToWorld(x, y) {
    return { x: (x - panX) / scale, y: (y - panY) / scale };
  }

  function tick() {
    const repulsionNodes = nodes.length > 450 ? nodes.slice(0, 450) : nodes;
    for (let i = 0; i < repulsionNodes.length; i++) {
      const a = repulsionNodes[i];
      if (a.fixed) continue;
      for (let j = i + 1; j < repulsionNodes.length; j++) {
        const b = repulsionNodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.1;
        const force = REPULSION_FORCE / (d * d);
        const fx = (dx / d) * force;
        const fy = (dy / d) * force;
        a.vx += fx; a.vy += fy;
        if (!b.fixed) { b.vx -= fx; b.vy -= fy; }
      }
    }

    edges.forEach((edge) => {
      const a = byId.get(edge.from);
      const b = byId.get(edge.to);
      if (!a || !b) return;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const force = (d - 150) * EDGE_ATTRACTION;
      const fx = (dx / d) * force;
      const fy = (dy / d) * force;
      if (!a.fixed) { a.vx += fx; a.vy += fy; }
      if (!b.fixed) { b.vx -= fx; b.vy -= fy; }
    });

    nodes.forEach((node) => {
      if (node.fixed) return;
      node.vx += (width / 2 - node.x) * CENTER_FORCE;
      node.vy += (height / 2 - node.y) * CENTER_FORCE;
      node.vx *= DAMPING;
      node.vy *= DAMPING;
      node.x += node.vx;
      node.y += node.vy;
    });
  }

  function drawArrow(edge, a, b) {
    const start = worldToScreen(a.x, a.y);
    const end = worldToScreen(b.x, b.y);
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const nx = dx / d;
    const ny = dy / d;
    const nodeRadius = Math.max(6, b.size * scale);
    const tx = end.x - nx * nodeRadius;
    const ty = end.y - ny * nodeRadius;

    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.lineTo(tx, ty);
    ctx.strokeStyle = "#6d7688";
    ctx.lineWidth = Math.max(1, edge.width * scale);
    ctx.stroke();

    const head = Math.max(7, (8 + edge.width) * scale);
    const px = -ny;
    const py = nx;
    ctx.beginPath();
    ctx.moveTo(tx, ty);
    ctx.lineTo(tx - nx * head + px * head * 0.45, ty - ny * head + py * head * 0.45);
    ctx.lineTo(tx - nx * head - px * head * 0.45, ty - ny * head - py * head * 0.45);
    ctx.closePath();
    ctx.fillStyle = "#6d7688";
    ctx.fill();

    if (edge.label && scale > 0.6) {
      ctx.font = `${Math.max(9, Math.round(10 * scale))}px monospace`;
      ctx.fillStyle = "#aab3c2";
      ctx.textAlign = "center";
      ctx.fillText(edge.label, (start.x + end.x) / 2, (start.y + end.y) / 2 - 5);
    }
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    edges.forEach((edge) => {
      const a = byId.get(edge.from);
      const b = byId.get(edge.to);
      if (a && b) drawArrow(edge, a, b);
    });

    nodes.forEach((node) => {
      const pos = worldToScreen(node.x, node.y);
      const radius = Math.max(5, node.size * scale);
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = node.color;
      ctx.fill();
      ctx.strokeStyle = "rgba(255,255,255,0.18)";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      if (scale > 0.4) {
        ctx.font = `${Math.max(9, Math.round(11 * scale))}px monospace`;
        ctx.fillStyle = "#e9edf5";
        ctx.textAlign = "center";
        ctx.fillText(node.label, pos.x, pos.y + radius + 13);
      }
    });
  }

  function hitNode(screenX, screenY) {
    const point = screenToWorld(screenX, screenY);
    for (let i = nodes.length - 1; i >= 0; i--) {
      const node = nodes[i];
      const dx = node.x - point.x;
      const dy = node.y - point.y;
      if (Math.sqrt(dx * dx + dy * dy) <= node.size) return node;
    }
    return null;
  }

  function showTooltip(event, node) {
    if (!node) {
      tooltip.style.display = "none";
      return;
    }
    tooltip.style.display = "block";
    tooltip.style.left = `${event.clientX + 14}px`;
    tooltip.style.top = `${event.clientY + 14}px`;
    tooltip.innerHTML =
      `<b>${node.id}</b><br>` +
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
      return;
    }
    if (panning) {
      panX = startPanX + event.clientX - startX;
      panY = startPanY + event.clientY - startY;
      return;
    }
    showTooltip(event, hitNode(x, y));
  });

  canvas.addEventListener("mousedown", (event) => {
    const rect = canvas.getBoundingClientRect();
    const node = hitNode(event.clientX - rect.left, event.clientY - rect.top);
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
    dragNode = null;
    panning = false;
  });

  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const mx = event.clientX - rect.left;
    const my = event.clientY - rect.top;
    const z = event.deltaY < 0 ? 1.1 : 0.91;
    panX = mx - (mx - panX) * z;
    panY = my - (my - panY) * z;
    scale = Math.max(0.08, Math.min(12, scale * z));
  }, { passive: false });

  document.getElementById("export-btn").addEventListener("click", function() {
    const allNodes = graph.nodes.concat(graph.isolated_nodes || []);
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

    const connData = graph.edges.map(e => ({
      "Source": e.from,
      "Destination": e.to,
      "Protocol": e.label || "",
      "Count": e.count,
    }));

    const wb = XLSX.utils.book_new();

    // Sheet 1: Assets
    const wsAssets = XLSX.utils.json_to_sheet(assetData);
    XLSX.utils.book_append_sheet(wb, wsAssets, "Assets");

    // Sheet 2: Connections
    const wsConns = XLSX.utils.json_to_sheet(connData);
    XLSX.utils.book_append_sheet(wb, wsConns, "Connections");

    // Sheet 3: Summary
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
    tick();
    draw();
    requestAnimationFrame(loop);
  }

  window.addEventListener("resize", () => {
    resize();
    draw();
  });

  resize();
  seedPositions();
  loop();
})();
</script>
</body>
</html>
"""


def generate_topology_html(graph: dict) -> str:
    graph_json = json.dumps(graph, separators=(",", ":"), ensure_ascii=False)
    return HTML_TEMPLATE.replace("__GRAPH_JSON__", graph_json.replace("</", "<\\/"))


def export_connections_csv(edges: dict, output_path: str) -> None:
    """Export connections to a CSV file at the given path."""
    if not edges:
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "destination", "protocol", "count",
                         "first_seen", "last_seen", "src_port", "dst_port"])
        for (src, dst), info in edges.items():
            writer.writerow([
                src,
                dst,
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

    result = {"json": json_path, "html": html_path, "connections_csv": csv_path}
    return result