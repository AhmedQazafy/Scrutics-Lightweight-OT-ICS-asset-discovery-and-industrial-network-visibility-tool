"""
Geometry checks for the topology page's layout, on what the canvas drew.

A drawing is a dict with the canvas size and the drawn primitives: node circles, connection curves
(quadratic Beziers), texts (with the rectangle drawn behind a boxed text), straight leader lines,
the off-screen banner state and any page overlays (boxes in canvas coordinates). The Node harness
`topology_layout_harness.js` and the browser check produce this shape.
"""

import json
import os
import random
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address
from pathlib import Path

HARNESS = Path(__file__).parent / "topology_layout_harness.js"
WINDOWS = [(1920, 1080), (1280, 800), (1100, 650), (900, 600)]
CURVE_SAMPLES = 24
OFFSCREEN_MARGIN = 28       # the page counts a node centre within 28 px of the edge as outside view

_PAGE_SCRIPTS_RE = re.compile(
    r'<script id="graph-data" type="application/json">(?P<data>.*?)</script>\s*<script>(?P<script>.*?)</script>',
    re.S,
)


def page_parts(page):
    """The graph data text and the graph script of a generated topology page."""
    match = _PAGE_SCRIPTS_RE.search(page)
    assert match, "graph script not found in the page"
    return match.group("data"), match.group("script")


def run_harness(node, tmp_path, script, runs, name="runs.json", processes=4):
    """runs: [(data_text, (window_width, window_height)), ...]; returns one result per run, in order."""
    chunks = [runs[i::processes] for i in range(processes) if runs[i::processes]]

    def run_chunk(index):
        path = Path(tmp_path) / f"{index}_{name}"
        path.write_text(json.dumps({"script": script, "runs": [{"data": d, "window": list(w)} for d, w in chunks[index]]}),
                        encoding="utf-8")
        result = subprocess.run([node, str(HARNESS), str(path)], capture_output=True, text=True, timeout=1800)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        parts = list(pool.map(run_chunk, range(len(chunks))))
    results = [None] * len(runs)
    for i, part in enumerate(parts):
        for k, r in enumerate(part):
            results[i + k * processes] = r
    return results


def find_node():
    return shutil.which("node") or os.environ.get("SCRUTICS_NODE")


# ── Graph structure ───────────────────────────────────────────────────────────

def groups(graph):
    """Group number of every node id, from the connections between nodes."""
    neighbours = {n["id"]: set() for n in graph["nodes"]}
    for e in graph["edges"]:
        if e["from"] in neighbours and e["to"] in neighbours:
            neighbours[e["from"]].add(e["to"])
            neighbours[e["to"]].add(e["from"])
    group = {}
    for start in neighbours:
        if start in group:
            continue
        group[start] = len(set(group.values()))
        stack = [start]
        while stack:
            for nxt in neighbours[stack.pop()]:
                if nxt not in group:
                    group[nxt] = group[start]
                    stack.append(nxt)
    return group


def relabel(graph, seed):
    """
    The same graph with new random node ids (MAC style) and labels (IPv4 addresses of varying
    length), nodes ordered by their new address as the export orders them, and connections shuffled.
    """
    rng = random.Random(seed)
    all_nodes = list(graph["nodes"]) + list(graph.get("isolated_nodes", []))
    used_ids, used_labels = set(), set()
    new_id, new_label = {}, {}
    for n in all_nodes:
        if n["id"] in new_id:
            continue
        while True:
            mac = "02:" + ":".join(f"{rng.randrange(256):02x}" for _ in range(5))
            if mac not in used_ids:
                break
        used_ids.add(mac)
        new_id[n["id"]] = mac
    for n in all_nodes:
        while True:
            octets = [rng.choice([rng.randrange(1, 10), rng.randrange(10, 100), rng.randrange(100, 255)])
                      for _ in range(4)]
            label = ".".join(map(str, octets))
            if label not in used_labels:
                break
        used_labels.add(label)
        new_label[id(n)] = label

    def node(n):
        out = dict(n)
        out["id"] = new_id[n["id"]]
        out["label"] = new_label[id(n)]
        return out

    nodes = sorted((node(n) for n in graph["nodes"]), key=lambda n: ip_address(n["label"]))
    isolated = sorted((node(n) for n in graph.get("isolated_nodes", [])), key=lambda n: ip_address(n["label"]))
    edges = [dict(e, **{"from": new_id[e["from"]], "to": new_id[e["to"]]}) for e in graph["edges"]]
    rng.shuffle(edges)
    return dict(graph, nodes=nodes, isolated_nodes=isolated, edges=edges)


# ── Geometry ──────────────────────────────────────────────────────────────────

def _polyline(c):
    points = []
    for i in range(CURVE_SAMPLES + 1):
        t = i / CURVE_SAMPLES
        u = 1 - t
        points.append((u * u * c["x0"] + 2 * u * t * c["cx"] + t * t * c["x"],
                       u * u * c["y0"] + 2 * u * t * c["cy"] + t * t * c["y"]))
    return points


def _bounds(points):
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    return min(xs), min(ys), max(xs), max(ys)


def _side(a, b, c):
    return (c[0] - a[0]) * (b[1] - a[1]) - (b[0] - a[0]) * (c[1] - a[1])


def _segments_cross(p1, p2, p3, p4):
    return (_side(p3, p4, p1) * _side(p3, p4, p2) < 0) and (_side(p1, p2, p3) * _side(p1, p2, p4) < 0)


def _polylines_cross(pa, pb):
    ba, bb = _bounds(pa), _bounds(pb)
    if ba[2] < bb[0] or bb[2] < ba[0] or ba[3] < bb[1] or bb[3] < ba[1]:
        return False
    return any(_segments_cross(pa[i], pa[i + 1], pb[j], pb[j + 1])
               for i in range(len(pa) - 1) for j in range(len(pb) - 1))


def crossings_by_group(graph, drawing):
    """Crossing connection curves per group; curves that share a node are not compared."""
    edges = [e for e in graph["edges"] if e["from"] != e["to"]]
    assert len(drawing["curves"]) == len(edges), "one drawn curve per connection expected"
    # The page draws connections in data order
    group = groups(graph)
    labels = {n["id"]: n["label"] for n in graph["nodes"]}
    lines = [_polyline(c) for c in drawing["curves"]]
    found = {}
    for i in range(len(edges)):
        for j in range(i + 1, len(edges)):
            a, b = edges[i], edges[j]
            if {a["from"], a["to"]} & {b["from"], b["to"]}:
                continue
            if group[a["from"]] != group[b["from"]]:
                continue
            if _polylines_cross(lines[i], lines[j]):
                found.setdefault(group[a["from"]], []).append(
                    f'{labels[a["from"]]}>{labels[a["to"]]} x {labels[b["from"]]}>{labels[b["to"]]}')
    return found


def connections_over_nodes(graph, drawing):
    """Connection curves that pass over a node other than their own two ends."""
    edges = [e for e in graph["edges"] if e["from"] != e["to"]]
    ids = [n["id"] for n in graph["nodes"]]
    labels = {n["id"]: n["label"] for n in graph["nodes"]}
    found = []
    for e, c in zip(edges, drawing["curves"]):
        points = _polyline(c)
        x0, y0, x1, y1 = _bounds(points)
        for node_id, circle in zip(ids, drawing["circles"]):
            if node_id in (e["from"], e["to"]):
                continue
            r = circle["r"]
            if circle["x"] + r < x0 or circle["x"] - r > x1 or circle["y"] + r < y0 or circle["y"] - r > y1:
                continue
            segment = lambda p, q: {"x0": p[0], "y0": p[1], "x1": q[0], "y1": q[1]}
            if any(_segment_on_circle(segment(points[i], points[i + 1]), circle) for i in range(len(points) - 1)):
                found.append(f'connection {labels[e["from"]]}>{labels[e["to"]]} over node {labels[node_id]}')
    return found


def text_box(t):
    size = float(t["font"].split("px")[0])
    x0 = {"center": t["x"] - t["width"] / 2, "right": t["x"] - t["width"], "end": t["x"] - t["width"]}.get(
        t["align"], t["x"])
    y0 = {"top": t["y"], "middle": t["y"] - size / 2}.get(t["baseline"], t["y"] - size)
    return (x0, y0, x0 + t["width"], y0 + size)


def labelled_boxes(graph, drawing):
    """(name, box) of every node label, edge label and off-screen badge drawn."""
    node_labels = {n["label"] for n in graph["nodes"]}
    boxes = []
    for t in drawing["texts"]:
        if t["box"]:
            b = t["box"]
            kind = "badge" if (t["text"] in node_labels or t["text"].startswith("+")) else "edge label"
            boxes.append((f"{kind} {t['text']}", (b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"])))
        elif t["text"] in node_labels:
            boxes.append(("node label " + t["text"], text_box(t)))
    return boxes


def _boxes_overlap(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def _box_on_circle(box, c):
    nx = min(max(c["x"], box[0]), box[2])
    ny = min(max(c["y"], box[1]), box[3])
    return (nx - c["x"]) ** 2 + (ny - c["y"]) ** 2 < c["r"] ** 2


def _segment_in_box(s, box):
    """Whether a segment passes through the inside of a box (touching its border does not count)."""
    x0, y0, x1, y1 = box[0] + 0.5, box[1] + 0.5, box[2] - 0.5, box[3] - 0.5
    if x0 >= x1 or y0 >= y1:
        return False
    dx, dy = s["x1"] - s["x0"], s["y1"] - s["y0"]
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, s["x0"] - x0), (dx, x1 - s["x0"]), (-dy, s["y0"] - y0), (dy, y1 - s["y0"])):
        if p == 0:
            if q < 0:
                return False
        else:
            t = q / p
            if p < 0:
                if t > t1:
                    return False
                t0 = max(t0, t)
            else:
                if t < t0:
                    return False
                t1 = min(t1, t)
    return t1 - t0 > 1e-9


def _segment_on_circle(s, c):
    dx, dy = s["x1"] - s["x0"], s["y1"] - s["y0"]
    length2 = dx * dx + dy * dy or 1
    t = max(0.0, min(1.0, ((c["x"] - s["x0"]) * dx + (c["y"] - s["y0"]) * dy) / length2))
    px, py = s["x0"] + t * dx - c["x"], s["y0"] + t * dy - c["y"]
    return px * px + py * py < c["r"] ** 2


def overlaps(graph, drawing):
    """Every pair of drawn elements that overlap: labels, badges, overlays, nodes and leader lines."""
    names = [n["label"] for n in graph["nodes"]]
    assert len(drawing["circles"]) == len(names), "one drawn circle per node expected"
    boxes = labelled_boxes(graph, drawing)
    boxes += [(f"overlay {i}", (o["x0"], o["y0"], o["x1"], o["y1"])) for i, o in enumerate(drawing.get("overlays", []))]
    found = []
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            if boxes[i][0].startswith("overlay") and boxes[j][0].startswith("overlay"):
                continue
            if _boxes_overlap(boxes[i][1], boxes[j][1]):
                found.append(f"{boxes[i][0]} / {boxes[j][0]}")
        for name, circle in zip(names, drawing["circles"]):
            if _box_on_circle(boxes[i][1], circle):
                found.append(f"{boxes[i][0]} on node {name}")
    # An edge label may touch the curves of one link (its own: both arcs of a two-way link), no other
    edges = [e for e in graph["edges"] if e["from"] != e["to"]]
    curve_lines = [_polyline(c) for c in drawing["curves"]]
    curve_bounds = [_bounds(points) for points in curve_lines]
    for name, box in boxes:
        if not name.startswith("edge label"):
            continue
        links = set()
        for e, points, cb in zip(edges, curve_lines, curve_bounds):
            if cb[2] < box[0] or cb[0] > box[2] or cb[3] < box[1] or cb[1] > box[3]:
                continue
            if any(_segment_in_box({"x0": points[i][0], "y0": points[i][1], "x1": points[i + 1][0], "y1": points[i + 1][1]}, box)
                   for i in range(len(points) - 1)):
                links.add(frozenset((e["from"], e["to"])))
        if len(links) > 1:
            found.append(f"{name} over {len(links) - 1} other link(s)")
    segments = drawing.get("segments", [])
    for k, s in enumerate(segments):
        for name, box in boxes:
            if _segment_in_box(s, box):
                found.append(f"leader line {k} through {name}")
        for name, circle in zip(names, drawing["circles"]):
            if _segment_on_circle(s, circle):
                found.append(f"leader line {k} through node {name}")
        for m in range(k + 1, len(segments)):
            t = segments[m]
            if _segments_cross((s["x0"], s["y0"]), (s["x1"], s["y1"]), (t["x0"], t["y0"]), (t["x1"], t["y1"])):
                found.append(f"leader lines {k} and {m} cross")
    return found


def outside_view(graph, drawing):
    """Everything that is not fully in view: the banner, badges, nodes and labels past the edges."""
    width, height = drawing["canvas"]
    found = []
    if drawing["banner"]["display"] not in ("", "none"):
        found.append("off-screen banner shown: " + re.sub(r"<[^>]+>", "", drawing["banner"]["text"]).strip())
    names = [n["label"] for n in graph["nodes"]]
    for name, c in zip(names, drawing["circles"]):
        if not (OFFSCREEN_MARGIN <= c["x"] <= width - OFFSCREEN_MARGIN and
                OFFSCREEN_MARGIN <= c["y"] <= height - OFFSCREEN_MARGIN):
            found.append(f"node {name} outside view")
    for name, box in labelled_boxes(graph, drawing):
        if name.startswith("badge"):
            found.append(f"{name} drawn")
        elif box[0] < 0 or box[1] < 0 or box[2] > width or box[3] > height:
            found.append(f"{name} past the canvas edge")
    return found
