"""
The topology page's layout, measured by running the page's own graph script under Node.

Fixtures (tests/data):
- topology_layout_4sics_151021.json: topology.json of 4SICS-GeekLounge-151021.pcap (public dataset),
  as written by a headless run with default options.
- topology_layout_ics_anonymized.json: topology.json of a real ICS capture with every IP address and
  MAC address replaced; groups, links, node sizes, label lengths and edge labels are kept.

Every group in both fixtures can be drawn without crossing connections: the 4SICS groups and two of
the ICS groups are trees (one 4SICS group is a star of 18 leaves around one device), and the
eight-node ICS group (one hub, three triangles on it, one pendant node) is drawn without crossings
with the hub's neighbours in ring order.

Each case is checked twice: when the layout has settled after the page opens, and after pressing F
(fit view). Window sizes are browser windows; the canvas is what the page's header and side panel
leave of them. Crossings are measured on the drawn curves, each sampled as straight segments; curves
that share a node are not compared, and no curve may pass over a node other than its two ends.
Overlaps cover node labels, edge labels, off-screen badges, the hint line over the canvas, nodes and
leader lines.
"""

import json
import os
from pathlib import Path

import pytest

from scrutics.topology import generate_topology_html
from tests.node_runtime import require_node
from tests.topology_layout_checks import (
    WINDOWS, connections_over_nodes, crossings_by_group, outside_view, overlaps, page_parts, relabel,
    run_harness,
)

DATA = Path(__file__).parent / "data"
FIXTURES = ["topology_layout_ics_anonymized.json", "topology_layout_4sics_151021.json"]
RELABELINGS = 20


def _node():
    return require_node("check the topology page layout")


def _graph(fixture):
    with open(DATA / fixture, encoding="utf-8") as f:
        return json.load(f)


def _run(tmp_path, graphs_and_windows):
    script = None
    runs = []
    for graph, window in graphs_and_windows:
        data, page_script = page_parts(generate_topology_html(graph))
        assert script in (None, page_script)
        script = page_script
        runs.append((data, window))
    results = run_harness(_node(), tmp_path, script, runs)
    for r in results:
        assert r["settled"], "the simulation did not settle"
    return results


def _drawing(result, state):
    return dict(result[state], canvas=result["canvas"], overlays=result["overlays"])


def _problems(graph, result):
    found = []
    for state in ("open", "fit"):
        drawing = _drawing(result, state)
        crossings = crossings_by_group(graph, drawing)
        found += [f"{state}: crossing {c}" for group in crossings.values() for c in group]
        found += [f"{state}: {o}" for o in connections_over_nodes(graph, drawing)]
        found += [f"{state}: {o}" for o in overlaps(graph, drawing)]
        found += [f"{state}: {o}" for o in outside_view(graph, drawing)]
    return found


@pytest.mark.parametrize("fixture", FIXTURES)
def test_no_crossings_overlaps_or_devices_outside_view(tmp_path, fixture):
    graph = _graph(fixture)
    results = _run(tmp_path, [(graph, window) for window in WINDOWS])
    found = {f"{w}x{h}": _problems(graph, r) for (w, h), r in zip(WINDOWS, results)}
    assert {k: v for k, v in found.items() if v} == {}


@pytest.mark.parametrize("fixture", FIXTURES)
def test_every_node_label_is_drawn_at_fit_view_from_1100x650(tmp_path, fixture):
    """Groups are packed closely enough that the fitted zoom draws labels (above 0.35)."""
    graph = _graph(fixture)
    windows = [w for w in WINDOWS if w[0] >= 1100 and w[1] >= 650]
    results = _run(tmp_path, [(graph, window) for window in windows])
    labels = {n["label"] for n in graph["nodes"]}
    for (w, h), result in zip(windows, results):
        for state in ("open", "fit"):
            drawn = {t["text"] for t in result[state]["texts"] if not t["box"]}
            assert labels <= drawn, f"{w}x{h} {state}: {sorted(labels - drawn)[:5]}"


@pytest.mark.parametrize("fixture", FIXTURES)
def test_layout_is_deterministic(tmp_path, fixture):
    graph = _graph(fixture)
    first, second = _run(tmp_path, [(graph, (1280, 800)), (graph, (1280, 800))])
    assert first["open"]["positions"] == second["open"]["positions"]
    assert first["fit"]["positions"] == second["fit"]["positions"]


@pytest.mark.parametrize("fixture", FIXTURES)
def test_ids_and_labels_do_not_decide_the_layout(tmp_path, fixture):
    """New random ids and labels, the export's ordering by address and shuffled connections."""
    base = _graph(fixture)
    cases = [(relabel(base, seed), window) for seed in range(RELABELINGS) for window in WINDOWS]
    results = _run(tmp_path, cases)
    found = {}
    for (graph, (w, h)), result, seed in zip(cases, results, [s for s in range(RELABELINGS) for _ in WINDOWS]):
        problems = _problems(graph, result)
        if problems:
            found[f"seed {seed} {w}x{h}"] = problems[:5]
    assert found == {}
