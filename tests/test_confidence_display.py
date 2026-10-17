"""
Every confidence shown on screen is the evidence-based classification confidence.

The headless table, the TUI table during a capture, the topology page (node size, isolated list,
tooltip, CSV export), the topology chat summary and the assistant's asset results and confidence
filter all use classification_confidence_pct, so a device shows the same confidence everywhere. The multi-factor confidence_pct is only computed while
the baseline runs, so a --no-baseline run would otherwise show 0% for every device.
"""

import asyncio
import json
import os
import re
import shutil
import subprocess

import pytest
from textual.widgets import DataTable

from scrutics.ai.tools import SessionContext, get_assets
from scrutics.capture.engine import CaptureEngine
from scrutics.cli import _print_table
from scrutics.db.inventory import Asset, AssetInventory
from scrutics.topology import HTML_TEMPLATE, build_graph_data, generate_topology_html, write_manifest
from scrutics.ui.tui import ScruticsApp

PLC_IP, PLC_MAC = "10.0.0.10", "00:0e:8c:00:00:10"
HMI_IP, HMI_MAC = "10.0.0.20", "00:0c:26:00:00:20"


def _inventory(classification, legacy):
    inv = AssetInventory({})
    asset = inv.update(PLC_IP, PLC_MAC, timestamp=0)
    asset.classification_confidence_pct = classification
    asset.confidence_pct = legacy
    return inv, asset


class _Inventory:
    def __init__(self, assets):
        self._assets = assets

    def get_all(self):
        return list(self._assets)


def test_headless_table_shows_classification_confidence(capsys):
    inv, _ = _inventory(classification=45, legacy=0)
    _print_table(inv)
    [row] = [line for line in capsys.readouterr().out.splitlines() if line.startswith(PLC_IP)]
    assert re.search(r"\s45\s+%\s", row)
    assert not re.search(r"\s0\s+%\s", row)


def test_capture_tui_table_shows_classification_confidence():
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            inv, asset = _inventory(classification=45, legacy=30)
            app.inventory, app.engine = inv, CaptureEngine(inventory=inv)
            table = app.query_one("#asset-table", DataTable)
            app._refresh_table()                      # rows built
            await pilot.pause()
            assert table.get_row_at(0)[5] == "45%"
            asset.classification_confidence_pct = 60
            app._refresh_table()                      # same rows: cells updated in place
            await pilot.pause()
            assert table.get_row_at(0)[5] == "60%"
    asyncio.run(run())


def test_topology_nodes_carry_classification_confidence_and_size_from_it():
    plc = Asset(ip=PLC_IP, mac=PLC_MAC, classification_confidence_pct=80, confidence_pct=0)
    hmi = Asset(ip=HMI_IP, mac=HMI_MAC, classification_confidence_pct=20, confidence_pct=100)
    lone = Asset(ip="10.0.0.30", mac="00:0c:26:00:00:30", classification_confidence_pct=0, confidence_pct=40)
    edges = {(hmi.primary_key, plc.primary_key): {"protocols": {"Modbus TCP"}, "count": 5}}
    graph = build_graph_data(_Inventory([plc, hmi, lone]), edges)
    nodes = {n["label"]: n for n in graph["nodes"] + graph["isolated_nodes"]}
    assert {ip: n["confidence"] for ip, n in nodes.items()} == {PLC_IP: 80, HMI_IP: 20, "10.0.0.30": 0}
    assert {ip: n["size"] for ip, n in nodes.items()} == {PLC_IP: 34, HMI_IP: 19, "10.0.0.30": 14}
    # The isolated list, the tooltip and the CSV export show the node's confidence
    for use in ("${node.confidence}%", "Confidence: ${node.confidence}%", '"Confidence %": n.confidence'):
        assert use in HTML_TEMPLATE


def _js_function(page, name):
    start = page.index(f"function {name}(")
    depth = 0
    for i in range(page.index("{", start), len(page)):
        depth += {"{": 1, "}": -1}.get(page[i], 0)
        if depth == 0:
            return page[start:i + 1]
    raise AssertionError(f"{name} not closed")


def _graph_summary(tmp_path, graph):
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("Node.js is required in CI to check the topology page scripts")
        pytest.skip("Node.js not installed")
    page = generate_topology_html(graph)
    script = "\n".join([
        f"var GRAPH = {json.dumps(json.dumps(graph))};",
        "var document = {getElementById: function () { return {textContent: GRAPH}; }};",
        _js_function(page, "buildGraphSummary"),
        "console.log(JSON.stringify(buildGraphSummary()));",
    ])
    path = tmp_path / "summary.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_chat_summary_shows_classification_confidence_and_zero_percent(tmp_path):
    plc = Asset(ip=PLC_IP, mac=PLC_MAC, protocols=["Modbus TCP"],
                classification_type="OT", classification_confidence_pct=75, confidence_pct=0)
    rtu = Asset(ip="10.0.0.11", mac="00:0e:8c:00:00:11", protocols=["Modbus TCP"],
                classification_type="OT", classification_confidence_pct=0, confidence_pct=60)
    summary = _graph_summary(tmp_path, build_graph_data(_Inventory([plc, rtu])))
    lines = summary.splitlines()
    assert any(line.startswith(f"  {PLC_IP} |") and line.endswith("| conf: 75%") for line in lines)
    assert any(line.startswith("  10.0.0.11 |") and line.endswith("| conf: 0%") for line in lines)
    assert "?%" not in summary


def test_assistant_reports_classification_confidence_on_a_no_baseline_session(tmp_path):
    inv = AssetInventory({})
    plc = inv.update(PLC_IP, PLC_MAC, timestamp=0)
    hmi = inv.update(HMI_IP, HMI_MAC, timestamp=0)
    plc.classification_confidence_pct, hmi.classification_confidence_pct = 90, 30
    assert plc.confidence_pct == hmi.confidence_pct == 0      # never computed without the baseline
    session = tmp_path / "scrutics_20261017_000000"
    session.mkdir()
    inv.export_csv(str(session / "assets.csv"))
    write_manifest(str(session))

    ctx = SessionContext(str(session))
    assert [a["ip"] for a in get_assets(ctx, min_confidence=80)] == [PLC_IP]
    reported = {a["ip"]: a["classification_confidence_pct"] for a in get_assets(ctx)}
    assert reported == {PLC_IP: 90, HMI_IP: 30}
