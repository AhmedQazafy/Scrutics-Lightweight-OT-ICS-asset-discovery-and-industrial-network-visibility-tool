"""
Vendor names are shown to people without trailing commas or whitespace, and exported verbatim.

The IEEE registry gives some names with a trailing comma ("Siemens AG," for 00:1B:1B). Screens
(TUI detail panel and asset tables), the CLI table, the topology page text and the assistant's tool
results show the name with only trailing commas and whitespace removed; assets.csv, the TUI asset
JSON export and the topology page's CSV export keep the registry name exactly.
"""

import csv
import json
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from scrutics.ai.tools import SessionContext, get_asset, get_assets
from scrutics.capture.engine import CaptureEngine
from scrutics.cli import _print_table
from scrutics.db.inventory import AssetInventory
from scrutics.topology import HTML_TEMPLATE, build_graph_data, write_manifest
from scrutics.ui.tui import DetailScreen, asset_identity_lines, vendor_cell
from scrutics.vendor_display import display_vendor_name

MAC, IP_ADDR = "00:1b:1b:00:00:41", "10.0.0.41"     # registered to "Siemens AG,"
STORED, SHOWN = "Siemens AG,", "Siemens AG"


@pytest.mark.parametrize("name, shown", [
    ("Siemens AG,", "Siemens AG"), ("Siemens AG, ,", "Siemens AG"), ("Moxa \t\n", "Moxa"),
    ("Cisco Systems, Inc", "Cisco Systems, Inc"), ("A,B,", "A,B"), ("  Leading kept", "  Leading kept"),
    ("Unknown", "Unknown"), ("", ""), (None, None),
])
def test_only_trailing_commas_and_whitespace_are_removed(name, shown):
    assert display_vendor_name(name) == shown


@pytest.fixture
def inventory():
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    pkt = Ether(src=MAC, dst="02:00:00:00:00:fe") / IP(src=IP_ADDR, dst="10.0.0.99") / TCP(sport=40001, dport=502, flags="S")
    engine._ingest_packet(pkt, "pcap")
    inv = engine.inventory
    assert inv.get(IP_ADDR).vendor == STORED
    return inv


def test_exports_keep_the_registry_name(inventory, tmp_path):
    inventory.export_csv(str(tmp_path / "assets.csv"))
    with open(tmp_path / "assets.csv", encoding="utf-8", newline="") as f:
        assert next(csv.DictReader(f))["vendor"] == STORED
    screen = SimpleNamespace(_inventory=inventory, _asset_ip=IP_ADDR, _engine=None,
                             app=SimpleNamespace(_session_dir=str(tmp_path), notify=lambda *a, **k: None))
    DetailScreen.export_asset(screen)
    [exported] = list(tmp_path.glob("asset_10_0_0_41_*.json"))
    assert json.loads(exported.read_text(encoding="utf-8"))["vendor"] == STORED
    [node] = build_graph_data(inventory)["isolated_nodes"]
    assert node["vendor"] == STORED                       # read by the topology page's CSV export
    assert '"Vendor": n.vendor || ""' in HTML_TEMPLATE


def test_screens_show_the_name_without_the_trailing_comma(inventory, capsys):
    asset = inventory.get(IP_ADDR)
    assert f"MAC: {asset.mac}    Vendor: {SHOWN}" in asset_identity_lines(asset)
    assert vendor_cell(asset, 20) == SHOWN
    assert vendor_cell(asset, 4) == "Siem"
    _print_table(inventory)
    out = capsys.readouterr().out
    assert SHOWN in out and STORED not in out


def test_topology_page_text_shows_the_name_without_the_trailing_comma(inventory):
    [node] = build_graph_data(inventory)["isolated_nodes"]
    assert node["vendor_display"] == SHOWN
    for use in ("${node.vendor_display || 'Unknown'}", "Vendor: ${node.vendor_display}", '(n.vendor_display||"Unknown")'):
        assert use in HTML_TEMPLATE
    # Only the CSV export reads the stored name
    assert HTML_TEMPLATE.count("n.vendor ||") == 1 and "node.vendor}" not in HTML_TEMPLATE


def test_assistant_tool_results_show_the_name_without_the_trailing_comma(inventory, tmp_path):
    inventory.export_csv(str(tmp_path / "assets.csv"))
    write_manifest(str(tmp_path))
    ctx = SessionContext(str(tmp_path))
    assert [a["vendor"] for a in get_assets(ctx)] == [SHOWN]
    assert get_asset(ctx, IP_ADDR)["vendor"] == SHOWN
