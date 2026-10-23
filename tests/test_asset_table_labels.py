"""
Labels of the asset tables: the protocol column is titled "Protocols", and an asset whose
classification_type is Unknown is shown as "Unclassified" in the TUI table, the TUI detail panel and
the headless table. The stored and exported classification_type stays "Unknown".
"""

import asyncio
import csv
import json
from types import SimpleNamespace

from textual.widgets import DataTable, Static

from scrutics.ai.tools import SessionContext, get_assets
from scrutics.capture.engine import CaptureEngine
from scrutics.cli import _print_table
from scrutics.db.inventory import AssetInventory
from scrutics.topology import HTML_TEMPLATE
from scrutics.ui.tui import DetailScreen, ScruticsApp, _asset_from_session_row, asset_row_cells

PLC, SWITCH, STATION = "10.0.0.10", "10.0.0.20", "10.0.0.30"


def _inventory():
    inv = AssetInventory({})
    inv.update(PLC, "00:80:f4:00:00:10", timestamp=0).classification_type = "OT"
    inv.update(SWITCH, "00:00:0c:00:00:20", timestamp=0).classification_type = "Infrastructure"
    station = inv.update(STATION, "02:00:00:00:00:30", timestamp=0)
    station.classification_type = "Unknown"
    station.contacted_ports.add(443)
    return inv


def _headless_rows(capsys, inv):
    _print_table(inv)
    lines = capsys.readouterr().out.splitlines()
    header = next(line for line in lines if line.startswith("IP "))
    rows = {line.split()[0]: line for line in lines if line.startswith("10.0.0.")}
    return header, rows


def test_tui_protocol_column_is_titled_protocols():
    async def run():
        app = ScruticsApp()
        async with app.run_test():
            table = app.query_one("#asset-table", DataTable)
            return [str(column.label) for column in table.columns.values()]
    labels = asyncio.run(run())
    assert labels[3] == "Protocols"


def test_headless_protocol_column_is_titled_protocols(capsys):
    header, _ = _headless_rows(capsys, _inventory())
    assert " PROTOCOLS " in header
    assert " PROTOCOL " not in header


def test_topology_page_labels_the_text_protocols():
    assert "`Protocols: ${node.protocol}<br>`" in HTML_TEMPLATE
    assert '"Protocols": n.protocol || ""' in HTML_TEMPLATE


def test_tui_type_cell_shows_unclassified_for_unknown():
    inv = _inventory()
    assert asset_row_cells(inv.get(STATION), 0)[8] == "Unclassified"
    assert asset_row_cells(inv.get(SWITCH), 0)[8] == "Infrastructure"
    assert asset_row_cells(inv.get(PLC), 0)[8] == "OT"
    assert inv.get(STATION).classification_type == "Unknown"


def test_headless_type_column_shows_the_classification(capsys):
    _, rows = _headless_rows(capsys, _inventory())
    assert rows[STATION].endswith(" Unclassified")
    assert rows[SWITCH].endswith(" Infrastructure")
    assert rows[PLC].endswith(" OT")
    assert "HTTPS (client, port)" in rows[STATION]


def test_detail_panel_shows_unclassified_for_unknown():
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            inv = _inventory()
            app.push_screen(DetailScreen(STATION, inv, CaptureEngine(inventory=inv)))
            await pilot.pause()
            return "\n".join(str(widget.render()) for widget in app.screen.query(Static))
    text = asyncio.run(run())
    assert "Classification: Unclassified" in text
    assert "Classification: Unknown" not in text


def test_exports_keep_unknown(tmp_path):
    inv = _inventory()
    inv.export_csv(str(tmp_path / "assets.csv"))
    with open(tmp_path / "assets.csv", newline="", encoding="utf-8") as f:
        rows = {row["ip"]: row for row in csv.DictReader(f)}
    assert rows[STATION]["classification_type"] == "Unknown"

    screen = SimpleNamespace(_inventory=inv, _asset_ip=STATION, _engine=None,
                             app=SimpleNamespace(_session_dir=str(tmp_path), notify=lambda *a, **k: None))
    DetailScreen.export_asset(screen)
    [exported] = list(tmp_path.glob("asset_10_0_0_30_*.json"))
    assert json.loads(exported.read_text(encoding="utf-8"))["classification_type"] == "Unknown"

    ctx = SessionContext.__new__(SessionContext)
    ctx.assets = ctx._load_assets(str(tmp_path / "assets.csv"))
    types = {asset["ip"]: asset["type"] for asset in get_assets(ctx)}
    assert types[STATION] == "Unknown"


def test_loaded_session_shows_unclassified_but_keeps_unknown():
    row = {"ip": STATION, "mac": "02:00:00:00:00:30", "protocol": "Unknown",
           "classification_type": "Unknown", "protocol_display": "HTTPS (client, port)"}
    loaded = _asset_from_session_row(row)
    assert loaded.classification_type == "Unknown"
    cells = asset_row_cells(loaded, 0)
    assert cells[3] == "HTTPS (client, port)"
    assert cells[8] == "Unclassified"
