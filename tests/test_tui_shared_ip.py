"""
Two assets on one IP in the TUI asset table.

A device replaced on the same address keeps its own asset (MAC identity), so the inventory can hold
two assets with one IP. The table, the detail view and session loading must show both, each by
its own identity.
"""

import asyncio
import json

from textual.widgets import DataTable

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.ui.tui import DetailScreen, ScruticsApp

IP = "10.0.0.20"
OLD_MAC = "00:80:f4:00:00:20"
NEW_MAC = "00:1b:1b:00:00:21"


def _shared_ip_inventory():
    inv = AssetInventory({})
    inv.update(IP, OLD_MAC, timestamp=0)
    inv.update(IP, NEW_MAC, timestamp=1)
    return inv


def _rows(table):
    return {key.value: table.get_row(key) for key in table.rows}


def test_inventory_holds_two_assets_on_one_ip():
    assets = _shared_ip_inventory().get_all()
    assert sorted((a.ip, a.mac) for a in assets) == [(IP, NEW_MAC), (IP, OLD_MAC)]


def test_table_shows_both_assets_sharing_an_ip():
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            inv = _shared_ip_inventory()
            app.inventory, app.engine = inv, CaptureEngine(inventory=inv)
            table = app.query_one("#asset-table", DataTable)
            app._refresh_table()
            await pilot.pause()
            rows = _rows(table)
            assert set(rows) == {OLD_MAC, NEW_MAC}
            assert {row[0] for row in rows.values()} == {IP}
            assert {row[1] for row in rows.values()} == {OLD_MAC, NEW_MAC}
            app._refresh_table()           # unchanged rows: updated in place
            await pilot.pause()
            assert _rows(table) == rows
    asyncio.run(run())


def test_moved_asset_row_keeps_its_own_cells():
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            inv = AssetInventory({})
            inv.update("10.0.0.1", "02:00:00:00:00:01", timestamp=0)
            inv.update("10.0.0.2", "02:00:00:00:00:02", timestamp=0)
            app.inventory, app.engine = inv, CaptureEngine(inventory=inv)
            table = app.query_one("#asset-table", DataTable)
            app._refresh_table()
            await pilot.pause()
            inv.update("10.0.0.3", "02:00:00:00:00:01", timestamp=1)   # same row count, new order
            app._refresh_table()
            await pilot.pause()
            rows = _rows(table)
            assert rows["02:00:00:00:00:01"][:2] == ["10.0.0.3", "02:00:00:00:00:01"]
            assert rows["02:00:00:00:00:02"][:2] == ["10.0.0.2", "02:00:00:00:00:02"]
            assert [key.value for key in table.rows] == ["02:00:00:00:00:02", "02:00:00:00:00:01"]
    asyncio.run(run())


def test_detail_view_opens_the_selected_asset(tmp_path):
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            inv = _shared_ip_inventory()
            app.inventory, app.engine = inv, CaptureEngine(inventory=inv)
            app._session_dir = str(tmp_path)
            table = app.query_one("#asset-table", DataTable)
            app._refresh_table()
            await pilot.pause()
            exported = []
            for row in range(table.row_count):
                expected = table.get_row_at(row)[1]
                table.move_cursor(row=row)
                app.action_view_detail()
                await pilot.pause()
                screen = app.screen
                assert isinstance(screen, DetailScreen)
                before = set(tmp_path.glob("asset_*.json"))
                screen.export_asset()
                [path] = set(tmp_path.glob("asset_*.json")) - before
                exported.append((expected, json.loads(path.read_text(encoding="utf-8"))["mac"]))
                path.unlink()
                screen.dismiss()
                await pilot.pause()
            assert sorted(exported) == [(NEW_MAC, NEW_MAC), (OLD_MAC, OLD_MAC)]
    asyncio.run(run())


def test_loaded_session_shows_both_assets_sharing_an_ip(tmp_path, monkeypatch):
    session = tmp_path / "scrutics_20261011_120000"
    session.mkdir()
    _shared_ip_inventory().export_csv(str(session / "assets.csv"))
    monkeypatch.setenv("SCRUTICS_AUTO_OUTPUT", str(tmp_path))

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            app._load_last_results()
            await pilot.pause()
            rows = _rows(app.query_one("#asset-table", DataTable))
            assert set(rows) == {OLD_MAC, NEW_MAC}
            assert {row[0] for row in rows.values()} == {IP}
    asyncio.run(run())
