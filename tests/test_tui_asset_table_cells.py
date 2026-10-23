"""
The asset table's cells for a live capture and for a loaded session.

Both tables build their rows with the same cell function. The Anomalies column counts anomalies
per IP address (live: the engine's newest 100; loaded: every row of anomalies.csv), and the Type
column shows the canonical classification_type ("Unclassified" for Unknown).
"""

import asyncio
import csv
import json

from textual.widgets import DataTable

from scrutics.db.inventory import AssetInventory, Evidence
from scrutics.ui.tui import ScruticsApp

PLC = "10.0.0.10"
SWITCH = "10.0.0.20"
UNKNOWN = "10.0.0.30"


def _inventory():
    inv = AssetInventory({})
    plc = inv.update(PLC, "00:80:f4:00:00:10", timestamp=0)
    plc.classification_type = "OT"
    for n in range(5):
        plc.evidence.append(Evidence(type="discovery", value=f"name {n}", weight=15, source="mDNS",
                                     confidence="HIGH"))
    switch = inv.update(SWITCH, "00:00:0c:00:00:20", timestamp=0)
    switch.classification_type = "Infrastructure"
    inv.update(UNKNOWN, "02:00:00:00:00:30", timestamp=0).classification_type = "Unknown"
    return inv


ANOMALIES = (
    [{"timestamp": "1", "ip": PLC, "type": "POLLING_RATE_CHANGE", "severity": "MEDIUM", "detail": "d"}] * 3
    + [{"timestamp": "2", "ip": SWITCH, "type": "NEW_PEER", "severity": "LOW", "detail": "d"}]
    + [{"timestamp": "3", "ip": "10.0.0.99", "type": "NEW_PEER", "severity": "LOW", "detail": "d"}]
)


class _Baseline:
    def get_anomalies(self):
        return list(ANOMALIES)


class _Engine:
    baseline = _Baseline()


def _rows(table):
    return {table.get_row(key)[0]: table.get_row(key) for key in table.rows}


def _live_rows():
    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            app.inventory, app.engine = _inventory(), _Engine()
            app._refresh_table()
            await pilot.pause()
            first = _rows(app.query_one("#asset-table", DataTable))
            app._refresh_table()                     # same rows: cells updated in place
            await pilot.pause()
            return first, _rows(app.query_one("#asset-table", DataTable))
    return asyncio.run(run())


def _loaded_rows(tmp_path, monkeypatch, write_anomalies=True):
    session = tmp_path / "scrutics_20261018_120000"
    session.mkdir()
    inv = _inventory()
    inv.export_csv(str(session / "assets.csv"))
    (session / "evidence.json").write_text(json.dumps(
        {a.ip: [e.to_dict() for e in a.evidence] for a in inv.get_all()}), encoding="utf-8")
    if write_anomalies:
        with open(session / "anomalies.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp", "ip", "type", "severity", "detail"])
            writer.writeheader()
            writer.writerows(ANOMALIES)
    monkeypatch.setenv("SCRUTICS_AUTO_OUTPUT", str(tmp_path))

    async def run():
        app = ScruticsApp()
        async with app.run_test() as pilot:
            app._load_last_results()
            await pilot.pause()
            return _rows(app.query_one("#asset-table", DataTable))
    return asyncio.run(run())


def test_loaded_anomalies_column_counts_anomalies_per_ip_from_anomalies_csv(tmp_path, monkeypatch):
    rows = _loaded_rows(tmp_path, monkeypatch)
    # the PLC has 5 evidence records and 3 anomalies: the column shows anomalies
    assert {ip: row[7] for ip, row in rows.items()} == {PLC: "3", SWITCH: "1", UNKNOWN: "0"}


def test_loaded_anomalies_column_is_zero_without_anomalies_csv(tmp_path, monkeypatch):
    rows = _loaded_rows(tmp_path, monkeypatch, write_anomalies=False)
    assert {row[7] for row in rows.values()} == {"0"}


def test_live_type_column_shows_classification_type():
    first, updated = _live_rows()
    expected = {PLC: "OT", SWITCH: "Infrastructure", UNKNOWN: "Unclassified"}
    assert {ip: row[8] for ip, row in first.items()} == expected
    assert {ip: row[8] for ip, row in updated.items()} == expected


def test_live_anomalies_column_counts_anomalies_per_ip():
    first, updated = _live_rows()
    assert {ip: row[7] for ip, row in first.items()} == {PLC: "3", SWITCH: "1", UNKNOWN: "0"}
    assert updated == first


def test_loaded_and_live_rows_are_identical_for_the_same_assets_and_anomalies(tmp_path, monkeypatch):
    live, _ = _live_rows()
    assert _loaded_rows(tmp_path, monkeypatch) == live
