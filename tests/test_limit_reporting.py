"""
Entries a device did not keep because a retention limit was reached are reported.

Each asset exports its counts of refused additions as columns appended to assets.csv (zero or empty
under the limits) and in its JSON export. A saved session reads the counts back, and records refused
while loading the session add to them. The run summary shows the totals over all assets.
"""

import csv
import json
import os
from types import SimpleNamespace

import pytest

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import (
    Asset, AssetInventory, Evidence, format_evidence_overflow, limit_summary_line,
    parse_evidence_overflow,
)
from scrutics.ui.tui import DetailScreen, ScruticsApp, _asset_from_session_row

LIMIT_COLUMNS = ["ip_history_dropped", "evidence_overflow", "evidence_overflow_by_type",
                 "dns_names_overflow", "peer_additions_rejected", "peer_first_seen_overflow"]
T0 = 1_700_000_000.0


def _overflowing_asset(ip="10.0.0.1", mac="02:00:00:00:00:01"):
    asset = Asset(ip=ip, mac=mac)
    for i in range(300):
        asset.record_ip(f"10.1.{i // 250}.{i % 250 + 1}", T0 + i)
    for i in range(70):
        asset.add_evidence("hostname", f"h{i}", 1, "DHCP")
    for i in range(66):
        asset.add_evidence("discovery", f"n{i}", 1, "mDNS")
    for i in range(65):
        asset.add_dns_name(f"f{i}.example")
    for i in range(4100):
        asset.add_peer(f"10.9.{i // 250}.{i % 250 + 1}")
        asset.record_peer_first_seen(f"10.9.{i // 250}.{i % 250 + 1}", T0 + i)
    return asset


def test_export_columns_are_appended_and_zero_under_the_limits():
    row = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01").to_dict()
    assert list(row)[-len(LIMIT_COLUMNS):] == LIMIT_COLUMNS
    assert [row[c] for c in LIMIT_COLUMNS] == [0, 0, "", 0, 0, 0]


def test_export_columns_report_refused_additions():
    row = _overflowing_asset().to_dict()
    assert {c: row[c] for c in LIMIT_COLUMNS} == {
        "ip_history_dropped": 44,
        "evidence_overflow": 8,
        "evidence_overflow_by_type": "discovery:2|hostname:6",
        "dns_names_overflow": 1,
        "peer_additions_rejected": 4,
        "peer_first_seen_overflow": 4,
    }
    assert row["peer_count"] == 4096


def test_evidence_overflow_cell_round_trips():
    counts = {"vendor": 3, "dns": 12, "os_hint": 1}
    assert format_evidence_overflow(counts) == "dns:12|os_hint:1|vendor:3"
    assert parse_evidence_overflow(format_evidence_overflow(counts)) == counts
    assert parse_evidence_overflow("") == {} and parse_evidence_overflow(None) == {}


def test_session_row_reads_the_counts_back(tmp_path):
    inv = AssetInventory({})
    asset = _overflowing_asset()
    inv._assets[asset.ip] = asset
    inv.export_csv(str(tmp_path / "assets.csv"))
    with open(tmp_path / "assets.csv", newline="") as f:
        [row] = list(csv.DictReader(f))
    loaded = _asset_from_session_row(row)
    assert loaded.limit_counts() == asset.limit_counts()
    assert loaded.evidence_overflow == {"hostname": 6, "discovery": 2}


def test_old_session_row_loads_with_zero_counts():
    row = {k: v for k, v in Asset(ip="10.0.0.1", mac="02:00:00:00:00:01").to_dict().items()
           if k not in LIMIT_COLUMNS}
    loaded = _asset_from_session_row({k: str(v) for k, v in row.items()})
    assert loaded.limit_counts() == dict.fromkeys(loaded.limit_counts(), 0)
    assert loaded.evidence_overflow == {}


class _Widget:
    def __getattr__(self, name):
        return lambda *a, **k: None


def test_loading_a_session_adds_refused_records_to_the_saved_counts(tmp_path, monkeypatch):
    session = tmp_path / "scrutics_20260101_000000"
    session.mkdir()
    asset = Asset(ip="10.0.0.1", mac="02:00:00:00:00:01", evidence_overflow={"discovery": 3})
    inv = AssetInventory({})
    inv._assets[asset.ip] = asset
    inv.export_csv(str(session / "assets.csv"))
    records = [Evidence(type="discovery", value=f"n{i}", weight=15, source="mDNS", confidence="HIGH").to_dict()
               for i in range(70)]
    (session / "evidence.json").write_text(json.dumps({"10.0.0.1": records}))
    app = SimpleNamespace(query_one=lambda *a, **k: _Widget(), notify=lambda *a, **k: None,
                          _set_status=lambda *a, **k: None)
    monkeypatch.setenv("SCRUTICS_AUTO_OUTPUT", str(tmp_path))
    ScruticsApp._load_last_results(app)
    loaded = app.inventory.get("10.0.0.1")
    assert [e.value for e in loaded.evidence] == [f"n{i}" for i in range(64)]
    assert loaded.evidence_overflow == {"discovery": 3 + 6}


def test_inventory_totals_and_summary_line():
    inv = AssetInventory({})
    for k in range(2):
        a = _overflowing_asset(ip=f"10.0.0.{k + 1}", mac=f"02:00:00:00:00:0{k + 1}")
        inv._assets[a.ip] = a
        inv._by_mac[a.mac] = a
    totals = inv.limit_totals()
    assert totals == {"ip_history_dropped": 88, "evidence_overflow": 16, "dns_names_overflow": 2,
                      "peer_additions_rejected": 8, "peer_first_seen_overflow": 8}
    assert limit_summary_line(totals) == (
        "Per-device limits: 88 IP history entries dropped | 16 evidence values refused | "
        "2 DNS names refused | 8 peer additions refused | 8 peer first-seen times refused")
    assert limit_summary_line(AssetInventory({}).limit_totals()) == (
        "Per-device limits: 0 IP history entries dropped | 0 evidence values refused | "
        "0 DNS names refused | 0 peer additions refused | 0 peer first-seen times refused")


def _capture_done(inventory):
    notices, statuses = [], []
    widget = SimpleNamespace(label="", remove_class=lambda *a: None)
    engine = CaptureEngine(inventory=inventory)
    app = SimpleNamespace(
        engine=engine, inventory=inventory, _session_dir="out", _paused=True,
        query_one=lambda *a, **k: widget, _export_session=lambda: None,
        _set_status=lambda text, **k: statuses.append(text),
        notify=lambda message, **kw: notices.append((message, kw)),
    )
    ScruticsApp._on_capture_done(app)
    return notices, statuses


def test_tui_summary_shows_the_total_and_warns_only_when_entries_were_not_kept():
    inv = AssetInventory({})
    notices, statuses = _capture_done(inv)
    assert "per-device limits: 0 not kept" in statuses[-1]
    assert [n for n in notices if n[1].get("severity") == "warning"] == []

    a = _overflowing_asset()
    inv._assets[a.ip] = a
    notices, statuses = _capture_done(inv)
    assert "per-device limits: 61 not kept" in statuses[-1]
    [(message, kwargs)] = [n for n in notices if n[1].get("severity") == "warning"]
    assert message == limit_summary_line(inv.limit_totals()) and kwargs.get("markup") is False


def test_asset_json_export_contains_the_counts(tmp_path):
    inv = AssetInventory({})
    a = _overflowing_asset()
    inv._assets[a.ip] = a
    screen = SimpleNamespace(_inventory=inv, _asset_ip=a.ip, _engine=None,
                             app=SimpleNamespace(_session_dir=str(tmp_path), notify=lambda *a, **k: None))
    DetailScreen.export_asset(screen)
    [exported] = list(tmp_path.glob(f"asset_{a.ip.replace('.', '_')}_*.json"))
    data = json.loads(exported.read_text(encoding="utf-8"))
    assert data["evidence_overflow_by_type"] == {"hostname": 6, "discovery": 2}
    assert {k: data[k] for k in a.limit_counts()} == a.limit_counts()


def test_cli_summary_prints_the_per_device_limit_totals(tmp_path, capsys):
    from scrutics.cli import build_parser, run_headless
    log = tmp_path / "eve.json"
    lines = [json.dumps({"event_type": "flow", "src_ip": "10.0.0.5", "dest_ip": f"10.9.{i // 250}.{i % 250 + 1}",
                         "dest_port": 502, "proto": "TCP"}) for i in range(4100)]
    log.write_text("\n".join(lines) + "\n")
    args = build_parser().parse_args(["--file", str(log), "--headless", "--no-baseline",
                                      "--output", str(tmp_path / "out")])
    run_headless(args)
    out = capsys.readouterr().out
    assert ("[!] Per-device limits: 0 IP history entries dropped | 0 evidence values refused | "
            "0 DNS names refused | 4 peer additions refused | 0 peer first-seen times refused") in out
