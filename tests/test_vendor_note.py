"""
An asset whose vendor is OT-associated but that this capture did not show serving OT carries the
display note "OT-associated vendor; no OT service observed in this capture".

The note is set only when vendor_class is OT, classification_type is not OT, and no OT service was
observed on the asset (no served OT-signature port, no validated OT protocol answered as the
server). It is display
text only: it adds no evidence and changes no score, class, role or confidence. One function
(scrutics.vendor_display) supplies it to every surface, so the asset CSV, the TUI detail panel and
asset export, the topology page and the AI tools always agree.
"""

import copy
import csv
import json
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from scrutics.ai.tools import SessionContext, get_asset, get_assets
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.topology import build_graph_data, write_manifest
from scrutics.ui.tui import DetailScreen, asset_identity_lines
from scrutics.vendor_display import VENDOR_NOTE, count_vendor_notes, vendor_note, vendor_note_for

OT_CLIENT = ("00:80:f4:00:00:31", "10.0.0.31")   # TELEMECANIQUE ELECTRIQUE (OT), contacts a PLC only
OT_PLC = ("00:80:f4:00:00:32", "10.0.0.32")      # same vendor, serves Modbus
IT_HOST = ("00:0c:29:00:00:33", "10.0.0.33")     # VMware (IT)


def _tcp(mac, ip, dst, sport, dport, flags):
    return Ether(src=mac, dst="02:00:00:00:00:fe") / IP(src=ip, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


@pytest.fixture
def inventory():
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    for pkt in (_tcp(*OT_CLIENT, "10.0.0.99", 40001, 502, "S"),
                _tcp(*OT_PLC, "10.0.0.98", 502, 40002, "SA"),
                _tcp(*IT_HOST, "10.0.0.99", 40003, 443, "S")):
        engine._ingest_packet(pkt, "pcap")
    return engine.inventory


def test_note_text_is_exact():
    assert VENDOR_NOTE == "OT-associated vendor; no OT service observed in this capture"


@pytest.mark.parametrize("vendor_class, classification_type, expected", [
    ("OT", "Unknown", VENDOR_NOTE), ("OT", "IT", VENDOR_NOTE), ("OT", "Infrastructure", VENDOR_NOTE),
    ("OT", "OT", ""), ("NEUTRAL", "Unknown", ""), ("IT", "IT", ""), ("UNKNOWN", "Unknown", ""), (None, None, ""),
])
def test_note_is_set_only_for_an_ot_vendor_on_a_non_ot_asset(vendor_class, classification_type, expected):
    assert vendor_note_for(vendor_class, classification_type) == expected


def test_assets_get_the_note_from_their_own_vendor_and_class(inventory):
    client, plc, it_host = (inventory.get(ip) for _, ip in (OT_CLIENT, OT_PLC, IT_HOST))
    assert client.vendor_class == "OT" and client.classification_type != "OT"
    assert vendor_note(client) == VENDOR_NOTE
    assert plc.classification_type == "OT" and vendor_note(plc) == ""
    assert vendor_note(it_host) == ""
    assert count_vendor_notes(inventory.get_all()) == 1


def _state(asset):
    return copy.deepcopy({
        "evidence": [e.to_dict() for e in asset.evidence],
        "fields": {f: getattr(asset, f) for f in (
            "classification_type", "role", "confidence", "classification_rule", "classification_reason",
            "classification_conflicts", "confidence_pct", "classification_confidence_pct", "oui_score",
            "protocol_score", "is_ot_vendor", "vendor", "vendor_class", "os_hints")},
    })


def test_note_changes_nothing_on_the_asset(inventory, tmp_path):
    before = {a.ip: _state(a) for a in inventory.get_all()}
    inventory.export_csv(str(tmp_path / "assets.csv"))
    build_graph_data(inventory)
    for asset in inventory.get_all():
        asset_identity_lines(asset)
        vendor_note(asset)
    assert {a.ip: _state(a) for a in inventory.get_all()} == before


def test_every_surface_shows_the_same_note(inventory, tmp_path):
    inventory.export_csv(str(tmp_path / "assets.csv"))
    write_manifest(str(tmp_path))
    with open(tmp_path / "assets.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0])[-1] == "vendor_note"
    csv_notes = {r["ip"]: r["vendor_note"] for r in rows}

    nodes = build_graph_data(inventory)
    topology_notes = {n["label"]: n["vendor_note"] for n in nodes["nodes"] + nodes["isolated_nodes"]}

    ctx = SessionContext(str(tmp_path))
    ai_list_notes = {a["ip"]: a["vendor_note"] for a in get_assets(ctx)}

    for asset in inventory.get_all():
        expected = vendor_note(asset)
        screen = SimpleNamespace(_inventory=inventory, _asset_ip=asset.ip, _engine=None,
                                 app=SimpleNamespace(_session_dir=str(tmp_path), notify=lambda *a, **k: None))
        DetailScreen.export_asset(screen)
        [exported] = list(tmp_path.glob(f"asset_{asset.ip.replace('.', '_')}_*.json"))
        json_note = json.loads(exported.read_text(encoding="utf-8"))["vendor_note"]
        detail_lines = asset_identity_lines(asset)
        assert csv_notes[asset.ip] == expected
        assert json_note == expected
        assert topology_notes[asset.ip] == expected
        assert ai_list_notes[asset.ip] == expected
        assert get_asset(ctx, asset.ip)["vendor_note"] == expected
        assert (f"Vendor note: {expected}" in detail_lines) == bool(expected)
    assert VENDOR_NOTE in csv_notes.values()


def test_sessions_saved_without_the_column_get_the_note_from_stored_values(inventory, tmp_path):
    inventory.export_csv(str(tmp_path / "assets.csv"))
    with open(tmp_path / "assets.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    with open(tmp_path / "assets.csv", "w", encoding="utf-8", newline="") as f:
        fields = [k for k in rows[0] if k != "vendor_note"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in fields})
    write_manifest(str(tmp_path))
    ctx = SessionContext(str(tmp_path))
    assert get_asset(ctx, OT_CLIENT[1])["vendor_note"] == VENDOR_NOTE
    assert get_asset(ctx, OT_PLC[1])["vendor_note"] == ""


def test_topology_page_shows_the_note_in_the_tooltip_and_export():
    from scrutics.topology import HTML_TEMPLATE
    assert "Vendor note: ${node.vendor_note}" in HTML_TEMPLATE
    assert '"Vendor note": n.vendor_note || ""' in HTML_TEMPLATE


def test_user_rule_classifying_an_ot_server_as_it_does_not_get_the_note(monkeypatch):
    from scrutics.classifier import protocol
    rule = {"name": "Lab gateway", "port": 502, "classify_as": "Lab Modbus gateway",
            "role": "Lab gateway", "is_ot": False}
    monkeypatch.setattr(protocol, "_USER_RULES", [rule])
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine._ingest_packet(_tcp(*OT_PLC, "10.0.0.98", 502, 40002, "SA"), "pcap")
    gateway = engine.inventory.get(OT_PLC[1])
    assert gateway.classification_rule == "user_rule" and gateway.classification_type == "IT"
    assert gateway.vendor_class == "OT" and 502 in gateway.ports_seen
    assert vendor_note(gateway) == ""
    assert gateway.to_dict()["vendor_note"] == ""


@pytest.mark.parametrize("ports_seen, summaries, expected", [
    ({502}, {}, ""),                                                            # OT signature port
    (set(), {"Modbus TCP": SimpleNamespace(answers_as_server=True)}, ""),       # validated server
    (set(), {"Modbus TCP": SimpleNamespace(answers_as_server=False)}, VENDOR_NOTE),   # requests only
    ({443}, {}, VENDOR_NOTE),                                                   # non-OT service
])
def test_an_observed_ot_service_suppresses_the_note(ports_seen, summaries, expected):
    asset = SimpleNamespace(vendor_class="OT", classification_type="IT",
                            ports_seen=ports_seen, protocol_summaries=summaries)
    assert vendor_note(asset) == expected


def test_saved_sessions_without_the_column_use_their_saved_ports(inventory, tmp_path, monkeypatch):
    from scrutics.classifier import protocol
    monkeypatch.setattr(protocol, "_USER_RULES", [{"name": "Lab gateway", "port": 502,
                                                    "classify_as": "Lab", "role": "Lab", "is_ot": False}])
    gateway = inventory.get(OT_PLC[1])
    from scrutics.classifier.asset_classifier import classify_asset
    classify_asset(gateway)
    assert gateway.classification_type == "IT"
    inventory.export_csv(str(tmp_path / "assets.csv"))
    with open(tmp_path / "assets.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    with open(tmp_path / "assets.csv", "w", encoding="utf-8", newline="") as f:
        fields = [k for k in rows[0] if k != "vendor_note"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in fields})
    write_manifest(str(tmp_path))
    ctx = SessionContext(str(tmp_path))
    assert get_asset(ctx, OT_PLC[1])["vendor_note"] == ""
    assert get_asset(ctx, OT_CLIENT[1])["vendor_note"] == VENDOR_NOTE
