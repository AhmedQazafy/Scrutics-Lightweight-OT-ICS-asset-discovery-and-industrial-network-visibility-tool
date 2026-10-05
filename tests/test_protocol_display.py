"""
Displayed protocol text: served, validated client use, and OT services contacted by port, each
labeled with how it is known. Classification never reads it.
"""

import csv
import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from scrutics.ai.tools import SessionContext, get_assets
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import Asset, AssetInventory
from scrutics.protocol_display import (
    format_protocol_entries, protocol_display_entries, protocol_display_text,
)
from scrutics.ui.tui import _asset_from_session_row

HMI_IP, PLC_IP = "10.0.0.5", "10.0.0.20"
HMI_MAC, PLC_MAC = "02:00:00:00:00:05", "02:00:00:00:00:20"


def _asset(**kwargs):
    return Asset(ip="10.0.0.1", mac="02:00:00:00:00:01", **kwargs)


def _observe(asset, protocol, *, sends_request):
    asset.record_protocol_observation(protocol, sends_request=sends_request, function_code=3)


def test_nothing_known_is_unknown():
    assert protocol_display_entries(_asset()) == []
    assert protocol_display_text(_asset()) == "Unknown"
    assert protocol_display_text(_asset(protocols=["Unknown"])) == "Unknown"


def test_served_protocol_known_only_from_a_port_is_labeled():
    assert protocol_display_entries(_asset(protocols=["Modbus TCP"])) == ["Modbus TCP (port)"]


def test_served_protocol_the_parser_saw_answered_is_unlabeled():
    asset = _asset(protocols=["Modbus TCP"])
    _observe(asset, "Modbus TCP", sends_request=False)
    assert protocol_display_entries(asset) == ["Modbus TCP"]


def test_parser_seen_requests_alone_do_not_validate_a_served_protocol():
    asset = _asset(protocols=["Modbus TCP"])
    _observe(asset, "Modbus TCP", sends_request=True)
    assert protocol_display_entries(asset) == ["Modbus TCP (port)", "Modbus TCP (client)"]


def test_it_standard_ports_text_is_shown_as_written():
    assert protocol_display_entries(_asset(protocols=["IT (standard ports only)"])) == [
        "IT (standard ports only)"
    ]


def test_validated_client_without_listeners():
    asset = _asset(contacted_ports={502})
    _observe(asset, "Modbus TCP", sends_request=True)
    # The contacted Modbus port adds nothing once the parser has validated the client use
    assert protocol_display_entries(asset) == ["Modbus TCP (client)"]


def test_ot_service_contacted_by_port_only():
    asset = _asset(contacted_ports={102, 443, 53})
    assert protocol_display_entries(asset) == ["S7comm / IEC 61850 MMS / ICCP (client, port)"]


def test_udp_only_ot_port_and_repeated_names_are_listed_once():
    asset = _asset(contacted_ports={47808, 55000, 55001})
    assert protocol_display_entries(asset) == ["BACnet/IP (client, port)", "FL-net (client, port)"]


def test_served_then_client_then_port_only_order():
    asset = _asset(protocols=["EtherNet/IP"], contacted_ports={102, 502})
    _observe(asset, "Modbus TCP", sends_request=True)
    _observe(asset, "EtherNet/IP", sends_request=False)
    assert protocol_display_entries(asset) == [
        "EtherNet/IP",
        "Modbus TCP (client)",
        "S7comm / IEC 61850 MMS / ICCP (client, port)",
    ]


def test_same_protocol_served_and_polled_shows_both():
    asset = _asset(protocols=["Modbus TCP"])
    _observe(asset, "Modbus TCP", sends_request=False)
    _observe(asset, "Modbus TCP", sends_request=True)
    assert protocol_display_entries(asset) == ["Modbus TCP", "Modbus TCP (client)"]


def test_display_does_not_change_served_protocols_or_classification_fields():
    asset = _asset(protocols=["Modbus TCP"], contacted_ports={102})
    before = (list(asset.protocols), asset.classification_type,
              asset.classification_confidence_pct, asset.confidence_pct, list(asset.evidence))
    protocol_display_text(asset, 20)
    assert (list(asset.protocols), asset.classification_type,
            asset.classification_confidence_pct, asset.confidence_pct,
            list(asset.evidence)) == before


def test_fitting_shortens_names_and_never_qualifiers():
    entries = ["S7comm / IEC 61850 MMS / ICCP (client, port)"]
    text = format_protocol_entries(entries, 32)
    assert len(text) <= 32
    assert text.endswith(" (client, port)")
    assert text.startswith("S7comm")

    text = format_protocol_entries(["Modbus TCP (port)", "Modbus TCP (client)"], 32)
    assert len(text) <= 32
    assert text.count("(port)") == 1 and text.count("(client)") == 1


def test_fitting_leaves_out_trailing_entries_when_names_cannot_shrink_further():
    entries = [f"Proto{i} (client, port)" for i in range(6)]
    text = format_protocol_entries(entries, 40)
    assert len(text) <= 40
    assert text.endswith(tuple(f"+{n}" for n in range(1, 6)))
    for part in text.split(", +")[0].split("), "):
        assert part.endswith("(client, port") or part.endswith("(client, port)")


def test_text_that_fits_is_unchanged():
    assert format_protocol_entries(["Modbus TCP (client)"], 32) == "Modbus TCP (client)"


# ── End to end through the capture engine ──────────────────────────────────

def _read_holding_registers_request(trans_id=0x0001, unit_id=0x01):
    # FC 03 request PDU: function code, starting address, quantity
    pdu = struct.pack(">BHH", 0x03, 0x0000, 2)
    return struct.pack(">HHHB", trans_id, 0x0000, len(pdu) + 1, unit_id) + pdu


def _read_holding_registers_response(trans_id=0x0001, unit_id=0x01):
    # FC 03 response PDU: function code, byte count, register values
    pdu = struct.pack(">BB", 0x03, 4) + struct.pack(">HH", 0x1234, 0x5678)
    return struct.pack(">HHHB", trans_id, 0x0000, len(pdu) + 1, unit_id) + pdu


def _engine():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    return inv, engine


def test_polling_hmi_shows_validated_client_use():
    inv, engine = _engine()
    engine._process_packet(
        Ether(src=HMI_MAC, dst=PLC_MAC) / IP(src=HMI_IP, dst=PLC_IP)
        / TCP(sport=40001, dport=502, flags="PA") / Raw(load=_read_holding_registers_request())
    )
    engine._process_packet(
        Ether(src=PLC_MAC, dst=HMI_MAC) / IP(src=PLC_IP, dst=HMI_IP)
        / TCP(sport=502, dport=40001, flags="PA") / Raw(load=_read_holding_registers_response())
    )
    hmi, plc = inv.get(HMI_IP), inv.get(PLC_IP)
    assert protocol_display_text(hmi) == "Modbus TCP (client)"
    assert hmi.protocols == []
    assert protocol_display_text(plc) == "Modbus TCP"


def test_client_of_unparsed_ot_port_shows_port_only_client_use():
    inv, engine = _engine()
    engine._process_packet(
        Ether(src=HMI_MAC, dst=PLC_MAC) / IP(src=HMI_IP, dst=PLC_IP)
        / TCP(sport=40002, dport=102, flags="S")
    )
    assert protocol_display_text(inv.get(HMI_IP)) == "S7comm / IEC 61850 MMS / ICCP (client, port)"


# ── Saved sessions and AI tools ─────────────────────────────────────────────

def _client_hmi_inventory():
    inv = AssetInventory()
    hmi = inv.get_or_create(ip=HMI_IP, mac=HMI_MAC, timestamp=1.0)
    hmi.contacted_ports.update({502, 102})
    _observe(hmi, "Modbus TCP", sends_request=True)
    return inv, hmi


def _saved_rows(tmp_path, inv):
    path = tmp_path / "assets.csv"
    inv.export_csv(str(path))
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_csv_keeps_served_protocols_and_saves_display_entries_last(tmp_path):
    inv, hmi = _client_hmi_inventory()
    row = _saved_rows(tmp_path, inv)[0]
    assert list(row)[-1] == "protocol_display"
    assert row["protocol"] == "Unknown"
    assert row["protocol_display"] == (
        "Modbus TCP (client)|S7comm / IEC 61850 MMS / ICCP (client, port)"
    )


def test_reloaded_session_shows_saved_display_entries(tmp_path):
    inv, hmi = _client_hmi_inventory()
    loaded = _asset_from_session_row(_saved_rows(tmp_path, inv)[0])
    assert loaded.protocols == ["Unknown"]
    assert protocol_display_entries(loaded) == protocol_display_entries(hmi)


def test_reloaded_asset_with_nothing_known_stays_unknown(tmp_path):
    inv = AssetInventory()
    inv.get_or_create(ip=HMI_IP, mac=HMI_MAC, timestamp=1.0)
    loaded = _asset_from_session_row(_saved_rows(tmp_path, inv)[0])
    assert protocol_display_text(loaded) == "Unknown"


def test_session_without_display_column_falls_back_to_served_protocols():
    row = {"ip": PLC_IP, "mac": PLC_MAC, "protocol": "Modbus TCP, S7comm"}
    assert protocol_display_entries(_asset_from_session_row(row)) == ["Modbus TCP", "S7comm"]
    row = {"ip": HMI_IP, "mac": HMI_MAC, "protocol": "Unknown"}
    assert protocol_display_text(_asset_from_session_row(row)) == "Unknown"


def _ai_context(tmp_path, rows, fieldnames):
    path = tmp_path / "assets.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    ctx = SessionContext.__new__(SessionContext)
    ctx.assets = ctx._load_assets(str(path))
    return ctx


def test_ai_asset_list_carries_display_entries(tmp_path):
    inv, hmi = _client_hmi_inventory()
    rows = _saved_rows(tmp_path, inv)
    ctx = _ai_context(tmp_path, rows, list(rows[0]))
    (asset,) = get_assets(ctx)
    assert asset["protocols"] == ["Unknown"]
    assert asset["protocol_display"] == [
        "Modbus TCP (client)", "S7comm / IEC 61850 MMS / ICCP (client, port)",
    ]


def test_ai_asset_list_falls_back_to_served_for_old_sessions(tmp_path):
    row = {"ip": PLC_IP, "mac": PLC_MAC, "protocol": "Modbus TCP"}
    ctx = _ai_context(tmp_path, [row], list(row))
    (asset,) = get_assets(ctx)
    assert asset["protocol_display"] == ["Modbus TCP"]
