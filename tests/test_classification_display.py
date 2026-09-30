"""
The classification basis is shown and exported, and the displayed role follows the class.
"""

import csv
import json
import struct
from types import SimpleNamespace

import pytest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import scrutics.classifier.protocol as protocol
from scrutics.ai.tools import SessionContext, get_asset
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.topology import write_manifest
from scrutics.ui.tui import DetailScreen, _asset_from_session_row, classification_basis_lines

CLIENT_IP = "10.0.0.5"
PLC_IP = "10.0.0.20"


def _adu(trans_id, pdu, unit_id=0x01):
    return struct.pack(">HHHB", trans_id, 0x0000, len(pdu) + 1, unit_id) + pdu


def modbus_read_request(trans_id=1):
    return _adu(trans_id, struct.pack(">BHH", 0x03, 0x0000, 2))


def modbus_read_response(trans_id=1):
    return _adu(trans_id, struct.pack(">BBHH", 0x03, 4, 0x0001, 0x0002))


def tcp(mac, ip, dst, sport, dport, payload=None, flags="PA"):
    pkt = Ether(src=mac, dst="02:00:00:00:00:ff") / IP(src=ip, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return pkt / Raw(load=payload) if payload is not None else pkt


def udp(mac, ip, dst, sport, dport, payload=b"\x00" * 8):
    return Ether(src=mac, dst="02:00:00:00:00:ff") / IP(src=ip, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def serves(mac, ip, port, payload=b"\x00"):
    return tcp(mac, ip, CLIENT_IP, port, 50000, payload, flags="SA")


def run(packets, oui_db=None):
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    if oui_db:
        engine._oui_db = oui_db
    for pkt in packets:
        engine._process_packet(pkt)
    return inv


M = "02:00:00:00:00:{:02x}".format

SCENARIOS = {
    "1 pure Modbus PLC": ([serves(M(1), "10.0.1.1", 502, modbus_read_response())], "10.0.1.1",
                          "OT", "PLC / RTU / Modbus Gateway"),
    "2 HMI serving web and Modbus": ([serves(M(2), "10.0.1.2", 80, b"HTTP/1.1 200"), serves(M(2), "10.0.1.2", 443, b"\x16"),
                                      serves(M(2), "10.0.1.2", 502, modbus_read_response())], "10.0.1.2",
                                     "OT", "PLC / RTU / Modbus Gateway"),
    "2b HMI polling Modbus": ([serves(M(3), "10.0.1.3", 80, b"HTTP/1.1 200"), serves(M(3), "10.0.1.3", 443, b"\x16"),
                               tcp(M(3), "10.0.1.3", PLC_IP, 40001, 502, modbus_read_request())], "10.0.1.3",
                              "OT", "OT client"),
    "3 switch serving SNMP": ([udp(M(4), "10.0.1.4", CLIENT_IP, 161, 50000, b"\x30\x26")], "10.0.1.4",
                              "Unknown", "Unclassified"),
    "4 firewall HTTPS and SNMP": ([serves(M(5), "10.0.1.5", 443, b"\x16"), udp(M(5), "10.0.1.5", CLIENT_IP, 161, 50000, b"\x30\x26")],
                                  "10.0.1.5", "Unknown", "Unclassified"),
    "5 OT device with SSH admin": ([serves(M(6), "10.0.1.6", 22, b"SSH-2.0"), serves(M(6), "10.0.1.6", 443, b"\x16"),
                                    serves(M(6), "10.0.1.6", 502, modbus_read_response())], "10.0.1.6",
                                   "OT", "PLC / RTU / Modbus Gateway"),
    "6 SMB and RDP server": ([serves(M(7), "10.0.1.7", 445), serves(M(7), "10.0.1.7", 3389, b"\x03")], "10.0.1.7",
                             "IT", "IT device"),
    "7 Modbus client": ([tcp(M(8), "10.0.1.8", PLC_IP, 40001, 502, modbus_read_request())], "10.0.1.8",
                        "OT", "OT client"),
    "8 SNMP and Modbus": ([udp(M(9), "10.0.1.9", CLIENT_IP, 161, 50000, b"\x30\x26"),
                           serves(M(9), "10.0.1.9", 502, modbus_read_response())], "10.0.1.9",
                          "OT", "PLC / RTU / Modbus Gateway"),
    "10 no observations": ([Ether(src=M(11), dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="10.0.1.11", hwsrc=M(11), pdst="10.0.0.1")],
                           "10.0.1.11", "Unknown", "Unclassified"),
    "11 web server only": ([serves(M(12), "10.0.1.12", 80, b"HTTP/1.1 200"), serves(M(12), "10.0.1.12", 443, b"\x16")],
                           "10.0.1.12", "Unknown", "Unclassified"),
    "SSH and RDP server": ([serves(M(13), "10.0.1.13", 22, b"SSH-2.0"), serves(M(13), "10.0.1.13", 3389, b"\x03")],
                           "10.0.1.13", "IT", "IT device"),
    "several OT port rules": ([serves(M(14), "10.0.1.14", 502, modbus_read_response()), serves(M(14), "10.0.1.14", 102, b"\x03")],
                              "10.0.1.14", "OT", "OT device (multiple OT protocols)"),
    "OT port without a port rule": ([udp(M(15), "10.0.1.15", CLIENT_IP, 34962, 50000)], "10.0.1.15",
                                    "OT", "OT device"),
    "contacted OT port only": ([tcp(M(16), "10.0.1.16", PLC_IP, 40001, 502, flags="S")], "10.0.1.16",
                               "Unknown", "Possible OT Client"),
    "contacted non-OT port only": ([tcp(M(17), "10.0.1.17", CLIENT_IP, 40001, 443, flags="S")], "10.0.1.17",
                                   "Unknown", "Unclassified"),
}

ROLES_BY_CLASS = {
    "OT": {"PLC / RTU / Modbus Gateway", "OT client", "OT device", "OT device (multiple OT protocols)"},
    "IT": {"IT device"},
    "Unknown": {"Unclassified", "Possible OT Client"},
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_role_follows_the_class(name):
    packets, ip, expected_class, expected_role = SCENARIOS[name]
    asset = run(packets).get(ip)
    assert (asset.classification_type, asset.role) == (expected_class, expected_role)
    assert asset.role in ROLES_BY_CLASS[asset.classification_type]


def test_user_rule_role_is_the_rules_role(monkeypatch):
    rule = {"name": "Lab gateway", "port": 502, "classify_as": "Lab", "role": "Lab gateway", "is_ot": False}
    monkeypatch.setattr(protocol, "_USER_RULES", [rule])
    asset = run([serves(M(18), "10.0.1.18", 502, modbus_read_response())]).get("10.0.1.18")
    assert (asset.classification_type, asset.role) == ("IT", "Lab gateway")


def _ot_asset_with_conflict():
    return run(SCENARIOS["5 OT device with SSH admin"][0]).get("10.0.1.6")


def _unknown_asset():
    return run(SCENARIOS["11 web server only"][0]).get("10.0.1.12")


def test_detail_panel_shows_basis_and_conflicts_for_ot_asset():
    assert classification_basis_lines(_ot_asset_with_conflict()) == [
        "Decision confidence: HIGH",
        "Decided by: serves a validated OT protocol",
        "Reason: serves validated OT protocol: Modbus TCP; serves: HTTPS (443)",
        "Conflict: also serves IT service: SSH/SFTP (22)",
    ]


def test_detail_panel_shows_reason_for_unknown_asset():
    assert classification_basis_lines(_unknown_asset()) == [
        "Decision confidence: LOW",
        "Decided by: no classifying evidence",
        "Reason: no classifying evidence; serves: HTTP (80), HTTPS (443)",
    ]


OLD_COLUMNS = [
    "ip", "mac", "vendor", "vendor_class", "protocol", "role", "confidence_pct", "type",
    "classification_type", "classification_confidence", "evidence_summary", "domain", "os_hints",
    "dns_names", "hostname", "oui_score", "protocol_score", "behavioral_score",
    "directionality_score", "baseline_status", "packet_count", "peer_count", "ports_seen",
    "contacted_ports", "initiates", "is_ot_vendor", "first_seen", "last_seen",
]
NEW_COLUMNS = ["classification_rule", "classification_reason", "classification_conflicts",
               "classification_decision_confidence"]


def _write_session(tmp_path, inv):
    path = tmp_path / "assets.csv"
    inv.export_csv(str(path))
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return reader.fieldnames, list(reader)


def test_csv_appends_basis_columns_and_round_trips(tmp_path):
    inv = run(SCENARIOS["5 OT device with SSH admin"][0])
    original = inv.get("10.0.1.6")
    header, rows = _write_session(tmp_path, inv)
    assert header == OLD_COLUMNS + NEW_COLUMNS
    row = next(r for r in rows if r["ip"] == "10.0.1.6")
    loaded = _asset_from_session_row(row)
    assert loaded.classification_rule == original.classification_rule
    assert loaded.classification_reason == original.classification_reason
    assert loaded.classification_conflicts == original.classification_conflicts == [
        "also serves IT service: SSH/SFTP (22)"]
    assert loaded.confidence == original.confidence == "HIGH"
    assert loaded.classification_type == "OT"


def test_old_session_row_loads_with_defaults(tmp_path):
    inv = run(SCENARIOS["1 pure Modbus PLC"][0])
    _, rows = _write_session(tmp_path, inv)
    old_row = {k: v for k, v in rows[0].items() if k in OLD_COLUMNS}
    loaded = _asset_from_session_row(old_row)
    assert (loaded.classification_rule, loaded.classification_reason, loaded.classification_conflicts) == ("", "", [])
    assert loaded.confidence == ""
    assert classification_basis_lines(loaded) == [
        "Decision confidence: not recorded",
        "Decided by: not recorded",
    ]


def test_asset_json_export_contains_basis(tmp_path):
    inv = run(SCENARIOS["5 OT device with SSH admin"][0])
    notices = []
    screen = SimpleNamespace(
        _inventory=inv, _asset_ip="10.0.1.6", _engine=None,
        app=SimpleNamespace(_session_dir=str(tmp_path), notify=lambda msg, **kw: notices.append(msg)),
    )
    DetailScreen.export_asset(screen)
    [exported] = list(tmp_path.glob("asset_10_0_1_6_*.json"))
    data = json.loads(exported.read_text(encoding="utf-8"))
    assert data["classification_rule"] == "serves_validated_ot_protocol"
    assert data["classification_reason"] == "serves validated OT protocol: Modbus TCP; serves: HTTPS (443)"
    assert data["classification_conflicts"] == ["also serves IT service: SSH/SFTP (22)"]


def test_ai_asset_lookup_includes_reason_and_conflicts(tmp_path):
    inv = run(SCENARIOS["5 OT device with SSH admin"][0])
    inv.export_csv(str(tmp_path / "assets.csv"))
    write_manifest(str(tmp_path))
    result = get_asset(SessionContext(str(tmp_path)), "10.0.1.6")
    assert result["classification_reason"] == "serves validated OT protocol: Modbus TCP; serves: HTTPS (443)"
    assert result["classification_conflicts"] == ["also serves IT service: SSH/SFTP (22)"]
