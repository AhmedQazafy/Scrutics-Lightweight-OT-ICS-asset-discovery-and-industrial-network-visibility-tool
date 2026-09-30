"""
Asset classification: one precedence classifier over observed facts.

Each test builds an asset from synthetic packets and checks the class, the decision
confidence, the deciding rule, conflict notes and the reason.
"""

import struct

import pytest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import scrutics.classifier.protocol as protocol
from scrutics.classifier.asset_classifier import classify_asset
from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine

CLIENT_IP, CLIENT_MAC = "10.0.0.5", "02:00:00:00:00:05"


def _adu(trans_id, pdu, unit_id=0x01):
    return struct.pack(">HHHB", trans_id, 0x0000, len(pdu) + 1, unit_id) + pdu


def modbus_read_request(trans_id=1):
    # FC 03 request: start address, quantity
    return _adu(trans_id, struct.pack(">BHH", 0x03, 0x0000, 2))


def modbus_read_response(trans_id=1):
    # FC 03 response: byte count, two registers
    return _adu(trans_id, struct.pack(">BBHH", 0x03, 4, 0x0001, 0x0002))


def tcp(src_mac, src_ip, dst_ip, sport, dport, payload=None, flags="PA"):
    pkt = Ether(src=src_mac, dst="02:00:00:00:00:ff") / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags=flags)
    return pkt / Raw(load=payload) if payload is not None else pkt


def udp(src_mac, src_ip, dst_ip, sport, dport, payload=b"\x00" * 8):
    return Ether(src=src_mac, dst="02:00:00:00:00:ff") / IP(src=src_ip, dst=dst_ip) / UDP(
        sport=sport, dport=dport) / Raw(load=payload)


def serves(mac, ip, port, payload=b"\x00", peer=CLIENT_IP, peer_port=50000):
    return tcp(mac, ip, peer, port, peer_port, payload, flags="SA")


def run(packets, oui_db=None):
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    if oui_db:
        engine._oui_db = oui_db
    for pkt in packets:
        engine._process_packet(pkt)
    return inv, engine


def decision(asset):
    return (asset.classification_type, asset.confidence, asset.classification_rule,
            asset.classification_conflicts, asset.classification_reason)


PLC_IP, PLC_MAC = "10.0.0.20", "02:00:00:00:00:20"


def test_pure_modbus_plc_is_ot_high_from_validated_protocol():
    inv, _ = run([serves(PLC_MAC, PLC_IP, 502, modbus_read_response())])
    assert decision(inv.get(PLC_IP)) == (
        "OT", "HIGH", "serves_validated_ot_protocol", [],
        "serves validated OT protocol: Modbus TCP",
    )


def test_hmi_serving_web_and_modbus_is_ot_high_with_web_listed_as_services():
    ip, mac = "10.0.0.21", "02:00:00:00:00:21"
    inv, _ = run([
        serves(mac, ip, 80, b"HTTP/1.1 200 OK"),
        serves(mac, ip, 443, b"\x16\x03\x01"),
        serves(mac, ip, 502, modbus_read_response()),
    ])
    assert decision(inv.get(ip)) == (
        "OT", "HIGH", "serves_validated_ot_protocol", [],
        "serves validated OT protocol: Modbus TCP; serves: HTTP (80), HTTPS (443)",
    )


def test_hmi_serving_web_and_polling_modbus_is_ot_client():
    ip, mac = "10.0.0.22", "02:00:00:00:00:22"
    inv, _ = run([
        serves(mac, ip, 80, b"HTTP/1.1 200 OK"),
        serves(mac, ip, 443, b"\x16\x03\x01"),
        tcp(mac, ip, PLC_IP, 40001, 502, modbus_read_request()),
    ])
    asset = inv.get(ip)
    assert decision(asset) == (
        "OT", "MEDIUM", "sends_validated_ot_requests", [],
        "sends validated OT protocol requests: Modbus TCP; serves: HTTP (80), HTTPS (443)",
    )
    assert asset.role == "OT client"


def test_switch_serving_only_snmp_is_unknown_with_services_and_vendor():
    ip, mac = "10.0.0.40", "00:00:0c:00:00:40"
    inv, _ = run([udp(mac, ip, CLIENT_IP, 161, 50000, b"\x30\x26")],
                 oui_db={"00000C": "Cisco Systems, Inc."})
    assert decision(inv.get(ip)) == (
        "Unknown", "LOW", "no_classifying_evidence", [],
        "no classifying evidence; serves: SNMP (161); vendor: Cisco Systems, Inc.",
    )


def test_firewall_with_https_snmp_and_many_peers_is_unknown():
    ip, mac = "10.0.0.41", "00:09:0f:00:00:41"
    packets = [serves(mac, ip, 443, b"\x16\x03\x01", peer=f"10.0.1.{n}") for n in range(1, 9)]
    packets.append(udp(mac, ip, CLIENT_IP, 161, 50000, b"\x30\x26"))
    inv, _ = run(packets, oui_db={"00090F": "Fortinet, Inc."})
    assert decision(inv.get(ip)) == (
        "Unknown", "LOW", "no_classifying_evidence", [],
        "no classifying evidence; serves: SNMP (161), HTTPS (443); vendor: Fortinet, Inc.",
    )


def test_ot_device_with_ssh_admin_records_it_conflict():
    ip, mac = "10.0.0.23", "02:00:00:00:00:23"
    inv, _ = run([
        serves(mac, ip, 22, b"SSH-2.0-dropbear"),
        serves(mac, ip, 443, b"\x16\x03\x01"),
        serves(mac, ip, 502, modbus_read_response()),
    ])
    assert decision(inv.get(ip)) == (
        "OT", "HIGH", "serves_validated_ot_protocol",
        ["also serves IT service: SSH/SFTP (22)"],
        "serves validated OT protocol: Modbus TCP; serves: HTTPS (443)",
    )


def test_smb_and_rdp_server_is_it_medium():
    ip, mac = "10.0.0.24", "02:00:00:00:00:24"
    inv, _ = run([serves(mac, ip, 445), serves(mac, ip, 3389, b"\x03")])
    assert decision(inv.get(ip)) == (
        "IT", "MEDIUM", "serves_it_port", [],
        "listens on IT port: RDP (3389); also: listens on IT port: SMB/CIFS (445)",
    )


def test_modbus_client_is_ot_client_medium():
    ip, mac = "10.0.0.25", "02:00:00:00:00:25"
    inv, _ = run([tcp(mac, ip, PLC_IP, 40001, 502, modbus_read_request())])
    asset = inv.get(ip)
    assert decision(asset) == (
        "OT", "MEDIUM", "sends_validated_ot_requests", [],
        "sends validated OT protocol requests: Modbus TCP",
    )
    assert asset.role == "OT client"


def test_snmp_and_modbus_is_ot_high_with_snmp_listed():
    ip, mac = "10.0.0.26", "02:00:00:00:00:26"
    inv, _ = run([
        udp(mac, ip, CLIENT_IP, 161, 50000, b"\x30\x26"),
        serves(mac, ip, 502, modbus_read_response()),
    ])
    assert decision(inv.get(ip)) == (
        "OT", "HIGH", "serves_validated_ot_protocol", [],
        "serves validated OT protocol: Modbus TCP; serves: SNMP (161)",
    )


def test_user_rule_wins_and_records_disagreeing_evidence(monkeypatch):
    rule = {"name": "Lab gateway", "port": 502, "classify_as": "Lab Modbus gateway",
            "role": "Lab gateway", "is_ot": False}
    monkeypatch.setattr(protocol, "_USER_RULES", [rule])
    ip, mac = "10.0.0.27", "02:00:00:00:00:27"
    inv, _ = run([serves(mac, ip, 502, modbus_read_response())])
    assert decision(inv.get(ip)) == (
        "IT", "HIGH", "user_rule",
        ["also serves validated OT protocol: Modbus TCP"],
        "user rule 'Lab gateway' matched port 502",
    )


def test_device_without_observations_is_unknown_with_reason():
    ip, mac = "10.0.0.28", "02:00:00:00:00:28"
    arp = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=ip, hwsrc=mac, pdst="10.0.0.1")
    inv, _ = run([arp])
    assert decision(inv.get(ip)) == (
        "Unknown", "LOW", "no_classifying_evidence", [],
        "no services or protocol observations",
    )


def test_web_server_only_is_unknown():
    ip, mac = "10.0.0.29", "02:00:00:00:00:29"
    inv, _ = run([serves(mac, ip, 80, b"HTTP/1.1 200 OK"), serves(mac, ip, 443, b"\x16\x03\x01")])
    assert decision(inv.get(ip)) == (
        "Unknown", "LOW", "no_classifying_evidence", [],
        "no classifying evidence; serves: HTTP (80), HTTPS (443)",
    )


def test_contacting_ot_port_without_validated_requests_is_possible_ot_client():
    ip, mac = "10.0.0.30", "02:00:00:00:00:30"
    inv, _ = run([tcp(mac, ip, PLC_IP, 40001, 502, flags="S")])
    asset = inv.get(ip)
    assert decision(asset) == (
        "Unknown", "LOW", "no_classifying_evidence", [],
        "possible OT client; contacted OT ports: Modbus TCP (502)",
    )
    assert asset.role == "Possible OT Client"


def test_ot_vendor_oui_alone_does_not_classify():
    ip, mac = "10.0.0.31", "00:80:f4:00:00:31"
    inv, _ = run([tcp(mac, ip, "10.0.0.99", 49152, 49153, flags="S")])
    assert decision(inv.get(ip)) == (
        "Unknown", "LOW", "no_classifying_evidence", [],
        "no services or protocol observations; vendor: Schneider Electric",
    )


def test_it_vendor_serving_validated_modbus_is_ot():
    ip, mac = "10.0.0.32", "00:00:0c:00:00:32"
    inv, _ = run([serves(mac, ip, 502, modbus_read_response())],
                 oui_db={"00000C": "Cisco Systems, Inc."})
    assert decision(inv.get(ip)) == (
        "OT", "HIGH", "serves_validated_ot_protocol", [],
        "serves validated OT protocol: Modbus TCP; vendor: Cisco Systems, Inc.",
    )


def test_same_class_lower_signals_are_supporting_detail_not_conflicts():
    # A Modbus gateway serving Modbus, listening on S7 port 102 and polling a downstream PLC
    ip, mac = "10.0.0.33", "02:00:00:00:00:33"
    inv, _ = run([
        serves(mac, ip, 502, modbus_read_response()),
        serves(mac, ip, 102, b"\x03\x00\x00\x16"),
        tcp(mac, ip, PLC_IP, 40002, 502, modbus_read_request()),
    ])
    assert decision(inv.get(ip)) == (
        "OT", "HIGH", "serves_validated_ot_protocol", [],
        "serves validated OT protocol: Modbus TCP; "
        "also: listens on OT port: S7comm / IEC 61850 MMS / ICCP (102); "
        "also: sends validated OT protocol requests: Modbus TCP",
    )


def _outputs(asset):
    return decision(asset) + (asset.role, asset.is_ot)


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 1, 0), (1, 2, 0)])
def test_classification_depends_only_on_current_state(order):
    ip, mac = "10.0.0.34", "02:00:00:00:00:34"
    packets = [
        serves(mac, ip, 22, b"SSH-2.0"),
        serves(mac, ip, 502, modbus_read_response()),
        tcp(mac, ip, PLC_IP, 40003, 502, modbus_read_request()),
    ]
    inv, _ = run([packets[i] for i in order])
    asset = inv.get(ip)
    first = _outputs(asset)
    assert first == (
        "OT", "HIGH", "serves_validated_ot_protocol",
        ["also serves IT service: SSH/SFTP (22)"],
        "serves validated OT protocol: Modbus TCP; "
        "also: sends validated OT protocol requests: Modbus TCP",
        "PLC / RTU / Modbus Gateway", True,
    )
    classify_asset(asset)
    classify_asset(asset)
    assert _outputs(asset) == first
