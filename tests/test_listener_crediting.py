"""
A listening port means the device offers that service.

A port is credited only on its signature's transport ("TCP/UDP" signatures on both). A rule
port takes the rule's protocol, or without one the transport of the port's signature, or both
transports when the port has no signature. Packets whose source and destination ports are
equal credit no listener unless the port's signature votes OT or IT; then both endpoints are
credited. The DHCP client port 68 is never credited.
"""

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import scrutics.classifier.protocol as protocol
from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine


def _engine():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    return inv, engine


def _udp(src_mac, src_ip, dst_ip, sport, dport, payload=b"\x00" * 8):
    return (
        Ether(src=src_mac, dst="02:00:00:00:00:ff")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(load=payload)
    )


def _ports(inv, ip):
    asset = inv.get(ip)
    return set(asset.ports_seen) if asset else None


def test_ntp_symmetric_exchange_credits_no_listener():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:46", "10.0.0.46", "10.0.0.47", 123, 123))
    engine._process_packet(_udp("02:00:00:00:00:47", "10.0.0.47", "10.0.0.46", 123, 123))
    assert _ports(inv, "10.0.0.46") == set()
    assert _ports(inv, "10.0.0.47") == set()


def test_ntp_server_reply_to_ephemeral_port_credits_the_server():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:48", "10.0.0.48", "10.0.0.5", 123, 50000))
    assert _ports(inv, "10.0.0.48") == {123}


def test_dhcp_client_port_68_is_never_credited():
    inv, engine = _engine()
    # Client renewing to the server, then the server replying to the client
    engine._process_packet(_udp("02:00:00:00:00:49", "10.0.0.49", "10.0.0.1", 68, 67, b"\x01" + b"\x00" * 239))
    engine._process_packet(_udp("02:00:00:00:00:01", "10.0.0.1", "10.0.0.49", 67, 68, b"\x02" + b"\x00" * 239))
    assert 68 not in _ports(inv, "10.0.0.49")
    assert 68 not in _ports(inv, "10.0.0.1")
    assert _ports(inv, "10.0.0.1") == {67}


def test_bacnet_symmetric_exchange_credits_both_endpoints():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:52", "10.0.0.52", "10.0.0.53", 47808, 47808, b"\x81\x0b\x00\x0c"))
    engine._process_packet(_udp("02:00:00:00:00:53", "10.0.0.53", "10.0.0.52", 47808, 47808, b"\x81\x0a\x00\x0c"))
    assert _ports(inv, "10.0.0.52") == {47808}
    assert _ports(inv, "10.0.0.53") == {47808}


def test_mdns_symmetric_announcement_credits_no_listener():
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:54", "10.0.0.54", "224.0.0.251", 5353, 5353, b"\x00" * 12))
    assert _ports(inv, "10.0.0.54") == set()


def _tcp(src_mac, src_ip, dst_ip, sport, dport, flags="PA", payload=b"\x00" * 8):
    return (
        Ether(src=src_mac, dst="02:00:00:00:00:ff")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags)
        / Raw(load=payload)
    )


@pytest.fixture
def rules(monkeypatch):
    def use(user_rules, builtin_rules=()):
        monkeypatch.setattr(protocol, "_USER_RULES", list(user_rules))
        monkeypatch.setattr(protocol, "_BUILTIN_RULES", list(builtin_rules))
    return use


def test_tcp_only_signature_is_not_credited_from_udp(rules):
    # IEC 60870-5-104 (2404) is TCP only; a Windows client may use 2404 as a UDP source port
    rules([], protocol.load_builtin_rules())
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:60", "10.0.0.60", "10.0.0.53", 2404, 53))
    engine._process_packet(_udp("02:00:00:00:00:61", "10.0.0.53", "10.0.0.60", 53, 2404))
    assert _ports(inv, "10.0.0.60") == set()
    assert _ports(inv, "10.0.0.53") == {53}


def test_udp_only_signature_is_not_credited_from_tcp(rules):
    # BACnet/IP (47808) is UDP only; 47808 is also a Linux ephemeral TCP port
    rules([], protocol.load_builtin_rules())
    inv, engine = _engine()
    engine._process_packet(_tcp("02:00:00:00:00:62", "10.0.0.62", "10.0.0.63", 47808, 443))
    engine._process_packet(_tcp("02:00:00:00:00:63", "10.0.0.63", "10.0.0.62", 443, 47808))
    assert _ports(inv, "10.0.0.62") == set()
    assert _ports(inv, "10.0.0.63") == {443}


def test_dual_transport_signature_is_credited_on_both_transports(rules):
    rules([])
    inv, engine = _engine()
    engine._process_packet(_tcp("02:00:00:00:00:64", "10.0.0.64", "10.0.0.5", 44818, 50000, flags="SA"))
    engine._process_packet(_udp("02:00:00:00:00:65", "10.0.0.65", "10.0.0.5", 44818, 50001))
    assert _ports(inv, "10.0.0.64") == {44818}
    assert _ports(inv, "10.0.0.65") == {44818}


def test_rule_port_without_protocol_takes_the_signature_transport(rules):
    rules([{"name": "IEC 104", "port": 2404, "classify_as": "IEC 104", "is_ot": True}])
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:66", "10.0.0.66", "10.0.0.5", 2404, 50000))
    engine._process_packet(_tcp("02:00:00:00:00:67", "10.0.0.67", "10.0.0.5", 2404, 50000, flags="SA"))
    assert _ports(inv, "10.0.0.66") == set()
    assert _ports(inv, "10.0.0.67") == {2404}


def test_rule_port_protocol_overrides_the_signature_transport(rules):
    rules([{"name": "IEC 104 over UDP", "port": 2404, "protocol": "UDP",
            "classify_as": "IEC 104", "is_ot": True}])
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:68", "10.0.0.68", "10.0.0.5", 2404, 50000))
    assert _ports(inv, "10.0.0.68") == {2404}


def test_rule_port_without_signature_or_protocol_is_credited_on_both_transports(rules):
    rules([{"name": "Lab service", "port": 9999, "classify_as": "Lab", "is_ot": True}])
    inv, engine = _engine()
    engine._process_packet(_tcp("02:00:00:00:00:69", "10.0.0.69", "10.0.0.5", 9999, 50000, flags="SA"))
    engine._process_packet(_udp("02:00:00:00:00:6a", "10.0.0.70", "10.0.0.5", 9999, 50001))
    assert _ports(inv, "10.0.0.69") == {9999}
    assert _ports(inv, "10.0.0.70") == {9999}


def test_rule_port_with_protocol_is_not_credited_on_the_other_transport(rules):
    rules([{"name": "Lab service", "port": 9999, "protocol": "TCP", "classify_as": "Lab", "is_ot": True}])
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:6b", "10.0.0.71", "10.0.0.5", 9999, 50000))
    assert _ports(inv, "10.0.0.71") == set()


ZEEK_CONN_HEADER = ("#separator \\x09\n#path\tconn\n"
                    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n")


def _zeek_conn(tmp_path, lines):
    path = tmp_path / "conn.log"
    path.write_text(ZEEK_CONN_HEADER + "".join(lines), encoding="utf-8")
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine.start_file(str(path))
    return engine


def _responder_ports(engine, ip):
    asset = engine.inventory.get(ip)
    return set(asset.ports_seen) if asset else set()


def test_flow_record_port_without_signature_is_not_credited(tmp_path, rules):
    rules([])
    engine = _zeek_conn(tmp_path, ["1700000000.0\tC1\t10.0.0.10\t40000\t10.0.1.1\t65000\ttcp\tSF\n"])
    assert _responder_ports(engine, "10.0.1.1") == set()


def test_flow_record_credits_only_on_the_signature_transport(tmp_path, rules):
    rules([])
    engine = _zeek_conn(tmp_path, [
        "1700000000.0\tC1\t10.0.0.10\t40000\t10.0.1.1\t502\tudp\tSF\n",
        "1700000001.0\tC2\t10.0.0.11\t40001\t10.0.1.2\t502\ttcp\tSF\n",
        "1700000002.0\tC3\t10.0.0.12\t0\t10.0.1.3\t502\ticmp\tOTH\n",
    ])
    assert _responder_ports(engine, "10.0.1.1") == set()
    assert _responder_ports(engine, "10.0.1.2") == {502}
    assert _responder_ports(engine, "10.0.1.3") == set()


# ── A rule change is seen by the next packet ─────────────────────────────────

def test_swapping_the_user_rules_changes_creditability_immediately(rules):
    rules([{"name": "Lab", "port": 9999, "protocol": "UDP", "classify_as": "Lab", "is_ot": True}])
    assert protocol.port_matches_transport(9999, "UDP") and not protocol.port_matches_transport(9999, "TCP")
    rules([{"name": "Lab", "port": 9999, "protocol": "TCP", "classify_as": "Lab", "is_ot": True}])
    assert protocol.port_matches_transport(9999, "TCP") and not protocol.port_matches_transport(9999, "UDP")
    rules([])
    assert not protocol.port_matches_transport(9999, "TCP")


def test_swapping_the_builtin_rules_changes_creditability_immediately(rules):
    rules([], [{"name": "Lab", "port": 9998, "classify_as": "Lab", "is_ot": True}])
    assert protocol.port_matches_transport(9998, "UDP")
    rules([], [])
    assert not protocol.port_matches_transport(9998, "UDP")


def test_a_rule_swap_between_packets_changes_what_the_next_packet_credits(rules):
    rules([{"name": "Lab", "port": 9999, "classify_as": "Lab", "is_ot": True}])
    inv, engine = _engine()
    engine._process_packet(_udp("02:00:00:00:00:6c", "10.0.0.72", "10.0.0.5", 9999, 50000))
    assert _ports(inv, "10.0.0.72") == {9999}
    rules([])
    engine._process_packet(_udp("02:00:00:00:00:6d", "10.0.0.73", "10.0.0.5", 9999, 50000))
    assert _ports(inv, "10.0.0.73") == set()


def test_reloading_rules_from_the_config_file_changes_creditability(tmp_path, monkeypatch):
    import scrutics.config.loader as loader
    path = tmp_path / "scrutics.yaml"
    monkeypatch.setattr(loader, "_USER_SEARCH_PATHS", [str(path)])
    try:
        path.write_text('rules:\n  - name: "Lab"\n    port: 9997\n    protocol: udp\n'
                        '    classify_as: "Lab"\n    role: "Lab device"\n    is_ot: true\n')
        protocol.reload_rules()
        assert protocol.port_matches_transport(9997, "UDP")
        path.write_text("rules: []\n")
        protocol.reload_rules()
        assert not protocol.port_matches_transport(9997, "UDP")
    finally:
        monkeypatch.undo()
        protocol.reload_rules()
