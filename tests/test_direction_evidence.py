"""
Which side of a packet offers the service is decided from the packet's own evidence.

A packet credits at most its sender's port and never creates its receiver. Evidence is ranked
and a weaker kind never overrides a stronger one:
  1. payload: a Modbus exception response, which only a server sends;
  2. connection: TCP SYN (the sender opens), SYN+ACK (the sender serves), RST (nothing);
  3. ports: a Modbus direction derived from port 502, then the signature table, with the lower
     port taken as the service when both are services;
  4. nothing.
Payload and connection evidence that contradict each other attribute nothing and are counted as
a field warning. Initiation evidence is MEDIUM from a SYN or a validated request and LOW from the
port heuristic; an asset keeps one record, raised from LOW to MEDIUM and never lowered.
"""

import struct

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

import scrutics.classifier.protocol as protocol
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.protocol_display import protocol_display_entries


@pytest.fixture(autouse=True)
def builtin_rules_only(monkeypatch):
    monkeypatch.setattr(protocol, "_USER_RULES", [])
    monkeypatch.setattr(protocol, "_BUILTIN_RULES", protocol.load_builtin_rules())


def _engine():
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    return engine


def _tcp(mac, src, dst, sport, dport, flags="PA", payload=b""):
    pkt = Ether(src=mac, dst="02:00:00:00:00:fe") / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return pkt / Raw(load=payload) if payload else pkt


def _udp(mac, src, dst, sport, dport, payload=b"\x00" * 8):
    return Ether(src=mac, dst="02:00:00:00:00:fe") / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def _adu(pdu, trans_id=1, unit_id=1):
    # Modbus TCP MBAP header: transaction ID, protocol ID 0, length (unit ID + PDU), unit ID
    return struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, unit_id) + pdu


READ_REQUEST = _adu(struct.pack(">BHH", 0x03, 0x0000, 2))           # FC 03, address 0, 2 registers
READ_RESPONSE = _adu(struct.pack(">BBHH", 0x03, 4, 0x0001, 0x0002))  # FC 03, 4 bytes
EXCEPTION_RESPONSE = _adu(struct.pack(">BB", 0x83, 0x02))           # FC 03 exception, illegal address


def _feed(engine, *packets):
    for pkt in packets:
        engine._ingest_packet(pkt, "pcap")


def _ports(engine, ip):
    asset = engine.inventory.get(ip)
    return set(asset.ports_seen) if asset else None


def _initiation(asset):
    records = [e for e in asset.evidence if e.type == "behavior" and e.value == "initiates_connections"]
    assert len(records) <= 1
    return records[0].confidence if records else None


WS, DNS, PLC, HMI = "10.0.0.10", "10.0.0.53", "10.0.0.20", "10.0.0.30"
WS_MAC, DNS_MAC, PLC_MAC, HMI_MAC = "02:00:00:00:00:10", "02:00:00:00:00:53", "02:00:00:00:00:20", "02:00:00:00:00:30"


# ── Client ports that equal a service port ───────────────────────────────────

def test_ethernet_ip_client_port_over_udp_is_resolved_only_by_the_lower_port():
    # 44818 is an EtherNet/IP signature on TCP and UDP and a Linux ephemeral port. Transport
    # alone cannot reject it; the DNS port 53 is lower, so 53 is the service in both datagrams.
    engine = _engine()
    _feed(engine, _udp(WS_MAC, WS, DNS, 44818, 53), _udp(DNS_MAC, DNS, WS, 53, 44818))
    assert _ports(engine, WS) == set()
    assert engine.inventory.get(WS).classification_type != "OT"
    assert _ports(engine, DNS) == {53}
    assert engine.inventory.get(DNS).contacted_ports == set()
    assert not any("EtherNet/IP" in e for e in protocol_display_entries(engine.inventory.get(DNS)))


def test_ethernet_ip_client_port_over_tcp_is_resolved_by_the_lower_port():
    engine = _engine()
    _feed(engine, _tcp(WS_MAC, WS, DNS, 44818, 443), _tcp(DNS_MAC, DNS, WS, 443, 44818))
    assert _ports(engine, WS) == set()
    assert _ports(engine, DNS) == {443}
    assert engine.inventory.get(WS).contacted_ports == {443}
    assert engine.inventory.get(DNS).contacted_ports == set()


def test_plc_reply_to_an_ot_numbered_ephemeral_port_is_not_shown_as_a_client_protocol():
    # The HMI's ephemeral port 2222 is an EtherNet/IP IO signature; the PLC's 502 is lower
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 2222, 502, payload=READ_REQUEST),
          _tcp(PLC_MAC, PLC, HMI, 502, 2222, payload=READ_RESPONSE))
    plc = engine.inventory.get(PLC)
    assert plc.contacted_ports == set()
    assert not any("EtherNet/IP" in e for e in protocol_display_entries(plc))
    assert _ports(engine, HMI) == set()


# ── Replies and initiation ───────────────────────────────────────────────────

def test_modbus_replies_never_make_the_plc_an_initiator():
    engine = _engine()
    for i in range(3):
        _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502, payload=READ_REQUEST),
              _tcp(PLC_MAC, PLC, HMI, 502, 40000, payload=READ_RESPONSE))
    plc, hmi = engine.inventory.get(PLC), engine.inventory.get(HMI)
    assert plc.initiates is False
    assert _initiation(plc) is None
    assert hmi.initiates is True
    assert _initiation(hmi) == "MEDIUM"


def test_replies_without_payload_never_make_the_sender_an_initiator():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502), _tcp(PLC_MAC, PLC, HMI, 502, 40000))
    assert engine.inventory.get(PLC).initiates is False
    assert _initiation(engine.inventory.get(HMI)) == "LOW"


def test_initiation_is_one_record_raised_to_medium_and_never_lowered():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502))                  # port heuristic: LOW
    hmi = engine.inventory.get(HMI)
    assert _initiation(hmi) == "LOW"
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40001, 502, flags="S"))       # SYN: MEDIUM
    assert _initiation(hmi) == "MEDIUM"
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40001, 502))                  # LOW again: kept MEDIUM
    assert _initiation(hmi) == "MEDIUM"
    # One record, so its weight is counted once
    assert [e.weight for e in hmi.evidence if e.value == "initiates_connections"] == [5]


def test_never_initiates_alert_states_low_initiation_evidence(monkeypatch):
    monkeypatch.setattr(protocol, "_USER_RULES", [{"name": "quiet", "mac_prefix": HMI_MAC, "classify_as": "X",
                                                   "role": "X", "is_ot": True, "never_initiates": True}])
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502))
    alerts = [a["detail"] for a in engine.baseline.anomaly_log if "NEVER_INITIATES" in a["detail"]]
    assert alerts and "LOW" in alerts[0]


# ── TCP connection evidence ──────────────────────────────────────────────────

def test_syn_only_scan_creates_no_receiver_asset():
    engine = _engine()
    _feed(engine, *[_tcp("02:00:00:00:00:66", "10.0.0.66", f"10.0.0.{100 + i}", 41000 + i, port, flags="S")
                    for i, port in enumerate([502, 102, 44818, 20000, 2404])])
    assert [a.ip for a in engine.inventory.get_all()] == ["10.0.0.66"]
    scanner = engine.inventory.get("10.0.0.66")
    assert scanner.contacted_ports == {502, 102, 44818, 20000, 2404}
    assert _initiation(scanner) == "MEDIUM"
    assert scanner.ports_seen == set()


def test_syn_ack_credits_the_sender_only():
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 502, 40000, flags="SA"))
    assert _ports(engine, PLC) == {502}
    assert engine.inventory.get(PLC).initiates is False
    assert engine.inventory.get(PLC).contacted_ports == set()
    assert engine.inventory.get(HMI) is None


@pytest.mark.parametrize("flags", ["R", "RA", "SR"])
def test_rst_credits_nothing(flags):
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 502, 40000, flags=flags))
    plc = engine.inventory.get(PLC)
    assert plc.ports_seen == set() and plc.contacted_ports == set() and plc.initiates is False


# ── A weaker kind of evidence never overrides a stronger one ─────────────────

def test_syn_ack_beats_the_lower_port():
    # ROC Plus 4000 answers a client whose port is 2404 (IEC 104): the lower port would pick 2404
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 4000, 2404, flags="SA"))
    assert _ports(engine, PLC) == {4000}
    assert engine.inventory.get(PLC).initiates is False


def test_syn_beats_the_lower_port():
    # A client opening from port 102 to 502: the lower port would credit 102 to the client
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 102, 502, flags="S"))
    hmi = engine.inventory.get(HMI)
    assert hmi.ports_seen == set()
    assert hmi.contacted_ports == {502}
    assert _initiation(hmi) == "MEDIUM"


def test_syn_ack_beats_a_modbus_direction_derived_from_the_port():
    # A valid Modbus request on a SYN+ACK sent to port 502: the handshake says the sender serves
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502, flags="SA", payload=READ_REQUEST))
    hmi = engine.inventory.get(HMI)
    assert hmi.initiates is False
    assert hmi.contacted_ports == set()


def test_exception_response_beats_the_lower_port():
    # The client's port 102 is lower than 502, but only a server sends an exception response
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 502, 102, payload=EXCEPTION_RESPONSE))
    plc = engine.inventory.get(PLC)
    assert plc.ports_seen == {502}
    assert plc.contacted_ports == set() and plc.initiates is False


def test_validated_request_beats_the_lower_port():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 102, 502, payload=READ_REQUEST))
    hmi = engine.inventory.get(HMI)
    assert hmi.ports_seen == set()
    assert hmi.contacted_ports == {502}
    assert _initiation(hmi) == "MEDIUM"


def test_exception_response_with_syn_ack_credits_the_sender():
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 502, 40000, flags="SA", payload=EXCEPTION_RESPONSE))
    assert _ports(engine, PLC) == {502}
    assert engine.ingest_stats.warned_total == 0


@pytest.mark.parametrize("flags", ["S", "R"])
def test_payload_and_connection_conflict_attributes_nothing_and_is_counted(flags):
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 502, 40000, flags=flags, payload=EXCEPTION_RESPONSE))
    plc = engine.inventory.get(PLC)
    assert plc.ports_seen == set() and plc.contacted_ports == set() and plc.initiates is False
    assert engine.ingest_stats.warned_total == 1
    assert engine.ingest_stats.has_issues()
    assert "1 field warnings" in engine.ingest_stats.summary_line()


# ── Ports ────────────────────────────────────────────────────────────────────

def test_midstream_modbus_session_keeps_the_plc_and_the_hmi():
    # No handshake in the capture: each side is decided from its own packets
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502, payload=READ_REQUEST),
          _tcp(PLC_MAC, PLC, HMI, 502, 40000, payload=READ_RESPONSE))
    plc, hmi = engine.inventory.get(PLC), engine.inventory.get(HMI)
    assert plc.ports_seen == {502} and plc.classification_type == "OT"
    assert hmi.ports_seen == set() and hmi.contacted_ports == {502}
    assert hmi.classification_type == "OT" and hmi.role == "OT client"


def test_midstream_session_without_payload_credits_the_service_side():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502), _tcp(PLC_MAC, PLC, HMI, 502, 40000))
    assert _ports(engine, PLC) == {502}
    assert engine.inventory.get(PLC).contacted_ports == set()
    assert _ports(engine, HMI) == set()
    assert engine.inventory.get(HMI).contacted_ports == {502}


def test_equal_tcp_ports_credit_each_peer_from_its_own_packets():
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 20000, 20000))
    assert _ports(engine, PLC) == {20000}
    assert engine.inventory.get(HMI) is None
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 20000, 20000))
    assert _ports(engine, HMI) == {20000}


def test_modbus_between_two_502_ports_uses_the_equal_port_rule():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 502, 502, payload=READ_REQUEST))
    hmi = engine.inventory.get(HMI)
    assert hmi.ports_seen == {502}
    assert hmi.initiates is False and hmi.contacted_ports == set()


def test_one_way_udp_receiver_is_not_credited_or_created():
    engine = _engine()
    _feed(engine, _udp(WS_MAC, WS, "10.0.0.5", 40000, 514))     # syslog to a silent collector
    assert engine.inventory.get("10.0.0.5") is None
    assert engine.inventory.get(WS).contacted_ports == {514}


def test_udp_request_and_response_credit_the_responder_from_its_own_datagram():
    engine = _engine()
    _feed(engine, _udp(WS_MAC, WS, "10.0.0.5", 40000, 161, b"\x30\x26"),
          _udp("02:00:00:00:00:05", "10.0.0.5", WS, 161, 40000, b"\x30\x26"))
    assert _ports(engine, "10.0.0.5") == {161}
    assert _ports(engine, WS) == set()
    assert engine.inventory.get(WS).contacted_ports == {161}
    assert engine.inventory.get("10.0.0.5").contacted_ports == set()


def test_ports_without_signatures_record_nothing():
    engine = _engine()
    _feed(engine, _tcp(WS_MAC, WS, DNS, 40000, 55556))
    ws = engine.inventory.get(WS)
    assert ws.ports_seen == set() and ws.contacted_ports == set() and ws.initiates is False


def test_receiver_with_its_own_evidence_keeps_its_asset_without_the_probed_port():
    engine = _engine()
    mdns = _udp(PLC_MAC, PLC, "224.0.0.251", 5353, 5353, b"\x00" * 12)
    _feed(engine, mdns, _tcp("02:00:00:00:00:66", "10.0.0.66", PLC, 41000, 502, flags="S"))
    plc = engine.inventory.get(PLC)
    assert plc is not None
    assert plc.ports_seen == set()


# ── Protocol observations take the decided direction ─────────────────────────

def _modbus_summary(engine, ip):
    return engine.inventory.get(ip).protocol_summaries["Modbus TCP"]


def test_modbus_observation_follows_the_handshake_over_the_port_direction():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502, flags="SA", payload=READ_REQUEST))
    summary = _modbus_summary(engine, HMI)
    assert summary.answers_as_server is True and summary.sends_requests is False
    # Parsed facts are kept as the parser produced them
    assert summary.function_codes == {0x03: 1} and summary.observation_count == 1


def test_modbus_observation_between_two_502_ports_has_no_direction():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 502, 502, payload=READ_REQUEST))
    summary = _modbus_summary(engine, HMI)
    assert summary.sends_requests is False and summary.answers_as_server is False
    assert summary.observation_count == 1
    assert engine.inventory.get(HMI).role != "OT client"


def test_modbus_observation_in_a_rst_has_no_direction():
    engine = _engine()
    _feed(engine, _tcp(PLC_MAC, PLC, HMI, 502, 40000, flags="RA", payload=READ_RESPONSE))
    summary = _modbus_summary(engine, PLC)
    assert summary.sends_requests is False and summary.answers_as_server is False
    detail = [e.detail for e in engine.inventory.get(PLC).evidence if e.source == "modbus_parser"][0]
    assert "direction=unresolved" in detail


def test_modbus_observation_direction_agrees_with_the_port_when_nothing_overrides_it():
    engine = _engine()
    _feed(engine, _tcp(HMI_MAC, HMI, PLC, 40000, 502, payload=READ_REQUEST),
          _tcp(PLC_MAC, PLC, HMI, 502, 40000, payload=READ_RESPONSE))
    assert _modbus_summary(engine, HMI).sends_requests is True
    assert _modbus_summary(engine, PLC).answers_as_server is True
