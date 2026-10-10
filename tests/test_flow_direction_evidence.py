"""
Zeek and Suricata records credit a responder only when the record shows it answered.

Zeek conn.log (base/protocols/conn/main.zeek):
  - TCP: the responder's port is credited for S1, SF, S2, S3, RSTO, RSTR. The originator is an
    initiator for S0, S1, SF, REJ, S2, S3, RSTO, RSTR, RSTOS0, SH. RSTRH, SHR, OTH, a missing
    conn_state, "-" or an unknown value attribute nothing.
  - UDP: a flow whose both sides sent (SF) is decided by the port heuristic; anything else
    attributes nothing.
Suricata EVE `flow` events (eve-json-format.rst): the flow source opened a TCP flow; the
destination's port is credited only when flow.pkts_toclient > 0, and not when the server's TCP
flags (tcp.tcp_flags_tc) show a RST without a SYN. A malformed pkts_toclient or tcp_flags_tc is
treated as absent and counted as a field warning; the line is kept. Alerts never credit a port or
mark an initiator: their addresses follow the packet that triggered them.
A responder that answered on a port with no signature is an asset without that port. Protocol
logs (Zeek modbus/dnp3/bacnet, Suricata modbus/dnp3/enip) keep crediting the protocol port.
"""

import json

import pytest

import scrutics.classifier.protocol as protocol
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory

ORIG, RESP = "10.0.0.10", "10.0.1.1"


@pytest.fixture(autouse=True)
def builtin_rules_only(monkeypatch):
    monkeypatch.setattr(protocol, "_USER_RULES", [])
    monkeypatch.setattr(protocol, "_BUILTIN_RULES", protocol.load_builtin_rules())


def _run(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine.start_file(str(path))
    return engine


def _zeek_conn(tmp_path, rows, with_state=True):
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"]
    if with_state:
        fields.append("conn_state")
    header = "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(fields) + "\n"
    lines = "".join("\t".join(["1700000000.0", f"C{i}"] + [str(v) for v in row]) + "\n"
                    for i, row in enumerate(rows))
    return _run(tmp_path, "conn.log", header + lines)


def _eve(tmp_path, events):
    return _run(tmp_path, "eve.json", "".join(json.dumps(e) + "\n" for e in events))


def _flow_event(proto="TCP", src_port=49175, dest_port=502, flow=None, **extra):
    event = {"timestamp": "2024-01-01T00:00:00.000000+0000", "event_type": "flow", "src_ip": ORIG,
             "src_port": src_port, "dest_ip": RESP, "dest_port": dest_port, "proto": proto}
    if flow is not None:
        event["flow"] = flow
    event.update(extra)
    return event


def _initiation(asset):
    records = [e.confidence for e in asset.evidence if e.value == "initiates_connections"]
    return records[0] if records else None


# ── Zeek conn.log, TCP ───────────────────────────────────────────────────────

ANSWERED = ["S1", "SF", "S2", "S3", "RSTO", "RSTR"]
OPENED_UNANSWERED = ["S0", "REJ", "RSTOS0", "SH"]
NO_ATTRIBUTION = ["RSTRH", "SHR", "OTH", "-", "XYZ"]


@pytest.mark.parametrize("state", ANSWERED)
def test_zeek_tcp_state_with_an_answer_credits_the_responder(tmp_path, state):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 502, "tcp", state)])
    assert engine.inventory.get(RESP).ports_seen == {502}
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == {502} and _initiation(orig) == "MEDIUM"


@pytest.mark.parametrize("state", OPENED_UNANSWERED)
def test_zeek_tcp_state_without_an_answer_credits_nothing_but_the_originator_opened(tmp_path, state):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 502, "tcp", state)])
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == {502} and _initiation(orig) == "MEDIUM"


@pytest.mark.parametrize("state", NO_ATTRIBUTION)
def test_zeek_tcp_state_without_an_observed_opening_attributes_nothing(tmp_path, state):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 502, "tcp", state)])
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == set() and orig.initiates is False


def test_zeek_conn_without_a_conn_state_column_attributes_nothing(tmp_path):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 502, "tcp")], with_state=False)
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == set() and orig.initiates is False


def test_zeek_unanswered_and_rejected_connections_create_no_assets(tmp_path):
    engine = _zeek_conn(tmp_path, [("10.0.0.66", 41000, "10.0.0.200", 502, "tcp", "S0"),
                                   ("10.0.0.66", 41001, "10.0.0.201", 102, "tcp", "REJ")])
    assert [a.ip for a in engine.inventory.get_all()] == ["10.0.0.66"]


def test_zeek_answered_on_a_port_without_signature_is_an_asset_without_the_port(tmp_path):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 65000, "tcp", "SF")])
    resp = engine.inventory.get(RESP)
    assert resp is not None and resp.ports_seen == set()
    assert resp.classification_reason


# ── Zeek conn.log, UDP ───────────────────────────────────────────────────────

def test_zeek_udp_with_both_sides_credits_the_service_side_by_port(tmp_path):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 161, "udp", "SF")])
    assert engine.inventory.get(RESP).ports_seen == {161}
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == {161} and _initiation(orig) == "LOW"


def test_zeek_udp_with_the_service_on_the_originator_credits_the_originator(tmp_path):
    # The originator answers from 53 to a client port with no signature: Zeek's originator is
    # the first sender seen, not necessarily the client
    engine = _zeek_conn(tmp_path, [(ORIG, 53, RESP, 40000, "udp", "SF")])
    orig, resp = engine.inventory.get(ORIG), engine.inventory.get(RESP)
    assert orig.ports_seen == {53} and orig.initiates is False and orig.contacted_ports == set()
    assert resp.ports_seen == set() and resp.contacted_ports == {53} and _initiation(resp) == "LOW"


def test_zeek_one_way_udp_attributes_nothing(tmp_path):
    engine = _zeek_conn(tmp_path, [(ORIG, 40000, RESP, 161, "udp", "S0")])
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.ports_seen == set() and orig.contacted_ports == set() and orig.initiates is False


def test_zeek_unusable_originator_port_is_ignored_and_reported(tmp_path):
    engine = _zeek_conn(tmp_path, [(ORIG, "abc", RESP, 502, "tcp", "SF")])
    assert engine.ingest_stats.rejected_total == 0
    assert engine.ingest_stats.warned_by_reason == {"Zeek field id.orig_p is not a port number (0-65535)": 1}
    assert engine.inventory.get(RESP).ports_seen == {502}


# ── Zeek protocol logs are unchanged ─────────────────────────────────────────

@pytest.mark.parametrize("path, port", [("modbus", 502), ("dnp3", 20000), ("bacnet", 47808)])
def test_zeek_protocol_logs_keep_crediting_the_protocol_port(tmp_path, path, port):
    text = f"#separator \\x09\n#path\t{path}\n#fields\tts\tid.orig_h\tid.resp_h\n1700000000.0\t{ORIG}\t{RESP}\n"
    engine = _run(tmp_path, f"{path}.log", text)
    assert engine.inventory.get(RESP).ports_seen == {port}
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == {port} and _initiation(orig) == "MEDIUM"


# ── Suricata flow events ─────────────────────────────────────────────────────

def test_suricata_tcp_flow_with_packets_to_the_client_credits_the_responder(tmp_path):
    engine = _eve(tmp_path, [_flow_event(flow={"pkts_toserver": 3, "pkts_toclient": 2})])
    assert engine.inventory.get(RESP).ports_seen == {502}
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == {502} and _initiation(orig) == "MEDIUM"


@pytest.mark.parametrize("flow", [{"pkts_toserver": 3, "pkts_toclient": 0}, {"pkts_toserver": 3}, None],
                         ids=["zero", "field absent", "flow object absent"])
def test_suricata_tcp_flow_without_packets_to_the_client_credits_nothing(tmp_path, flow):
    engine = _eve(tmp_path, [_flow_event(flow=flow)])
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == {502} and _initiation(orig) == "MEDIUM"
    assert engine.ingest_stats.warned_total == 0


@pytest.mark.parametrize("flow", [{"pkts_toclient": "2"}, {"pkts_toclient": True}, {"pkts_toclient": -1},
                                  {"pkts_toclient": 2.0}, {"pkts_toclient": None}, "closed"],
                         ids=["string", "bool", "negative", "float", "null", "flow not an object"])
def test_suricata_malformed_pkts_toclient_credits_nothing_and_is_reported(tmp_path, flow):
    engine = _eve(tmp_path, [_flow_event(flow=flow)])
    assert engine.ingest_stats.rejected_total == 0
    assert engine.ingest_stats.warned_by_reason == {"EVE field flow.pkts_toclient is not a non-negative integer": 1}
    assert engine.inventory.get(RESP) is None
    assert engine.inventory.get(ORIG) is not None


def test_suricata_answered_on_a_port_without_signature_is_an_asset_without_the_port(tmp_path):
    engine = _eve(tmp_path, [_flow_event(dest_port=65000, flow={"pkts_toclient": 1})])
    resp = engine.inventory.get(RESP)
    assert resp is not None and resp.ports_seen == set()


def test_suricata_udp_flow_with_a_reply_credits_the_service_side_by_port(tmp_path):
    engine = _eve(tmp_path, [_flow_event(proto="UDP", src_port=40000, dest_port=161, flow={"pkts_toclient": 1})])
    assert engine.inventory.get(RESP).ports_seen == {161}
    assert _initiation(engine.inventory.get(ORIG)) == "LOW"


def test_suricata_one_way_udp_flow_attributes_nothing(tmp_path):
    engine = _eve(tmp_path, [_flow_event(proto="UDP", src_port=40000, dest_port=161, flow={"pkts_toclient": 0})])
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == set() and orig.initiates is False


def test_suricata_unusable_source_port_is_ignored_and_reported(tmp_path):
    engine = _eve(tmp_path, [_flow_event(src_port="x", flow={"pkts_toclient": 1})])
    assert engine.ingest_stats.rejected_total == 0
    assert engine.ingest_stats.warned_by_reason == {"EVE field src_port is not a port number (0-65535)": 1}
    assert engine.inventory.get(RESP).ports_seen == {502}


# ── Suricata alerts and other events ─────────────────────────────────────────

@pytest.mark.parametrize("direction", ["to_client", "to_server", None])
def test_suricata_alert_never_credits_a_port_or_marks_an_initiator(tmp_path, direction):
    # A to_client alert's top-level source is the server (eve-json-format.rst alert example):
    # here the PLC at 10.0.1.1:502 answering a client whose port 44818 is an OT signature
    alert = {"timestamp": "2024-01-01T00:00:00.000000+0000", "event_type": "alert",
             "src_ip": RESP, "src_port": 502, "dest_ip": ORIG, "dest_port": 44818, "proto": "TCP",
             "alert": {"signature": "test", "category": "x", "severity": 2},
             "flow": {"pkts_toserver": 5, "pkts_toclient": 5, "src_ip": ORIG, "dest_ip": RESP}}
    if direction:
        alert["direction"] = direction
    engine = _eve(tmp_path, [alert])
    for ip in (ORIG, RESP):
        asset = engine.inventory.get(ip)
        if asset is not None:
            assert asset.ports_seen == set() and asset.contacted_ports == set() and asset.initiates is False
    assert [a["type"] for a in engine.baseline.anomaly_log] == ["SURICATA_ALERT"]


@pytest.mark.parametrize("etype", ["dns", "http", "tls", "netflow", "anomaly"])
def test_suricata_other_events_attribute_nothing(tmp_path, etype):
    engine = _eve(tmp_path, [_flow_event(event_type=etype, flow={"pkts_toclient": 3})])
    assert engine.inventory.get(RESP) is None
    orig = engine.inventory.get(ORIG)
    assert orig.contacted_ports == set() and orig.initiates is False


@pytest.mark.parametrize("etype, port", [("modbus", 502), ("dnp3", 20000), ("enip", 44818)])
def test_suricata_protocol_events_keep_crediting_the_protocol_port(tmp_path, etype, port):
    engine = _eve(tmp_path, [_flow_event(event_type=etype, dest_port=port)])
    assert engine.inventory.get(RESP).ports_seen == {port}
    assert _initiation(engine.inventory.get(ORIG)) == "MEDIUM"


# ── Suricata server TCP flags (tcp.tcp_flags_tc: hex OR of the flags the server sent) ──

def test_suricata_tcp_flow_answered_only_by_a_rst_credits_nothing(tmp_path):
    # RST+ACK (0x14) and no SYN: the attempt was rejected
    engine = _eve(tmp_path, [_flow_event(flow={"pkts_toclient": 1}, tcp={"tcp_flags_tc": "14"})])
    assert engine.inventory.get(RESP) is None
    assert _initiation(engine.inventory.get(ORIG)) == "MEDIUM"


def test_suricata_tcp_session_closed_by_a_server_rst_credits_the_responder(tmp_path):
    # SYN+ACK, data and a RST at the end of the session (0x1e)
    engine = _eve(tmp_path, [_flow_event(flow={"pkts_toclient": 9}, tcp={"tcp_flags_tc": "1e"})])
    assert engine.inventory.get(RESP).ports_seen == {502}


def test_suricata_tcp_flags_absent_falls_back_to_packets_to_the_client(tmp_path):
    engine = _eve(tmp_path, [_flow_event(flow={"pkts_toclient": 1}, tcp={"tcp_flags_ts": "02"})])
    assert engine.inventory.get(RESP).ports_seen == {502}
    assert engine.ingest_stats.warned_total == 0


@pytest.mark.parametrize("tcp", [{"tcp_flags_tc": "zz"}, {"tcp_flags_tc": 20}, {"tcp_flags_tc": "100"},
                                 {"tcp_flags_tc": None}, "closed"],
                         ids=["not hex", "integer", "three digits", "null", "tcp not an object"])
def test_suricata_malformed_tcp_flags_are_ignored_and_reported(tmp_path, tcp):
    engine = _eve(tmp_path, [_flow_event(flow={"pkts_toclient": 1}, tcp=tcp)])
    assert engine.ingest_stats.rejected_total == 0
    assert engine.ingest_stats.warned_by_reason == {"EVE field tcp.tcp_flags_tc is not a TCP flags hex string": 1}
    # Ignored: the packets-to-client rule decides
    assert engine.inventory.get(RESP).ports_seen == {502}
