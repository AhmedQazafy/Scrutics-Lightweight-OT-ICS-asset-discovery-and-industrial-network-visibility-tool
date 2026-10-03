"""
Malformed input is rejected or skipped at its source, never raised out of processing.

Each case feeds a known malformed packet or log line between valid ones through every ingestion
path it can arrive on, and checks that the run completes, the valid items are processed, the
malformed one is counted as rejected where it is dropped by validation, and no unexpected error
had to be contained.
"""

import json
import struct

import pytest
import scapy.all
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap, wrpcapng

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory, is_inventory_ip
from scrutics.parsers.zeek import ZeekFormatError

GOOD_A, GOOD_B = "10.0.0.1", "10.0.0.2"
MDNS_HOST = "10.0.0.9"

# Malformed inputs
ARP_NON_IPV4_FRAME = bytes.fromhex(
    "ffffffffffff02000000000c080600011234060400010000000000000a0000050000000000000a000001")
MDNS_QUERY_NON_UTF8 = bytes.fromhex("00000100000100000000000001ff056c6f63616c0000010001")
MDNS_QUESTION_NOT_A_RECORD = bytes.fromhex("00000000000100000000000031dc")


def _dns_query(*names):
    # DNS header (RFC 1035 section 4.1.1) with one question per name, QTYPE A, QCLASS IN
    body = b""
    for name in names:
        for label in name.split(b"."):
            if label:
                body += bytes([len(label)]) + label
        body += b"\x00" + struct.pack(">HH", 1, 1)
    return struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0) + body


def _good(ip, i, t=1_700_000_000.0):
    p = Ether(src="02:00:00:00:00:%02x" % i, dst="02:ff:ff:ff:ff:fe") / IP(src=ip, dst="10.0.0.200") / TCP(sport=40000, dport=502)
    p.time = t + i
    return p


def _mdns(payload, t=1_700_000_000.5):
    p = Ether(src="02:00:00:00:00:09", dst="01:00:5e:00:00:fb") / IP(src=MDNS_HOST, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / Raw(payload)
    p.time = t
    return p


def _frame(raw, t=1_700_000_000.5):
    p = Ether(raw)
    p.time = t
    return p


def _engine():
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    return engine


def _run_packets(path, packets, tmp_path, monkeypatch):
    engine = _engine()
    if path == "live":
        def fake_sniff(prn=None, **kwargs):
            # Deliver each packet dissected from its bytes, as a capture socket does
            for p in packets:
                captured = Ether(bytes(p))
                captured.time = p.time
                prn(captured)
            engine.request_stop()
        monkeypatch.setattr(scapy.all, "sniff", fake_sniff)
        engine.start_live(interface="test0", timeout=5)
    elif path == "pcap":
        f = tmp_path / "capture.pcap"
        wrpcap(str(f), packets)
        engine.start_file(str(f))
    else:
        f = tmp_path / "capture.pcapng"
        wrpcapng(str(f), packets)
        engine.start_file(str(f))
    return engine


def _assert_clean(engine, rejected=0):
    assert engine.inventory.get(GOOD_A) is not None
    assert engine.inventory.get(GOOD_B) is not None
    assert engine.ingest_stats.contained_total == 0, engine.ingest_stats.summary_line()
    assert engine.ingest_stats.rejected_total == rejected, engine.ingest_stats.summary_line()


PACKET_PATHS = ["live", "pcap", "pcapng"]


@pytest.mark.parametrize("path", PACKET_PATHS)
def test_arp_with_non_ipv4_address_is_not_an_asset(path, tmp_path, monkeypatch):
    engine = _run_packets(path, [_good(GOOD_A, 1), _frame(ARP_NON_IPV4_FRAME), _good(GOOD_B, 2)],
                          tmp_path, monkeypatch)
    _assert_clean(engine)
    assert engine.inventory.count() == 3   # the two senders and their common destination


def test_non_string_addresses_are_not_inventory_ips():
    assert is_inventory_ip(b"\x0a\x00\x00\x05") is False
    assert is_inventory_ip(167772161) is False
    assert is_inventory_ip(True) is False
    assert is_inventory_ip("10.0.0.5") is True


@pytest.mark.parametrize("path", PACKET_PATHS)
def test_mdns_query_name_not_utf8_is_skipped(path, tmp_path, monkeypatch):
    packets = [_good(GOOD_A, 1), _good(MDNS_HOST, 9), _mdns(MDNS_QUERY_NON_UTF8), _good(GOOD_B, 2)]
    engine = _run_packets(path, packets, tmp_path, monkeypatch)
    _assert_clean(engine)
    assert not [e for e in engine.inventory.get(MDNS_HOST).evidence if e.type == "discovery"]


@pytest.mark.parametrize("path", PACKET_PATHS)
def test_mdns_query_keeps_the_valid_question_after_an_invalid_name(path, tmp_path, monkeypatch):
    payload = _dns_query(b"\xff.local", b"printer.local")
    packets = [_good(GOOD_A, 1), _good(MDNS_HOST, 9), _mdns(payload), _good(GOOD_B, 2)]
    engine = _run_packets(path, packets, tmp_path, monkeypatch)
    _assert_clean(engine)
    discovery = [e.value for e in engine.inventory.get(MDNS_HOST).evidence if e.type == "discovery"]
    assert discovery == ["printer.local."]


@pytest.mark.parametrize("path", PACKET_PATHS)
def test_mdns_question_that_is_not_a_record_is_skipped(path, tmp_path, monkeypatch):
    packets = [_good(GOOD_A, 1), _good(MDNS_HOST, 9), _mdns(MDNS_QUESTION_NOT_A_RECORD), _good(GOOD_B, 2)]
    engine = _run_packets(path, packets, tmp_path, monkeypatch)
    _assert_clean(engine)
    assert not [e for e in engine.inventory.get(MDNS_HOST).evidence if e.type == "discovery"]


@pytest.mark.parametrize("path", ["live", "pcapng"])
def test_packet_timestamp_out_of_range_is_rejected(path, tmp_path, monkeypatch):
    bad = _good("10.0.0.77", 7)
    bad.time = 1e12   # year 33658
    engine = _run_packets(path, [_good(GOOD_A, 1), bad, _good(GOOD_B, 2)], tmp_path, monkeypatch)
    _assert_clean(engine, rejected=1)
    assert engine.ingest_stats.rejected_by_reason == {"timestamp out of range": 1}
    assert engine.inventory.get("10.0.0.77") is None


ZEEK_HEADER = ("#separator \\x09\n#path\tconn\n"
               "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n")


def _zeek_line(ts, ip):
    return f"{ts}\tC1\t{ip}\t40000\t10.0.0.200\t502\ttcp\n"


def _run_file(tmp_path, name, text):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    engine = _engine()
    engine.start_file(str(f))
    return engine


def test_zeek_timestamps_out_of_range_are_rejected(tmp_path):
    bad = "".join(_zeek_line(ts, f"10.0.0.{70 + i}") for i, ts in enumerate(["nan", "inf", "1e20", "-1e15"]))
    engine = _run_file(tmp_path, "conn.log",
                       ZEEK_HEADER + _zeek_line("1700000000.1", GOOD_A) + bad + _zeek_line("1700000000.2", GOOD_B))
    _assert_clean(engine, rejected=4)
    assert engine.ingest_stats.rejected_by_reason == {"timestamp out of range": 4}


def test_zeek_empty_separator_is_a_clear_file_error(tmp_path):
    engine = _engine()
    f = tmp_path / "conn.log"
    f.write_text("#separator \n#path\tconn\n#fields\tts\tid.orig_h\n1700000000.1\t10.0.0.1\n")
    with pytest.raises(ZeekFormatError, match=r"line 1: #separator is empty"):
        engine.start_file(str(f))
    assert engine.ingest_stats.contained_total == 0


def test_zeek_data_without_fields_header_is_a_clear_file_error(tmp_path):
    engine = _engine()
    f = tmp_path / "conn.log"
    f.write_text("#separator \\x09\n#path\tconn\n1700000000.1\t10.0.0.1\t10.0.0.2\n")
    with pytest.raises(ZeekFormatError, match=r"no #fields header"):
        engine.start_file(str(f))
    assert engine.ingest_stats.contained_total == 0


def _eve(*events):
    good_a = {"timestamp": "2024-01-01T00:00:00.000000+0000", "event_type": "flow",
              "src_ip": GOOD_A, "dest_ip": "10.0.0.200", "dest_port": 502, "proto": "TCP"}
    good_b = dict(good_a, src_ip=GOOD_B)
    lines = [json.dumps(good_a)] + [e if isinstance(e, str) else json.dumps(e) for e in events] + [json.dumps(good_b)]
    return "\n".join(lines) + "\n"


def _ev(**fields):
    e = {"timestamp": "2024-01-01T00:00:00.000000+0000", "event_type": "flow",
         "src_ip": "10.0.0.70", "dest_ip": "10.0.0.200", "dest_port": 502, "proto": "TCP"}
    e.update(fields)
    return e


def test_suricata_timestamps_out_of_range_are_rejected(tmp_path):
    engine = _run_file(tmp_path, "eve.json", _eve(_ev(timestamp="1e20"), _ev(timestamp="nan"), _ev(timestamp=1e20)))
    _assert_clean(engine, rejected=3)
    assert engine.ingest_stats.rejected_by_reason == {"timestamp out of range": 3}


def test_suricata_lines_that_are_not_objects_are_rejected(tmp_path):
    engine = _run_file(tmp_path, "eve.json", _eve("[1, 2, 3]", "42", '"x"'))
    _assert_clean(engine, rejected=3)
    assert engine.ingest_stats.rejected_by_reason == {"EVE line is not a JSON object": 3}


def test_suricata_wrong_field_types_are_rejected(tmp_path):
    engine = _run_file(tmp_path, "eve.json", _eve(
        _ev(proto=6), _ev(proto=None), _ev(event_type="alert", alert="bad"),
        _ev(event_type="alert", alert={"signature": "x", "severity": "high"}),
        _ev(dest_port="502"), _ev(dest_port=[502]), _ev(dest_port={}), _ev(dest_port=502.5),
        _ev(src_ip=167772161), _ev(src_ip=True), _ev(dest_ip=167772162),
    ))
    _assert_clean(engine, rejected=11)
    assert engine.ingest_stats.rejected_by_reason == {
        "EVE field proto is not a string": 2,
        "EVE field alert is not an object": 1,
        "EVE field alert.severity is not an integer": 1,
        "EVE field dest_port is not an integer": 4,
        "EVE field src_ip is not a string": 2,
        "EVE field dest_ip is not a string": 1,
    }
    assert engine.inventory.get("10.0.0.70") is None
