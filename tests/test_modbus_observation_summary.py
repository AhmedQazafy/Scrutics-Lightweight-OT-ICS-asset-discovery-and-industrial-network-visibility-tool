"""
Per-asset Modbus TCP observation summary.

Every valid observation updates the asset's summary (directions, function codes, exception
names, total count). The parser evidence record stays one per asset and keeps the first
observation's detail. A request carrying the exception bit is not a valid observation.
"""

import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine
from scrutics.parsers.modbus import parse_modbus_payload

GATEWAY_IP, GATEWAY_MAC = "10.0.0.30", "02:00:00:00:00:30"
CLIENT_IP = "10.0.0.5"
DOWNSTREAM_IP = "10.0.0.40"


def _adu(trans_id, pdu, unit_id=0x01):
    return struct.pack(">HHHB", trans_id, 0x0000, len(pdu) + 1, unit_id) + pdu


def _read_registers_response(trans_id, fc=0x03):
    return _adu(trans_id, struct.pack(">BBHH", fc, 4, 0x0001, 0x0002))


def _read_registers_request(trans_id, fc=0x04):
    return _adu(trans_id, struct.pack(">BHH", fc, 0x0010, 2))


def _write_single_register_response(trans_id):
    return _adu(trans_id, struct.pack(">BHH", 0x06, 0x0001, 0x00FF))


def _exception_response(trans_id, fc, code):
    return _adu(trans_id, struct.pack(">BB", fc | 0x80, code))


def _packet(src_ip, dst_ip, sport, dport, payload, t):
    pkt = (
        Ether(src=GATEWAY_MAC, dst="02:00:00:00:00:99")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags="PA")
        / Raw(load=payload)
    )
    pkt.time = t
    return pkt


def _from_gateway_as_server(payload, t):
    return _packet(GATEWAY_IP, CLIENT_IP, 502, 40001, payload, t)


def _from_gateway_as_client(payload, t):
    return _packet(GATEWAY_IP, DOWNSTREAM_IP, 40100, 502, payload, t)


def _engine():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    return inv, engine


def test_summary_accumulates_function_codes_directions_and_exceptions_across_packets():
    inv, engine = _engine()
    packets = [
        _from_gateway_as_server(_read_registers_response(1), 1.0),
        _from_gateway_as_server(_read_registers_response(2), 2.0),
        _from_gateway_as_server(_write_single_register_response(3), 3.0),
        _from_gateway_as_client(_read_registers_request(4), 4.0),
        _from_gateway_as_server(_exception_response(5, 0x03, 0x02), 5.0),
        _from_gateway_as_client(_read_registers_request(6), 6.0),
        # Two complete ADUs in one payload: both are counted
        _from_gateway_as_server(
            _exception_response(7, 0x03, 0x0B) + _read_registers_response(8), 7.0
        ),
        # Undefined exception codes stay distinct in the summary, keyed with the raw code
        _from_gateway_as_server(_exception_response(9, 0x03, 0x09), 8.0),
        _from_gateway_as_server(_exception_response(10, 0x03, 0x0C), 9.0),
    ]
    for pkt in packets:
        engine._process_packet(pkt)

    asset = inv.get(GATEWAY_IP)
    summary = asset.protocol_summaries["Modbus TCP"]
    assert summary.answers_as_server is True
    assert summary.sends_requests is True
    assert summary.function_codes == {0x03: 3, 0x06: 1, 0x04: 2, 0x83: 4}
    assert summary.exceptions == {
        "Illegal Data Address": 1,
        "Gateway Target Device Failed To Respond": 1,
        "Unknown (0x09)": 1,
        "Unknown (0x0C)": 1,
    }
    assert summary.observation_count == 10

    # The parser evidence record stays single and keeps the first observation's detail
    parser_evidence = [e for e in asset.evidence if e.source == "modbus_parser"]
    assert len(parser_evidence) == 1
    assert "TransID=0x0001" in parser_evidence[0].detail
    assert "direction=from_server" in parser_evidence[0].detail


def test_request_with_exception_bit_produces_no_observation_or_summary_change():
    request_with_exception_bit = _exception_response(9, 0x03, 0x02)
    assert parse_modbus_payload(request_with_exception_bit, 40100, 502) == []

    inv, engine = _engine()
    engine._process_packet(_from_gateway_as_client(_read_registers_request(1), 1.0))
    asset = inv.get(GATEWAY_IP)
    summary = asset.protocol_summaries["Modbus TCP"]
    before = (summary.sends_requests, summary.answers_as_server, dict(summary.function_codes),
              dict(summary.exceptions), summary.observation_count)
    parser_evidence_before = [(e.type, e.value, e.weight, e.confidence, e.detail)
                              for e in asset.evidence if e.source == "modbus_parser"]

    engine._process_packet(_from_gateway_as_client(request_with_exception_bit, 2.0))

    after = (summary.sends_requests, summary.answers_as_server, dict(summary.function_codes),
             dict(summary.exceptions), summary.observation_count)
    assert after == before
    assert [(e.type, e.value, e.weight, e.confidence, e.detail)
            for e in asset.evidence if e.source == "modbus_parser"] == parser_evidence_before
