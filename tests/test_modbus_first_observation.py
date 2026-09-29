"""
A valid Modbus TCP ADU on the first packet from a device produces parser evidence.

The source asset is created while the packet is processed; the Modbus observation
must still be recorded for that asset.
"""

import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine


def _read_holding_registers_response(trans_id=0x0001, unit_id=0x01):
    # FC 03 response PDU: function code, byte count, register values
    pdu = struct.pack(">BB", 0x03, 4) + struct.pack(">HH", 0x1234, 0x5678)
    mbap = struct.pack(">HHHB", trans_id, 0x0000, len(pdu) + 1, unit_id)
    return mbap + pdu


def test_first_packet_from_new_device_produces_parser_evidence():
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)
    engine.no_baseline = True
    assert inv.get("10.0.0.20") is None

    pkt = (
        Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:05")
        / IP(src="10.0.0.20", dst="10.0.0.5")
        / TCP(sport=502, dport=40001, flags="PA")
        / Raw(load=_read_holding_registers_response())
    )
    engine._process_packet(pkt)

    asset = inv.get("10.0.0.20")
    assert asset is not None
    parser_evidence = [e for e in asset.evidence if e.source == "modbus_parser"]
    assert len(parser_evidence) == 1
    ev = parser_evidence[0]
    assert ev.type == "protocol"
    assert ev.value == "Modbus TCP"
    assert ev.weight == 20
    assert ev.confidence == "HIGH"
    assert "Function 0x03" in ev.detail
    assert "direction=from_server" in ev.detail
