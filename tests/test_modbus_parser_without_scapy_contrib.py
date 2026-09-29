"""
The Modbus TCP parser decodes ADUs from raw bytes and does not need scapy.contrib.modbus.
"""

import importlib
import struct
import sys

import pytest

import scrutics.parsers


def test_parser_works_when_scapy_contrib_modbus_unavailable(monkeypatch):
    # A None entry in sys.modules makes any import of the module raise ImportError
    monkeypatch.setitem(sys.modules, "scapy.contrib.modbus", None)
    # Force a fresh import of the parser; the original module is restored after the test
    monkeypatch.delitem(sys.modules, "scrutics.parsers.modbus", raising=False)
    monkeypatch.delattr(scrutics.parsers, "modbus", raising=False)
    with pytest.raises(ImportError):
        importlib.import_module("scapy.contrib.modbus")

    modbus = importlib.import_module("scrutics.parsers.modbus")

    # FC 03 request: start address 0x0010, quantity 2
    request = struct.pack(">HHHB", 0x0102, 0x0000, 6, 0x11) + struct.pack(">BHH", 0x03, 0x0010, 2)
    # FC 03 response: byte count 4, two register values
    response = struct.pack(">HHHB", 0x0102, 0x0000, 7, 0x11) + struct.pack(">BBHH", 0x03, 4, 1, 2)
    # Exception response to FC 06: exception code 0x02
    exception = struct.pack(">HHHB", 0x0103, 0x0000, 3, 0x11) + struct.pack(">BB", 0x86, 0x02)

    [req] = modbus.parse_modbus_payload(request, 49152, 502)
    assert (req.transaction_id, req.unit_id, req.function_code) == (0x0102, 0x11, 0x03)
    assert req.direction == "to_server"
    assert (req.starting_address, req.quantity) == (0x0010, 2)
    assert req.is_exception is False

    [resp] = modbus.parse_modbus_payload(response, 502, 49152)
    assert (resp.function_code, resp.direction) == (0x03, "from_server")
    assert (resp.starting_address, resp.quantity) == (None, None)

    [exc] = modbus.parse_modbus_payload(exception, 502, 49152)
    assert exc.function_code == 0x86
    assert exc.is_exception is True
    assert exc.exception_code == 0x02
