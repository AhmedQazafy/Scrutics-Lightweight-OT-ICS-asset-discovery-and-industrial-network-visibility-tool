"""
Tests for Modbus TCP protocol parser.

Tests cover MBAP validation, function code parsing, request/response direction,
evidence integration, and edge cases including multiple ADUs and malformed packets.
"""

import struct
import pytest
from scrutics.parsers.modbus import parse_modbus_payload, ModbusObservation


def build_modbus_request(func_code, trans_id=1, unit_id=1, start_addr=0, quantity=10):
    """
    Build a valid Modbus TCP request ADU.
    
    Args:
        func_code: Modbus function code
        trans_id: Transaction ID
        unit_id: Unit ID
        start_addr: Starting address (for read functions)
        quantity: Quantity of coils/registers (for read functions)
        
    Returns:
        bytes: Complete Modbus TCP ADU
    """
    # MBAP header: TransID (2), ProtoID (2), Length (2), UnitID (1)
    # Length = UnitID (1) + PDU length
    if func_code in (0x01, 0x02, 0x03, 0x04):
        # Read request: FuncCode (1) + StartAddr (2) + Quantity (2) = 5 bytes PDU
        length = 6
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BHH", func_code, start_addr, quantity)
    elif func_code == 0x05:
        # Write Single Coil: FuncCode (1) + Addr (2) + Value (2) = 5 bytes PDU
        length = 6
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        value = 0xFF00 if quantity else 0x0000  # ON=0xFF00, OFF=0x0000
        pdu = struct.pack(">BHH", func_code, start_addr, value)
    elif func_code == 0x06:
        # Write Single Register: FuncCode (1) + Addr (2) + Value (2) = 5 bytes PDU
        length = 6
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BHH", func_code, start_addr, quantity)  # quantity reused as value
    elif func_code == 0x0F:
        # Write Multiple Coils: FuncCode (1) + StartAddr (2) + Quantity (2) + ByteCount (1) + Values (N)
        byte_count = (quantity + 7) // 8  # Round up to nearest byte
        length = 7 + byte_count
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BHHB", func_code, start_addr, quantity, byte_count)
        pdu += b'\xFF' * byte_count
    elif func_code == 0x10:
        # Write Multiple Registers: FuncCode (1) + StartAddr (2) + Quantity (2) + ByteCount (1) + Values (N)
        byte_count = quantity * 2
        length = 7 + byte_count
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BHHB", func_code, start_addr, quantity, byte_count)
        pdu += (b'\x00\x64' * quantity)  # Value 0x0064 repeated
    else:
        raise ValueError(f"Unsupported function code: {func_code}")
    
    return mbap + pdu


def build_modbus_response(func_code, trans_id=1, unit_id=1, data_bytes=None):
    """
    Build a valid Modbus TCP response ADU.
    
    Args:
        func_code: Modbus function code
        trans_id: Transaction ID
        unit_id: Unit ID
        data_bytes: Response data bytes (varies by function)
        
    Returns:
        bytes: Complete Modbus TCP ADU
    """
    if data_bytes is None:
        data_bytes = b'\x00\x0A'  # Default 2 bytes
    
    if func_code in (0x01, 0x02, 0x03, 0x04):
        # Read response: FuncCode (1) + ByteCount (1) + Data (N)
        byte_count = len(data_bytes)
        length = 3 + byte_count
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BB", func_code, byte_count) + data_bytes
    elif func_code in (0x05, 0x06):
        # Write response: FuncCode (1) + Addr (2) + Value (2) = 5 bytes PDU
        length = 6
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BHH", func_code, 0x0000, 0x0064)
    elif func_code in (0x0F, 0x10):
        # Write Multiple response: FuncCode (1) + StartAddr (2) + Quantity (2) = 5 bytes PDU
        length = 6
        mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
        pdu = struct.pack(">BHH", func_code, 0x0000, 0x000A)
    else:
        raise ValueError(f"Unsupported function code: {func_code}")
    
    return mbap + pdu


def build_modbus_exception(func_code, trans_id=1, unit_id=1, exception_code=0x02):
    """
    Build a Modbus TCP exception response.
    
    Args:
        func_code: Base function code (will be OR'd with 0x80)
        trans_id: Transaction ID
        unit_id: Unit ID
        exception_code: Modbus exception code (0x01-0x08)
        
    Returns:
        bytes: Complete Modbus TCP exception ADU
    """
    # Exception response: FuncCode|0x80 (1) + ExceptionCode (1) = 2 bytes PDU
    length = 3
    mbap = struct.pack(">HHHB", trans_id, 0x0000, length, unit_id)
    pdu = struct.pack(">BB", func_code | 0x80, exception_code)
    return mbap + pdu


class TestMBAPValidation:
    """Tests for MBAP header validation."""
    
    def test_valid_mbap(self):
        """Valid MBAP with correct protocol ID and length."""
        payload = build_modbus_request(0x03, trans_id=0x0001, unit_id=0x01)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].validated is True
        assert result[0].transaction_id == 0x0001
    
    def test_invalid_protocol_id(self):
        """Protocol ID != 0x0000 should be rejected."""
        # Build payload with invalid protocol ID
        mbap = struct.pack(">HHHB", 0x0001, 0x0001, 0x0006, 0x01)  # ProtoID = 0x0001
        pdu = struct.pack(">BHH", 0x03, 0x0000, 0x000A)
        payload = mbap + pdu
        
        result = parse_modbus_payload(payload, 49152, 502)
        assert len(result) == 0
    
    def test_truncated_payload(self):
        """Payload shorter than declared length should be rejected."""
        # MBAP declares length=6, but only provide 4 bytes after length field
        mbap = struct.pack(">HHHB", 0x0001, 0x0000, 0x0006, 0x01)
        pdu = struct.pack(">BH", 0x03, 0x0000)  # Missing quantity field
        payload = mbap + pdu
        
        result = parse_modbus_payload(payload, 49152, 502)
        assert len(result) == 0
    
    def test_payload_shorter_than_8_bytes(self):
        """Payload shorter than minimum ADU should be rejected."""
        payload = b'\x00\x01\x00\x00\x00'  # Only 5 bytes
        result = parse_modbus_payload(payload, 49152, 502)
        assert len(result) == 0


class TestFunctionCodeParsing:
    """Tests for parsing different Modbus function codes."""
    
    def test_function_01_read_coils(self):
        """Parse Function 01 (Read Coils) request."""
        payload = build_modbus_request(0x01, trans_id=0x1234, start_addr=0x0000, quantity=20)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x01
        assert result[0].transaction_id == 0x1234
        assert result[0].is_exception is False
    
    def test_function_02_read_discrete_inputs(self):
        """Parse Function 02 (Read Discrete Inputs) request."""
        payload = build_modbus_request(0x02, trans_id=0x5678, start_addr=0x0064, quantity=15)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x02
        assert result[0].transaction_id == 0x5678
    
    def test_function_03_read_holding_registers(self):
        """Parse Function 03 (Read Holding Registers) request with address extraction."""
        payload = build_modbus_request(0x03, trans_id=0xABCD, unit_id=0x05, start_addr=0x1000, quantity=10)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x03
        assert result[0].unit_id == 0x05
        assert result[0].starting_address == 0x1000
        assert result[0].quantity == 10
    
    def test_function_04_read_input_registers(self):
        """Parse Function 04 (Read Input Registers) request with address extraction."""
        payload = build_modbus_request(0x04, start_addr=0x0200, quantity=25)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x04
        assert result[0].starting_address == 0x0200
        assert result[0].quantity == 25
    
    def test_function_05_write_single_coil(self):
        """Parse Function 05 (Write Single Coil) request."""
        payload = build_modbus_request(0x05, start_addr=0x0AC, quantity=1)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x05
    
    def test_function_06_write_single_register(self):
        """Parse Function 06 (Write Single Register) request."""
        payload = build_modbus_request(0x06, start_addr=0x0001, quantity=0x0064)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x06
    
    def test_function_0F_write_multiple_coils(self):
        """Parse Function 0x0F (Write Multiple Coils) request."""
        payload = build_modbus_request(0x0F, start_addr=0x0013, quantity=10)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x0F
    
    def test_function_10_write_multiple_registers(self):
        """Parse Function 0x10 (Write Multiple Registers) request."""
        payload = build_modbus_request(0x10, start_addr=0x0001, quantity=2)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].function_code == 0x10


class TestResponseParsing:
    """Tests for parsing Modbus responses."""
    
    def test_function_03_response(self):
        """Parse Function 03 response."""
        data = b'\x00\x0A' * 10  # 10 register values
        payload = build_modbus_response(0x03, trans_id=0x0001, data_bytes=data)
        result = parse_modbus_payload(payload, 502, 49152)  # from_server
        
        assert len(result) == 1
        assert result[0].function_code == 0x03
        assert result[0].direction == "from_server"
    
    def test_function_06_response(self):
        """Parse Function 06 response."""
        payload = build_modbus_response(0x06, trans_id=0x0002)
        result = parse_modbus_payload(payload, 502, 49152)
        
        assert len(result) == 1
        assert result[0].function_code == 0x06
        assert result[0].direction == "from_server"
    
    def test_function_10_response(self):
        """Parse Function 0x10 response."""
        payload = build_modbus_response(0x10, trans_id=0x0003)
        result = parse_modbus_payload(payload, 502, 49152)
        
        assert len(result) == 1
        assert result[0].function_code == 0x10


class TestExceptionResponses:
    """Tests for parsing Modbus exception responses."""
    
    def test_exception_response_function_03(self):
        """Parse exception response for Function 03."""
        payload = build_modbus_exception(0x03, trans_id=0x0001, exception_code=0x02)
        result = parse_modbus_payload(payload, 502, 49152)
        
        assert len(result) == 1
        assert result[0].function_code == 0x83  # 0x03 | 0x80
        assert result[0].is_exception is True
        assert result[0].exception_code == 0x02
    
    def test_exception_response_function_06(self):
        """Parse exception response for Function 06."""
        payload = build_modbus_exception(0x06, trans_id=0xFFFF, exception_code=0x01)
        result = parse_modbus_payload(payload, 502, 49152)
        
        assert len(result) == 1
        assert result[0].function_code == 0x86
        assert result[0].is_exception is True
        assert result[0].exception_code == 0x01


class TestExceptionSemanticNames:
    """Tests for exception code semantic name decoding."""
    
    def test_all_defined_exception_codes(self):
        """Each specification-defined exception code maps to correct semantic name."""
        from scrutics.parsers.modbus import get_exception_name
        
        expected = {
            0x01: "Illegal Function",
            0x02: "Illegal Data Address",
            0x03: "Illegal Data Value",
            0x04: "Slave Device Failure",
            0x05: "Acknowledge",
            0x06: "Slave Device Busy",
            0x07: "Negative Acknowledge",
            0x08: "Memory Parity Error",
            0x0A: "Gateway Path Unavailable",
            0x0B: "Gateway Target Device Failed To Respond",
        }
        
        for code, expected_name in expected.items():
            assert get_exception_name(code) == expected_name
    
    def test_undefined_exception_code_gap(self):
        """0x09 (specification gap) returns 'Unknown'."""
        from scrutics.parsers.modbus import get_exception_name
        assert get_exception_name(0x09) == "Unknown"
    
    def test_undefined_exception_code_high_value(self):
        """Vendor-specific exception codes return 'Unknown'."""
        from scrutics.parsers.modbus import get_exception_name
        assert get_exception_name(0x80) == "Unknown"
        assert get_exception_name(0xFF) == "Unknown"
    
    def test_exception_code_zero(self):
        """Exception code 0x00 (invalid) returns 'Unknown'."""
        from scrutics.parsers.modbus import get_exception_name
        assert get_exception_name(0x00) == "Unknown"


class TestExceptionEvidenceDetail:
    """Tests for exception semantic names in evidence detail strings."""
    
    def test_exception_detail_includes_semantic_name(self):
        """Exception evidence detail includes both hex code and semantic name."""
        from scrutics.capture.engine import CaptureEngine
        from scrutics.db.inventory import AssetInventory
        
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        
        # Create asset
        asset = inventory.update(ip="192.168.1.10", mac="00:11:22:33:44:55", dst_ip="192.168.1.20", dst_port=502, timestamp=1000.0)
        
        # Build a packet with Modbus exception 0x02
        exception_payload = build_modbus_exception(0x03, trans_id=0x1234, exception_code=0x02)
        
        # Process the payload
        engine._process_modbus_payload(exception_payload, "192.168.1.10", 502, 49152, 1000.0)
        
        # Find the Modbus protocol evidence
        modbus_evidence = [e for e in asset.evidence if e.type == "protocol" and e.value == "Modbus TCP"]
        assert len(modbus_evidence) == 1
        
        detail = modbus_evidence[0].detail
        assert "ExceptionCode=0x02" in detail
        assert "(Illegal Data Address)" in detail
    
    def test_undefined_exception_in_detail(self):
        """Undefined exception code shows 'Unknown' in evidence detail."""
        from scrutics.capture.engine import CaptureEngine
        from scrutics.db.inventory import AssetInventory
        
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        
        # Create asset
        asset = inventory.update(ip="192.168.1.10", mac="00:11:22:33:44:55", dst_ip="192.168.1.20", dst_port=502, timestamp=1000.0)
        
        # Build a packet with undefined exception 0x09
        exception_payload = build_modbus_exception(0x03, trans_id=0x1234, exception_code=0x09)
        
        # Process the payload
        engine._process_modbus_payload(exception_payload, "192.168.1.10", 502, 49152, 1000.0)
        
        # Find the Modbus protocol evidence
        modbus_evidence = [e for e in asset.evidence if e.type == "protocol" and e.value == "Modbus TCP"]
        assert len(modbus_evidence) == 1
        
        detail = modbus_evidence[0].detail
        assert "ExceptionCode=0x09" in detail
        assert "(Unknown)" in detail
    
    def test_non_exception_responses_unaffected(self):
        """Non-exception Modbus responses have unchanged evidence detail format."""
        from scrutics.capture.engine import CaptureEngine
        from scrutics.db.inventory import AssetInventory
        
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        
        # Create asset
        asset = inventory.update(ip="192.168.1.10", mac="00:11:22:33:44:55", dst_ip="192.168.1.20", dst_port=502, timestamp=1000.0)
        
        # Build a normal (non-exception) request
        request_payload = build_modbus_request(0x03, start_addr=0x0000, quantity=10)
        
        # Process the payload
        engine._process_modbus_payload(request_payload, "192.168.1.10", 49152, 502, 1000.0)
        
        # Find the Modbus protocol evidence
        modbus_evidence = [e for e in asset.evidence if e.type == "protocol" and e.value == "Modbus TCP"]
        assert len(modbus_evidence) == 1
        
        detail = modbus_evidence[0].detail
        # Non-exception should not contain exception-related text
        assert "ExceptionCode" not in detail
        assert "Illegal" not in detail
        assert "Acknowledge" not in detail


class TestDirection:
    """Tests for request/response direction detection."""
    
    def test_to_server_direction(self):
        """dst_port == 502 should be 'to_server'."""
        payload = build_modbus_request(0x03)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].direction == "to_server"
    
    def test_from_server_direction(self):
        """src_port == 502 should be 'from_server'."""
        payload = build_modbus_response(0x03)
        result = parse_modbus_payload(payload, 502, 49152)
        
        assert len(result) == 1
        assert result[0].direction == "from_server"


class TestMultipleADUs:
    """Tests for handling multiple ADUs in one payload."""
    
    def test_two_complete_adus(self):
        """Two complete ADUs in one payload should both be parsed."""
        adu1 = build_modbus_request(0x03, trans_id=0x0001, start_addr=0x0000, quantity=10)
        adu2 = build_modbus_request(0x06, trans_id=0x0002, start_addr=0x0001, quantity=0x0064)
        payload = adu1 + adu2
        
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 2
        assert result[0].function_code == 0x03
        assert result[0].transaction_id == 0x0001
        assert result[1].function_code == 0x06
        assert result[1].transaction_id == 0x0002
    
    def test_complete_adu_plus_trailing_partial(self):
        """Complete ADU followed by partial ADU should parse the first, discard the rest."""
        adu1 = build_modbus_request(0x03, trans_id=0x0001)
        partial_adu = struct.pack(">HHHB", 0x0002, 0x0000, 0x0006, 0x01)  # MBAP only, no PDU
        payload = adu1 + partial_adu
        
        result = parse_modbus_payload(payload, 49152, 502)
        
        # Should parse the first ADU, ignore the incomplete one
        assert len(result) == 1
        assert result[0].transaction_id == 0x0001


class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_unsupported_function_code(self):
        """Unsupported function code should be rejected."""
        # Build ADU with unsupported function code 0x14
        mbap = struct.pack(">HHHB", 0x0001, 0x0000, 0x0006, 0x01)
        pdu = struct.pack(">BHH", 0x14, 0x0000, 0x000A)
        payload = mbap + pdu
        
        result = parse_modbus_payload(payload, 49152, 502)
        assert len(result) == 0
    
    def test_non_modbus_payload_on_port_502(self):
        """Random bytes on port 502 should be rejected gracefully."""
        payload = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        result = parse_modbus_payload(payload, 49152, 502)
        assert len(result) == 0
    
    def test_unit_id_broadcast(self):
        """Unit ID 0x00 (broadcast) should be parsed correctly."""
        payload = build_modbus_request(0x05, unit_id=0x00)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].unit_id == 0x00
    
    def test_unit_id_gateway_downstream(self):
        """Unit ID 0x01-0xF7 (gateway downstream) should be parsed correctly."""
        payload = build_modbus_request(0x03, unit_id=0x05)
        result = parse_modbus_payload(payload, 49152, 502)
        
        assert len(result) == 1
        assert result[0].unit_id == 0x05
    
    def test_malformed_mbap_no_exception_raised(self):
        """Malformed MBAP should not raise exception, just return empty list."""
        payload = b'\x00\x01'  # Too short
        result = parse_modbus_payload(payload, 49152, 502)
        assert result == []


class TestIntegrationWithEngine:
    """
    Integration tests verifying evidence is added correctly.
    
    These tests verify that:
    1. Port evidence is added regardless of parsing success
    2. Protocol evidence is added only on successful parse
    3. Evidence weights and confidence levels are correct
    """
    
    def test_valid_modbus_adds_protocol_evidence(self):
        """Valid Modbus payload should result in protocol evidence being added."""
        from scrutics.db.inventory import AssetInventory
        from scrutics.capture.engine import CaptureEngine
        
        inv = AssetInventory()
        engine = CaptureEngine(inventory=inv)
        
        # Create asset
        asset = inv.update(ip="10.0.0.1", mac="00:11:22:33:44:55", dst_ip="10.0.0.2", dst_port=502, timestamp=1.0)
        
        # Build valid Modbus payload
        payload = build_modbus_request(0x03, trans_id=0x1234, unit_id=0x01)
        
        # Process the payload
        engine._process_modbus_payload(payload, "10.0.0.1", 49152, 502, 1.0)
        
        # Check that protocol evidence was added
        protocol_evidence = [e for e in asset.evidence if e.type == "protocol" and e.source == "modbus_parser"]
        assert len(protocol_evidence) == 1
        assert protocol_evidence[0].value == "Modbus TCP"
        assert protocol_evidence[0].confidence == "HIGH"
        assert "Function 0x03" in protocol_evidence[0].detail
        assert "TransID=0x1234" in protocol_evidence[0].detail
    
    def test_non_modbus_on_port_502_no_protocol_evidence(self):
        """Non-Modbus payload on port 502 should not add protocol evidence."""
        from scrutics.db.inventory import AssetInventory
        from scrutics.capture.engine import CaptureEngine
        
        inv = AssetInventory()
        engine = CaptureEngine(inventory=inv)
        
        # Create asset
        asset = inv.update(ip="10.0.0.1", mac="00:11:22:33:44:55", dst_ip="10.0.0.2", dst_port=502, timestamp=1.0)
        
        # Random non-Modbus payload
        payload = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        
        # Process the payload
        engine._process_modbus_payload(payload, "10.0.0.1", 49152, 502, 1.0)
        
        # Check that NO protocol evidence was added
        protocol_evidence = [e for e in asset.evidence if e.type == "protocol" and e.source == "modbus_parser"]
        assert len(protocol_evidence) == 0
