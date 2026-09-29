"""
Modbus TCP protocol parser for passive network observation.

This parser validates and extracts metadata from Modbus TCP Application Data Units
(ADUs) observed in network traffic. It operates on packet-local payloads without
TCP stream reassembly or stateful correlation.

Supports function codes: 01, 02, 03, 04, 05, 06, 15 (0x0F), 16 (0x10), and 
exception responses (function code with high bit set).

ADUs are decoded directly from the payload bytes. References:
- MBAP header: Modbus Messaging on TCP/IP Implementation Guide V1.0b, section 3.1.3
- Function code PDUs: Modbus Application Protocol Specification V1.1b3, sections 6.1-6.6,
  6.11 and 6.12
- Exception responses: Modbus Application Protocol Specification V1.1b3, section 7
"""

import struct
from dataclasses import dataclass
from typing import Optional


# Supported public function codes
# Source: Modbus Application Protocol Specification V1.1b3, sections 6.1-6.6, 6.11, 6.12
SUPPORTED_FUNCTION_CODES = {
    0x01,  # Read Coils
    0x02,  # Read Discrete Inputs
    0x03,  # Read Holding Registers
    0x04,  # Read Input Registers
    0x05,  # Write Single Coil
    0x06,  # Write Single Register
    0x0F,  # Write Multiple Coils
    0x10,  # Write Multiple Registers
}

# Modbus exception code semantic names
# Source: Modbus Application Protocol Specification V1.1b3, Section 7
# Note: 0x09 is not defined in the specification (intentional gap)
EXCEPTION_CODE_NAMES = {
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


@dataclass
class ModbusObservation:
    """
    Structured result of Modbus TCP payload parsing.
    
    Attributes:
        validated: Whether MBAP header passed all validation checks
        transaction_id: MBAP Transaction ID field
        unit_id: MBAP Unit ID field (0x00 = broadcast, 0x01-0xF7 = downstream device)
        function_code: Modbus function code (0x01-0x10, or 0x81-0x90 for exceptions)
        is_exception: True if this is an exception response
        exception_code: Exception code (0x01-0x08) if is_exception is True
        direction: 'to_server' if dst_port==502, 'from_server' if src_port==502
        starting_address: Starting register/coil address (function codes 03/04 only)
        quantity: Number of registers/coils requested (function codes 03/04 only)
    """
    validated: bool
    transaction_id: int
    unit_id: int
    function_code: int
    is_exception: bool
    exception_code: Optional[int]
    direction: str
    starting_address: Optional[int] = None
    quantity: Optional[int] = None


def _validate_mbap(payload_bytes: bytes) -> bool:
    """
    Validate MBAP header fields before parsing.
    
    The MBAP (Modbus Application Protocol) header structure:
    - Transaction ID (2 bytes)
    - Protocol ID (2 bytes) - must be 0x0000 for Modbus TCP
    - Length (2 bytes) - number of bytes following this field (Unit ID + PDU)
    - Unit ID (1 byte)
    
    Args:
        payload_bytes: Raw TCP payload bytes
        
    Returns:
        True if MBAP header is valid, False otherwise
    """
    # Check minimum payload length (MBAP header + at least function code)
    if len(payload_bytes) < 8:
        return False
    
    # Extract MBAP fields
    try:
        trans_id, proto_id, declared_length, unit_id = struct.unpack(">HHHB", payload_bytes[:7])
    except struct.error:
        return False
    
    # Protocol ID must be 0x0000 for Modbus TCP
    if proto_id != 0x0000:
        return False
    
    # Validate length field consistency
    # The Length field declares the number of bytes following it (Unit ID + PDU)
    # So total ADU size = 6 (MBAP prefix before Length) + declared_length
    required_adu_size = 6 + declared_length
    
    if len(payload_bytes) < required_adu_size:
        return False
    
    return True


def _is_supported_function_code(func_code: int) -> bool:
    """
    Check if function code is in the supported set.
    
    Args:
        func_code: Modbus function code (0x01-0xFF)
        
    Returns:
        True if supported (either a base code or valid exception encoding)
    """
    # Check base function code
    base_code = func_code & 0x7F
    return base_code in SUPPORTED_FUNCTION_CODES


def get_exception_name(exception_code: int) -> str:
    """
    Get the semantic name for a Modbus exception code.
    
    Maps numeric exception codes to their specification-defined names per
    Modbus Application Protocol Specification V1.1b3, Section 7.
    
    Args:
        exception_code: Numeric exception code (0x01-0xFF)
        
    Returns:
        Semantic name if defined in specification, "Unknown" otherwise
    """
    return EXCEPTION_CODE_NAMES.get(exception_code, "Unknown")


# Minimum PDU length (function code included) for each supported function code.
# Requests: FC 01-06 carry a 2-byte address and a 2-byte quantity or value; FC 0F and 10
# add a 1-byte byte count. Responses: FC 01-04 carry a 1-byte byte count; FC 05, 06, 0F
# and 10 echo a 2-byte address and a 2-byte value or quantity.
# Source: Modbus Application Protocol Specification V1.1b3, sections 6.1-6.6, 6.11, 6.12
_MIN_REQUEST_PDU_LENGTH = {
    0x01: 5, 0x02: 5, 0x03: 5, 0x04: 5, 0x05: 5, 0x06: 5, 0x0F: 6, 0x10: 6,
}
_MIN_RESPONSE_PDU_LENGTH = {
    0x01: 2, 0x02: 2, 0x03: 2, 0x04: 2, 0x05: 5, 0x06: 5, 0x0F: 5, 0x10: 5,
}

# Exception response PDU: function code with the high bit set, then 1-byte exception code
# Source: Modbus Application Protocol Specification V1.1b3, section 7
_EXCEPTION_PDU_LENGTH = 2


def parse_modbus_payload(payload_bytes: bytes, src_port: int, dst_port: int) -> list[ModbusObservation]:
    """
    Parse Modbus TCP payload and extract protocol metadata.
    
    This function handles multiple complete ADUs within a single payload by using
    the MBAP Length field to determine boundaries. Incomplete trailing ADUs are
    discarded.
    
    Processing stops at the first ADU that fails MBAP validation or whose PDU is
    shorter than its function code requires. ADUs with an unsupported function code
    are skipped.
    
    Args:
        payload_bytes: Raw TCP payload bytes from packet
        src_port: TCP source port
        dst_port: TCP destination port
        
    Returns:
        List of ModbusObservation objects (one per complete ADU found)
        Empty list if no valid Modbus ADUs are present
    """
    observations = []
    offset = 0
    
    while offset < len(payload_bytes):
        remaining = payload_bytes[offset:]
        
        # Check if enough bytes remain for minimum ADU
        if len(remaining) < 8:
            break
        
        # Validate MBAP header
        if not _validate_mbap(remaining):
            break
        
        # Extract declared length to find ADU boundary
        declared_length = struct.unpack(">H", remaining[4:6])[0]
        adu_size = 6 + declared_length
        
        # Check if complete ADU is available
        if len(remaining) < adu_size:
            break
        
        # Extract this ADU
        adu_bytes = remaining[:adu_size]
        
        # Determine direction from port
        if dst_port == 502:
            direction = "to_server"
        elif src_port == 502:
            direction = "from_server"
        else:
            # Neither port is 502, should not happen given caller check
            break
        
        # MBAP header (7 bytes) is followed by the PDU, which starts with the function code.
        # The Length field must cover at least the Unit ID and the function code.
        if declared_length < 2:
            break
        transaction_id, _, _, unit_id = struct.unpack(">HHHB", adu_bytes[:7])
        pdu = adu_bytes[7:]
        func_code = pdu[0]

        # Unsupported function code, skip this ADU
        if not _is_supported_function_code(func_code):
            offset += adu_size
            continue

        is_exception = (func_code & 0x80) != 0
        exception_code = None
        starting_address = None
        quantity = None

        if is_exception:
            # Exception codes are carried only by server responses
            if direction == "from_server":
                if len(pdu) < _EXCEPTION_PDU_LENGTH:
                    break
                exception_code = pdu[1]
        else:
            if direction == "to_server":
                min_length = _MIN_REQUEST_PDU_LENGTH[func_code]
            else:
                min_length = _MIN_RESPONSE_PDU_LENGTH[func_code]
            if len(pdu) < min_length:
                break

            # Read requests for FC 03 and 04: starting address then quantity of registers
            if direction == "to_server" and func_code in (0x03, 0x04):
                starting_address, quantity = struct.unpack(">HH", pdu[1:5])

        observations.append(ModbusObservation(
            validated=True,
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=func_code,
            is_exception=is_exception,
            exception_code=exception_code,
            direction=direction,
            starting_address=starting_address,
            quantity=quantity
        ))

        # Move to next potential ADU
        offset += adu_size
    
    return observations
