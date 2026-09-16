"""
Curated offline DHCP fingerprint database.
Illustrative rather than authoritative; covers common OT and IT device signatures.
No external network calls, downloads, or third-party dependencies.
"""

# Mapping of normalized Option 55 tuple to OS / Device family description
# Parameter Request List (Option 55) signatures from standard reference captures:
DHCP_OPTION55_FINGERPRINTS = {
    # Windows Desktop / Server variants
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 43): "Windows 7 / Windows Server 2008 R2",
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): "Windows 10 / Windows 11 / Server 2016+",
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 249, 43): "Windows XP / Windows Server 2003",
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47): "Windows Server / Legacy Client",
    
    # Linux distributions
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42): "Ubuntu / Debian Linux (ISC DHCP)",
    (1, 3, 6, 12, 15, 26, 28, 42, 119, 121): "Red Hat / CentOS / Fedora Linux",
    (1, 3, 6, 12, 15, 28, 42): "Generic Linux / Unix Client",
    (1, 3, 6, 15, 26, 28, 51, 58, 59): "Embedded Linux / BusyBox (udhcp)",
    
    # Apple
    (1, 3, 6, 15, 119, 95, 252, 44, 46, 47): "Apple macOS / iOS (Darwin)",
    
    # Industrial / OT Controller signatures
    (1, 3, 6, 15, 28, 33): "Siemens SIMATIC / Scalance Device",
    (1, 3, 6, 12, 15, 28): "Schneider Electric Modicon PLC",
    (1, 3, 6, 15, 43): "Rockwell Automation / Allen-Bradley Controller",
    (1, 3, 6, 15): "Generic Industrial RTOS / Controller",
}

# Vendor Class Identifier (Option 60) substring patterns to recognized description
OPTION60_PATTERNS = [
    # Industrial Automation / OT
    ("Schneider", "Schneider Electric Automation Device"),
    ("Modicon", "Schneider Electric Modicon Controller"),
    ("Siemens", "Siemens Industrial Device"),
    ("SIMATIC", "Siemens SIMATIC Industrial Controller"),
    ("Rockwell", "Rockwell Automation Controller"),
    ("Allen-Bradley", "Allen-Bradley Industrial Device"),
    ("Beckhoff", "Beckhoff Industrial PC / TwinCAT"),
    ("WAGO", "WAGO I/O System"),
    ("Moxa", "Moxa Industrial Networking"),
    
    # IT / Enterprise / OS
    ("MSFT 5.0", "Microsoft Windows Client / Server (MSFT 5.0)"),
    ("MSFT 98", "Microsoft Windows 98 / ME"),
    ("Cisco", "Cisco Systems Network Infrastructure"),
    ("dhcpcd", "Linux DHCP Client (dhcpcd)"),
    ("udhcp", "Embedded Linux udhcp client"),
    ("android-dhcp", "Android Mobile OS"),
]


def lookup_dhcp_fingerprint(option55) -> str | None:
    """
    Look up OS / device fingerprint from DHCP Option 55 (Parameter Request List).
    Returns matched OS description or None if no match found.
    Never returns 'Unknown fingerprint' on a non-match.
    """
    if not option55:
        return None

    if isinstance(option55, (bytes, bytearray)):
        norm_key = tuple(int(b) for b in option55)
    elif isinstance(option55, str):
        try:
            norm_key = tuple(int(x.strip()) for x in option55.split(",") if x.strip())
        except (ValueError, TypeError):
            return None
    elif isinstance(option55, (list, tuple)):
        try:
            norm_key = tuple(int(x) for x in option55)
        except (ValueError, TypeError):
            return None
    else:
        return None

    return DHCP_OPTION55_FINGERPRINTS.get(norm_key)


def classify_option60(option60: str | bytes | None) -> str | None:
    """
    Classify DHCP Option 60 (Vendor Class Identifier) against recognized patterns.
    Returns recognized description or None.
    Does not modify OUI vendor fields.
    """
    if not option60:
        return None

    if isinstance(option60, (bytes, bytearray)):
        try:
            s = option60.decode("utf-8", errors="ignore").replace("\x00", "").strip()
        except Exception:
            return None
    else:
        s = str(option60).replace("\x00", "").strip()

    if not s:
        return None

    s_lower = s.lower()
    for pattern, desc in OPTION60_PATTERNS:
        if pattern.lower() in s_lower:
            return desc

    return None


def parse_option_81(val: bytes | str | None) -> str | None:
    """
    Parse RFC 4702 DHCP Option 81 (Client FQDN).
    
    Structure:
      Byte 0: Flags (Bit 2: Encoding bit 'E'. 0 = ASCII, 1 = Canonical DNS wire format)
      Byte 1: RCODE1
      Byte 2: RCODE2
      Bytes 3+: Domain Name
      
    Returns clean decoded FQDN string or None if malformed/empty.
    """
    if not val:
        return None
    if isinstance(val, str):
        val = val.encode("latin1", errors="ignore")
    if not isinstance(val, (bytes, bytearray)) or len(val) < 4:
        return None

    flags = val[0]
    e_bit = bool(flags & 0x04)
    name_data = val[3:]
    if not name_data:
        return None

    if not e_bit:
        # ASCII format: strip null padding
        try:
            decoded = name_data.decode("utf-8", errors="ignore").replace("\x00", "").strip()
            return decoded if decoded else None
        except Exception:
            return None
    else:
        # Canonical DNS wire-format
        try:
            labels = []
            idx = 0
            length = len(name_data)
            while idx < length:
                label_len = name_data[idx]
                if label_len == 0:
                    idx += 1
                    break
                idx += 1
                if idx + label_len > length:
                    # Truncated or malformed label
                    return None
                label = name_data[idx:idx + label_len].decode("utf-8", errors="ignore")
                if not label:
                    return None
                labels.append(label)
                idx += label_len
            if not labels:
                return None
            return ".".join(labels)
        except Exception:
            return None
