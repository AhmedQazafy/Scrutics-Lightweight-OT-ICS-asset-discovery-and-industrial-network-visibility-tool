"""
Passive signature registry for Scrutics.
Describes what Scrutics can observe, not what it means.

Each signature describes a passive observation:
- Port/service observed
- Protocol detected
- Discovery announcement received
- OS hint from TTL

The classifier interprets evidence, not signatures directly.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortSignature:
    """Describes what a port observation means as evidence."""
    port: int
    transport: str  # "TCP" | "UDP" | "Both"
    name: str       # Protocol/service name
    evidence_type: str  # "ot_port" | "it_port" | "infra_port" | "discovery_port" | "service"
    weight: int     # Evidence weight (0-100)
    confidence: str  # "HIGH" | "MEDIUM" | "LOW" | "TENTATIVE"
    ambiguity: Optional[str] = None  # Note if port is shared by multiple protocols
    category: str = "Unknown"  # "OT" | "IT" | "Infrastructure" | "Discovery" | "Service"
    detail: str = ""  # Additional context


# ── OT/ICS Protocol Ports ──────────────────────────────────────────────────────

OT_PORT_SIGNATURES = [
    # Universal ICS protocols
    PortSignature(502, "TCP", "Modbus TCP", "ot_port", 20, "HIGH",
                  category="OT", detail="Universal PLC/RTU communication"),
    
    # Siemens
    PortSignature(102, "TCP", "S7comm / IEC 61850 MMS / ICCP", "ot_port", 15, "MEDIUM",
                  ambiguity="Port 102 is shared by multiple protocols: S7comm (Siemens PLC), IEC 61850 MMS (substation automation), ICCP/TASE.2 (utility control centers)",
                  category="OT", detail="Siemens PLC or substation/utility device"),
    
    # Rockwell/Allen-Bradley
    PortSignature(44818, "TCP/UDP", "EtherNet/IP", "ot_port", 20, "HIGH",
                  category="OT", detail="Rockwell/Allen-Bradley industrial Ethernet"),
    PortSignature(2222, "TCP/UDP", "EtherNet/IP IO", "ot_port", 18, "HIGH",
                  category="OT", detail="Rockwell/Allen-Bradley I/O communication"),
    
    # Utility/SCADA
    PortSignature(20000, "TCP/UDP", "DNP3", "ot_port", 20, "HIGH",
                  category="OT", detail="Distributed Network Protocol — power grid/utility SCADA"),
    PortSignature(2404, "TCP", "IEC 60870-5-104", "ot_port", 20, "HIGH",
                  category="OT", detail="Power grid telecontrol — substations, RTUs"),
    
    # Building Automation
    PortSignature(47808, "UDP", "BACnet/IP", "ot_port", 18, "HIGH",
                  category="OT", detail="Building automation and control (HVAC, lighting, fire)"),
    PortSignature(1911, "TCP", "Niagara Fox", "ot_port", 16, "HIGH",
                  category="OT", detail="Tridium/Honeywell building automation framework"),
    PortSignature(4911, "TCP", "Niagara Fox (alt)", "ot_port", 14, "MEDIUM",
                  category="OT", detail="Tridium/Honeywell building automation (alternate port)"),
    
    # Industrial Ethernet
    PortSignature(34962, "UDP", "PROFINET RT (Real-Time)", "ot_port", 18, "HIGH",
                  category="OT", detail="PROFINET real-time communication — Siemens/PROFIBUS"),
    PortSignature(34964, "UDP", "PROFINET RT (Real-Time)", "ot_port", 18, "HIGH",
                  category="OT", detail="PROFINET real-time communication"),
    PortSignature(34980, "UDP", "EtherCAT", "ot_port", 18, "HIGH",
                  category="OT", detail="High-performance Ethernet fieldbus — motion control/robotics"),
    
    # OPC UA
    PortSignature(4840, "TCP", "OPC-UA Discovery", "ot_port", 16, "HIGH",
                  category="OT", detail="OPC-UA server discovery/gateway"),
    
    # Other major OT protocols
    PortSignature(5094, "TCP/UDP", "HART-IP", "ot_port", 16, "HIGH",
                  category="OT", detail="Highway Addressable Remote Transducer — field instruments"),
    PortSignature(9600, "TCP", "FINS", "ot_port", 16, "HIGH",
                  category="OT", detail="Omron PLC communication"),
    PortSignature(2455, "TCP", "CODESYS", "ot_port", 16, "HIGH",
                  category="OT", detail="CODESYS V3 PLC runtime"),
    PortSignature(5450, "TCP", "OSIsoft PI Server", "ot_port", 14, "HIGH",
                  category="OT", detail="PI data historian — energy, utilities, manufacturing"),
    PortSignature(4000, "TCP/UDP", "ROC Plus", "ot_port", 14, "HIGH",
                  category="OT", detail="Emerson Fisher ROC RTUs — oil/gas pipeline"),
    PortSignature(789, "TCP", "Red Lion Crimson", "ot_port", 14, "HIGH",
                  category="OT", detail="Red Lion HMI/SCADA configuration"),
    
    # DCS protocols
    PortSignature(55555, "TCP/UDP", "Foxboro FoxApi", "ot_port", 14, "HIGH",
                  category="OT", detail="Foxboro/Invensys DCS communication"),
    PortSignature(45678, "TCP/UDP", "Foxboro AIMAPI", "ot_port", 14, "HIGH",
                  category="OT", detail="Foxboro/Invensys DCS AIMAPI"),
    
    # Building automation (additional)
    PortSignature(11001, "TCP/UDP", "Metasys N1", "ot_port", 14, "HIGH",
                  category="OT", detail="Johnson Controls Metasys building automation"),
    PortSignature(18000, "TCP", "Genesis32", "ot_port", 14, "HIGH",
                  category="OT", detail="Iconics SCADA HMI communication"),
    
    # Fieldbus
    PortSignature(1089, "TCP/UDP", "Foundation Fieldbus HSE", "ot_port", 14, "HIGH",
                  category="OT", detail="Process automation — chemical, oil, gas"),
    PortSignature(1090, "TCP/UDP", "Foundation Fieldbus HSE", "ot_port", 14, "HIGH",
                  category="OT", detail="Process automation"),
    PortSignature(1091, "TCP/UDP", "Foundation Fieldbus HSE", "ot_port", 14, "HIGH",
                  category="OT", detail="Process automation"),
    
    # Japanese industrial Ethernet
    PortSignature(55000, "UDP", "FL-net", "ot_port", 14, "HIGH",
                  category="OT", detail="Japanese industrial Ethernet — FANUC, Mitsubishi"),
    PortSignature(55001, "UDP", "FL-net", "ot_port", 14, "HIGH",
                  category="OT", detail="Japanese industrial Ethernet"),
    PortSignature(55002, "UDP", "FL-net", "ot_port", 14, "HIGH",
                  category="OT", detail="Japanese industrial Ethernet"),
    PortSignature(55003, "UDP", "FL-net", "ot_port", 14, "HIGH",
                  category="OT", detail="Japanese industrial Ethernet"),
    
    # Phoenix Contact
    PortSignature(20547, "TCP", "PCWorx", "ot_port", 14, "HIGH",
                  category="OT", detail="Phoenix Contact PLC communication"),
    PortSignature(1962, "TCP", "PCWorx", "ot_port", 14, "HIGH",
                  category="OT", detail="Phoenix Contact PLC communication"),

    # GE
    PortSignature(18245, "TCP", "GE SRTP", "ot_port", 14, "HIGH",
                  category="OT", detail="GE PLC communication"),
]

# ── IT Service Ports ──────────────────────────────────────────────────────────

IT_PORT_SIGNATURES = [
    # Web services (low weight - ubiquitous in OT)
    PortSignature(80, "TCP", "HTTP", "service", 3, "LOW",
                  category="Service", detail="Web service - common in OT for HMIs, cameras, etc."),
    PortSignature(443, "TCP", "HTTPS", "service", 4, "LOW",
                  category="Service", detail="Secure web service - common in OT"),
    PortSignature(8080, "TCP", "HTTP (alternate)", "service", 3, "LOW",
                  category="Service", detail="Alternate web port"),
    PortSignature(8443, "TCP", "HTTPS (alternate)", "service", 4, "LOW",
                  category="Service", detail="Alternate secure web port"),
    
    # Remote access
    PortSignature(22, "TCP", "SSH/SFTP", "it_port", 8, "MEDIUM",
                  category="IT", detail="Secure shell - remote administration"),
    PortSignature(23, "TCP", "Telnet", "it_port", 6, "MEDIUM",
                  category="IT", detail="Insecure remote access - plaintext credentials"),
    PortSignature(3389, "TCP", "RDP", "it_port", 8, "MEDIUM",
                  category="IT", detail="Remote desktop - operator stations"),
    PortSignature(5900, "TCP", "VNC", "it_port", 6, "MEDIUM",
                  category="IT", detail="Remote desktop - HMI access"),
    
    # File sharing
    PortSignature(139, "TCP", "NetBIOS/SMB", "it_port", 6, "MEDIUM",
                  category="IT", detail="Windows file sharing"),
    PortSignature(445, "TCP", "SMB/CIFS", "it_port", 8, "MEDIUM",
                  category="IT", detail="Windows file sharing"),
    PortSignature(137, "UDP", "NetBIOS", "it_port", 4, "LOW",
                  category="IT", detail="Windows network browsing"),
    PortSignature(138, "UDP", "NetBIOS", "it_port", 4, "LOW",
                  category="IT", detail="Windows network browsing"),
    
    # Email
    PortSignature(25, "TCP", "SMTP", "it_port", 4, "LOW",
                  category="IT", detail="Email sending"),
    PortSignature(110, "TCP", "POP3", "it_port", 4, "LOW",
                  category="IT", detail="Email retrieval"),
    PortSignature(143, "TCP", "IMAP", "it_port", 4, "LOW",
                  category="IT", detail="Email retrieval"),
    
    # Database
    PortSignature(1433, "TCP", "MSSQL", "it_port", 6, "MEDIUM",
                  category="IT", detail="Microsoft SQL Server"),
    PortSignature(1434, "UDP", "MSSQL", "it_port", 4, "LOW",
                  category="IT", detail="Microsoft SQL Server"),
    PortSignature(3306, "TCP", "MySQL", "it_port", 6, "MEDIUM",
                  category="IT", detail="MySQL database"),
    PortSignature(5432, "TCP", "PostgreSQL", "it_port", 6, "MEDIUM",
                  category="IT", detail="PostgreSQL database"),
    
    # Directory services
    PortSignature(389, "TCP/UDP", "LDAP", "it_port", 6, "MEDIUM",
                  category="IT", detail="Directory services"),
    PortSignature(636, "TCP", "LDAPS", "it_port", 6, "MEDIUM",
                  category="IT", detail="Secure directory services"),
]

# ── Infrastructure Service Ports ─────────────────────────────────────────────

INFRASTRUCTURE_PORT_SIGNATURES = [
    PortSignature(53, "TCP/UDP", "DNS", "infra_port", 8, "MEDIUM",
                  category="Infrastructure", detail="Domain name resolution"),
    PortSignature(67, "UDP", "DHCP", "infra_port", 8, "MEDIUM",
                  category="Infrastructure", detail="Dynamic IP configuration"),
    PortSignature(68, "UDP", "DHCP", "infra_port", 8, "MEDIUM",
                  category="Infrastructure", detail="Dynamic IP configuration"),
    PortSignature(123, "UDP", "NTP", "infra_port", 6, "MEDIUM",
                  category="Infrastructure", detail="Time synchronization"),
    PortSignature(161, "UDP", "SNMP", "infra_port", 10, "HIGH",
                  category="Infrastructure", detail="Network device monitoring"),
    PortSignature(162, "UDP", "SNMP Trap", "infra_port", 6, "MEDIUM",
                  category="Infrastructure", detail="SNMP trap receiver"),
    PortSignature(514, "UDP", "Syslog", "infra_port", 6, "MEDIUM",
                  category="Infrastructure", detail="System logging"),
]

# ── Discovery Protocol Ports ──────────────────────────────────────────────────

DISCOVERY_PORT_SIGNATURES = [
    PortSignature(5353, "UDP", "mDNS", "discovery_port", 15, "HIGH",
                  category="Discovery", detail="Multicast DNS — device self-announcement"),
    PortSignature(3702, "UDP", "WS-Discovery", "discovery_port", 15, "HIGH",
                  category="Discovery", detail="Web Services Dynamic Discovery"),
]

# ── All Signatures ────────────────────────────────────────────────────────────

ALL_SIGNATURES: list[PortSignature] = (
    OT_PORT_SIGNATURES +
    IT_PORT_SIGNATURES +
    INFRASTRUCTURE_PORT_SIGNATURES +
    DISCOVERY_PORT_SIGNATURES
)

# ── Lookup Functions ──────────────────────────────────────────────────────────

def get_signature(port: int, transport: str = "TCP") -> Optional[PortSignature]:
    """Look up a port signature by port and transport."""
    for sig in ALL_SIGNATURES:
        if sig.port != port:
            continue
        # Dual-transport signatures ("TCP/UDP") match both TCP and UDP packets
        if sig.transport in ("Both", "TCP/UDP") or sig.transport == transport:
            return sig
    return None


def get_signatures_by_category(category: str) -> list[PortSignature]:
    """Get all signatures in a category."""
    return [s for s in ALL_SIGNATURES if s.category == category]


def get_ot_ports() -> set[int]:
    """Get all OT port numbers."""
    return {s.port for s in OT_PORT_SIGNATURES}


def get_it_ports() -> set[int]:
    """Get all IT port numbers."""
    return {s.port for s in IT_PORT_SIGNATURES}


def get_infrastructure_ports() -> set[int]:
    """Get all infrastructure port numbers."""
    return {s.port for s in INFRASTRUCTURE_PORT_SIGNATURES}


def get_discovery_ports() -> set[int]:
    """Get all discovery port numbers."""
    return {s.port for s in DISCOVERY_PORT_SIGNATURES}


def get_listener_ports() -> set[int]:
    """Ports that can be credited as a listening service: every signature port."""
    return {s.port for s in ALL_SIGNATURES}


def get_all_service_ports() -> set[int]:
    """Get all service-related ports."""
    return get_ot_ports() | get_it_ports() | get_infrastructure_ports() | get_discovery_ports()