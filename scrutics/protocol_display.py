"""
Protocol text shown and exported for an asset.

Display only: classification never reads these values. Each entry names a protocol and says how
it is known, so the text never states more than the evidence does:

- a served protocol is shown by name when a parser saw the asset answer as a server for it, and
  with " (port)" when it is known only from a listening port;
- a protocol a parser saw the asset send requests for is shown with " (client)";
- a service the asset only contacted by port is shown with " (client, port)";
- a discovery protocol the asset used is shown with " (discovery)".

OT entries come first, then IT services the asset serves, then IT services it contacted, each IT
group in IT_DISPLAY_ORDER, then discovery protocols.
"""

from scrutics.classifier.signatures import get_signature

PORT_QUALIFIER = " (port)"
CLIENT_QUALIFIER = " (client)"
CLIENT_PORT_QUALIFIER = " (client, port)"
DISCOVERY_QUALIFIER = " (discovery)"
QUALIFIERS = (CLIENT_PORT_QUALIFIER, CLIENT_QUALIFIER, PORT_QUALIFIER, DISCOVERY_QUALIFIER)

# Characters given to protocol text in the TUI and CLI asset tables
PROTOCOL_COLUMN_WIDTH = 32

# Title of the protocol text wherever it is labeled for users
PROTOCOL_COLUMN_TITLE = "Protocols"

# Shown when no protocol entry is known
NONE_OBSERVED = "None observed"

# Separates entries in the protocol_display CSV column; an entry itself can contain ", "
DISPLAY_SEPARATOR = "|"

# Served value that states it rests on standard ports only; shown as written when none of the
# served IT ports has a signature name
IT_PORTS_ONLY = "IT (standard ports only)"

# Display order of IT, service and infrastructure signature names: remote access and file sharing
# first, web, DNS, NTP and DHCP last. Names not listed follow, by port.
IT_DISPLAY_ORDER = (
    "Telnet", "RDP", "VNC", "SSH/SFTP",
    "SMB/CIFS", "NetBIOS/SMB",
    "MSSQL", "MySQL", "PostgreSQL", "LDAP", "LDAPS",
    "SNMP", "SNMP Trap",
    "SMTP", "POP3", "IMAP",
    "NetBIOS", "Syslog",
    "HTTP", "HTTPS", "HTTP (alternate)", "HTTPS (alternate)",
    "DNS", "NTP", "DHCP",
)
IT_CATEGORIES = ("IT", "Service", "Infrastructure")

# DHCP server and client ports (RFC 2131 section 4.1): a client contacting the server port is
# shown as DHCP discovery, never as a contacted service
DHCP_SERVER_PORT = 67
DHCP_PORTS = (67, 68)
DISCOVERY_ORDER = ("mDNS", "WS-Discovery", "DHCP")
# Evidence sources that show the asset used a discovery protocol
DISCOVERY_SOURCES = {"mDNS": "mDNS", "WS-Discovery": "WS-Discovery", "DHCP": "DHCP"}


def _port_signature(port):
    return get_signature(port, "TCP") or get_signature(port, "UDP")


def _it_names(ports) -> list:
    """Signature names of the IT, service and infrastructure ports, in IT_DISPLAY_ORDER."""
    names = []
    for port in sorted(ports):
        sig = _port_signature(port)
        if sig is not None and sig.category in IT_CATEGORIES and sig.name not in names:
            names.append(sig.name)
    rank = {name: i for i, name in enumerate(IT_DISPLAY_ORDER)}
    # sorted() is stable, so unlisted names keep their port order after the listed ones
    return sorted(names, key=lambda name: rank.get(name, len(rank)))


def _discovery_names(asset) -> list:
    """Discovery protocols shown by the asset's evidence or its contacted ports."""
    found = set()
    for ev in getattr(asset, "evidence", None) or []:
        source = getattr(ev, "source", None)
        name = DISCOVERY_SOURCES.get(source) if isinstance(source, str) else None
        if name:
            found.add(name)
    for port in getattr(asset, "contacted_ports", None) or ():
        if port == DHCP_SERVER_PORT:
            found.add("DHCP")
            continue
        sig = _port_signature(port)
        if sig is not None and sig.category == "Discovery":
            found.add(sig.name)
    for port in getattr(asset, "ports_seen", None) or ():
        sig = _port_signature(port)
        if sig is not None and sig.category == "Discovery":
            found.add(sig.name)
    ordered = [name for name in DISCOVERY_ORDER if name in found]
    return ordered + sorted(found.difference(ordered))


def protocol_display_entries(asset) -> list:
    """
    The asset's protocol entries in display order: OT served, OT validated client use, OT
    services contacted by port only, IT services served, IT services contacted, then discovery
    protocols. Empty when none is known.

    An asset loaded from a saved session has no capture state, so the entries read back with it
    are returned instead.
    """
    restored = getattr(asset, "restored_protocol_display", None)
    if restored is not None:
        return list(restored)

    summaries = getattr(asset, "protocol_summaries", None) or {}
    entries = []

    served = getattr(asset, "protocols", None) or []
    for name in served:
        if not name or name == "Unknown" or name == IT_PORTS_ONLY:
            continue
        summary = summaries.get(name)
        if summary is not None and summary.answers_as_server:
            entry = name
        else:
            entry = name + PORT_QUALIFIER
        if entry not in entries:
            entries.append(entry)

    client_names = [name for name, summary in summaries.items() if summary.sends_requests]
    for name in sorted(client_names):
        entries.append(name + CLIENT_QUALIFIER)

    contacted = getattr(asset, "contacted_ports", None) or ()
    port_only = []
    for port in sorted(contacted):
        sig = _port_signature(port)
        if sig is None or sig.category != "OT":
            continue
        if sig.name in client_names or sig.name in port_only:
            continue
        port_only.append(sig.name)
    entries.extend(name + CLIENT_PORT_QUALIFIER for name in port_only)

    it_served = [name + PORT_QUALIFIER for name in _it_names(getattr(asset, "ports_seen", None) or ())]
    # A standard IT port without a signature name keeps the classifier's text
    if not it_served and IT_PORTS_ONLY in served:
        it_served = [IT_PORTS_ONLY]
    entries.extend(e for e in it_served if e not in entries)

    it_contacted = _it_names(p for p in contacted if p not in DHCP_PORTS)
    entries.extend(name + CLIENT_PORT_QUALIFIER for name in it_contacted)

    entries.extend(name + DISCOVERY_QUALIFIER for name in _discovery_names(asset))
    return entries


def split_display_column(value) -> list:
    """Entries from a saved protocol_display column value."""
    return [entry for entry in (value or "").split(DISPLAY_SEPARATOR) if entry]


def protocol_display_text(asset, width: int | None = None) -> str:
    """The asset's protocol entries as one line, "None observed" when none is known."""
    return format_protocol_entries(protocol_display_entries(asset), width)


def _split_qualifier(entry: str) -> tuple:
    for qualifier in QUALIFIERS:
        if entry.endswith(qualifier):
            return entry[: -len(qualifier)], qualifier
    return entry, ""


def format_protocol_entries(entries, width: int | None = None) -> str:
    """
    Join entries with ", " ("None observed" when there are none), fitting the text in width
    characters when one is given.

    Entries are in priority order, so trailing entries are left out first and the count left
    out is shown as "+N". Only when the first entry alone (with its "+N") still does not fit is
    its protocol name shortened, with a trailing "~"; qualifiers are never cut.
    """
    entries = [e for e in entries if e]
    if not entries:
        return NONE_OBSERVED
    text = ", ".join(entries)
    if width is None or len(text) <= width:
        return text

    def render(items, hidden):
        out = ", ".join(items)
        return out + (f", +{hidden}" if hidden else "")

    for hidden in range(1, len(entries)):
        text = render(entries[: len(entries) - hidden], hidden)
        if len(text) <= width:
            return text

    hidden = len(entries) - 1
    name, qualifier = _split_qualifier(entries[0])
    min_name = 3
    while len(render([name + qualifier], hidden)) > width and len(name.rstrip("~")) > min_name:
        name = name.rstrip("~")
        name = name[: max(min_name, len(name) - 1) - 1] + "~"
    return render([name + qualifier], hidden)
