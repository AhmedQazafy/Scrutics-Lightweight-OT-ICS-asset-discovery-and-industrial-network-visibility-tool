"""
Protocol text shown and exported for an asset.

Display only: classification never reads these values. Each entry names a protocol and says how
it is known, so the text never states more than the evidence does:

- a served protocol is shown by name when a parser saw the asset answer as a server for it, and
  with " (port)" when it is known only from a listening port;
- a protocol a parser saw the asset send requests for is shown with " (client)";
- an OT service the asset only contacted by port is shown with " (client, port)".
"""

from scrutics.classifier.signatures import get_signature

PORT_QUALIFIER = " (port)"
CLIENT_QUALIFIER = " (client)"
CLIENT_PORT_QUALIFIER = " (client, port)"
QUALIFIERS = (CLIENT_PORT_QUALIFIER, CLIENT_QUALIFIER, PORT_QUALIFIER)

# Characters given to protocol text in the TUI and CLI asset tables
PROTOCOL_COLUMN_WIDTH = 32

# Separates entries in the protocol_display CSV column; an entry itself can contain ", "
DISPLAY_SEPARATOR = "|"

# Served value that already states it rests on standard ports only; shown as written
IT_PORTS_ONLY = "IT (standard ports only)"


def protocol_display_entries(asset) -> list:
    """
    The asset's protocol entries in display order: served, then validated client use, then OT
    services contacted by port only. Empty when none is known.

    An asset loaded from a saved session has no capture state, so the entries read back with it
    are returned instead.
    """
    restored = getattr(asset, "restored_protocol_display", None)
    if restored is not None:
        return list(restored)

    summaries = getattr(asset, "protocol_summaries", None) or {}
    entries = []

    for name in getattr(asset, "protocols", None) or []:
        if not name or name == "Unknown":
            continue
        summary = summaries.get(name)
        if name == IT_PORTS_ONLY or (summary is not None and summary.answers_as_server):
            entry = name
        else:
            entry = name + PORT_QUALIFIER
        if entry not in entries:
            entries.append(entry)

    client_names = [name for name, summary in summaries.items() if summary.sends_requests]
    for name in sorted(client_names):
        entries.append(name + CLIENT_QUALIFIER)

    port_only = []
    for port in sorted(getattr(asset, "contacted_ports", None) or ()):
        sig = get_signature(port, "TCP") or get_signature(port, "UDP")
        if sig is None or sig.category != "OT":
            continue
        if sig.name in client_names or sig.name in port_only:
            continue
        port_only.append(sig.name)
    entries.extend(name + CLIENT_PORT_QUALIFIER for name in port_only)

    return entries


def split_display_column(value) -> list:
    """Entries from a saved protocol_display column value."""
    return [entry for entry in (value or "").split(DISPLAY_SEPARATOR) if entry]


def protocol_display_text(asset, width: int | None = None) -> str:
    """The asset's protocol entries as one line, "Unknown" when none is known."""
    return format_protocol_entries(protocol_display_entries(asset), width)


def _split_qualifier(entry: str) -> tuple:
    for qualifier in QUALIFIERS:
        if entry.endswith(qualifier):
            return entry[: -len(qualifier)], qualifier
    return entry, ""


def format_protocol_entries(entries, width: int | None = None) -> str:
    """
    Join entries with ", " ("Unknown" when there are none), fitting the text in width characters
    when one is given.

    Qualifiers are never cut: the longest protocol name is shortened first, with a trailing "~".
    When every name is down to a few characters and the text still does not fit, trailing
    entries are left out and the count left out is shown as "+N".
    """
    entries = [e for e in entries if e]
    if not entries:
        return "Unknown"
    text = ", ".join(entries)
    if width is None or len(text) <= width:
        return text

    parts = [list(_split_qualifier(e)) for e in entries]
    min_name = 3

    def render(items, hidden):
        out = ", ".join(name + qualifier for name, qualifier in items)
        return out + (f", +{hidden}" if hidden else "")

    hidden = 0
    while True:
        shown = parts[: len(parts) - hidden]
        while len(render(shown, hidden)) > width:
            longest = max(shown, key=lambda p: len(p[0]))
            if len(longest[0]) <= min_name:
                break
            name = longest[0].rstrip("~")
            longest[0] = name[: max(min_name, len(name) - 1) - 1] + "~"
        text = render(shown, hidden)
        if len(text) <= width or len(shown) <= 1:
            return text
        hidden += 1
        parts = [list(_split_qualifier(e)) for e in entries]
