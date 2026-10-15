"""
Vendor text shown and exported for an asset. Display only: classification never reads it, and it
adds no evidence and changes no score, class, role or confidence.

Vendor name: stored and exported exactly as the IEEE registry gives it, which can end in a comma
("Siemens AG,"). Screens, the CLI table, the topology page text and the assistant's tool results
show display_vendor_name instead, which drops only trailing commas and whitespace; CSV and JSON
exports keep the stored name.

Vendor note: says that the MAC prefix belongs to an OT-associated vendor while the capture showed
no OT service on the device. It never states that the device is OT, nor that it has no OT service.
It is set only when all hold: the vendor class is OT; classification_type is not OT; and no OT
service was observed on the device, meaning no served port whose signature category is OT and no
validated OT protocol answered as the server. The last condition matters when a user rule
classifies a device that serves an OT port as non-OT.
Every surface (asset CSV, TUI detail panel and asset export, topology page, AI tools, CLI summary)
takes the text from vendor_note_for, so they always agree. A saved session keeps its stored vendor
data, so its note follows the vendor stored with it.
"""

from scrutics.classifier.signatures import ALL_SIGNATURES

VENDOR_NOTE = "OT-associated vendor; no OT service observed in this capture"

# The classifier's own tables: port -> signature category, validated protocol name -> class
_PORT_CATEGORY = {sig.port: sig.category for sig in ALL_SIGNATURES}
_PROTOCOL_CLASS = {sig.name: sig.category for sig in ALL_SIGNATURES if sig.category in ("OT", "IT")}


def display_vendor_name(name):
    """The vendor name as shown to people: trailing commas and whitespace removed, nothing else."""
    if not isinstance(name, str):
        return name
    return name.rstrip(", \t\r\n")


def ot_service_observed(ports_seen, protocol_summaries=None) -> bool:
    """Whether a served port has an OT signature, or a validated OT protocol answered as the server."""
    if any(_PORT_CATEGORY.get(port) == "OT" for port in ports_seen or ()):
        return True
    return any(_PROTOCOL_CLASS.get(name) == "OT" and getattr(summary, "answers_as_server", False)
               for name, summary in (protocol_summaries or {}).items())


def vendor_note_for(vendor_class, classification_type, ot_service: bool = False) -> str:
    """
    The note for these field values: set when the vendor class is OT, the asset is not OT and no
    OT service was observed on it.
    """
    if vendor_class == "OT" and classification_type != "OT" and not ot_service:
        return VENDOR_NOTE
    return ""


def vendor_note(asset) -> str:
    """The note for an asset (empty when it does not apply)."""
    return vendor_note_for(
        getattr(asset, "vendor_class", None), getattr(asset, "classification_type", None),
        ot_service_observed(getattr(asset, "ports_seen", ()), getattr(asset, "protocol_summaries", None)),
    )


def count_vendor_notes(assets) -> int:
    """How many of the assets carry the note."""
    return sum(1 for asset in assets if vendor_note(asset))
