"""
Vendor text shown and exported for an asset. Display only: classification never reads it, and it
adds no evidence and changes no score, class, role or confidence.

Vendor name: stored and exported exactly as the IEEE registry gives it, which can end in a comma
("Siemens AG,"). Screens, the CLI table, the topology page text and the assistant's tool results
show display_vendor_name instead, which drops only trailing commas and whitespace; CSV and JSON
exports keep the stored name.

Vendor note: says that the MAC prefix belongs to an OT-associated vendor while the capture showed
no OT service on the device. It never states that the device is OT, nor that it has no OT service.
Every surface (asset CSV, TUI detail panel and asset export, topology page, AI tools, CLI summary)
takes the text from vendor_note_for, so they always agree. A saved session keeps its stored vendor
data, so its note follows the vendor stored with it.
"""

VENDOR_NOTE = "OT-associated vendor; no OT service observed in this capture"


def display_vendor_name(name):
    """The vendor name as shown to people: trailing commas and whitespace removed, nothing else."""
    if not isinstance(name, str):
        return name
    return name.rstrip(", \t\r\n")


def vendor_note_for(vendor_class, classification_type) -> str:
    """The note for these field values: set when the vendor class is OT and the asset is not OT."""
    if vendor_class == "OT" and classification_type != "OT":
        return VENDOR_NOTE
    return ""


def vendor_note(asset) -> str:
    """The note for an asset (empty when it does not apply)."""
    return vendor_note_for(getattr(asset, "vendor_class", None), getattr(asset, "classification_type", None))


def count_vendor_notes(assets) -> int:
    """How many of the assets carry the note."""
    return sum(1 for asset in assets if vendor_note(asset))
