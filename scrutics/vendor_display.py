"""
Vendor note shown and exported for an asset.

Display only: classification never reads it, and it adds no evidence and changes no score, class,
role or confidence. It says that the MAC prefix belongs to an OT-associated vendor while the
capture showed no OT service on the device. It never states that the device is OT, nor that it
has no OT service.

Every surface (asset CSV, TUI detail panel and asset export, topology page, AI tools, CLI summary)
takes the text from vendor_note_for, so they always agree. A saved session keeps its stored vendor
data, so its note follows the vendor stored with it.
"""

VENDOR_NOTE = "OT-associated vendor; no OT service observed in this capture"


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
