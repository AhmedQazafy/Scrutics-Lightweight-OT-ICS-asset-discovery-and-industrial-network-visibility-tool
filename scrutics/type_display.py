"""
Classification type text shown in the asset tables and the TUI detail panel. Display only: the
stored and exported classification_type keeps "Unknown", so session files, CSV and JSON exports
and the AI tools see the value unchanged.
"""

UNCLASSIFIED = "Unclassified"


def classification_type_label(classification_type) -> str:
    """The classification type as shown to people: "Unclassified" for "Unknown"."""
    if not classification_type or classification_type == "Unknown":
        return UNCLASSIFIED
    return str(classification_type)
