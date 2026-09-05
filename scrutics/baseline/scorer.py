"""
Multi-factor confidence scoring for Scrutics.
OUI (0-30) + Protocol (0-40) + Behavioral (0-20) + Directionality (0-10) = 0-100%
"""

OUI_WEIGHT         = 30
PROTOCOL_WEIGHT    = 40
BEHAVIORAL_WEIGHT  = 20
DIRECTIONAL_WEIGHT = 10


def oui_score(is_ot_vendor: bool) -> int:
    return OUI_WEIGHT if is_ot_vendor else 0


def protocol_score(matched_ics: bool, matched_it: bool) -> int:
    if matched_ics:  return PROTOCOL_WEIGHT
    elif matched_it: return 15
    return 0


def confidence_pct(oui_s: int, protocol_s: int, behavioral_s: int, directional_s: int,
                   evidence: list = None) -> int:
    """Calculate confidence percentage."""
    if evidence:
        return confidence_from_evidence(evidence)
    return min(oui_s + protocol_s + behavioral_s + directional_s, 100)


def confidence_from_evidence(evidence: list) -> int:
    """Calculate confidence percentage from evidence list."""
    if not evidence:
        return 0
    total_weight = sum(e.weight for e in evidence)
    # Cap at 100
    return min(total_weight, 100)


def confidence_color(pct: int) -> str:
    if pct >= 70: return "bold green"
    elif pct >= 40: return "yellow"
    return "red"