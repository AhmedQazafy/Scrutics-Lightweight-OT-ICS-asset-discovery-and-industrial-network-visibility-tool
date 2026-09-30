"""
Asset classification from observed facts.

classify_asset() is the only code that decides an asset's classification_type during
capture. The decision is a precedence list; the first rule that matches wins:

  1. a user rule matches the asset by listening port or MAC      -> the rule's class
  2. device-level infrastructure evidence                       -> Infrastructure
     (no such evidence type exists yet, so this rule never matches)
  3. serves a validated OT protocol                             -> OT, HIGH
  4. listens on a port whose signature is OT                    -> OT, MEDIUM
  5. sends validated OT protocol requests                       -> OT, MEDIUM, role "OT client"
  6. listens on a port whose signature is IT                    -> IT, MEDIUM
  7. otherwise                                                  -> Unknown, LOW, with a reason

Class votes come only from the port signature table: listening-port signatures of category
OT or IT, and validated protocol names matched to signature names. Vendor/OUI, DHCP, OS
hints, hostnames, behavior, discovery, infrastructure-service ports and generic management
ports never vote; they are listed in the reason.

The result depends only on the asset's current state (listening and contacted ports,
protocol observation summaries, evidence, MAC) and the loaded user rules. The function
never reads its own outputs, so repeated calls give the same result.
"""

from dataclasses import dataclass

from scrutics.classifier.protocol import match_user_rule
from scrutics.classifier.signatures import ALL_SIGNATURES

_VOTING_CATEGORIES = ("OT", "IT")

# Port -> signature, and validated protocol name -> class, both from the signature table
_SIGNATURE_BY_PORT = {sig.port: sig for sig in ALL_SIGNATURES}
_PROTOCOL_CLASS = {
    sig.name: sig.category for sig in ALL_SIGNATURES if sig.category in _VOTING_CATEGORIES
}

RULE_USER = "user_rule"
RULE_SERVES_VALIDATED_OT_PROTOCOL = "serves_validated_ot_protocol"
RULE_SERVES_OT_PORT = "serves_ot_port"
RULE_SENDS_VALIDATED_OT_REQUESTS = "sends_validated_ot_requests"
RULE_SERVES_IT_PORT = "serves_it_port"
RULE_NONE = "no_classifying_evidence"

REASON_NO_OBSERVATIONS = "no services or protocol observations"
REASON_NO_CLASSIFYING_EVIDENCE = "no classifying evidence"
REASON_POSSIBLE_OT_CLIENT = "possible OT client"

OT_CLIENT_ROLE = "OT client"


@dataclass(frozen=True)
class _Signal:
    rank: int          # precedence position; lower wins
    rule: str
    service: tuple     # ("serves" | "sends", service name); one signal per service
    cls: str
    confidence: str
    reason: str        # text when this signal decides or supports the result
    note: str          # text when this signal conflicts with the result


def _signals(asset) -> list:
    signals = []
    summaries = getattr(asset, "protocol_summaries", {}) or {}
    for name in sorted(summaries):
        summary = summaries[name]
        if _PROTOCOL_CLASS.get(name) != "OT":
            continue
        if summary.answers_as_server:
            signals.append(_Signal(
                3, RULE_SERVES_VALIDATED_OT_PROTOCOL, ("serves", name), "OT", "HIGH",
                f"serves validated OT protocol: {name}",
                f"also serves validated OT protocol: {name}",
            ))
        if summary.sends_requests:
            signals.append(_Signal(
                5, RULE_SENDS_VALIDATED_OT_REQUESTS, ("sends", name), "OT", "MEDIUM",
                f"sends validated OT protocol requests: {name}",
                f"also sends validated OT protocol requests: {name}",
            ))
    for port in sorted(asset.ports_seen):
        sig = _SIGNATURE_BY_PORT.get(port)
        if sig is None or sig.category not in _VOTING_CATEGORIES:
            continue
        label = f"{sig.name} ({port})"
        if sig.category == "OT":
            signals.append(_Signal(
                4, RULE_SERVES_OT_PORT, ("serves", sig.name), "OT", "MEDIUM",
                f"listens on OT port: {label}", f"also serves OT service: {label}",
            ))
        else:
            signals.append(_Signal(
                6, RULE_SERVES_IT_PORT, ("serves", sig.name), "IT", "MEDIUM",
                f"listens on IT port: {label}", f"also serves IT service: {label}",
            ))
    # A service validated by its parser and also seen on its port is one signal (the stronger)
    best = {}
    for signal in sorted(signals, key=lambda s: (s.rank, s.reason)):
        best.setdefault(signal.service, signal)
    return sorted(best.values(), key=lambda s: (s.rank, s.reason))


def _service_label(port: int) -> str:
    sig = _SIGNATURE_BY_PORT.get(port)
    return f"{sig.name} ({port})" if sig else f"port {port}"


def _non_voting_details(asset) -> dict:
    """
    Observed facts that never vote, listed so a result can be explained.
    Keys: "contacted" (OT ports contacted but not served), "served" (non-voting services
    the asset offers), "vendor" (vendor evidence values); each is a text part or None.
    """
    details = {"contacted": None, "served": None, "vendor": None}
    contacted_ot = sorted(
        port for port in asset.contacted_ports
        if port not in asset.ports_seen
        and getattr(_SIGNATURE_BY_PORT.get(port), "category", None) == "OT"
    )
    if contacted_ot:
        details["contacted"] = "contacted OT ports: " + ", ".join(_service_label(p) for p in contacted_ot)
    served = sorted(
        port for port in asset.ports_seen
        if getattr(_SIGNATURE_BY_PORT.get(port), "category", None) not in _VOTING_CATEGORIES
    )
    if served:
        details["served"] = "serves: " + ", ".join(_service_label(p) for p in served)
    vendors = sorted({
        str(e.value) for e in asset.evidence
        if e.type == "vendor" and e.value and e.value != "Unknown"
    })
    if vendors:
        details["vendor"] = "vendor: " + ", ".join(vendors)
    return details


def _join(base: str, parts: list) -> str:
    return "; ".join([base] + parts)


def classify_asset(asset) -> None:
    """Decide classification_type, decision confidence, rule, reason and conflicts."""
    signals = _signals(asset)
    details = _non_voting_details(asset)
    # Non-voting services and vendors explain a decided class but never change it
    decided_details = [d for d in (details["served"], details["vendor"]) if d]

    rule, matched_port, confidence_override = match_user_rule(asset.ports_seen, asset.mac)
    if rule is not None:
        cls = "OT" if rule.get("is_ot") else "IT"
        how = f"port {matched_port}" if matched_port is not None else "MAC"
        asset.classification_type = cls
        asset.confidence = confidence_override or rule.get("confidence", "HIGH")
        asset.classification_rule = RULE_USER
        asset.classification_reason = _join(
            f"user rule '{rule.get('name', '')}' matched {how}",
            [f"also: {s.reason}" for s in signals if s.cls == cls] + decided_details,
        )
        asset.classification_conflicts = [s.note for s in signals if s.cls != cls]
        return

    if signals:
        winner = signals[0]
        rest = signals[1:]
        asset.classification_type = winner.cls
        asset.confidence = winner.confidence
        asset.classification_rule = winner.rule
        asset.classification_reason = _join(
            winner.reason,
            [f"also: {s.reason}" for s in rest if s.cls == winner.cls] + decided_details,
        )
        asset.classification_conflicts = [s.note for s in rest if s.cls != winner.cls]
        if winner.rule == RULE_SENDS_VALIDATED_OT_REQUESTS:
            asset.role = OT_CLIENT_ROLE
        return

    if details["contacted"]:
        base = REASON_POSSIBLE_OT_CLIENT
    elif details["served"]:
        base = REASON_NO_CLASSIFYING_EVIDENCE
    else:
        base = REASON_NO_OBSERVATIONS
    asset.classification_type = "Unknown"
    asset.confidence = "LOW"
    asset.classification_rule = RULE_NONE
    asset.classification_reason = _join(
        base, [d for d in (details["contacted"], details["served"], details["vendor"]) if d]
    )
    asset.classification_conflicts = []
