"""Protocol-based device classification.

Rule precedence:  user rules → builtin YAML rules → hardcoded ICS_PORTS fallback.
Hot-reload via reload_rules() — replaces both rule sets in-place, thread-safe via GIL.
"""

import threading

from scrutics.config.loader import load_user_rules, load_builtin_rules, match_rule

# ── Hardcoded fallback (used only if builtin_rules.yaml fails to load) ─────────
ICS_PORTS = {
    502:   {"protocol": "Modbus TCP",      "role": "PLC / RTU / Modbus Gateway"},
    102:   {"protocol": "S7comm",          "role": "Siemens PLC"},
    44818: {"protocol": "EtherNet/IP",     "role": "Rockwell / Allen-Bradley Device"},
    2222:  {"protocol": "EtherNet/IP IO",  "role": "Rockwell IO Device"},
    20000: {"protocol": "DNP3",            "role": "Utility RTU / IED"},
    1911:  {"protocol": "Niagara Fox",     "role": "Building Automation Controller"},
    4840:  {"protocol": "OPC-UA",          "role": "OPC-UA Server / Gateway"},
    9600:  {"protocol": "OMRON FINS",      "role": "Omron PLC"},
    18245: {"protocol": "GE SRTP",         "role": "GE PLC"},
    2404:  {"protocol": "IEC 60870-5-104", "role": "Power Grid RTU / IED"},
    1962:  {"protocol": "PCWorx",          "role": "Phoenix Contact PLC"},
    47808: {"protocol": "BACnet/IP",       "role": "Building Automation Device"},
}
IT_PORTS = {80, 443, 22, 23, 21, 25, 53, 110, 143, 3389, 5900}

CONFIDENCE_HIGH   = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW    = "LOW"

# ── Live rule sets (replaced atomically on reload) ─────────────────────────────
_RULE_LOCK = threading.RLock()
_USER_RULES    = load_user_rules()
_BUILTIN_RULES = load_builtin_rules()


def reload_rules():
    """Hot-reload both rule sets from YAML. Raises ConfigError on bad config."""
    global _USER_RULES, _BUILTIN_RULES
    new_user_rules = load_user_rules(strict=True)
    new_builtin_rules = load_builtin_rules(strict=True)
    with _RULE_LOCK:
        _USER_RULES = new_user_rules
        _BUILTIN_RULES = new_builtin_rules
    return {
        "user_rules": len(new_user_rules),
        "builtin_rules": len(new_builtin_rules),
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def known_service_ports() -> set[int]:
    """Return ports that are meaningful listener/service signals."""
    with _RULE_LOCK:
        rules = list(_USER_RULES) + list(_BUILTIN_RULES)
    ports = set(IT_PORTS) | set(ICS_PORTS)
    for rule in rules:
        port = rule.get("port")
        if isinstance(port, int):
            ports.add(port)
    return ports


_BEHAVIORAL_FIELDS = frozenset({
    "never_initiates", "allowed_peers", "allowed_ports",
    "alert_on_new_port", "max_new_peers_per_hour",
})


def _rule_to_result(rule: dict, source: str, confidence: str = None) -> dict:
    result = {
        "protocols":              [rule.get("classify_as", "Custom Protocol")],
        "role":                   rule.get("role", "Custom Device"),
        "is_ot":                  rule.get("is_ot", None),
        "confidence":             confidence or rule.get("confidence", CONFIDENCE_HIGH),
        "matched_rule":           source,
        "behavioral_constraints": {k: rule[k] for k in _BEHAVIORAL_FIELDS if k in rule},
    }
    return result


def classify_by_ports(ports_seen: set, mac: str = None) -> dict:
    with _RULE_LOCK:
        user_rules = list(_USER_RULES)
        builtin_rules = list(_BUILTIN_RULES)

    # 1. User rules — single match, early return
    for port in ports_seen:
        rule = match_rule(user_rules, port=port, mac=mac)
        if rule:
            return _rule_to_result(rule, "user")
    if mac:
        rule = match_rule(user_rules, mac=mac)
        if rule:
            return _rule_to_result(rule, "user", confidence=CONFIDENCE_MEDIUM)

    # 2. Builtin YAML rules — collect all matches for multi-protocol detection
    if builtin_rules:
        matched = [match_rule(builtin_rules, port=p) for p in ports_seen]
        matched = [r for r in matched if r]
        if matched:
            if len(matched) > 1:
                # Merge behavioral constraints across all matched rules
                merged_constraints = {}
                for r in matched:
                    for k in _BEHAVIORAL_FIELDS:
                        if k in r:
                            merged_constraints[k] = r[k]
                return {
                    "protocols":              [r.get("classify_as", "Unknown") for r in matched],
                    "role":                   "SCADA Server / HMI (multi-protocol)",
                    "is_ot":                  True,
                    "confidence":             CONFIDENCE_HIGH,
                    "matched_rule":           "builtin",
                    "behavioral_constraints": merged_constraints,
                }
            return _rule_to_result(matched[0], "builtin")

    # 3. Hardcoded fallback (builtin YAML missing or empty)
    else:
        matched_ics = [{**ICS_PORTS[p], "port": p} for p in ports_seen if p in ICS_PORTS]
        if matched_ics:
            role = ("SCADA Server / HMI (multi-protocol)"
                    if len(matched_ics) > 1 else matched_ics[0]["role"])
            return {
                "protocols":              [m["protocol"] for m in matched_ics],
                "role":                   role,
                "is_ot":                  True,
                "confidence":             CONFIDENCE_HIGH,
                "matched_rule":           "builtin",
                "behavioral_constraints": {},
            }

    # 4. IT-only or unclassified
    it_only = bool(ports_seen) and ports_seen.issubset(IT_PORTS)
    if it_only:
        return {
            "protocols":              ["IT (standard ports only)"],
            "role":                   "IT Device",
            "is_ot":                  False,
            "confidence":             CONFIDENCE_MEDIUM,
            "matched_rule":           "builtin",
            "behavioral_constraints": {},
        }
    return {
        "protocols":              ["Unknown"],
        "role":                   "Unclassified -- review manually",
        "is_ot":                  None,
        "confidence":             CONFIDENCE_LOW,
        "matched_rule":           None,
        "behavioral_constraints": {},
    }


# ── Evidence generation from matched port classifications ─────────────────────

def classification_evidence_from_ports(ports_seen: set, mac: str = None) -> list:
    """Generate evidence objects from observed ports and MAC."""
    evidence = []

    # Check ICS ports
    for port in ports_seen:
        if port in ICS_PORTS:
            evidence.append({
                "type": "port",
                "value": str(port),
                "weight": 10,
                "source": "traffic",
                "confidence": "HIGH",
                "detail": f"OT port {port} ({ICS_PORTS[port]['protocol']})"
            })
        elif port in IT_PORTS:
            evidence.append({
                "type": "port",
                "value": str(port),
                "weight": 5,
                "source": "traffic",
                "confidence": "MEDIUM",
                "detail": f"IT port {port}"
            })

    # Check MAC vendor (if provided)
    if mac:
        from scrutics.classifier.oui import (
            lookup_vendor, classify_vendor,
            VENDOR_CLASS_OT, VENDOR_CLASS_IT, VENDOR_CLASS_NEUTRAL
        )
        # Load OUI DB (lazy import to avoid circular dependency)
        try:
            from scrutics.classifier.oui import load_oui_db
            oui_db = load_oui_db()
            vendor = lookup_vendor(mac, oui_db)
            if vendor and vendor != "Unknown":
                vclass = classify_vendor(vendor)
                if vclass == VENDOR_CLASS_OT:
                    evidence.append({
                        "type": "vendor",
                        "value": vendor,
                        "weight": 30,
                        "source": "OUI",
                        "confidence": "HIGH",
                        "detail": f"OT vendor: {vendor}"
                    })
                elif vclass == VENDOR_CLASS_IT:
                    evidence.append({
                        "type": "vendor",
                        "value": vendor,
                        "weight": 15,
                        "source": "OUI",
                        "confidence": "MEDIUM",
                        "detail": f"IT/networking vendor: {vendor}"
                    })
                elif vclass == VENDOR_CLASS_NEUTRAL:
                    evidence.append({
                        "type": "vendor",
                        "value": vendor,
                        "weight": 10,
                        "source": "OUI",
                        "confidence": "MEDIUM",
                        "detail": f"Dual-use vendor: {vendor}"
                    })
                else:
                    evidence.append({
                        "type": "vendor",
                        "value": vendor,
                        "weight": 5,
                        "source": "OUI",
                        "confidence": "LOW",
                        "detail": f"Vendor: {vendor}"
                    })
        except Exception:
            pass  # Silently fail if OUI DB can't be loaded

    return evidence