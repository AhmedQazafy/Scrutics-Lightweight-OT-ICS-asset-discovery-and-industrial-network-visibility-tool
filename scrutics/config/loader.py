"""
Configuration loader for Scrutics.

Search order for user config:
  1. ~/.scrutics/scrutics.yaml    (advanced override, home directory)
  2. package custom_rules.yaml    (default, always present, users edit this directly)

  The intended workflow is simple: edit scrutics/config/custom_rules.yaml directly.
  The ~/.scrutics/scrutics.yaml path exists for advanced users who want a
  machine-wide config independent of the cloned repository.

Builtin rules always load from the package builtin_rules.yaml.
User/custom rules always take precedence over builtin rules.
"""

import os
import ipaddress
from typing import Any

import yaml

_PKG_DIR         = os.path.dirname(__file__)
_BUILTIN_PATH    = os.path.join(_PKG_DIR, "builtin_rules.yaml")
_CUSTOM_TEMPLATE = os.path.join(_PKG_DIR, "custom_rules.yaml")
_VALID_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
_VALID_PROTOCOLS = {"TCP", "UDP"}
_VALID_SINK_FORMATS = {"json", "cef", "leef", "plain"}

_USER_SEARCH_PATHS = [
    os.path.join(os.path.expanduser("~"), ".scrutics", "scrutics.yaml"),
]


class ConfigError(ValueError):
    """Raised when a Scrutics YAML config file is malformed."""


def get_user_config_paths() -> list[str]:
    """Return user-editable config paths in search order."""
    return list(_USER_SEARCH_PATHS)


def get_active_user_config_path() -> str | None:
    """Return the active user config path. Checks override paths first, then the package default."""
    for path in _USER_SEARCH_PATHS:
        if os.path.exists(path):
            return path
    # Package custom_rules.yaml is always the active config when no override exists
    return _CUSTOM_TEMPLATE


def _load_yaml(path: str, *, strict: bool = False) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        if strict:
            raise ConfigError(f"{path}: YAML parse error: {e}") from e
        return {}
    except OSError as e:
        if strict:
            raise ConfigError(f"{path}: cannot read config: {e}") from e
        return {}
    if not isinstance(data, dict):
        if strict:
            raise ConfigError(f"{path}: top-level YAML value must be a mapping")
        return {}
    return data


def _find_user_config(*, strict: bool = False) -> dict:
    for path in _USER_SEARCH_PATHS:
        if os.path.exists(path):
            return _load_yaml(path, strict=strict)
    return _load_yaml(_CUSTOM_TEMPLATE, strict=strict)


def _require_mapping_list(value: Any, field: str, source: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{source}: {field} must be a list")
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ConfigError(f"{source}: {field}[{index}] must be a mapping")
    return value


def validate_rules(rules: list, *, source: str = "rules") -> list:
    """Validate classification rules and return them unchanged."""
    rules = _require_mapping_list(rules, "rules", source)
    for index, rule in enumerate(rules, start=1):
        label = f"{source}: rule #{index}"
        for field in ("name", "classify_as", "role", "is_ot"):
            if field not in rule:
                raise ConfigError(f"{label}: missing required field '{field}'")
        if not isinstance(rule["is_ot"], bool):
            raise ConfigError(f"{label}: is_ot must be true or false")
        if "port" in rule and not isinstance(rule["port"], int):
            raise ConfigError(f"{label}: port must be an integer")
        if "confidence" in rule:
            confidence = str(rule["confidence"]).upper()
            if confidence not in _VALID_CONFIDENCE:
                raise ConfigError(f"{label}: confidence must be HIGH, MEDIUM, or LOW")
            rule["confidence"] = confidence
        if "protocol" in rule:
            protocol = str(rule["protocol"]).upper()
            if protocol not in _VALID_PROTOCOLS:
                raise ConfigError(f"{label}: protocol must be TCP or UDP")
            rule["protocol"] = protocol
        # ── Behavioral constraint validation ───────────────────────────────
        if "never_initiates" in rule and not isinstance(rule["never_initiates"], bool):
            raise ConfigError(f"{label}: never_initiates must be true or false")
        if "alert_on_new_port" in rule and not isinstance(rule["alert_on_new_port"], bool):
            raise ConfigError(f"{label}: alert_on_new_port must be true or false")
        if "allowed_peers" in rule:
            peers = rule["allowed_peers"]
            if not isinstance(peers, list):
                raise ConfigError(f"{label}: allowed_peers must be a list of IP addresses")
        if "allowed_ports" in rule:
            ports = rule["allowed_ports"]
            if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
                raise ConfigError(f"{label}: allowed_ports must be a list of integers")
        if "max_new_peers_per_hour" in rule:
            v = rule["max_new_peers_per_hour"]
            if not isinstance(v, int) or v < 1:
                raise ConfigError(f"{label}: max_new_peers_per_hour must be a positive integer")
    return rules


def validate_sinks_config(sinks: list, *, source: str = "output.sinks") -> list:
    """Validate sink configuration and return it unchanged."""
    sinks = _require_mapping_list(sinks, "output.sinks", source)
    for index, sink in enumerate(sinks, start=1):
        label = f"{source}: sink #{index}"
        kind = str(sink.get("type", "")).lower()
        if kind not in {"syslog", "splunk_hec"}:
            raise ConfigError(f"{label}: type must be syslog or splunk_hec")
        sink["type"] = kind
        if kind == "syslog":
            if "host" not in sink:
                raise ConfigError(f"{label}: missing required field 'host'")
            if "port" in sink and not isinstance(sink["port"], int):
                raise ConfigError(f"{label}: port must be an integer")
            protocol = str(sink.get("protocol", "udp")).lower()
            if protocol not in {"udp", "tcp"}:
                raise ConfigError(f"{label}: protocol must be udp or tcp")
            sink["protocol"] = protocol
            fmt = str(sink.get("format", "json")).lower()
            if fmt not in _VALID_SINK_FORMATS:
                raise ConfigError(f"{label}: format must be json, cef, leef, or plain")
            sink["format"] = fmt
        elif kind == "splunk_hec":
            for field in ("url", "token"):
                if field not in sink:
                    raise ConfigError(f"{label}: missing required field '{field}'")
            if "verify_ssl" in sink and not isinstance(sink["verify_ssl"], bool):
                raise ConfigError(f"{label}: verify_ssl must be true or false")
    return sinks


def validate_inventory_config(config: dict | None, *, source: str = "inventory") -> dict:
    """Validate inventory scoping settings and return them unchanged."""
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ConfigError(f"{source}: inventory must be a mapping")
    if "include_public_ips" in config and not isinstance(config["include_public_ips"], bool):
        raise ConfigError(f"{source}: include_public_ips must be true or false")
    cidrs = config.get("cidrs", [])
    if cidrs is None:
        return config
    if not isinstance(cidrs, list):
        raise ConfigError(f"{source}: cidrs must be a list")
    for index, cidr in enumerate(cidrs, start=1):
        try:
            ipaddress.ip_network(str(cidr), strict=False)
        except ValueError as e:
            raise ConfigError(f"{source}: cidrs[{index}] is not a valid CIDR") from e
    return config


def load_user_config(*, strict: bool = False) -> dict:
    """Load and validate user config. Builtin/template defaults are allowed."""
    data = _find_user_config(strict=strict)
    if strict:
        validate_rules(data.get("rules", []), source="user config")
        output = data.get("output", {}) or {}
        if not isinstance(output, dict):
            raise ConfigError("user config: output must be a mapping")
        validate_sinks_config(output.get("sinks", []), source="user config")
        validate_inventory_config(data.get("inventory", {}), source="user config")
    return data


def load_builtin_rules(*, strict: bool = False) -> list:
    """Load rules from builtin_rules.yaml. Returns empty list on failure."""
    rules = _load_yaml(_BUILTIN_PATH, strict=strict).get("rules", [])
    if strict:
        validate_rules(rules, source="builtin rules")
    return rules


def load_user_rules(*, strict: bool = False) -> list:
    """Load only the user's custom rules. Empty list if none defined."""
    rules = load_user_config(strict=strict).get("rules", [])
    if strict:
        validate_rules(rules, source="user rules")
    return rules


def load_rules() -> list:
    """
    Return merged rule list: user rules first, builtin rules appended.
    User rules with the same port/mac as a builtin shadow the builtin.
    """
    return load_user_rules() + load_builtin_rules()


def load_sinks_config(*, strict: bool = False) -> list:
    """Return list of sink config dicts from user config. Empty list if none."""
    output = load_user_config(strict=strict).get("output", {}) or {}
    if not isinstance(output, dict):
        if strict:
            raise ConfigError("user config: output must be a mapping")
        return []
    sinks = output.get("sinks", [])
    if strict:
        validate_sinks_config(sinks, source="user sinks")
    return sinks


def load_inventory_config(*, strict: bool = False) -> dict:
    """Return inventory scoping config from user config."""
    inventory = load_user_config(strict=strict).get("inventory", {}) or {}
    if strict:
        validate_inventory_config(inventory, source="user inventory")
    return inventory


def match_rule(rules: list, port: int = None, mac: str = None, proto: str = None) -> dict | None:
    """
    Check if any rule in the list matches the given indicators.
    Returns the first matching rule dict, or None.
    """
    for rule in rules:
        port_match  = True
        mac_match   = True
        proto_match = True

        if "port" in rule:
            port_match = (port is not None) and (rule["port"] == port)

        if "mac_prefix" in rule:
            if mac is not None:
                normalized = mac.upper().replace("-", ":")
                mac_match  = normalized.startswith(rule["mac_prefix"].upper())
            else:
                mac_match = False

        if "protocol" in rule:
            proto_match = proto is not None and rule["protocol"].upper() == proto.upper()

        if port_match and mac_match and proto_match:
            return rule

    return None
