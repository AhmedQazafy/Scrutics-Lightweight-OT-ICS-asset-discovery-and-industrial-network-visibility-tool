"""
Unit tests for Scrutics classifier modules.
These tests do not require a live network interface.
"""

import pytest
from scrutics.classifier.protocol import classify_by_ports, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW
from scrutics.config import loader
from scrutics.config.loader import (
    ConfigError, load_builtin_rules, load_sinks_config,
    load_inventory_config, load_user_rules, match_rule, validate_rules,
)
from scrutics.classifier.oui import lookup_vendor, is_ot_vendor
from scrutics.db.inventory import AssetInventory, is_inventory_ip
from scrutics.integrations.sinks import format_cef, format_json, format_leef, format_plain


# ── Protocol Classifier Tests ──────────────────────────────────────────────

class TestProtocolClassifier:

    def test_modbus_port_classified_as_ot(self):
        result = classify_by_ports({502})
        assert result["is_ot"] is True
        assert result["confidence"] == CONFIDENCE_HIGH
        assert "Modbus TCP" in result["protocols"]

    def test_s7comm_port_classified_as_siemens(self):
        result = classify_by_ports({102})
        assert result["is_ot"] is True
        assert "Siemens PLC" in result["role"]

    def test_dnp3_port_classified_as_utility(self):
        result = classify_by_ports({20000})
        assert result["is_ot"] is True
        assert "DNP3" in result["protocols"]

    def test_it_only_ports_classified_correctly(self):
        result = classify_by_ports({80, 443, 22})
        assert result["is_ot"] is False
        assert result["confidence"] == CONFIDENCE_MEDIUM

    def test_unknown_ports_return_low_confidence(self):
        result = classify_by_ports({55555, 66666})
        assert result["confidence"] == CONFIDENCE_LOW
        assert result["is_ot"] is None

    def test_multiple_ics_ports_detected_as_hmi(self):
        result = classify_by_ports({502, 102, 44818})
        assert result["is_ot"] is True
        assert "multi-protocol" in result["role"]
        assert len(result["protocols"]) > 1


# ── OUI Lookup Tests (using known MAC prefixes) ───────────────────────────

class TestOUILookup:

    def test_unknown_mac_returns_unknown(self):
        # Use a zeroed-out OUI that won't be in the database
        result = lookup_vendor("00:00:00:00:00:00", {})
        assert result == "Unknown"

    def test_known_oui_returns_vendor(self):
        # Inject a fake OUI DB entry for testing
        fake_db = {"AABBCC": "Siemens AG"}
        result = lookup_vendor("AA:BB:CC:DD:EE:FF", fake_db)
        assert result == "Siemens AG"

    def test_mac_format_with_dashes(self):
        fake_db = {"AABBCC": "Moxa Technologies"}
        result = lookup_vendor("AA-BB-CC-DD-EE-FF", fake_db)
        assert result == "Moxa Technologies"

    def test_is_ot_vendor_siemens(self):
        assert is_ot_vendor("Siemens AG") is True

    def test_is_ot_vendor_moxa(self):
        assert is_ot_vendor("Moxa Technologies Co., Ltd.") is True

    def test_is_ot_vendor_dell_is_false(self):
        assert is_ot_vendor("Dell Inc.") is False


# ── Asset Inventory Tests ─────────────────────────────────────────────────

class TestAssetInventory:

    def test_new_asset_created_on_first_packet(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        assert inv.count() == 1

    def test_packet_count_increments(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        assert inv.get("10.0.0.1").packet_count == 2

    def test_peer_ip_tracked(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", dst_ip="10.0.0.2")
        assert "10.0.0.2" in inv.get("10.0.0.1").peer_ips

    def test_contacted_port_tracked_separately(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF", dst_port=502)
        asset = inv.get("10.0.0.1")
        assert 502 in asset.contacted_ports
        assert 502 not in asset.ports_seen

    def test_listener_port_tracked(self):
        inv = AssetInventory()
        inv.credit_listener_port("10.0.0.1", 502)
        assert 502 in inv.get("10.0.0.1").ports_seen

    def test_multiple_assets(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        inv.update(ip="10.0.0.2", mac="11:22:33:44:55:66")
        assert inv.count() == 2

    def test_to_dict_has_required_keys(self):
        inv = AssetInventory()
        inv.update(ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        d = inv.get("10.0.0.1").to_dict()
        for key in ["ip", "mac", "vendor", "role", "confidence_pct", "packet_count"]:
            assert key in d

    def test_special_ips_are_not_inventory_assets(self):
        inv = AssetInventory()
        for ip in ["0.0.0.0", "224.0.0.1", "239.1.2.3", "192.168.1.255", "255.255.255.255"]:
            inv.update(ip=ip, mac="AA:BB:CC:DD:EE:FF")
        assert inv.count() == 0

    def test_special_peer_ips_are_not_tracked(self):
        inv = AssetInventory()
        inv.update(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:FF", dst_ip="239.1.2.3")
        asset = inv.get("192.168.1.10")
        assert asset is not None
        assert asset.peer_ips == set()

    def test_is_inventory_ip_accepts_normal_unicast(self):
        assert is_inventory_ip("192.168.1.10") is True
        assert is_inventory_ip("10.0.0.255") is False
        assert is_inventory_ip("8.8.8.8") is False
        assert is_inventory_ip("8.8.8.8", include_public_ips=True) is True

    def test_inventory_can_include_public_ips_when_configured(self):
        inv = AssetInventory({"include_public_ips": True})
        inv.update(ip="8.8.8.8", mac="AA:BB:CC:DD:EE:FF")
        assert inv.count() == 1

    def test_inventory_cidrs_restrict_assets(self):
        inv = AssetInventory({"cidrs": ["192.168.88.0/24"]})
        inv.update(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:FF")
        inv.update(ip="192.168.88.10", mac="AA:BB:CC:DD:EE:FF")
        assert inv.count() == 1
        assert inv.get("192.168.88.10") is not None


class TestRuleLoader:

    def test_protocol_specific_rule_requires_proto_argument(self):
        rules = [{
            "name": "UDP Device",
            "port": 9999,
            "protocol": "UDP",
            "classify_as": "UDP Device",
            "role": "Field Device",
            "is_ot": True,
        }]
        assert match_rule(rules, port=9999) is None
        assert match_rule(rules, port=9999, proto="UDP") == rules[0]

    def test_validate_rules_rejects_missing_required_fields(self):
        with pytest.raises(ConfigError):
            validate_rules([{"name": "Broken", "port": 502}], source="test")

    def test_validate_rules_rejects_non_integer_port(self):
        with pytest.raises(ConfigError):
            validate_rules([{
                "name": "Broken",
                "port": "502",
                "classify_as": "Modbus TCP",
                "role": "PLC",
                "is_ot": True,
            }], source="test")

    def test_validate_rules_rejects_bad_confidence(self):
        with pytest.raises(ConfigError):
            validate_rules([{
                "name": "Broken",
                "port": 502,
                "classify_as": "Modbus TCP",
                "role": "PLC",
                "is_ot": True,
                "confidence": "CERTAIN",
            }], source="test")

    def test_load_builtin_rules_reads_yaml_rules(self):
        rules = load_builtin_rules(strict=True)
        assert any(rule["classify_as"] == "Modbus TCP" for rule in rules)

    def test_load_user_rules_reads_first_user_config(self, tmp_path, monkeypatch):
        config = tmp_path / "custom_rules.yaml"
        config.write_text(
            """
rules:
  - name: Custom Historian
    port: 5461
    classify_as: PI Historian
    role: Data Historian
    is_ot: true
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(loader, "_USER_SEARCH_PATHS", [str(config)])
        rules = load_user_rules(strict=True)
        assert rules[0]["classify_as"] == "PI Historian"

    def test_load_sinks_config_reads_output_sinks(self, tmp_path, monkeypatch):
        config = tmp_path / "custom_rules.yaml"
        config.write_text(
            """
rules: []
output:
  sinks:
    - type: syslog
      host: 127.0.0.1
      port: 514
      protocol: udp
      format: json
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(loader, "_USER_SEARCH_PATHS", [str(config)])
        sinks = load_sinks_config(strict=True)
        assert sinks[0]["type"] == "syslog"

    def test_load_inventory_config_reads_scope(self, tmp_path, monkeypatch):
        config = tmp_path / "custom_rules.yaml"
        config.write_text(
            """
rules: []
inventory:
  include_public_ips: true
  cidrs:
    - 192.168.88.0/24
""",
            encoding="utf-8",
        )
        monkeypatch.setattr(loader, "_USER_SEARCH_PATHS", [str(config)])
        inventory = load_inventory_config(strict=True)
        assert inventory["include_public_ips"] is True
        assert inventory["cidrs"] == ["192.168.88.0/24"]


class TestSinkFormatters:

    def test_sink_formatters_include_anomaly_fields(self):
        anomaly = {
            "timestamp": 1,
            "ip": "192.168.1.10",
            "type": "NEW_PEER",
            "severity": "HIGH",
            "detail": "New peer(s): 192.168.1.20",
        }
        for formatter in (format_json, format_cef, format_leef, format_plain):
            output = formatter(anomaly)
            assert "192.168.1.10" in output
            assert "NEW_PEER" in output
