"""
Classification rules are loaded once and reused while packets are processed.

Rule files are read at startup and by a reload (TUI key, SIGHUP, config file watcher), never
per packet. A reload takes effect for every rule consumer; an invalid edit keeps the rules in use.
"""

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

import scrutics.classifier.protocol as protocol
import scrutics.config.loader as loader
from scrutics.capture.engine import CaptureEngine
from scrutics.config.loader import ConfigError
from scrutics.db.inventory import AssetInventory

RULE_WITH_CONSTRAINT = """
rules:
  - name: "Test PLC"
    port: 9999
    classify_as: "Test Protocol"
    role: "Test PLC"
    is_ot: true
    never_initiates: true
"""
RULE_WITHOUT_CONSTRAINT = """
rules:
  - name: "Test PLC"
    port: 9999
    classify_as: "Test Protocol"
    role: "Test PLC"
    is_ot: true
"""


def _client_packet(src_ip, src_mac, dport):
    # A client with no listening port contacting a service
    return Ether(bytes(Ether(src=src_mac, dst="02:ff:ff:ff:ff:fe") / IP(src=src_ip, dst="10.0.0.10")
                       / TCP(sport=40000, dport=dport, flags="S")))


@pytest.fixture
def user_config(tmp_path, monkeypatch):
    path = tmp_path / "scrutics.yaml"
    monkeypatch.setattr(loader, "_USER_SEARCH_PATHS", [str(path)])
    yield path
    monkeypatch.undo()
    protocol.reload_rules()


def test_packets_are_processed_without_reading_rule_files(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("rule files were read while processing packets")

    for module in (protocol, loader):
        monkeypatch.setattr(module, "load_user_rules", fail)
        monkeypatch.setattr(module, "load_builtin_rules", fail)
    monkeypatch.setattr(loader, "_load_yaml", fail)

    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    for i in range(20):
        engine._process_packet(_client_packet(f"10.0.0.{i + 1}", f"02:00:00:00:01:{i:02x}", 502))
    assert engine.inventory.get("10.0.0.1").contacted_ports == {502}


def test_reloaded_rules_apply_to_constraints(user_config):
    user_config.write_text(RULE_WITH_CONSTRAINT)
    protocol.reload_rules()
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine._process_packet(_client_packet("10.0.0.5", "02:00:00:00:02:05", 9999))
    assert engine.inventory.get("10.0.0.5").behavioral_constraints.get("never_initiates") is True

    # An edit is not seen until the rules are reloaded
    user_config.write_text(RULE_WITHOUT_CONSTRAINT)
    engine._process_packet(_client_packet("10.0.0.6", "02:00:00:00:02:06", 9999))
    assert engine.inventory.get("10.0.0.6").behavioral_constraints.get("never_initiates") is True

    protocol.reload_rules()
    engine._process_packet(_client_packet("10.0.0.7", "02:00:00:00:02:07", 9999))
    assert "never_initiates" not in engine.inventory.get("10.0.0.7").behavioral_constraints


def test_invalid_edit_keeps_the_rules_in_use(user_config):
    user_config.write_text(RULE_WITH_CONSTRAINT)
    protocol.reload_rules()
    user_config.write_text("rules: [this is: not valid: yaml")
    with pytest.raises(ConfigError):
        protocol.reload_rules()

    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine._process_packet(_client_packet("10.0.0.8", "02:00:00:00:02:08", 9999))
    assert engine.inventory.get("10.0.0.8").behavioral_constraints.get("never_initiates") is True
