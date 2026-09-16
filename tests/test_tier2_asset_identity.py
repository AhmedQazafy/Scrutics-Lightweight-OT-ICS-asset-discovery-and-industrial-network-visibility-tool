"""
Unit tests for Tier 2 MAC-Based Device Identity Model.
Step 1: Asset ip_history, record_ip, and primary_key property.
"""

import pytest
from scrutics.db.inventory import Asset


def test_asset_primary_key_uses_mac_when_known():
    asset = Asset(ip="10.0.0.5", mac="00:1A:2B:3C:4D:5E")
    assert asset.primary_key == "00:1a:2b:3c:4d:5e"


def test_asset_primary_key_falls_back_to_ip_when_mac_unknown_or_empty():
    asset_unknown = Asset(ip="10.0.0.5", mac="Unknown")
    assert asset_unknown.primary_key == "10.0.0.5"

    asset_none = Asset(ip="10.0.0.6", mac="")
    assert asset_none.primary_key == "10.0.0.6"


def test_record_ip_initial_and_repeat_same_ip():
    asset = Asset(ip="10.0.0.5", mac="00:11:22:33:44:55")
    assert asset.ip_history == []

    # 1. First record_ip call
    asset.record_ip("10.0.0.5", 1000.0)
    assert len(asset.ip_history) == 1
    assert asset.ip_history[0] == {
        "ip": "10.0.0.5",
        "first_seen": 1000.0,
        "last_seen": 1000.0,
    }
    assert asset.ip == "10.0.0.5"
    assert asset.last_seen_epoch == 1000.0

    # 2. Repeated traffic from the same IP bumps last_seen only
    asset.record_ip("10.0.0.5", 1050.0)
    assert len(asset.ip_history) == 1
    assert asset.ip_history[0] == {
        "ip": "10.0.0.5",
        "first_seen": 1000.0,
        "last_seen": 1050.0,
    }
    assert asset.last_seen_epoch == 1050.0


def test_record_ip_chronological_episodes_no_deduplication():
    """
    Chronological IP-assignment episodes:
    A device moving A -> B -> A must produce 3 entries [A, B, A] in order,
    preserving the timeline evidence rather than collapsing into 2.
    """
    asset = Asset(ip="10.0.0.1", mac="00:11:22:33:44:55")

    # Episode 1: Device is at 10.0.0.1
    asset.record_ip("10.0.0.1", 100.0)
    asset.record_ip("10.0.0.1", 110.0)

    # Episode 2: Device moves to 10.0.0.2
    asset.record_ip("10.0.0.2", 200.0)
    asset.record_ip("10.0.0.2", 215.0)

    # Episode 3: Device moves back to 10.0.0.1
    asset.record_ip("10.0.0.1", 300.0)
    asset.record_ip("10.0.0.1", 320.0)

    assert len(asset.ip_history) == 3
    assert asset.ip_history[0] == {
        "ip": "10.0.0.1",
        "first_seen": 100.0,
        "last_seen": 110.0,
    }
    assert asset.ip_history[1] == {
        "ip": "10.0.0.2",
        "first_seen": 200.0,
        "last_seen": 215.0,
    }
    assert asset.ip_history[2] == {
        "ip": "10.0.0.1",
        "first_seen": 300.0,
        "last_seen": 320.0,
    }

    # Current state reflects latest episode
    assert asset.ip == "10.0.0.1"
    assert asset.last_seen_epoch == 320.0

# ── Step 2 Tests: AssetInventory MAC-based resolution & get_or_create ─────────

from scrutics.db.inventory import AssetInventory


def test_scenario_a_device_moves_a_to_b():
    """
    Scenario A: Device with MAC-1 moves from IP A (10.0.0.5) to IP B (10.0.0.8).
    - Exactly 1 Asset exists.
    - Same MAC.
    - Two IP episodes in order [A, B].
    - Current IP is B.
    - inv.get(B) returns that Asset.
    - inv.get(A) returns None (old current-IP index is cleaned up).
    - inv.get_by_mac(MAC) returns that Asset.
    """
    inv = AssetInventory()
    asset1 = inv.get_or_create("10.0.0.5", "00:11:22:33:44:55", 100.0)
    assert asset1 is not None
    assert inv.count() == 1
    assert inv.get("10.0.0.5") is asset1

    # Move to 10.0.0.8
    asset2 = inv.get_or_create("10.0.0.8", "00:11:22:33:44:55", 200.0)
    assert asset2 is asset1  # Exactly ONE physical asset
    assert inv.count() == 1
    assert asset2.mac == "00:11:22:33:44:55"
    assert asset2.ip == "10.0.0.8"

    # Verify IP episodes
    assert len(asset2.ip_history) == 2
    assert asset2.ip_history[0]["ip"] == "10.0.0.5"
    assert asset2.ip_history[1]["ip"] == "10.0.0.8"

    # Current-IP lookup vs historical record
    assert inv.get("10.0.0.8") is asset2
    assert inv.get("10.0.0.5") is None  # Cleaned up!
    assert inv.get_by_mac("00:11:22:33:44:55") is asset2


def test_scenario_b_device_moves_a_to_b_to_a():
    """
    Scenario B: Device moves A -> B -> A.
    - Exactly 1 Asset exists.
    - Three chronological IP episodes: [A, B, A] without collapsing.
    - Current IP is A.
    - inv.get(A) returns Asset.
    - inv.get(B) returns None.
    """
    inv = AssetInventory()
    inv.get_or_create("10.0.0.1", "AA:BB:CC:DD:EE:FF", 100.0)
    inv.get_or_create("10.0.0.2", "AA:BB:CC:DD:EE:FF", 200.0)
    asset = inv.get_or_create("10.0.0.1", "AA:BB:CC:DD:EE:FF", 300.0)

    assert inv.count() == 1
    assert asset.ip == "10.0.0.1"
    assert len(asset.ip_history) == 3
    assert [e["ip"] for e in asset.ip_history] == ["10.0.0.1", "10.0.0.2", "10.0.0.1"]

    assert inv.get("10.0.0.1") is asset
    assert inv.get("10.0.0.2") is None


def test_scenario_c_different_mac_claims_old_ip_mac_changed():
    """
    Scenario C: Device 1 (MAC-1) is at 10.0.0.5.
    Then Device 2 (MAC-2) appears at 10.0.0.5 (MAC_CHANGED / device replacement).
    - Exactly 2 Assets exist.
    - Old Asset is preserved in inventory (via _by_mac).
    - New Asset is created for MAC-2.
    - inv.get("10.0.0.5") returns new Asset.
    - Old Asset can become stale based on its un-updated last_seen_epoch.
    """
    inv = AssetInventory()
    old_asset = inv.get_or_create("10.0.0.5", "11:11:11:11:11:11", 100.0)
    assert inv.count() == 1

    # Device 2 claims 10.0.0.5 at t=200
    new_asset = inv.get_or_create("10.0.0.5", "22:22:22:22:22:22", 200.0)
    assert new_asset is not old_asset
    assert inv.count() == 2

    # Current IP points to the new asset
    assert inv.get("10.0.0.5") is new_asset
    assert inv.get_by_mac("22:22:22:22:22:22") is new_asset

    # Old asset is preserved by MAC
    assert inv.get_by_mac("11:11:11:11:11:11") is old_asset

    # Old asset last seen was at t=100; at t=150 with timeout=30 it is stale
    assert old_asset.is_stale(now_epoch=150.0, timeout=30.0) is True
    # New asset last seen was at t=200; at t=210 it is not stale
    assert new_asset.is_stale(now_epoch=210.0, timeout=30.0) is False


def test_scenario_d_brand_new_ip_and_mac():
    """Scenario D: Both IP and MAC are new -> one asset indexed by both."""
    inv = AssetInventory()
    asset = inv.get_or_create("192.168.1.50", "00:AA:BB:CC:DD:EE", 500.0)
    assert asset is not None
    assert inv.count() == 1
    assert inv.get("192.168.1.50") is asset
    assert inv.get_by_mac("00:aa:bb:cc:dd:ee") is asset
    assert asset.ip == "192.168.1.50"
    assert asset.mac == "00:AA:BB:CC:DD:EE"


def test_scenario_e_mac_less_fallback():
    """
    Scenario E: MAC is unknown/empty -> preserves pure IP-based semantics.
    Multiple MAC-less observations at different IPs create separate assets.
    """
    inv = AssetInventory()
    asset1 = inv.get_or_create("10.0.0.1", "Unknown", 100.0)
    asset2 = inv.get_or_create("10.0.0.2", None, 100.0)
    asset3 = inv.get_or_create("10.0.0.3", "", 100.0)

    assert inv.count() == 3
    assert asset1 is not asset2
    assert asset2 is not asset3
    assert inv.get("10.0.0.1") is asset1
    assert inv.get("10.0.0.2") is asset2
    assert inv.get("10.0.0.3") is asset3
    assert inv.get_by_mac("Unknown") is None


def test_scenario_f_repeated_observations_same_mac_and_ip():
    """
    Scenario F: Repeated observations of same MAC + same IP.
    No duplicate Asset, no duplicate IP-history episode.
    """
    inv = AssetInventory()
    asset1 = inv.get_or_create("10.0.0.1", "00:11:22:33:44:55", 100.0)
    asset2 = inv.get_or_create("10.0.0.1", "00:11:22:33:44:55", 150.0)

    assert asset1 is asset2
    assert inv.count() == 1
    assert len(asset1.ip_history) == 1
    assert asset1.ip_history[0]["first_seen"] == 100.0
    assert asset1.ip_history[0]["last_seen"] == 150.0
    assert asset1.last_seen_epoch == 150.0


def test_scenario_g_normalization():
    """
    Scenario G: MAC normalization handles uppercase, lowercase, Windows hyphens,
    and whitespace consistently with existing conventions.
    """
    inv = AssetInventory()
    # Initial observation with colons & lowercase
    asset = inv.get_or_create("10.0.0.1", "00:aa:bb:cc:dd:ee", 100.0)

    # Subsequent observation with uppercase and Windows hyphens and surrounding whitespace
    same_asset = inv.get_or_create("10.0.0.1", "  00-AA-BB-CC-DD-EE  ", 200.0)
    assert same_asset is asset
    assert inv.count() == 1

    # Lookup by any valid normalized variant works
    assert inv.get_by_mac("00:AA:BB:CC:DD:EE") is asset
    assert inv.get_by_mac("00-aa-bb-cc-dd-ee") is asset


def test_scenario_h_learning_mac_for_macless_asset():
    """
    Scenario H: An asset seen without MAC initially has its MAC learned later.
    Becomes indexed by MAC without creating a duplicate asset.
    """
    inv = AssetInventory()
    asset = inv.get_or_create("10.0.0.1", "Unknown", 100.0)
    assert asset.mac == "Unknown"
    assert inv.count() == 1

    # Later packet reveals MAC
    updated = inv.get_or_create("10.0.0.1", "00:11:22:33:44:55", 200.0)
    assert updated is asset
    assert inv.count() == 1
    assert asset.mac == "00:11:22:33:44:55"
    assert inv.get_by_mac("00:11:22:33:44:55") is asset

# ── Step 3 Tests: CaptureEngine caller migration & end-to-end integration ───

from scrutics.capture.engine import CaptureEngine


def test_engine_migration_scenario_a_device_moves():
    """
    Scenario A: Device with MAC moves 10.0.0.1 -> 10.0.0.2 in CaptureEngine.
    - One Asset for the moving device.
    - IP history [10.0.0.1, 10.0.0.2].
    - Current IP is 10.0.0.2; lookup for 10.0.0.1 returns None.
    - DEVICE_MOVED anomaly is emitted with MEDIUM severity.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    engine._process_flow_data(
        src_ip="10.0.0.1",
        src_mac="AA:BB:CC:11:22:33",
        dst_ip="10.0.0.99",
        dst_port=502,
        proto="TCP",
        ts=100.0,
    )
    assert inv.get("10.0.0.1") is not None
    assert inv.get("10.0.0.1").mac == "AA:BB:CC:11:22:33"

    # Device moves to 10.0.0.2
    engine._process_flow_data(
        src_ip="10.0.0.2",
        src_mac="AA:BB:CC:11:22:33",
        dst_ip="10.0.0.99",
        dst_port=502,
        proto="TCP",
        ts=200.0,
    )

    asset = inv.get("10.0.0.2")
    assert asset is not None
    assert asset.mac == "AA:BB:CC:11:22:33"
    assert asset.ip == "10.0.0.2"
    assert [e["ip"] for e in asset.ip_history] == ["10.0.0.1", "10.0.0.2"]
    assert inv.get("10.0.0.1") is None

    # Verify DEVICE_MOVED anomaly
    anomalies = [a for a in engine.baseline.get_anomalies() if a["type"] == "DEVICE_MOVED"]
    assert len(anomalies) == 1
    assert anomalies[0]["severity"] == "MEDIUM"
    assert "10.0.0.1" in anomalies[0]["detail"]
    assert "10.0.0.2" in anomalies[0]["detail"]


def test_engine_migration_scenario_b_device_moves_back():
    """
    Scenario B: Device moves 10.0.0.1 -> 10.0.0.2 -> 10.0.0.1.
    - One Asset for the moving device.
    - IP history [10.0.0.1, 10.0.0.2, 10.0.0.1].
    - Current IP is 10.0.0.1; lookup for 10.0.0.2 returns None.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:22:33", None, None, None, ts=100.0)
    engine._process_flow_data("10.0.0.2", "AA:BB:CC:11:22:33", None, None, None, ts=200.0)
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:22:33", None, None, None, ts=300.0)

    asset = inv.get("10.0.0.1")
    assert asset is not None
    assert asset.ip == "10.0.0.1"
    assert [e["ip"] for e in asset.ip_history] == ["10.0.0.1", "10.0.0.2", "10.0.0.1"]
    assert inv.get("10.0.0.2") is None


def test_engine_migration_scenario_c_mac_changed():
    """
    Scenario C: Device 1 at 10.0.0.1 replaced by Device 2 at 10.0.0.1.
    - Two Assets exist.
    - MAC_CHANGED anomaly fired with HIGH severity.
    - Old asset preserved and naturally becomes stale.
    - New asset is the active device at 10.0.0.1.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:22:33", None, None, None, ts=100.0)
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:99:99:99", None, None, None, ts=200.0)

    assert inv.count() == 2
    assert inv.get("10.0.0.1").mac == "AA:BB:CC:99:99:99"

    old_asset = inv.get_by_mac("AA:BB:CC:11:22:33")
    assert old_asset is not None
    assert old_asset.is_stale(now_epoch=250.0, timeout=30.0) is True

    anomalies = [a for a in engine.baseline.get_anomalies() if a["type"] == "MAC_CHANGED"]
    assert len(anomalies) == 1
    assert anomalies[0]["severity"] == "HIGH"


def test_engine_migration_scenario_d_macless():
    """
    Scenario D: MAC-less traffic preserves IP-based identity semantics.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    engine._process_flow_data("10.0.0.1", "Unknown", None, None, None, ts=100.0)
    engine._process_flow_data("10.0.0.2", None, None, None, None, ts=100.0)

    assert inv.count() == 2
    assert inv.get("10.0.0.1") is not None
    assert inv.get("10.0.0.2") is not None
    assert inv.get("10.0.0.1") is not inv.get("10.0.0.2")


def test_engine_migration_scenario_e_repeated_packets():
    """
    Scenario E: Repeated packets for the same device increment packet count,
    bump last_seen, and create no duplicate assets or IP episodes.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    engine._process_flow_data("10.0.0.1", "00:11:22:33:44:55", None, None, None, ts=100.0)
    engine._process_flow_data("10.0.0.1", "00:11:22:33:44:55", None, None, None, ts=110.0)
    engine._process_flow_data("10.0.0.1", "00:11:22:33:44:55", None, None, None, ts=120.0)

    assert inv.count() == 1
    asset = inv.get("10.0.0.1")
    assert asset.packet_count == 3
    assert len(asset.ip_history) == 1
    assert asset.last_seen_epoch == 120.0
