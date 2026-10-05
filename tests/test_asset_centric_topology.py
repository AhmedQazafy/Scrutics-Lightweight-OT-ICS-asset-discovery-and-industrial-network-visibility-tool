# ── Step 4 Tests: Asset-Centric Topology Migration ────────────────────────────
#
# These tests verify the core topology invariant:
# Every topology edge has two resolved Asset identities at capture time.
# No IP-only fallback identities are permitted in topology_edges.
# Edge keys are (src_asset.primary_key, dst_asset.primary_key).

from scrutics.db.inventory import Asset, AssetInventory
from scrutics.capture.engine import CaptureEngine
from scrutics.topology import build_graph_data, export_connections_csv
import csv
import os
import tempfile


def test_topology_edge_keyed_by_primary_key():
    """
    Edge key must be (src.primary_key, dst.primary_key), not (src_ip, dst_ip).
    When both source and destination are resolved Assets with MACs,
    the edge key uses their MAC-based primary_keys.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    # Create source and destination assets
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", "10.0.0.2", 502, "TCP", ts=100.0)
    engine._process_flow_data("10.0.0.2", "AA:BB:CC:22:22:22", None, None, None, ts=100.0)

    # Now send traffic from src to dst; both are known Assets
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", "10.0.0.2", 502, "TCP", ts=200.0)

    # Verify edge key is primary_keys (MACs), not IPs
    src_pk = inv.get("10.0.0.1").primary_key
    dst_pk = inv.get("10.0.0.2").primary_key
    assert src_pk == "aa:bb:cc:11:11:11"
    assert dst_pk == "aa:bb:cc:22:22:22"

    assert (src_pk, dst_pk) in engine.topology_edges
    # The old IP-based key must NOT exist
    assert ("10.0.0.1", "10.0.0.2") not in engine.topology_edges

    edge = engine.topology_edges[(src_pk, dst_pk)]
    # IP metadata is preserved for display/export purposes
    assert edge["source_ip"] == "10.0.0.1"
    assert edge["destination_ip"] == "10.0.0.2"
    assert edge["count"] >= 1


def test_topology_edge_requires_both_assets():
    """
    No edge is created when the destination is not a known Asset.
    topology_edges is an asset relationship aggregate, not a record of
    every unresolved communication observation.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    # Source is in-subnet, destination is NOT (set to None by _process_flow_data)
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", None, None, "TCP", ts=100.0)

    # No edges should exist
    assert len(engine.topology_edges) == 0


def test_topology_edge_unresolved_dst_no_retrospective_merge():
    """
    An initially unresolved in-subnet destination that later becomes an Asset
    does NOT cause retrospective reconstruction of old observations.

    Old observations are not backfilled when the destination later becomes known.
    This is exactly the behavior we want; otherwise we'd quietly reintroduce
    retrospective identity reconstruction.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    # Step 1: Source sends to destination that has no Asset yet.
    # _record_topology_edge is called BEFORE credit_listener_port,
    # so if 10.0.0.99 has never been a source, dst_asset = None at edge time.
    # However, credit_listener_port may create a MAC-less Asset at 10.0.0.99.
    # The edge was already attempted (and skipped) before that creation.
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", "10.0.0.99", 502, "TCP", ts=100.0)

    src_pk = inv.get("10.0.0.1").primary_key

    # Step 2: 10.0.0.99 later appears as a source (becomes a proper Asset with MAC)
    engine._process_flow_data("10.0.0.99", "AA:BB:CC:99:99:99", None, None, None, ts=200.0)
    dst_pk = inv.get("10.0.0.99").primary_key

    # Before NEW traffic: check if old observation was backfilled
    # If credit_listener_port created a MAC-less asset at 10.0.0.99 during Step 1,
    # that asset's primary_key would be "10.0.0.99" (IP fallback).
    # After Step 2, it might be the same or different Asset depending on identity rules.
    # The key point: no edge from the Step 1 observation should exist with the
    # MAC-based dst_pk, because the MAC wasn't known at Step 1 edge time.

    # Step 3: NEW traffic from src to dst; NOW an edge should be created
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", "10.0.0.99", 502, "TCP", ts=300.0)

    assert (src_pk, dst_pk) in engine.topology_edges
    edge = engine.topology_edges[(src_pk, dst_pk)]
    # The edge's first_seen should be from Step 3 (t=300), not Step 1 (t=100),
    # proving no retrospective backfill occurred.
    assert edge["first_seen"] >= 200.0


def test_topology_edge_device_moves_preserves_identity():
    """
    MAC-X moving from IP A to IP B: the topology edge key stays
    (mac-x-pk, dst-pk) with updated source_ip metadata.
    The physical relationship persists across IP changes.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    # Create both endpoints
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", None, None, None, ts=100.0)
    engine._process_flow_data("10.0.0.2", "AA:BB:CC:22:22:22", None, None, None, ts=100.0)

    # Traffic from 10.0.0.1 to 10.0.0.2
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", "10.0.0.2", 502, "TCP", ts=200.0)

    src_pk = "aa:bb:cc:11:11:11"
    dst_pk = "aa:bb:cc:22:22:22"
    assert (src_pk, dst_pk) in engine.topology_edges
    edge = engine.topology_edges[(src_pk, dst_pk)]
    assert edge["source_ip"] == "10.0.0.1"
    count_before = edge["count"]

    # Source device moves to 10.0.0.3
    engine._process_flow_data("10.0.0.3", "AA:BB:CC:11:11:11", "10.0.0.2", 502, "TCP", ts=300.0)

    # Same edge key: physical relationship preserved
    assert (src_pk, dst_pk) in engine.topology_edges
    edge = engine.topology_edges[(src_pk, dst_pk)]
    assert edge["count"] > count_before
    # IP metadata updated to reflect new source IP
    assert edge["source_ip"] == "10.0.0.3"
    assert edge["destination_ip"] == "10.0.0.2"


def test_topology_edge_mac_changed_produces_separate_edges():
    """
    MAC-X then MAC-Y at the same IP produce distinct topology edges.
    Device replacement creates a new physical identity; the topology
    must reflect this as a separate relationship.
    """
    inv = AssetInventory()
    engine = CaptureEngine(inventory=inv)

    # Create destination
    engine._process_flow_data("10.0.0.2", "AA:BB:CC:22:22:22", None, None, None, ts=100.0)

    # Device 1 (MAC-X) at 10.0.0.1 talks to 10.0.0.2
    engine._process_flow_data("10.0.0.1", "AA:BB:CC:11:11:11", "10.0.0.2", 502, "TCP", ts=200.0)

    mac_x_pk = "aa:bb:cc:11:11:11"
    dst_pk = "aa:bb:cc:22:22:22"
    assert (mac_x_pk, dst_pk) in engine.topology_edges

    # Device 2 (MAC-Y) replaces Device 1 at 10.0.0.1, talks to 10.0.0.2
    engine._process_flow_data("10.0.0.1", "DD:EE:FF:33:33:33", "10.0.0.2", 502, "TCP", ts=400.0)

    mac_y_pk = "dd:ee:ff:33:33:33"

    # Two distinct edges exist, one for each physical device
    assert (mac_x_pk, dst_pk) in engine.topology_edges
    assert (mac_y_pk, dst_pk) in engine.topology_edges
    assert mac_x_pk != mac_y_pk


def test_build_graph_data_uses_primary_key():
    """
    build_graph_data produces nodes with:
    - node['id'] = Asset.primary_key (persistent identity)
    - node['label'] = Asset.ip (human-friendly display)

    The graph builder delegates identity fallback entirely to Asset.primary_key.
    It must NOT independently implement identity fallback logic.
    """
    inv = AssetInventory()
    inv.get_or_create("10.0.0.1", "AA:BB:CC:11:11:11", 100.0)
    inv.get_or_create("10.0.0.2", None, 100.0)  # MAC-less asset

    # Build edges keyed by primary_key (as the engine now produces)
    edges = {
        ("aa:bb:cc:11:11:11", "10.0.0.2"): {
            "protocols": {"Modbus"},
            "count": 5,
            "first_seen": 100.0,
            "last_seen": 200.0,
            "src_port": 49001,
            "dst_port": 502,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
        }
    }

    graph = build_graph_data(inv, edges)

    # Find nodes by their IDs
    node_by_id = {n["id"]: n for n in graph["nodes"] + graph["isolated_nodes"]}

    # MAC-based asset: id = MAC primary_key, label = IP
    assert "aa:bb:cc:11:11:11" in node_by_id
    mac_node = node_by_id["aa:bb:cc:11:11:11"]
    assert mac_node["label"] == "10.0.0.1"

    # MAC-less asset: id = IP (primary_key fallback), label = IP
    assert "10.0.0.2" in node_by_id
    ip_node = node_by_id["10.0.0.2"]
    assert ip_node["label"] == "10.0.0.2"

    # Edge uses primary_keys
    assert len(graph["edges"]) == 1
    edge = graph["edges"][0]
    assert edge["from"] == "aa:bb:cc:11:11:11"
    assert edge["to"] == "10.0.0.2"


def test_csv_export_writes_ips_not_keys():
    """
    CSV source/destination columns contain IPs (from edge metadata),
    NOT primary_key values. This preserves compatibility with
    scrutics/ai/tools.py which reads source/destination as IPs.
    """
    edges = {
        ("aa:bb:cc:11:11:11", "aa:bb:cc:22:22:22"): {
            "protocols": {"Modbus"},
            "count": 10,
            "first_seen": 100.0,
            "last_seen": 200.0,
            "src_port": 49001,
            "dst_port": 502,
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "connections.csv")
        export_connections_csv(edges, csv_path)

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        # CSV contains IPs, not MAC primary_keys
        assert rows[0]["source"] == "10.0.0.1"
        assert rows[0]["destination"] == "10.0.0.2"
        # NOT the primary_keys
        assert rows[0]["source"] != "aa:bb:cc:11:11:11"
        assert rows[0]["destination"] != "aa:bb:cc:22:22:22"


def test_topology_macless_asset_uses_ip_as_node_id():
    """
    When an Asset has no MAC (MAC-less/Unknown), its primary_key falls back
    to IP. The graph builder must NOT independently implement this fallback;
    it trusts Asset.primary_key.
    """
    inv = AssetInventory()
    asset = inv.get_or_create("10.0.0.50", "Unknown", 100.0)
    assert asset.primary_key == "10.0.0.50"

    graph = build_graph_data(inv)
    all_nodes = graph["nodes"] + graph["isolated_nodes"]
    assert len(all_nodes) == 1
    assert all_nodes[0]["id"] == "10.0.0.50"
    assert all_nodes[0]["label"] == "10.0.0.50"
