import json

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.topology import build_graph_data, export_topology


def test_engine_records_topology_edge_for_destination_service_port():
    inventory = AssetInventory()
    engine = CaptureEngine(inventory=inventory)
    engine.no_baseline = True

    engine._process_flow_data(
        src_ip="192.168.1.10",
        src_mac="00:11:22:33:44:55",
        dst_ip="192.168.1.20",
        src_port=40000,
        dst_port=502,
        proto="TCP",
        ts=1.0,
    )

    edge = engine.topology_edges[("192.168.1.10", "192.168.1.20")]
    assert edge["count"] == 1
    assert "Modbus TCP" in edge["protocols"]

def test_export_connections_csv(tmp_path):
    from scrutics.topology import export_connections_csv
    
    edges = {
        ("192.168.1.10", "192.168.1.20"): {
            "protocols": {"Modbus TCP"},
            "count": 7,
            "first_seen": 1700000000.0,
            "last_seen": 1700000100.0,
            "src_port": 40000,
            "dst_port": 502,
        },
        ("192.168.1.10", "192.168.1.30"): {
            "protocols": {"S7comm"},
            "count": 3,
            "first_seen": 1700000050.0,
            "last_seen": 1700000120.0,
            "src_port": 40001,
            "dst_port": 102,
        },
    }
    
    csv_path = tmp_path / "connections.csv"
    export_connections_csv(edges, str(csv_path))
    assert csv_path.exists()
    
    import csv
    with open(csv_path, "r") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert rows[0]["source"] == "192.168.1.10"
    assert rows[0]["destination"] == "192.168.1.20"
    assert rows[0]["protocol"] == "Modbus TCP"
    
def test_engine_records_topology_edge_for_source_service_port():
    inventory = AssetInventory()
    engine = CaptureEngine(inventory=inventory)
    engine.no_baseline = True

    engine._process_flow_data(
        src_ip="192.168.1.20",
        src_mac="00:11:22:33:44:55",
        dst_ip="192.168.1.10",
        src_port=502,
        dst_port=40000,
        proto="TCP",
        ts=1.0,
    )

    edge = engine.topology_edges[("192.168.1.20", "192.168.1.10")]
    assert edge["count"] == 1
    assert "Modbus TCP" in edge["protocols"]


def test_build_graph_data_uses_known_assets_only():
    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55", dst_ip="192.168.1.20")
    inventory.credit_listener_port("192.168.1.20", 502)
    inventory.credit_listener_port("192.168.1.30", 102)

    graph = build_graph_data(
        inventory,
        {
            ("192.168.1.10", "192.168.1.20"): {
                "protocols": {"Modbus TCP"},
                "count": 7,
            },
            ("192.168.1.10", "192.168.1.99"): {
                "protocols": {"TCP"},
                "count": 2,
            },
        },
    )

    assert graph["summary"]["assets"] == 3
    assert graph["summary"]["connections"] == 1
    assert graph["edges"][0]["from"] == "192.168.1.10"
    assert graph["edges"][0]["to"] == "192.168.1.20"
    assert graph["edges"][0]["label"] == "Modbus TCP"


def test_export_topology_writes_json_and_html(tmp_path):
    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55")

    paths = export_topology(inventory, {}, str(tmp_path))

    assert set(paths) == {"json", "html", "connections_csv"}
    graph = json.loads((tmp_path / "topology.json").read_text(encoding="utf-8"))
    html = (tmp_path / "topology.html").read_text(encoding="utf-8")
    # The asset has no edges, so it should be in isolated_nodes, not nodes
    assert graph["isolated_nodes"][0]["id"] == "192.168.1.10"
    assert "Scrutics Topology" in html