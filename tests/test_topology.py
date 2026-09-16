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

    edge = engine.topology_edges[("00:11:22:33:44:55", "192.168.1.20")]
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

    edge = engine.topology_edges[("00:11:22:33:44:55", "192.168.1.10")]
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
    assert graph["edges"][0]["from"] == "00:11:22:33:44:55"
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
    assert graph["isolated_nodes"][0]["id"] == "00:11:22:33:44:55"
    assert graph["isolated_nodes"][0]["label"] == "192.168.1.10"
    assert "Scrutics Topology" in html


# ── Browser-side AI sidebar presence tests ───────────────────────────────────

def test_topology_html_contains_byok_button_and_panel(tmp_path):
    """Generated topology.html must contain the unified AI button and panel with tabs."""
    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55")

    export_topology(inventory, {}, str(tmp_path))
    html = (tmp_path / "topology.html").read_text(encoding="utf-8")

    # Single unified entry-point button
    assert 'id="ai-unified-btn"' in html
    # Panel with three tabs
    assert 'id="ai-panel"' in html
    assert 'data-tab="configure"' in html
    assert 'data-tab="chat"' in html
    assert 'data-tab="launch"' in html
    # Tips / guidance present
    assert "free tier" in html.lower() or "free api key" in html.lower()
    assert "local models" in html.lower() or "scrutics ai" in html.lower()
    # Old byok elements must be gone
    assert 'id="byok-btn"' not in html
    assert 'id="byok-panel"' not in html


def test_topology_html_never_contains_literal_api_key(tmp_path):
    """No literal API key may ever appear in static generated HTML."""
    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55")
    export_topology(inventory, {}, str(tmp_path))
    html = (tmp_path / "topology.html").read_text(encoding="utf-8")

    suspicious_patterns = ["sk-", "AIza", "sk-ant-"]
    for pat in suspicious_patterns:
        assert pat not in html, f"Suspicious pattern '{pat}' found in static HTML"


def test_new_providers_importable():
    """All three new provider classes must be importable without a live API key."""
    from scrutics.ai.openai_provider import OpenAIProvider
    from scrutics.ai.anthropic_provider import AnthropicProvider
    from scrutics.ai.gemini_provider import GeminiProvider
    from scrutics.ai.config import _resolve_env_var
    # Classes exist
    assert OpenAIProvider
    assert AnthropicProvider
    assert GeminiProvider
    # Non-env-var strings pass through unchanged
    assert _resolve_env_var("literal") == "literal"


def test_topology_html_uses_curved_edges_quadratic_bezier(tmp_path):
    """Generated topology.html must draw connection edges with quadratic Bezier curves."""
    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55")
    export_topology(inventory, {}, str(tmp_path))
    html = (tmp_path / "topology.html").read_text(encoding="utf-8")

    assert "quadraticCurveTo" in html
    assert "edgeHash" in html