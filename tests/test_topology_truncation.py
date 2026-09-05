"""
Test for topology edge truncation warning.
Verifies that truncation logs a warning.
"""
import logging
import pytest
from scrutics.db.inventory import AssetInventory
from scrutics.topology import build_graph_data


class TestTopologyTruncation:
    
    def test_edge_truncation_warns(self, caplog):
        """Verify that edge truncation generates a warning."""
        inventory = AssetInventory()

        # Create edges (100 edges, truncate to 10)
        edges = {}
        for i in range(100):
            src = f"192.168.1.{i}"
            dst = f"192.168.1.{i+1}"
            inventory.update(ip=src, mac=f"AA:BB:CC:DD:EE:{i:02d}")
            inventory.update(ip=dst, mac=f"AA:BB:CC:DD:EE:{i+1:02d}")
            edges[(src, dst)] = {"protocols": {"TCP"}, "count": i}

        # Capture logs at WARNING level
        with caplog.at_level(logging.WARNING):
            graph = build_graph_data(inventory, edges, max_edges=10)

        assert len(graph['edges']) == 10, "Should truncate to max_edges"
        assert "Topology truncated" in caplog.text, "Warning should be logged"