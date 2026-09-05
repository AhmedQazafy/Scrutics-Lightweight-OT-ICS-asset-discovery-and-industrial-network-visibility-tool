"""
Test for behavioral constraint ordering bug.
Verifies that classification-derived constraints are applied before
_check_behavioral_constraints() on the first packet.
"""

import time
import pytest
from scrutics.db.inventory import AssetInventory
from scrutics.capture.engine import CaptureEngine
from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.config.loader import load_user_rules, load_builtin_rules


class TestBehavioralConstraints:
    
    def test_constraints_applied_on_first_packet(self, tmp_path):
        """
        Trace: packet → _process_flow_data() → classification →
        asset.behavioral_constraints → _check_behavioral_constraints()
        """
        # Create a temporary custom rule file with behavioral constraints
        custom_rules = tmp_path / "custom_rules.yaml"
        custom_rules.write_text("""
rules:
  - name: "Test PLC"
    port: 9999
    classify_as: "Test Protocol"
    role: "Test PLC"
    is_ot: true
    never_initiates: true
inventory:
  include_public_ips: false
  cidrs: []
output:
  sinks: []
""")
        
        # Patch the config loader to use this file
        import scrutics.config.loader as loader
        original_paths = loader._USER_SEARCH_PATHS
        loader._USER_SEARCH_PATHS = [str(custom_rules)]
        
        try:
            # Reload rules to pick up the test config
            from scrutics.classifier.protocol import reload_rules
            reload_rules()
            
            # Create inventory and engine
            inventory = AssetInventory()
            engine = CaptureEngine(inventory=inventory)
            engine.no_baseline = False
            
            # Process first packet that matches the rule
            engine._process_flow_data(
                src_ip="10.0.0.5",
                src_mac="00:11:22:33:44:55",
                dst_ip="10.0.0.10",
                src_port=40000,
                dst_port=9999,  # Matches the custom rule
                proto="TCP",
                ts=time.time()
            )
            
            # Check if the asset got behavioral constraints
            asset = inventory.get("10.0.0.5")
            assert asset is not None, "Asset should be created"
            
            # The rule says never_initiates: true
            # The asset initiates a connection, so we expect an anomaly
            assert hasattr(asset, 'behavioral_constraints'), "Asset should have behavioral constraints"
            assert asset.behavioral_constraints.get('never_initiates') is True, "never_initiates should be True"
            
            # Check if the anomaly was generated
            anomalies = engine.baseline.get_anomalies()
            violation_anomalies = [a for a in anomalies if a.get('type') == 'BEHAVIORAL_VIOLATION']
            
            # If this fails, the bug exists (constraints not applied on first packet)
            # If it passes, the bug does NOT exist
            if not violation_anomalies:
                pytest.fail(
                    "BEHAVIORAL_VIOLATION not generated on first packet. "
                    "This confirms the ordering bug exists."
                )
            
            # Verify the violation was for the right asset
            assert violation_anomalies[0]['ip'] == '10.0.0.5'
            assert 'NEVER_INITIATES' in violation_anomalies[0]['detail']
            
        finally:
            # Restore original config paths
            loader._USER_SEARCH_PATHS = original_paths