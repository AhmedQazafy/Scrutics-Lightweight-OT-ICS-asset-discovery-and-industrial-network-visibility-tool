"""
Test for Suricata EVE JSON detection robustness.
"""

import json
import tempfile
from scrutics.parsers.detector import detect_file_type


class TestSuricataDetection:
    
    def test_suricata_detection_with_leading_comments(self, tmp_path):
        """Verify Suricata detection works with leading comments."""
        
        # Create an EVE file with a leading comment
        eve_path = tmp_path / "eve.json"
        with open(eve_path, "w") as f:
            f.write("# This is a comment\n")
            f.write(json.dumps({
                "event_type": "flow",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2"
            }) + "\n")
        
        # Current detection only checks first line
        # This should fail for files with comments
        detected = detect_file_type(str(eve_path))
        
        # This test will FAIL, confirming the detection issue
        # Expected: "suricata", Actual: "unknown"
        assert detected == "suricata", \
               f"Detection failed for EVE with comments (got {detected})"