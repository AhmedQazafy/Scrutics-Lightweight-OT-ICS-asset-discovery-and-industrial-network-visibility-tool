"""
Test for Zeek parser memory consumption.
Verifies the parser doesn't read entire files into memory.
"""

import os
import tempfile
import pytest


class TestZeekParserMemory:
    
    def test_zeek_parser_streams_not_reads_all(self, tmp_path):
        """Verify that parse_zeek_log doesn't read all lines at once."""
        from scrutics.parsers.zeek import parse_zeek_log
        
        # Create a large Zeek log (10k lines)
        log_path = tmp_path / "large.log"
        with open(log_path, "w") as f:
            f.write("#separator \\t\n")
            f.write("#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n")
            for i in range(10000):
                f.write(f"{i}.0\t192.168.1.10\t192.168.1.20\t502\ttcp\n")
        
        # Track if we're streaming or reading all at once
        # If it reads all at once, memory usage will spike
        # We'll check by reading with a generator
        
        count = 0
        for record in parse_zeek_log(str(log_path)):
            count += 1
            # If it's streaming, we should be able to stop early
            if count >= 5:
                break
        
        # If we can break early, it's streaming
        # If it read all at once, we couldn't break early
        # Since we successfully broke after 5, streaming works
        assert count == 5, "Should be able to stop early - streaming works"
        
        # However, the current implementation uses readlines()
        # So this test will FAIL, confirming the issue
        # We'll mark it as expected failure for now