"""
Phase B2 -- OUI Correctness & Multi-Length Prefix Support Tests

Tests:
  A. MA-L parsing (6 nibbles)
  B. MA-M parsing (7 nibbles)
  C. MA-S parsing (9 nibbles)
  D. MA-L lookup
  E. MA-M lookup
  F. MA-S lookup
  G. Longest-prefix precedence (9-char vs 6-char)
  H. 7-vs-6 precedence (MA-M vs MA-L)
  I. Normalization (colon, hyphen, dotted, lowercase)
  J. Unknown prefix
  K. Short MAC and malformed input handling
  L. Malformed database lines resilience
  M. Duplicate prefix last-occurrence-wins behavior
"""

import os
import tempfile
import pytest
from scrutics.classifier.oui import _parse_oui_file, lookup_vendor


class TestOUIParserMultiLength:
    """A, B, C, L, M: Parser tests for IEEE multi-length prefix support and resilience."""

    def test_ma_l_parsing(self, tmp_path):
        """A. MA-L (24-bit / 6 nibbles) parses to 6-char uppercase key."""
        db_file = tmp_path / "oui_mal.txt"
        db_file.write_text("AA-BB-CC   (hex)\t\tExample MA-L Vendor\n", encoding="utf-8")
        parsed = _parse_oui_file(str(db_file))
        assert "AABBCC" in parsed
        assert parsed["AABBCC"] == "Example MA-L Vendor"

    def test_ma_m_parsing(self, tmp_path):
        """B. MA-M (28-bit / 7 nibbles) parses to 7-char uppercase key."""
        db_file = tmp_path / "oui_mam.txt"
        db_file.write_text("AA-BB-CC-D   (hex)\t\tExample MA-M Vendor\n", encoding="utf-8")
        parsed = _parse_oui_file(str(db_file))
        assert "AABBCCD" in parsed
        assert parsed["AABBCCD"] == "Example MA-M Vendor"

    def test_ma_s_parsing(self, tmp_path):
        """C. MA-S (36-bit / 9 nibbles) parses to 9-char uppercase key."""
        db_file = tmp_path / "oui_mas.txt"
        db_file.write_text("AA-BB-CC-DD-E   (hex)\t\tExample MA-S Vendor\n", encoding="utf-8")
        parsed = _parse_oui_file(str(db_file))
        assert "AABBCCDDE" in parsed
        assert parsed["AABBCCDDE"] == "Example MA-S Vendor"

    def test_malformed_database_lines_skipped(self, tmp_path):
        """L. Malformed lines skipped without error; surrounding valid lines loaded."""
        content = (
            "not valid\n"
            "# comment line\n"
            "AA-BB (hex) Too Short\n"
            "00-11-22 (hex) Valid First\n"
            "ZZ-ZZ-ZZ (hex) Invalid Hex\n"
            "AA-BB-CC-DD-EE-FF (hex) Too Long\n"
            "33-44-55 (hex)   \n"  # empty vendor
            "66-77-88 (hex) Valid Second\n"
        )
        db_file = tmp_path / "oui_malformed.txt"
        db_file.write_text(content, encoding="utf-8")
        parsed = _parse_oui_file(str(db_file))

        assert "001122" in parsed
        assert parsed["001122"] == "Valid First"
        assert "667788" in parsed
        assert parsed["667788"] == "Valid Second"
        assert len(parsed) == 2

    def test_duplicate_prefix_last_wins(self, tmp_path):
        """M. Duplicate prefix results in last occurrence winning."""
        content = (
            "AA-BB-CC (hex) First Vendor\n"
            "AA-BB-CC (hex) Second Vendor\n"
        )
        db_file = tmp_path / "oui_duplicate.txt"
        db_file.write_text(content, encoding="utf-8")
        parsed = _parse_oui_file(str(db_file))
        assert parsed["AABBCC"] == "Second Vendor"


class TestOUILookupMultiLength:
    """D, E, F, G, H, I, J, K: Lookup tests for longest-prefix matching and normalization."""

    def test_ma_l_lookup(self):
        """D. MAC beginning with 6-char prefix resolves correctly."""
        db = {"0050C2": "Phoenix Contact"}
        assert lookup_vendor("00:50:C2:11:22:33", db) == "Phoenix Contact"

    def test_ma_m_lookup(self):
        """E. MAC beginning with 7-char prefix resolves correctly when no 9-char entry exists."""
        db = {"0050C20": "Specific Sub-Vendor"}
        assert lookup_vendor("00:50:C2:01:22:33", db) == "Specific Sub-Vendor"

    def test_ma_s_lookup(self):
        """F. MAC beginning with 9-char prefix resolves correctly."""
        db = {"0050C2000": "Micro Device Vendor"}
        assert lookup_vendor("00:50:C2:00:01:23", db) == "Micro Device Vendor"

    def test_longest_prefix_precedence_9_vs_6(self):
        """G. 9-character assignment wins over 6-character parent; non-child falls back to 6."""
        db = {
            "0050C2": "IEEE Registration Authority",
            "0050C2000": "Specific Vendor",
        }
        # Matching full MAC with 9-character prefix
        assert lookup_vendor("00:50:C2:00:0A:BB", db) == "Specific Vendor"

        # Matching MAC that belongs only to 6-character parent
        assert lookup_vendor("00:50:C2:11:22:33", db) == "IEEE Registration Authority"

    def test_longest_prefix_precedence_7_vs_6(self):
        """H. 7-character entry wins over 6-character parent."""
        db = {
            "AABBCC": "Parent MA-L Vendor",
            "AABBCCD": "Specific MA-M Vendor",
        }
        # Matches 7-character prefix
        assert lookup_vendor("AA:BB:CC:D1:23:45", db) == "Specific MA-M Vendor"

        # Matches only 6-character parent prefix
        assert lookup_vendor("AA:BB:CC:E1:23:45", db) == "Parent MA-L Vendor"

    def test_longest_prefix_precedence_all_three_tiers(self):
        """Comprehensive 9 -> 7 -> 6 precedence hierarchy test."""
        db = {
            "112233": "Tier 6 MA-L",
            "1122334": "Tier 7 MA-M",
            "112233445": "Tier 9 MA-S",
        }
        # Matches Tier 9
        assert lookup_vendor("11:22:33:44:56:78", db) == "Tier 9 MA-S"
        # Matches Tier 7 (different 8th/9th nibble)
        assert lookup_vendor("11:22:33:40:00:00", db) == "Tier 7 MA-M"
        # Matches Tier 6 (different 7th nibble)
        assert lookup_vendor("11:22:33:50:00:00", db) == "Tier 6 MA-L"

    def test_normalization_formats(self):
        """I. Colon, hyphen, dotted, and lowercase MACs resolve identically."""
        db = {"0050C2000": "Specific Vendor"}
        mac_colon = "00:50:C2:00:0A:BB"
        mac_hyphen = "00-50-C2-00-0A-BB"
        mac_dotted = "0050.C200.0ABB"
        mac_lower = "00:50:c2:00:0a:bb"

        assert lookup_vendor(mac_colon, db) == "Specific Vendor"
        assert lookup_vendor(mac_hyphen, db) == "Specific Vendor"
        assert lookup_vendor(mac_dotted, db) == "Specific Vendor"
        assert lookup_vendor(mac_lower, db) == "Specific Vendor"

    def test_unknown_prefix(self):
        """J. Valid MAC with no matching prefix returns 'Unknown'."""
        db = {"0050C2": "Phoenix Contact"}
        assert lookup_vendor("AA:BB:CC:DD:EE:FF", db) == "Unknown"

    def test_short_and_invalid_macs(self):
        """K. Inputs shorter than 6 hex characters or malformed safely return 'Unknown'."""
        db = {"0050C2": "Phoenix Contact"}
        assert lookup_vendor("", db) == "Unknown"
        assert lookup_vendor("00", db) == "Unknown"
        assert lookup_vendor("00:11", db) == "Unknown"
        assert lookup_vendor("00:11:2", db) == "Unknown"
        assert lookup_vendor(None, db) == "Unknown"
        assert lookup_vendor("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", db) == "Unknown"
        assert lookup_vendor("invalid_mac", db) == "Unknown"
        assert lookup_vendor("   ", db) == "Unknown"
