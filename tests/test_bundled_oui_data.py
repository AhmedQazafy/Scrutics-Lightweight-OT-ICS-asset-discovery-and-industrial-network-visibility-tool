"""
The bundled vendor file is the IEEE registry subset built by scripts/build_bundled_oui.py.

A prefix resolves to the organisation the IEEE registry assigns it to, or to nothing; shared
blocks held by the IEEE Registration Authority are never attributed to one vendor. Every listed
organisation has a vendor class, and curated family hints carry a cited source.
"""

import re

import pytest

from scrutics.classifier import oui
from scrutics.classifier.oui import _parse_oui_file, classify_vendor, lookup_vendor

DB = _parse_oui_file(oui.OUI_BUNDLED_PATH)


def _header():
    with open(oui.OUI_BUNDLED_PATH, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.startswith("#")]


# Registry owners (IEEE Registration Authority listing retrieved 2026-10-10)
@pytest.mark.parametrize("mac, owner", [
    ("00:90:27:12:34:56", "Intel Corporation"),
    ("00:0C:F1:12:34:56", "Intel Corporation"),
    ("00:0E:8C:12:34:56", "Siemens AG"),
    ("00:90:E8:12:34:56", "MOXA TECHNOLOGIES CORP., LTD."),
    ("00:D0:C9:12:34:56", "ADVANTECH CO., LTD."),
    ("00:30:11:12:34:56", "HMS Industrial Networks"),
    ("00:80:F4:12:34:56", "TELEMECANIQUE ELECTRIQUE"),
    ("00:40:9D:12:34:56", "DigiBoard"),
    ("00:1B:1B:12:34:56", "Siemens AG,"),
    ("00:0C:29:12:34:56", "VMware, Inc."),
])
def test_prefixes_resolve_to_their_registry_owner(mac, owner):
    assert lookup_vendor(mac, DB) == owner


def test_the_shared_00_50_c2_block_is_not_one_vendor():
    # 00:50:C2 is held by the IEEE Registration Authority and divided into IAB blocks
    assert "0050C2" not in DB
    assert lookup_vendor("00:50:C2:00:00:01", DB) == "Unknown"
    assert all(len(k) == 9 for k in DB if k.startswith("0050C2"))


def test_no_listed_block_contains_a_smaller_listed_block():
    # Only blocks held by the IEEE Registration Authority are divided into smaller assignments
    short = {k for k in DB if len(k) == 6}
    assert not [k for k in DB if len(k) > 6 and k[:6] in short]


def test_every_listed_organisation_has_a_vendor_class():
    assert [v for v in DB.values() if classify_vendor(v) == oui.VENDOR_CLASS_UNKNOWN] == []


def test_header_names_the_registry_its_retrieval_date_and_hashes():
    header = _header()
    assert header[0] == "# Vendor assignments from the IEEE Registration Authority registry"
    assert any("Retrieved 2026-10-10" in line for line in header)
    for registry in ("MA-L", "MA-M", "MA-S", "IAB"):
        assert any(re.match(rf"#   {registry}: \S+\.csv SHA-256 [0-9a-f]{{64}}$", line) for line in header)


def test_bundled_family_hints_cite_a_source():
    import yaml
    with open(oui.CURATED_OUI_BUNDLED_PATH, encoding="utf-8") as f:
        entries = yaml.safe_load(f) or {}
    assert all(isinstance(e, dict) and e.get("source") for e in entries.values())
