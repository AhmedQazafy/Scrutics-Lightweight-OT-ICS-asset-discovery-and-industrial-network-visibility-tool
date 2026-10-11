"""
scripts/build_bundled_oui.py builds the bundled vendor file from IEEE registry CSV files.

The fixtures here are small synthetic registry files written in the registry's CSV layout; no
test reads or downloads the real registry.
"""

import hashlib
import importlib.util
import os
import random

import pytest

from scrutics.classifier.oui import _parse_oui_file, lookup_vendor

_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "build_bundled_oui.py")
_spec = importlib.util.spec_from_file_location("build_bundled_oui", _SCRIPT)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

HEADER = "Registry,Assignment,Organization Name,Organization Address\n"
MA_L = [
    ("MA-L", "001B1B", "Siemens AG,", "Nuremberg DE"),
    ("MA-L", "00000C", "Cisco Systems, Inc", "San Jose US"),
    ("MA-L", "009027", "Intel Corporation", "Hillsboro US"),
    ("MA-L", "0090E8", "MOXA TECHNOLOGIES CORP., LTD.", "Taipei TW"),
    ("MA-L", "001122", "Example Fabrication Ltd", "Nowhere"),            # no vendor class
    ("MA-L", "0050C2", "IEEE Registration Authority", "Piscataway US"),  # shared block
    ("MA-L", "70B3D5", "IEEE Registration Authority", "Piscataway US"),  # shared block
    ("MA-L", "00D0C9", "ADVANTECH CO., LTD.", "Taipei TW"),
]
MA_M = [("MA-M", "70B3D5A", "Pilz GmbH & Co.", "Ostfildern DE"),
        ("MA-M", "70B3D5B", "Example Fabrication Ltd", "Nowhere")]
MA_S = [("MA-S", "70B3D5C12", "HMS Industrial Networks", "Halmstad SE")]
IAB = [("IAB", "0050C2123", "Phoenix Contact GmbH & Co. KG", "Blomberg DE"),
       ("IAB", "0050C2456", "Example Fabrication Ltd", "Nowhere")]


def _csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(HEADER)
        for r in rows:
            f.write(",".join(f'"{v}"' if "," in v else v for v in r) + "\n")


@pytest.fixture
def registry(tmp_path):
    def write(ma_l=MA_L, ma_m=MA_M, ma_s=MA_S, iab=IAB):
        paths = {"MA-L": tmp_path / "oui.csv", "MA-M": tmp_path / "mam.csv",
                 "MA-S": tmp_path / "oui36.csv", "IAB": tmp_path / "iab.csv"}
        for (reg, path), rows in zip(paths.items(), (ma_l, ma_m, ma_s, iab)):
            _csv(path, rows)
        return {k: str(v) for k, v in paths.items()}
    return write


def _entries(text):
    return [line for line in text.splitlines() if "(hex)" in line]


def test_assignments_with_a_vendor_class_are_written_with_their_registry_prefix(registry):
    text = gen.build(registry(), "2026-10-10")
    assert _entries(text) == [
        "00-00-0C   (hex)\t\tCisco Systems, Inc",
        "00-1B-1B   (hex)\t\tSiemens AG,",
        "00-50-C2-12-3   (hex)\t\tPhoenix Contact GmbH & Co. KG",
        "00-90-27   (hex)\t\tIntel Corporation",
        "00-90-E8   (hex)\t\tMOXA TECHNOLOGIES CORP., LTD.",
        "00-D0-C9   (hex)\t\tADVANTECH CO., LTD.",
        "70-B3-D5-A   (hex)\t\tPilz GmbH & Co.",
        "70-B3-D5-C1-2   (hex)\t\tHMS Industrial Networks",
    ]


def test_organisations_without_a_vendor_class_are_not_written(registry):
    assert "Example Fabrication" not in gen.build(registry(), "2026-10-10")


def test_shared_blocks_are_never_attributed_to_one_vendor(registry, tmp_path):
    out = tmp_path / "ics_oui.txt"
    out.write_text(gen.build(registry(), "2026-10-10"), encoding="utf-8")
    db = _parse_oui_file(str(out))
    assert "0050C2" not in db and "70B3D5" not in db
    # A MAC in a shared block resolves to the holder of its smaller block, or to nothing
    assert lookup_vendor("00:50:C2:12:34:56", db) == "Phoenix Contact GmbH & Co. KG"
    assert lookup_vendor("00:50:C2:45:60:00", db) == "Unknown"       # holder without a vendor class
    assert lookup_vendor("00:50:C2:99:00:00", db) == "Unknown"       # no listed holder
    assert lookup_vendor("70:B3:D5:A0:00:01", db) == "Pilz GmbH & Co."
    assert lookup_vendor("70:B3:D5:C1:20:01", db) == "HMS Industrial Networks"
    assert lookup_vendor("70:B3:D5:B0:00:01", db) == "Unknown"


def test_organisation_names_are_written_exactly_as_registered(registry, tmp_path):
    out = tmp_path / "ics_oui.txt"
    out.write_text(gen.build(registry(), "2026-10-10"), encoding="utf-8")
    db = _parse_oui_file(str(out))
    assert db["001B1B"] == "Siemens AG,"
    assert db["0090E8"] == "MOXA TECHNOLOGIES CORP., LTD."


def test_header_names_the_sources_their_date_and_hashes(registry):
    paths = registry()
    text = gen.build(paths, "2026-10-10")
    header = [line for line in text.splitlines() if line.startswith("#")]
    assert header[0] == "# Vendor assignments from the IEEE Registration Authority registry"
    assert any("Retrieved 2026-10-10" in line for line in header)
    for reg, path in paths.items():
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        assert f"#   {reg}: {os.path.basename(path)} SHA-256 {digest}" in header
    assert "#   MA-L: OT 3, IT 2" in header
    # Header lines are not read as entries
    assert all("(hex)" not in line for line in header)


def _without_hashes(text):
    # A reordered input file has different bytes, so only its SHA-256 line may differ
    return [line for line in text.splitlines() if "SHA-256" not in line]


def test_output_does_not_depend_on_input_order(registry):
    first = gen.build(registry(), "2026-10-10")
    assert gen.build(registry(), "2026-10-10") == first                  # same input, same bytes
    for seed in range(3):
        rows = list(MA_L)
        random.Random(seed).shuffle(rows)
        shuffled = gen.build(registry(ma_l=rows, iab=list(reversed(IAB))), "2026-10-10")
        assert _without_hashes(shuffled) == _without_hashes(first)


@pytest.mark.parametrize("rows, message", [
    ([("MA-L", "00909", "Short Assignment Ltd", "x")], "is not 6 hexadecimal digits"),
    ([("MA-L", "00XX27", "Siemens AG", "x")], "is not 6 hexadecimal digits"),
    ([("MA-M", "001B1B", "Siemens AG", "x")], "expected MA-L"),
])
def test_unusable_rows_stop_the_build(registry, rows, message):
    with pytest.raises(gen.RegistryError, match=message):
        gen.build(registry(ma_l=rows), "2026-10-10")


def test_a_missing_column_stops_the_build(registry, tmp_path):
    paths = registry()
    with open(paths["MA-S"], "w", encoding="utf-8") as f:
        f.write("Registry,Assignment\nMA-S,70B3D5C12\n")
    with pytest.raises(gen.RegistryError, match="missing column"):
        gen.build(paths, "2026-10-10")


def test_one_prefix_held_by_two_organisations_stops_the_build(registry):
    rows = MA_L + [("MA-L", "001B1B", "Siemens Mobility GmbH", "x")]
    with pytest.raises(gen.RegistryError, match="held by both"):
        gen.build(registry(ma_l=rows), "2026-10-10")


def test_command_line_writes_the_file_and_reports_failures(registry, tmp_path, capsys):
    paths = registry()
    out = tmp_path / "ics_oui.txt"
    args = ["--ma-l", paths["MA-L"], "--ma-m", paths["MA-M"], "--ma-s", paths["MA-S"],
            "--iab", paths["IAB"], "--retrieved", "2026-10-10", "--out", str(out)]
    assert gen.main(args) == 0
    assert out.read_text(encoding="utf-8") == gen.build(paths, "2026-10-10")
    out.write_text("previous content", encoding="utf-8")
    missing = args.copy()
    missing[1] = str(tmp_path / "absent.csv")
    assert gen.main(missing) == 1
    assert out.read_text(encoding="utf-8") == "previous content"        # left untouched
    assert "absent.csv" in capsys.readouterr().err
