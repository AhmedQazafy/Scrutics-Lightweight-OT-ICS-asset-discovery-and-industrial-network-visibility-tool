"""
Phase B4 + B5 — Curated OUI Metadata and OUI Database Lifecycle Tests.

Covers:
  B4:
    - Curated OUI metadata loading and parsing
    - Prefix normalization and longest-prefix lookup (MA-S -> MA-M -> MA-L)
    - User-local override (~/.scrutics/curated_oui.yaml overrides bundled per prefix)
    - Non-authoritative evidence generation: device_family_hint as os_hint (weight=5, LOW confidence)
    - INVARIANT: device_family_hint never changes classification_type independently
    - Non-matching or malformed MAC handling

  B5:
    - OUI database resolution precedence (~/.scrutics/oui.txt > local > bundled)
    - validate_oui_file on valid, malformed, empty, and non-existent files
    - Tier counts (MA-L, MA-M, MA-S) calculation
    - Metadata tracking (read_oui_meta, write_oui_meta)
    - Freshness calculation (<180d Current, 180-364d Aging, >=365d Outdated)
    - Atomic database replacement and .bak backup
    - Rollback resilience on corrupted input
    - CLI commands:
        - scrutics oui status (exit code 0)
        - scrutics oui validate (exit code 0 on valid, 1 on invalid)
        - scrutics oui import (exit code 0 on valid, 1 on failure)
        - scrutics oui update (mocked network; exit code 0 on success, 1 on network failure)
    - Diagnostics & Doctor: OUI section present, outdated database is non-blocking (doctor returns 0)
    - Startup info: non-blocking warning displayed when database >= 180 days old
"""

import os
import json
import datetime
import pytest
from unittest.mock import patch, MagicMock

from scrutics.classifier.oui import (
    load_curated_oui_metadata,
    lookup_oui_metadata,
    validate_oui_file,
    read_oui_meta,
    write_oui_meta,
    get_oui_freshness,
    get_active_oui_path,
    load_oui_db,
    install_oui_database,
    download_ieee_oui,
    import_oui_file,
    FRESHNESS_CURRENT,
    FRESHNESS_AGING,
    FRESHNESS_OUTDATED,
    OUI_USER_PATH,
    OUI_USER_BAK_PATH,
    OUI_META_PATH,
    VENDOR_CLASS_OT,
)
from scrutics.db.inventory import Asset, AssetInventory
from scrutics.capture.engine import CaptureEngine
from scrutics.diagnostics import full_report, check_oui_db, print_startup_info
from scrutics.cli import (
    run_doctor,
    run_oui,
    run_oui_status,
    run_oui_validate,
    run_oui_update,
    run_oui_import,
    build_parser,
    should_use_tui,
)


@pytest.fixture(autouse=True)
def _isolate_oui_meta(tmp_path, monkeypatch):
    """Keep OUI metadata writes out of the real ~/.scrutics; tests may patch the path again."""
    monkeypatch.setattr("scrutics.classifier.oui.OUI_META_PATH", str(tmp_path / "oui_meta.json"))


# ═══════════════════════════════════════════════════════════════════════════════
# B4: Curated OUI Metadata Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCuratedOUIMetadata:

    def test_bundled_curated_metadata_loaded(self):
        """Bundled curated_oui.yaml is parsed and provides OT device family hints."""
        meta = load_curated_oui_metadata(force_reload=True)
        assert isinstance(meta, dict)
        assert len(meta) >= 25

        # Siemens S7 / SCALANCE
        assert "001B1B" in meta
        assert "SIMATIC S7" in meta["001B1B"]["device_family_hint"]

        # Schneider Modicon / Quantum
        assert "0080F4" in meta
        assert "Modicon" in meta["0080F4"]["device_family_hint"]

        # Rockwell ControlLogix
        assert "0000BC" in meta
        assert "ControlLogix" in meta["0000BC"]["device_family_hint"]

        # Moxa NPort / EDS
        assert "000E8C" in meta
        assert "Moxa" in meta["000E8C"]["device_family_hint"]

    def test_lookup_oui_metadata_mac_formats(self):
        """Lookup accepts colon, hyphen, dotted, unseparated, and lowercase MACs."""
        # 00:1B:1B is Siemens
        res1 = lookup_oui_metadata("00:1b:1b:34:56:78")
        assert res1 is not None
        assert "SIMATIC S7" in res1["device_family_hint"]

        res2 = lookup_oui_metadata("00-1B-1B-34-56-78")
        assert res2 is not None
        assert "SIMATIC S7" in res2["device_family_hint"]

        res3 = lookup_oui_metadata("001b.1b34.5678")
        assert res3 is not None
        assert "SIMATIC S7" in res3["device_family_hint"]

        res4 = lookup_oui_metadata("001B1B")
        assert res4 is not None
        assert "SIMATIC S7" in res4["device_family_hint"]

    def test_lookup_oui_metadata_longest_prefix(self):
        """Longest prefix matches first: MA-S (9) -> MA-M (7) -> MA-L (6)."""
        custom_meta = {
            "001B1B": {"device_family_hint": "Generic Siemens Family", "tier": "MA-L"},
            "001B1BC": {"device_family_hint": "Siemens Specific Sub-family", "tier": "MA-M"},
            "001B1BCDE": {"device_family_hint": "Siemens Specific Device", "tier": "MA-S"},
        }
        # 9-nibble exact match
        match_mas = lookup_oui_metadata("00:1B:1B:CD:E0:11", curated_meta=custom_meta)
        assert match_mas["device_family_hint"] == "Siemens Specific Device"

        # 7-nibble match
        match_mam = lookup_oui_metadata("00:1B:1B:CF:00:11", curated_meta=custom_meta)
        assert match_mam["device_family_hint"] == "Siemens Specific Sub-family"

        # 6-nibble fallback match
        match_mal = lookup_oui_metadata("00:1B:1B:00:00:11", curated_meta=custom_meta)
        assert match_mal["device_family_hint"] == "Generic Siemens Family"

    def test_user_local_curated_override(self, tmp_path, monkeypatch):
        """User-local curated_oui.yaml overrides bundled entry for matching prefix."""
        user_curated = tmp_path / "curated_oui.yaml"
        user_curated.write_text(
            '001B1B:\n  device_family_hint: "Custom User Siemens PLC"\n',
            encoding="utf-8"
        )
        try:
            monkeypatch.setattr("scrutics.classifier.oui.CURATED_OUI_USER_PATH", str(user_curated))
            meta = load_curated_oui_metadata(force_reload=True)
            assert meta["001B1B"]["device_family_hint"] == "Custom User Siemens PLC"
            # Other bundled keys remain intact
            assert "0080F4" in meta
            assert "Modicon" in meta["0080F4"]["device_family_hint"]
        finally:
            monkeypatch.undo()
            load_curated_oui_metadata(force_reload=True)

    def test_lookup_unknown_or_malformed_returns_none(self):
        """Lookup returns None for non-existent prefix or invalid MAC format."""
        assert lookup_oui_metadata("FF:FF:FF:00:11:22") is None
        assert lookup_oui_metadata("00:11") is None
        assert lookup_oui_metadata("") is None
        assert lookup_oui_metadata(None) is None
        assert lookup_oui_metadata("not-a-mac") is None

    def test_engine_enriches_evidence_with_device_family_hint(self):
        """
        When traffic from a known industrial MAC is observed, engine enriches asset evidence
        with os_hint (weight=5, confidence='LOW', source='OUI_metadata').
        """
        engine = CaptureEngine(inventory=AssetInventory())
        # Siemens MAC 00:1B:1B:11:22:33
        engine._process_flow_data(
            src_ip="192.168.1.50",
            src_mac="00:1B:1B:11:22:33",
            dst_ip="192.168.1.1",
            dst_port=80,
            proto="TCP",
            ts=1000.0,
        )
        asset = engine.inventory.get("192.168.1.50")
        assert asset is not None
        assert asset.vendor_class == VENDOR_CLASS_OT

        # Check evidence list for OUI_metadata hint
        hints = [e for e in asset.evidence if e.source == "OUI_metadata"]
        assert len(hints) == 1
        ev = hints[0]
        assert ev.type == "os_hint"
        assert "SIMATIC S7" in ev.value
        assert ev.weight == 5
        assert ev.confidence == "LOW"

    def test_invariant_device_family_hint_does_not_change_classification_type(self):
        """
        INVARIANT: Device family hint is low-confidence supporting evidence.
        It NEVER directly establishes classification_type as OT or IT without port evidence.
        """
        engine = CaptureEngine(inventory=AssetInventory())
        # Device contacts a port but has no listening ports seen
        engine._process_flow_data(
            src_ip="192.168.1.60",
            src_mac="00:80:F4:00:11:22",  # Schneider Electric Modicon
            dst_ip="192.168.1.1",
            dst_port=80,
            proto="TCP",
            ts=1000.0,
        )
        asset = engine.inventory.get("192.168.1.60")
        assert asset is not None
        # OUI match produces evidence
        assert any(e.source == "OUI_metadata" for e in asset.evidence)
        # However, classification_type must NOT be forced to OT solely by OUI metadata
        assert asset.classification_type != "OT"


# ═══════════════════════════════════════════════════════════════════════════════
# B5: OUI Database Validation & Lifecycle Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestOUIValidationAndLifecycle:

    def test_validate_oui_file_valid(self, tmp_path):
        """Valid OUI file with MA-L, MA-M, and MA-S entries is validated properly."""
        oui_file = tmp_path / "test_oui.txt"
        content = (
            "# Sample OUI Registry\n"
            "00-11-22   (hex)\t\tVendor MAL 1\n"
            "00-11-33   (hex)\t\tVendor MAL 2\n"
            "AA-BB-CC-D   (hex)\t\tVendor MAM\n"
            "AA-BB-CC-DD-E   (hex)\t\tVendor MAS\n"
        )
        oui_file.write_text(content, encoding="utf-8")

        res = validate_oui_file(str(oui_file))
        assert res["valid"] is True
        assert res["entry_count"] == 4
        assert res["tiers"]["ma_l"] == 2
        assert res["tiers"]["ma_m"] == 1
        assert res["tiers"]["ma_s"] == 1
        assert res["malformed_count"] == 0
        assert res["total_lines"] == 5
        assert len(res["sha256"]) == 64

    def test_validate_oui_file_with_malformed_lines(self, tmp_path):
        """Malformed lines are counted without invalidating surrounding entries."""
        oui_file = tmp_path / "test_oui_malformed.txt"
        content = (
            "00-11-22   (hex)\t\tValid Vendor\n"
            "ZZ-ZZ-ZZ   (hex)\t\tInvalid Hex\n"
            "00-11   (hex)\t\tToo Short\n"
            "00-22-33   (hex)\t\t\n"  # Empty vendor
            "00-33-44   (hex)\t\tValid Vendor 2\n"
        )
        oui_file.write_text(content, encoding="utf-8")

        res = validate_oui_file(str(oui_file))
        assert res["valid"] is True
        assert res["entry_count"] == 2
        assert res["malformed_count"] == 3

    def test_validate_oui_file_empty_or_missing(self, tmp_path):
        """Empty or non-existent file returns valid: False."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("", encoding="utf-8")
        assert validate_oui_file(str(empty_file))["valid"] is False

        missing_file = tmp_path / "non_existent.txt"
        assert validate_oui_file(str(missing_file))["valid"] is False

    def test_database_resolution_order(self, tmp_path, monkeypatch):
        """Precedence: ~/.scrutics/oui.txt > local repo oui.txt > bundled ics_oui.txt."""
        user_db = tmp_path / "user_oui.txt"
        local_db = tmp_path / "local_oui.txt"
        bundled_db = tmp_path / "bundled_oui.txt"

        user_db.write_text("00-00-01   (hex)\t\tUser DB Vendor\n", encoding="utf-8")
        local_db.write_text("00-00-02   (hex)\t\tLocal DB Vendor\n", encoding="utf-8")
        bundled_db.write_text("00-00-03   (hex)\t\tBundled DB Vendor\n", encoding="utf-8")

        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_PATH", str(user_db))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_FULL_PATH", str(local_db))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_BUNDLED_PATH", str(bundled_db))

        # 1. User DB takes precedence
        path, db_type = get_active_oui_path()
        assert path == str(user_db)
        assert db_type == "user-updated"

        # 2. When User DB is missing, local takes precedence
        user_db.unlink()
        path, db_type = get_active_oui_path()
        assert path == str(local_db)
        assert db_type == "local"

        # 3. When local is missing, bundled is used
        local_db.unlink()
        path, db_type = get_active_oui_path()
        assert path == str(bundled_db)
        assert db_type == "bundled"

    def test_install_oui_database_atomic_with_backup(self, tmp_path, monkeypatch):
        """install_oui_database atomically replaces user db and keeps .bak backup."""
        user_dir = tmp_path / ".scrutics"
        user_db = user_dir / "oui.txt"
        bak_db = user_dir / "oui.txt.bak"
        meta_file = user_dir / "oui_meta.json"

        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_DIR", str(user_dir))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_PATH", str(user_db))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_BAK_PATH", str(bak_db))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_META_PATH", str(meta_file))

        initial_content = "00-11-22   (hex)\t\tInitial Vendor\n"
        ok, msg, _ = install_oui_database(initial_content, source_type="test-v1", min_entries=1)
        assert ok is True
        assert user_db.exists()
        assert not bak_db.exists()

        # Update with new content
        new_content = "00-33-44   (hex)\t\tUpdated Vendor\n"
        ok, msg, _ = install_oui_database(new_content, source_type="test-v2", min_entries=1)
        assert ok is True
        assert bak_db.exists()
        assert "Initial Vendor" in bak_db.read_text(encoding="utf-8")
        assert "Updated Vendor" in user_db.read_text(encoding="utf-8")

        # Metadata should be recorded
        assert meta_file.exists()
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert meta["source"] == "test-v2"
        assert meta["entry_count"] == 1

    def test_install_oui_database_rejects_corrupted_content(self, tmp_path, monkeypatch):
        """install_oui_database aborts and retains existing DB if new data fails validation."""
        user_dir = tmp_path / ".scrutics"
        user_db = user_dir / "oui.txt"
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_DIR", str(user_dir))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_PATH", str(user_db))

        initial_content = "00-11-22   (hex)\t\tOriginal Valid Vendor\n"
        install_oui_database(initial_content, source_type="valid", min_entries=1)

        corrupted = "NOT AN OUI FILE\nNo hex lines\n"
        ok, msg, _ = install_oui_database(corrupted, source_type="corrupted", min_entries=1)
        assert ok is False
        assert "Validation failed" in msg
        # Original remains intact
        assert "Original Valid Vendor" in user_db.read_text(encoding="utf-8")

    def test_freshness_categories(self, tmp_path, monkeypatch):
        """Freshness policy: <180d Current, 180-364d Aging, >=365d Outdated."""
        user_dir = tmp_path / ".scrutics"
        user_db = user_dir / "oui.txt"
        meta_file = user_dir / "oui_meta.json"
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_DIR", str(user_dir))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_PATH", str(user_db))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_META_PATH", str(meta_file))

        user_dir.mkdir(parents=True, exist_ok=True)
        user_db.write_text("00-11-22   (hex)\t\tVendor A\n", encoding="utf-8")

        now = datetime.datetime(2026, 9, 16, 12, 0, tzinfo=datetime.timezone.utc)

        # 1. 30 days old -> Current
        date_30d = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%d")
        write_oui_meta(source="test", entry_count=1, tiers={"ma_l": 1, "ma_m": 0, "ma_s": 0},
                       sha256="abc", source_date=date_30d)
        f1 = get_oui_freshness(now=now)
        assert f1["freshness"] == FRESHNESS_CURRENT
        assert f1["age_days"] == 30

        # 2. 200 days old -> Aging
        date_200d = (now - datetime.timedelta(days=200)).strftime("%Y-%m-%d")
        write_oui_meta(source="test", entry_count=1, tiers={"ma_l": 1, "ma_m": 0, "ma_s": 0},
                       sha256="abc", source_date=date_200d)
        f2 = get_oui_freshness(now=now)
        assert f2["freshness"] == FRESHNESS_AGING
        assert f2["age_days"] == 200

        # 3. 400 days old -> Outdated
        date_400d = (now - datetime.timedelta(days=400)).strftime("%Y-%m-%d")
        write_oui_meta(source="test", entry_count=1, tiers={"ma_l": 1, "ma_m": 0, "ma_s": 0},
                       sha256="abc", source_date=date_400d)
        f3 = get_oui_freshness(now=now)
        assert f3["freshness"] == FRESHNESS_OUTDATED
        assert f3["age_days"] == 400


# ═══════════════════════════════════════════════════════════════════════════════
# B5: CLI Commands & Diagnostics Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestOUICLICommands:

    def test_cli_parser_oui_subcommands(self):
        """CLI parser accepts oui status, validate, update, import."""
        parser = build_parser()

        args_status = parser.parse_args(["oui", "status"])
        assert args_status.command == "oui"
        assert args_status.oui_action == "status"
        assert should_use_tui(args_status) is False

        args_validate = parser.parse_args(["oui", "validate", "my_file.txt"])
        assert args_validate.command == "oui"
        assert args_validate.oui_action == "validate"
        assert args_validate.file == "my_file.txt"

        args_import = parser.parse_args(["oui", "import", "offline_oui.txt"])
        assert args_import.command == "oui"
        assert args_import.oui_action == "import"
        assert args_import.file == "offline_oui.txt"

        args_update = parser.parse_args(["oui", "update", "--url", "http://example.com/oui.txt"])
        assert args_update.command == "oui"
        assert args_update.oui_action == "update"
        assert args_update.url == "http://example.com/oui.txt"

    def test_run_oui_status(self, capsys):
        """scrutics oui status displays database path and freshness and exits 0."""
        parser = build_parser()
        args = parser.parse_args(["oui", "status"])
        code = run_oui(args)
        assert code == 0
        out = capsys.readouterr().out
        assert "Scrutics OUI Database Status" in out
        assert "Active Database:" in out
        assert "Freshness:" in out

    def test_run_oui_validate_valid_and_invalid(self, tmp_path, capsys):
        """scrutics oui validate returns 0 on valid file, 1 on invalid file."""
        parser = build_parser()

        # Valid file
        valid_file = tmp_path / "valid.txt"
        valid_file.write_text("00-11-22   (hex)\t\tValid Inc\n", encoding="utf-8")
        args_val = parser.parse_args(["oui", "validate", str(valid_file)])
        assert run_oui(args_val) == 0
        out = capsys.readouterr().out
        assert "[✓] Valid OUI database:" in out

        # Invalid file
        invalid_file = tmp_path / "invalid.txt"
        invalid_file.write_text("Corrupted file content\n", encoding="utf-8")
        args_inval = parser.parse_args(["oui", "validate", str(invalid_file)])
        assert run_oui(args_inval) == 1
        out = capsys.readouterr().out
        assert "[✗] Validation failed:" in out

    def test_run_oui_import_success_and_failure(self, tmp_path, monkeypatch, capsys):
        """scrutics oui import copies valid file and returns 0; fails on bad file."""
        user_dir = tmp_path / ".scrutics"
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_DIR", str(user_dir))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_PATH", str(user_dir / "oui.txt"))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_BAK_PATH", str(user_dir / "oui.txt.bak"))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_META_PATH", str(user_dir / "oui_meta.json"))

        parser = build_parser()

        # Import valid file
        src_file = tmp_path / "offline_ieee.txt"
        src_file.write_text("AA-BB-CC   (hex)\t\tOffline Vendor\n", encoding="utf-8")
        args_import = parser.parse_args(["oui", "import", str(src_file)])
        assert run_oui(args_import) == 0
        out = capsys.readouterr().out
        assert "[✓]" in out
        assert (user_dir / "oui.txt").exists()

        # Import non-existent file
        args_bad = parser.parse_args(["oui", "import", str(tmp_path / "missing.txt")])
        assert run_oui(args_bad) == 1
        out_bad = capsys.readouterr().out
        assert "[✗] Import failed:" in out_bad

    def test_run_oui_update_mocked_network(self, tmp_path, monkeypatch, capsys):
        """scrutics oui update contacts network only when executed, and installs safely."""
        user_dir = tmp_path / ".scrutics"
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_DIR", str(user_dir))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_PATH", str(user_dir / "oui.txt"))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_USER_BAK_PATH", str(user_dir / "oui.txt.bak"))
        monkeypatch.setattr("scrutics.classifier.oui.OUI_META_PATH", str(user_dir / "oui_meta.json"))

        # Generate mock IEEE database with >1000 entries
        mock_entries = []
        for i in range(1100):
            p1 = (i >> 8) & 0xFF
            p2 = i & 0xFF
            mock_entries.append(f"00-{p1:02X}-{p2:02X}   (hex)\t\tVendor {i}\n")
        mock_data = "".join(mock_entries).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.headers = {"Last-Modified": "Mon, 01 Mar 2026 12:00:00 GMT"}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            parser = build_parser()
            args = parser.parse_args(["oui", "update"])
            assert run_oui(args) == 0
            out = capsys.readouterr().out
            assert "Successfully installed OUI database" in out

        assert (user_dir / "oui.txt").exists()
        meta = json.loads((user_dir / "oui_meta.json").read_text(encoding="utf-8"))
        assert meta["entry_count"] == 1100
        assert meta["source_date"] == "2026-03-01"

    def test_run_oui_update_network_failure(self, tmp_path, monkeypatch, capsys):
        """When network download fails, error is reported and non-zero code is returned."""
        with patch("urllib.request.urlopen", side_effect=OSError("Connection timed out")):
            parser = build_parser()
            args = parser.parse_args(["oui", "update"])
            assert run_oui(args) == 1
            out = capsys.readouterr().out
            assert "[✗] Update failed:" in out

    def test_doctor_includes_oui_and_remains_non_blocking(self, monkeypatch, capsys):
        """scrutics doctor includes OUI section and outdated OUI does NOT cause doctor failure."""
        monkeypatch.setattr("scrutics.diagnostics.check_libpcap", lambda: {"ok": True, "detail": "libpcap found"})
        report = full_report()
        assert "oui" in report
        assert report["oui"]["ok"] is True
        assert "freshness" in report["oui"]

        # Run doctor: must succeed (exit 0) even if OUI database is outdated
        code = run_doctor()
        assert code == 0
        out = capsys.readouterr().out
        assert "OUI Database" in out
        assert "database:" in out
        assert "entries:" in out

    def test_startup_info_displays_warning_if_aging_or_outdated(self, monkeypatch, capsys):
        """Startup warning is shown if active OUI database is >= 180 days old."""
        mock_oui_info = {
            "exists": True,
            "age_days": 210,
            "freshness": "Aging",
        }
        monkeypatch.setattr("scrutics.diagnostics.check_oui_db", lambda: mock_oui_info)
        print_startup_info()
        out = capsys.readouterr().out
        assert "OUI database is 210 days old (Aging) — run 'scrutics oui update'" in out
