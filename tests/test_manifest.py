import json
import os
import threading
import pytest

from scrutics.db.inventory import AssetInventory, Asset
from scrutics.capture.engine import CaptureEngine
from scrutics.topology import write_manifest, read_manifest, export_topology
from scrutics.cli import _checkpoint_session as cli_checkpoint_session


def test_write_manifest_creates_valid_json(tmp_path):
    """1. write_manifest() writes a valid, well-formed JSON file."""
    session_dir = str(tmp_path / "scrutics_20260905_140000")
    manifest_path = write_manifest(session_dir)

    assert os.path.exists(manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, dict)
    assert data["format"] == "scrutics-evidence"
    assert data["version"] == 1


def test_write_manifest_required_fields(tmp_path):
    """2. write_manifest() includes all required top-level fields and stats."""
    session_dir = str(tmp_path / "scrutics_20260905_140000")
    manifest_path = write_manifest(session_dir)

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    expected_keys = {
        "format",
        "version",
        "scrutics_version",
        "created_at",
        "capture_started",
        "capture_ended",
        "sensor_id",
        "scope",
        "files",
        "stats",
    }
    assert expected_keys.issubset(set(data.keys()))

    expected_files = {
        "assets",
        "connections",
        "evidence",
        "events",
        "anomalies",
        "topology",
        "topology_html",
    }
    assert expected_files.issubset(set(data["files"].keys()))

    expected_stats = {
        "asset_count",
        "ot_count",
        "it_count",
        "unknown_count",
        "connection_count",
        "anomaly_count",
    }
    assert expected_stats.issubset(set(data["stats"].keys()))


def test_write_manifest_handles_missing_data_gracefully(tmp_path):
    """3. write_manifest() handles missing/unavailable data gracefully (defaults, never raises)."""
    # Test with None metadata, empty directory
    session_dir = str(tmp_path / "empty_session")
    manifest_path = write_manifest(session_dir, metadata=None)

    assert os.path.exists(manifest_path)
    manifest = read_manifest(session_dir)
    assert manifest["stats"]["asset_count"] == 0
    assert manifest["stats"]["ot_count"] == 0
    assert manifest["stats"]["it_count"] == 0
    assert manifest["stats"]["unknown_count"] == 0
    assert manifest["stats"]["connection_count"] == 0
    assert manifest["stats"]["anomaly_count"] == 0
    assert manifest["scope"] == ""
    assert isinstance(manifest["sensor_id"], str) and len(manifest["sensor_id"]) > 0

    # Non-existent/unwritable path should not raise
    bad_path = "/dev/null/impossible/path" if os.name != "nt" else "Z:\\impossible\\nonexistent\\path"
    try:
        res = write_manifest(bad_path)
        assert isinstance(res, str)
    except Exception as e:
        pytest.fail(f"write_manifest raised an exception: {e}")


def test_read_manifest_valid(tmp_path):
    """4. read_manifest() correctly reads and returns a valid manifest."""
    session_dir = str(tmp_path / "scrutics_20260905_120000")
    write_manifest(session_dir, metadata={"sensor_id": "sensor-test-42", "scope": "10.0.0.0/24"})

    manifest = read_manifest(session_dir)
    assert manifest["sensor_id"] == "sensor-test-42"
    assert manifest["scope"] == "10.0.0.0/24"
    assert manifest["format"] == "scrutics-evidence"
    assert manifest["version"] == 1


def test_read_manifest_missing_and_malformed(tmp_path):
    """5. read_manifest() raises clear, specific errors for missing/malformed files."""
    # Missing file
    missing_dir = str(tmp_path / "nonexistent")
    with pytest.raises(FileNotFoundError) as exc_info:
        read_manifest(missing_dir)
    assert "manifest.json not found" in str(exc_info.value)

    # Invalid JSON syntax
    bad_json_dir = tmp_path / "bad_json"
    bad_json_dir.mkdir()
    (bad_json_dir / "manifest.json").write_text("{broken json", encoding="utf-8")
    with pytest.raises(ValueError) as exc_info:
        read_manifest(str(bad_json_dir))
    assert "Invalid JSON" in str(exc_info.value)

    # Missing required fields
    incomplete_dir = tmp_path / "incomplete"
    incomplete_dir.mkdir()
    (incomplete_dir / "manifest.json").write_text(json.dumps({"format": "scrutics-evidence"}), encoding="utf-8")
    with pytest.raises(ValueError) as exc_info:
        read_manifest(str(incomplete_dir))
    assert "Missing required manifest field" in str(exc_info.value)

    # Wrong format
    wrong_format_dir = tmp_path / "wrong_format"
    wrong_format_dir.mkdir()
    manifest_data = {
        "format": "wrong-format",
        "version": 1,
        "scrutics_version": "0.6.0",
        "created_at": "2026-09-05T12:00:00Z",
        "capture_started": "2026-09-05T12:00:00Z",
        "capture_ended": "2026-09-05T12:00:00Z",
        "sensor_id": "sensor",
        "scope": "",
        "files": {},
        "stats": {
            "asset_count": 0,
            "ot_count": 0,
            "it_count": 0,
            "unknown_count": 0,
            "connection_count": 0,
            "anomaly_count": 0,
        },
    }
    (wrong_format_dir / "manifest.json").write_text(json.dumps(manifest_data), encoding="utf-8")
    with pytest.raises(ValueError) as exc_info:
        read_manifest(str(wrong_format_dir))
    assert "Invalid manifest format" in str(exc_info.value)


def test_checkpoint_writes_manifest_cli(tmp_path):
    """6a. Manifest is written during CLI checkpointing."""
    session_dir = str(tmp_path / "scrutics_20260905_130000")
    os.makedirs(session_dir, exist_ok=True)

    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55")
    asset = inventory.get("192.168.1.10")
    asset.is_ot = True

    engine = CaptureEngine(inventory=inventory)
    engine.no_baseline = True
    lock = threading.Lock()

    cli_checkpoint_session(inventory, engine, session_dir, lock)

    manifest_path = os.path.join(session_dir, "manifest.json")
    assert os.path.exists(manifest_path)

    manifest = read_manifest(session_dir)
    assert manifest["stats"]["asset_count"] == 1
    assert manifest["stats"]["ot_count"] == 1
    assert manifest["stats"]["it_count"] == 0


def test_checkpoint_and_export_writes_manifest_tui(tmp_path):
    """6b. Manifest is written during TUI checkpointing and export."""
    from unittest.mock import MagicMock
    from scrutics.ui.tui import ScruticsApp

    session_dir = str(tmp_path / "scrutics_20260905_140000")
    os.makedirs(session_dir, exist_ok=True)

    # Use ScruticsApp instance with mocked UI elements
    app = ScruticsApp.__new__(ScruticsApp)
    app._session_dir = session_dir
    app._checkpoint_lock = threading.Lock()
    app._capture_running = threading.Event()
    app._capture_running.set()

    inventory = AssetInventory()
    inventory.update("192.168.1.20", "00:aa:bb:cc:dd:ee")
    asset = inventory.get("192.168.1.20")
    asset.is_ot = False
    app.inventory = inventory

    engine = CaptureEngine(inventory=inventory)
    engine.no_baseline = True
    app.engine = engine

    # Run checkpoint
    app._checkpoint_session()

    manifest_path = os.path.join(session_dir, "manifest.json")
    assert os.path.exists(manifest_path)
    manifest = read_manifest(session_dir)
    assert manifest["stats"]["asset_count"] == 1
    assert manifest["stats"]["it_count"] == 1

    # Run final export
    app._export_session()
    assert os.path.exists(manifest_path)


def test_export_topology_writes_manifest(tmp_path):
    """7. export_topology() writes manifest.json at session end."""
    session_dir = str(tmp_path / "scrutics_20260905_150000")
    inventory = AssetInventory()
    inventory.update("192.168.1.10", "00:11:22:33:44:55")

    edges = {
        ("192.168.1.10", "192.168.1.20"): {
            "protocols": {"Modbus TCP"},
            "count": 5,
        }
    }

    paths = export_topology(inventory, edges, session_dir)
    manifest_path = os.path.join(session_dir, "manifest.json")
    assert os.path.exists(manifest_path)

    manifest = read_manifest(session_dir)
    assert manifest["stats"]["connection_count"] == 1


def test_capture_started_fallback_and_override(tmp_path):
    """8. Session directory falls back to capture_ended without explicit started timestamp."""
    unmatched_dir = str(tmp_path / "random_fixture_name_dir")
    write_manifest(unmatched_dir)
    manifest = read_manifest(unmatched_dir)
    assert manifest["capture_started"] == manifest["capture_ended"]

    # Explicit override takes priority
    write_manifest(unmatched_dir, metadata={"capture_started": "2026-09-01T00:00:00Z"})
    manifest2 = read_manifest(unmatched_dir)
    assert manifest2["capture_started"] == "2026-09-01T00:00:00Z"

    # Engine capture_started attribute is respected
    inventory = AssetInventory()
    engine = CaptureEngine(inventory=inventory)
    engine.capture_started = "2026-09-01T10:00:00Z"
    write_manifest(unmatched_dir, metadata={"engine": engine})
    manifest3 = read_manifest(unmatched_dir)
    assert manifest3["capture_started"] == "2026-09-01T10:00:00Z"

