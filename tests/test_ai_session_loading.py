"""The AI session loader reads cells of any size and reports every file or row it could not load."""

from __future__ import annotations

import csv
import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace

import pytest

from scrutics import cli
from scrutics.ai.agent import TOOL_REGISTRY
from scrutics.ai.tools import SessionContext, describe_load_issue, get_statistics

HEADER = "ip,mac,vendor,type,evidence_summary\n"
BIG_CELL = "x" * 200_000


def _manifest(directory, files=None, **stats):
    counts = {k: 0 for k in ("asset_count", "ot_count", "it_count", "unknown_count",
                             "connection_count", "anomaly_count")}
    counts.update(stats)
    (directory / "manifest.json").write_text(json.dumps({
        "format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
        "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
        "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {},
        "files": files if files is not None else {"assets": "assets.csv"}, "stats": counts,
    }))


def _asset_row(n, summary="ok"):
    return f"10.0.0.{n},aa:bb:cc:00:00:{n:02x},Vendor,OT,{summary}\n"


def _issue(ctx, name):
    return next(entry for entry in ctx.load_issues if entry["file"] == name)


def test_loading_a_session_raises_the_csv_field_limit(tmp_path):
    _manifest(tmp_path, asset_count=1)
    (tmp_path / "assets.csv").write_text(HEADER + _asset_row(1))
    SessionContext(str(tmp_path))
    assert csv.field_size_limit() >= 2**31 - 1


def test_a_200_kb_cell_in_row_2_of_3_loads_all_three_assets(tmp_path):
    _manifest(tmp_path, asset_count=3, ot_count=3)
    (tmp_path / "assets.csv").write_text(HEADER + _asset_row(1) + _asset_row(2, BIG_CELL) + _asset_row(3))
    ctx = SessionContext(str(tmp_path))
    assert [a["ip"] for a in ctx.assets] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert ctx.assets[1]["_raw"]["evidence_summary"] == BIG_CELL
    assert ctx.load_issues == []
    assert "loaded" not in get_statistics(ctx)


def test_a_corrupt_evidence_file_is_reported(tmp_path):
    _manifest(tmp_path, files={"assets": "assets.csv", "evidence": "evidence.json"}, asset_count=1)
    (tmp_path / "assets.csv").write_text(HEADER + _asset_row(1))
    (tmp_path / "evidence.json").write_text('{"10.0.0.1": [')
    ctx = SessionContext(str(tmp_path))
    entry = _issue(ctx, "evidence.json")
    assert entry["status"] == "unreadable" and "JSONDecodeError" in entry["reason"]
    assert ctx.evidence == {}
    stats = get_statistics(ctx)
    assert [i["file"] for i in stats["load_issues"]] == ["evidence.json"]


def test_evidence_that_is_not_a_json_object_is_reported(tmp_path):
    _manifest(tmp_path)
    (tmp_path / "evidence.json").write_text("[1, 2]")
    entry = _issue(SessionContext(str(tmp_path)), "evidence.json")
    assert entry["status"] == "unreadable" and "list" in entry["reason"]


def test_a_non_utf8_csv_is_reported(tmp_path):
    _manifest(tmp_path, asset_count=2)
    (tmp_path / "assets.csv").write_bytes((HEADER + _asset_row(1) + "10.0.0.2,aa,Soci\xe9t\xe9,OT,x\n").encode("latin-1"))
    ctx = SessionContext(str(tmp_path))
    entry = _issue(ctx, "assets.csv")
    assert entry["status"] in ("unreadable", "partial")
    assert "UnicodeDecodeError" in entry["reason"]
    assert entry["rows_not_loaded"] is None


def test_reading_that_stops_part_way_keeps_the_rows_before_it(tmp_path):
    _manifest(tmp_path, asset_count=401)
    good = "".join(_asset_row(n % 250, "y" * 200) for n in range(400))
    (tmp_path / "assets.csv").write_bytes((HEADER + good).encode() + b"10.0.0.9,aa,Soci\xe9t\xe9,OT,x\n")
    ctx = SessionContext(str(tmp_path))
    entry = _issue(ctx, "assets.csv")
    assert entry["status"] == "partial"
    assert 0 < entry["rows_loaded"] == len(ctx.assets) <= 400
    assert f"stopped at row {entry['rows_loaded'] + 1}" in entry["reason"]


def test_a_row_that_cannot_be_converted_is_counted_and_the_rest_load(tmp_path):
    _manifest(tmp_path, files={"anomalies": "anomalies.csv"}, anomaly_count=3)
    # The second row is short: its severity is missing, so it cannot be read as an anomaly
    (tmp_path / "anomalies.csv").write_text(
        "timestamp,ip,type,severity,detail\n"
        "2026-10-16 00:00:01,10.0.0.1,NEW_PORT,HIGH,a\n"
        "2026-10-16 00:00:02,10.0.0.2,NEW_PORT\n"
        "2026-10-16 00:00:03,10.0.0.3,NEW_PORT,LOW,c\n")
    ctx = SessionContext(str(tmp_path))
    assert [a["ip"] for a in ctx.anomalies] == ["10.0.0.1", "10.0.0.3"]
    entry = _issue(ctx, "anomalies.csv")
    assert entry["status"] == "ok" and entry["rows_loaded"] == 2 and entry["rows_not_loaded"] == 1
    assert "row 2" in entry["reason"]


def test_a_file_the_manifest_names_but_that_is_absent_is_reported(tmp_path):
    _manifest(tmp_path, files={"assets": "assets.csv", "connections": "connections.csv"})
    (tmp_path / "assets.csv").write_text(HEADER)
    ctx = SessionContext(str(tmp_path))
    assert [(e["file"], e["status"]) for e in ctx.load_issues] == [("connections.csv", "missing")]


def test_an_absent_file_the_manifest_does_not_name_stays_silent(tmp_path):
    _manifest(tmp_path, files={})
    assert SessionContext(str(tmp_path)).load_issues == []


def test_statistics_report_loaded_against_manifest_counts_when_they_differ(tmp_path):
    _manifest(tmp_path, asset_count=5, ot_count=5)
    (tmp_path / "assets.csv").write_text(HEADER + _asset_row(1) + _asset_row(2) + _asset_row(3))
    ctx = SessionContext(str(tmp_path))
    stats = TOOL_REGISTRY["get_statistics"](ctx)
    assert stats["asset_count"] == 5
    assert stats["loaded"] == {"asset_count": 3, "connection_count": 0, "anomaly_count": 0}
    assert stats["load_issues"] == []


def test_statistics_carry_the_load_issues_for_the_model(tmp_path):
    _manifest(tmp_path, asset_count=3)
    (tmp_path / "assets.csv").write_bytes((HEADER + _asset_row(1)).encode() + b"10.0.0.2,aa,\xff,OT,x\n")
    stats = get_statistics(SessionContext(str(tmp_path)))
    assert stats["loaded"]["asset_count"] < 3
    issue = stats["load_issues"][0]
    assert issue["file"] == "assets.csv" and "UnicodeDecodeError" in issue["reason"]
    assert set(issue) == {"file", "status", "rows_loaded", "rows_not_loaded", "reason"}


def test_the_cli_tells_the_user_what_was_not_loaded(tmp_path):
    _manifest(tmp_path, files={"assets": "assets.csv", "evidence": "evidence.json"}, asset_count=1)
    (tmp_path / "assets.csv").write_text(HEADER + _asset_row(1))
    (tmp_path / "evidence.json").write_text("{corrupt")
    out = io.StringIO()
    with redirect_stdout(out):
        cli._print_session_context(str(tmp_path), SessionContext(str(tmp_path)))
    lines = [line for line in out.getvalue().splitlines() if line.startswith("Not loaded")]
    assert len(lines) == 1 and "evidence.json: not loaded (JSONDecodeError" in lines[0]


def test_the_cli_prints_nothing_extra_for_a_clean_session(tmp_path):
    _manifest(tmp_path, asset_count=1)
    (tmp_path / "assets.csv").write_text(HEADER + _asset_row(1))
    out = io.StringIO()
    with redirect_stdout(out):
        cli._print_session_context(str(tmp_path), SessionContext(str(tmp_path)))
    assert "Not loaded" not in out.getvalue()


def test_the_tui_assistant_shows_each_issue_once_with_markup_escaped():
    from scrutics.ui.tui import AIAssistantModal

    written = []
    modal = SimpleNamespace(query_one=lambda *a, **k: SimpleNamespace(write_line=written.append))
    issue = {"file": "assets.csv", "status": "unreadable", "rows_loaded": 0, "rows_not_loaded": None,
             "reason": "OSError: [bold]markup-like[/bold] text"}
    AIAssistantModal._show_load_issues(modal, [issue])
    AIAssistantModal._show_load_issues(modal, [issue])
    assert len(written) == 1
    assert "\\[bold]markup-like" in written[0]


@pytest.mark.parametrize("entry,expected", [
    ({"file": "a.csv", "status": "missing", "rows_loaded": 0, "rows_not_loaded": None,
      "reason": "listed in manifest.json but not found"}, "a.csv: listed in manifest.json but not found"),
    ({"file": "a.csv", "status": "partial", "rows_loaded": 4, "rows_not_loaded": None,
      "reason": "reading stopped at row 5: csv.Error"}, "a.csv: 4 row(s) loaded, the rest not loaded"),
    ({"file": "a.csv", "status": "ok", "rows_loaded": 4, "rows_not_loaded": 2,
      "reason": "2 row(s) could not be read"}, "a.csv: 2 row(s) not loaded"),
])
def test_issue_descriptions(entry, expected):
    assert describe_load_issue(entry).startswith(expected)
