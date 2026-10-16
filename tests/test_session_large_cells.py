"""Every Scrutics CSV reader accepts large cells, whichever modules the process imported first."""

from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import textwrap

import scrutics
from scrutics.csv_input import FIELD_LIMIT, allow_large_fields

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(scrutics.__file__)))
BIG = 200_000


def _write_session(output_base):
    """A saved session of three assets whose second row holds a 200 KB classification reason."""
    from scrutics.db.inventory import Asset, AssetInventory

    session = os.path.join(output_base, "scrutics_20261016_120000")
    os.makedirs(session)
    inventory = AssetInventory()
    for n in (1, 2, 3):
        asset = Asset(ip=f"10.0.0.{n}", mac=f"00:0e:8c:00:00:0{n}")
        inventory._assets[asset.ip] = asset
    path = os.path.join(session, "assets.csv")
    inventory.export_csv(path)
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields, rows = reader.fieldnames, list(reader)
    rows[1]["classification_reason"] = "r" * BIG
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return session


def _run_fresh(script, env_extra):
    """Run script in a new, isolated interpreter that imports Scrutics from ROOT."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env.update(env_extra)
    prelude = f"import sys; sys.path.insert(0, {ROOT!r})\n"
    result = subprocess.run([sys.executable, "-I", "-c", prelude + textwrap.dedent(script)],
                            capture_output=True, text=True, env=env, timeout=300)
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_the_tui_loads_a_200_kb_cell_in_a_process_that_never_imports_the_ai_module(tmp_path):
    _write_session(str(tmp_path))
    out = _run_fresh("""
        import asyncio, csv, json, sys
        from textual.widgets import DataTable
        from scrutics.ui.tui import ScruticsApp

        result = {}

        async def run():
            app = ScruticsApp()
            async with app.run_test() as pilot:
                app._load_last_results()
                await pilot.pause()
                table = app.query_one("#asset-table", DataTable)
                result["rows"] = sorted(str(table.get_row_at(i)[0]) for i in range(table.row_count))
                result["reason_length"] = len(app.inventory.get("10.0.0.2").classification_reason or "")

        asyncio.run(run())
        result["ai_modules"] = sorted(m for m in sys.modules if m.startswith("scrutics.ai"))
        result["limit"] = csv.field_size_limit()
        print(json.dumps(result))
    """, {"SCRUTICS_AUTO_OUTPUT": str(tmp_path), "HOME": str(tmp_path)})
    assert out["ai_modules"] == []
    assert out["rows"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert out["reason_length"] == BIG
    assert out["limit"] == FIELD_LIMIT


def test_the_ai_loader_reads_the_same_session_in_a_fresh_process(tmp_path):
    session = _write_session(str(tmp_path))
    with open(os.path.join(session, "manifest.json"), "w") as f:
        stats = {k: 0 for k in ("asset_count", "ot_count", "it_count", "unknown_count",
                                "connection_count", "anomaly_count")}
        stats["asset_count"] = 3
        json.dump({"format": "scrutics-evidence", "version": 1, "scrutics_version": "0.7",
                   "created_at": "2026-10-16T00:00:00Z", "capture_started": "2026-10-16T00:00:00Z",
                   "capture_ended": "2026-10-16T00:01:00Z", "sensor_id": "s", "scope": {},
                   "files": {"assets": "assets.csv"}, "stats": stats}, f)
    out = _run_fresh(f"""
        import json
        from scrutics.ai.tools import SessionContext
        ctx = SessionContext({session!r})
        print(json.dumps({{"assets": len(ctx.assets), "issues": len(ctx.load_issues)}}))
    """, {"HOME": str(tmp_path)})
    assert out == {"assets": 3, "issues": 0}


def test_the_shared_helper_raises_the_limit_and_never_lowers_it():
    allow_large_fields()
    assert csv.field_size_limit() == FIELD_LIMIT
    allow_large_fields()
    assert csv.field_size_limit() == FIELD_LIMIT


def test_every_csv_reader_calls_the_shared_helper():
    reader_call = re.compile(r"\bcsv\.(DictReader|reader)\(")
    readers, missing = [], []
    for top in ("scrutics", "scripts"):
        for directory, _dirs, files in os.walk(os.path.join(ROOT, top)):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(directory, name)
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                if reader_call.search(text):
                    readers.append(os.path.relpath(path, ROOT))
                    if "allow_large_fields()" not in text:
                        missing.append(os.path.relpath(path, ROOT))
    assert readers, "expected CSV readers in the package"
    assert missing == []
