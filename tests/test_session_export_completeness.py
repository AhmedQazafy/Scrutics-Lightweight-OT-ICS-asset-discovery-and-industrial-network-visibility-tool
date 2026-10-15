"""
Session export completeness.

events.csv and anomalies.csv are written only by RollingWriter, one append per record, and are
never rewritten from the in-memory display buffers (500 events, 100 anomalies). The manifest
states per record kind how many were observed, exported and dropped, and says the export is
complete only when nothing is missing from the final files. A write error never stops capture: a
lost append makes the export incomplete; a snapshot file (assets, evidence, topology, manifest)
that a later write repairs is listed as recovered. Frames are struct.pack bytes.
"""

import csv
import json
import os
import struct
import subprocess
import sys
import textwrap
import threading
from types import SimpleNamespace

import scapy.layers.inet  # noqa: F401  (registers the Ether -> IPv4 binding used to decode frames)
from scapy.layers.l2 import Ether

from scrutics.capture.engine import CaptureEngine
from scrutics.cli import _checkpoint_session
from scrutics.db.inventory import AssetInventory
from scrutics.db.session_export import (
    REASON_SHARED_IP, REASON_WRITE_ERROR, export_summary_line, write_session_snapshot,
)
from scrutics.db.writer import RollingWriter
from scrutics.topology import read_manifest
from scrutics.ui.tui import ScruticsApp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTS = 300          # 300 MAC changes: more than the 100 anomalies and 500 events kept in memory


def _frame_bytes(src_mac, src_ip, dst_ip="10.0.9.9", sport=40000, dport=80):
    eth = bytes([2, 0, 0, 0, 0, 0xfe]) + src_mac + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                     bytes(map(int, src_ip.split("."))), bytes(map(int, dst_ip.split("."))))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 8192, 0, 0)
    return eth + ip + tcp


def _mac_change_frames():
    """Each host sends 3 frames, then a replacement device on the same IP sends 3 (MAC_CHANGED)."""
    frames = []
    for generation in (0, 1):
        for i in range(HOSTS):
            ip = f"10.0.{i // 200}.{i % 200 + 1}"
            mac = bytes([2, 0, generation, 0, i // 256, i % 256])
            frames.extend([_frame_bytes(mac, ip)] * 3)
    return frames


def _moved_device_frames():
    """Each device sends 3 frames, then moves to a new IP and sends 3 (DEVICE_MOVED, no shared IP)."""
    frames = []
    for generation in (0, 1):
        for i in range(HOSTS):
            ip = f"10.{generation + 1}.{i // 200}.{i % 200 + 1}"
            mac = bytes([2, 0, 0, 0, i // 256, i % 256])
            frames.extend([_frame_bytes(mac, ip)] * 3)
    return frames


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, data in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i // 100, (i % 100) * 10_000, len(data), len(data)) + data
    return out


def _rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _session_engine(session_dir):
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.no_baseline = True
    engine.writer = RollingWriter(str(session_dir))
    return engine


def _feed(engine, frames):
    for i, data in enumerate(frames):
        pkt = Ether(data)
        pkt.time = 1_700_000_000 + i * 0.01
        engine._ingest_packet(pkt, "pcap")


def _run_cli(tmp_path, pcap_bytes, prelude=""):
    path = tmp_path / "capture.pcap"
    path.write_bytes(pcap_bytes)
    out = tmp_path / "out"
    code = textwrap.dedent(prelude) + textwrap.dedent(f"""
        import sys
        sys.argv = ["scrutics", "--file", {str(path)!r}, "--headless", "--no-baseline", "--output", {str(out)!r}]
        from scrutics.__main__ import main
        main()
    """)
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(tmp_path),
                            env=dict(os.environ, HOME=str(tmp_path), PYTHONPATH=ROOT), timeout=600)
    [session] = [os.path.join(out, d) for d in os.listdir(out)]
    return result, session


# ── a complete export ─────────────────────────────────────────────────────────

def test_headless_export_keeps_every_event_and_anomaly(tmp_path):
    result, session = _run_cli(tmp_path, _pcap(_moved_device_frames()))
    manifest = read_manifest(session)
    records = manifest["records"]
    events, anomalies = _rows(os.path.join(session, "events.csv")), _rows(os.path.join(session, "anomalies.csv"))
    # RollingWriter's own headers: the files were not rewritten
    assert events[0] == ["timestamp", "message"]
    assert anomalies[0] == ["timestamp", "ip", "type", "severity", "detail"]
    assert len(anomalies) - 1 == HOSTS == records["anomalies"]["observed"] == records["anomalies"]["exported"]
    assert len(events) - 1 == records["events"]["observed"] == records["events"]["exported"] > 500
    assert sum(1 for row in anomalies[1:] if row[2] == "DEVICE_MOVED") == HOSTS
    assert records["events"]["dropped"] == records["anomalies"]["dropped"] == 0
    assert manifest["stats"]["anomaly_count"] == HOSTS
    assert manifest["export_complete"] is True and manifest["export_errors"] == []
    assert "Export incomplete" not in result.stdout


def test_checkpoints_never_rewrite_the_append_only_files(tmp_path):
    engine = _session_engine(tmp_path)
    _feed(engine, _mac_change_frames()[:60])
    before = {name: (tmp_path / name).read_bytes() for name in ("events.csv", "anomalies.csv")}
    for _ in range(3):
        _checkpoint_session(engine.inventory, engine, str(tmp_path), threading.Lock())
    assert {name: (tmp_path / name).read_bytes() for name in before} == before
    assert read_manifest(str(tmp_path))["export_complete"] is False      # a checkpoint is not final


def test_rolling_writer_output_bytes_are_unchanged(tmp_path):
    writer = RollingWriter(str(tmp_path))
    writer.write_event("12:00:00", 'a "quoted", message')
    writer.write_anomaly({"timestamp": 0, "ip": "10.0.0.1", "type": "MAC_CHANGED", "severity": "HIGH",
                          "detail": "x"})
    import datetime
    ts = datetime.datetime.fromtimestamp(0).strftime("%Y-%m-%d %H:%M:%S")
    assert (tmp_path / "events.csv").read_bytes() == b'timestamp,message\r\n12:00:00,"a ""quoted"", message"\r\n'
    assert (tmp_path / "anomalies.csv").read_bytes() == (
        b"timestamp,ip,type,severity,detail\r\n" + f"{ts},10.0.0.1,MAC_CHANGED,HIGH,x\r\n".encode())
    assert writer.written == {"events": 1, "anomalies": 1}


# ── write errors ──────────────────────────────────────────────────────────────

def _fail_after(writer, kind, after):
    original = writer._append

    def append(k, write):
        if k == kind and writer.written[k] + writer.failed[k] >= after:
            return original(k, lambda: (_ for _ in ()).throw(OSError(28, "No space left on device")))
        return original(k, write)
    writer._append = append


def test_a_lost_append_is_reported_and_capture_continues(tmp_path):
    engine = _session_engine(tmp_path)
    _fail_after(engine.writer, "anomalies", 120)
    frames = _mac_change_frames()
    _feed(engine, frames)
    assert engine._ingest_index == len(frames) and engine.ingest_stats.contained_total == 0
    result = write_session_snapshot(str(tmp_path), engine.inventory, engine, final=True)
    anomalies = result["records"]["anomalies"]
    assert (anomalies["observed"], anomalies["exported"], anomalies["dropped"]) == (HOSTS, 120, HOSTS - 120)
    assert anomalies["dropped_by_reason"] == {REASON_WRITE_ERROR: HOSTS - 120}
    assert len(_rows(tmp_path / "anomalies.csv")) - 1 == 120
    assert result["export_complete"] is False
    [error] = result["export_errors"]
    assert error["file"] == "anomalies.csv" and error["count"] == HOSTS - 120 and error["recovered"] is False
    assert "No space left on device" in error["first_error"]
    manifest = read_manifest(str(tmp_path))
    assert manifest["export_complete"] is False and manifest["records"]["anomalies"] == anomalies
    line = export_summary_line(result)
    assert line.startswith("Export incomplete: ")
    assert f"anomalies {HOSTS} observed, 120 written, {HOSTS - 120} not written (write error: {HOSTS - 120})" in line


def test_a_snapshot_error_repaired_by_a_later_write_is_recovered(tmp_path, monkeypatch):
    engine = _session_engine(tmp_path)
    _feed(engine, _mac_change_frames()[:30])
    calls = {"n": 0}
    original = AssetInventory.export_csv

    def flaky(self, path):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PermissionError(13, "Permission denied")
        return original(self, path)
    monkeypatch.setattr(AssetInventory, "export_csv", flaky)
    first = write_session_snapshot(str(tmp_path), engine.inventory, engine)
    assert first["unrecovered"] == ["assets.csv"]
    final = write_session_snapshot(str(tmp_path), engine.inventory, engine, final=True)
    assert final["export_complete"] is True
    assert final["export_errors"] == [{"file": "assets.csv", "count": 1,
                                       "first_error": "[Errno 13] Permission denied", "recovered": True}]
    assert export_summary_line(final) == ""


def test_a_snapshot_error_at_the_end_makes_the_export_incomplete(tmp_path, monkeypatch):
    engine = _session_engine(tmp_path)
    _feed(engine, _mac_change_frames()[:30])
    monkeypatch.setattr(AssetInventory, "export_csv",
                        lambda self, path: (_ for _ in ()).throw(PermissionError(13, "Permission denied")))
    result = write_session_snapshot(str(tmp_path), engine.inventory, engine, final=True)
    assert result["export_complete"] is False and result["unrecovered"] == ["assets.csv"]
    assert "assets.csv not written ([Errno 13] Permission denied)" in export_summary_line(result)


def test_cli_reports_a_lost_append(tmp_path):
    prelude = """
        from scrutics.db.writer import RollingWriter
        original = RollingWriter._append
        def append(self, kind, write):
            if kind == "anomalies":
                def write():
                    raise OSError(28, "No space left on device")
            return original(self, kind, write)
        RollingWriter._append = append
    """
    result, session = _run_cli(tmp_path, _pcap(_moved_device_frames()), prelude)
    assert (f"[!] Export incomplete: anomalies {HOSTS} observed, 0 written, {HOSTS} not written "
            f"(write error: {HOSTS}); first anomalies.csv error: [Errno 28] No space left on device.") in result.stdout
    manifest = read_manifest(session)
    assert manifest["export_complete"] is False
    assert manifest["records"]["anomalies"]["dropped"] == HOSTS


def test_tui_warns_when_the_export_is_incomplete(tmp_path):
    engine = _session_engine(tmp_path)
    _fail_after(engine.writer, "events", 5)
    _feed(engine, _mac_change_frames()[:60])
    result = write_session_snapshot(str(tmp_path), engine.inventory, engine, final=True)
    notices = []
    widget = SimpleNamespace(label="", remove_class=lambda *a: None)
    app = SimpleNamespace(
        engine=engine, inventory=engine.inventory, _session_dir=str(tmp_path), _paused=True,
        query_one=lambda *a, **k: widget, _export_session=lambda: None, _export_result=result,
        _set_status=lambda text, **k: None,
        notify=lambda message, **kw: notices.append((message, kw)),
    )
    ScruticsApp._on_capture_done(app)
    assert (export_summary_line(result), {"severity": "warning", "markup": False}) in notices


# ── records left out of their file ────────────────────────────────────────────

def test_every_replaced_device_loses_its_evidence_entry_and_says_so(tmp_path):
    result, session = _run_cli(tmp_path, _pcap(_mac_change_frames()))
    manifest = read_manifest(session)
    assert manifest["records"]["evidence"] == {"observed": 2 * HOSTS, "exported": HOSTS, "dropped": HOSTS,
                                               "dropped_by_reason": {REASON_SHARED_IP: HOSTS}}
    assert manifest["records"]["anomalies"]["exported"] == HOSTS == manifest["records"]["anomalies"]["observed"]
    assert manifest["export_complete"] is False
    assert (f"[!] Export incomplete: evidence {2 * HOSTS} observed, {HOSTS} written, {HOSTS} not written "
            f"({REASON_SHARED_IP}: {HOSTS}).") in result.stdout


def test_evidence_lost_to_a_shared_ip_is_counted(tmp_path):
    engine = _session_engine(tmp_path)
    _feed(engine, _mac_change_frames()[:3] + _mac_change_frames()[3 * HOSTS:3 * HOSTS + 3])
    assert len(engine.inventory.get_all()) == 2 and len({a.ip for a in engine.inventory.get_all()}) == 1
    result = write_session_snapshot(str(tmp_path), engine.inventory, engine, final=True)
    assert result["records"]["evidence"] == {"observed": 2, "exported": 1, "dropped": 1,
                                             "dropped_by_reason": {REASON_SHARED_IP: 1}}
    assert result["export_complete"] is False
    assert f"evidence 2 observed, 1 written, 1 not written ({REASON_SHARED_IP}: 1)" in export_summary_line(result)


def test_a_shortened_topology_view_is_counted_but_connections_are_complete(tmp_path):
    engine = _session_engine(tmp_path)
    inv = engine.inventory
    for i in range(2002):
        inv.update(f"10.1.{i // 250}.{i % 250 + 1}", f"02:01:00:00:{i // 256:02x}:{i % 256:02x}", timestamp=0)
    assets = inv.get_all()
    hub = assets[0]
    for other in assets[1:]:
        engine._record_topology_edge(hub, other, hub.ip, other.ip, 40000, 502, "TCP", set(), 0)
    result = write_session_snapshot(str(tmp_path), inv, engine, final=True)
    records = result["records"]
    assert records["connections"] == {"observed": 2001, "exported": 2001, "dropped": 0, "dropped_by_reason": {}}
    assert records["topology_edges"]["exported"] == 2000
    assert records["topology_edges"]["dropped_by_reason"] == {"topology view limit (2000)": 1}
    assert len(_rows(tmp_path / "connections.csv")) - 1 == 2001
    assert result["export_complete"] is True


def test_an_unwritable_events_file_never_stops_capture(tmp_path):
    engine = _session_engine(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    engine.writer._events_path = str(blocked)               # every event append fails
    frames = _moved_device_frames()
    _feed(engine, frames)
    assert engine._ingest_index == len(frames) and engine.ingest_stats.contained_total == 0
    assert len(engine.inventory.get_all()) == HOSTS
    result = write_session_snapshot(str(tmp_path), engine.inventory, engine, final=True)
    events = result["records"]["events"]
    assert events["exported"] == 0 and events["dropped"] == events["observed"] > 500
    assert result["export_complete"] is False


# ── headless checkpoint messages ──────────────────────────────────────────────

def _checkpoint_lines(capsys, engine, session_dir, reported):
    _checkpoint_session(engine.inventory, engine, str(session_dir), threading.Lock(), reported=reported)
    return [line.lstrip("\r") for line in capsys.readouterr().out.splitlines() if line.strip()]


def test_checkpoint_reports_lost_rows_only_when_the_count_changes(tmp_path, capsys):
    engine = _session_engine(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    engine.writer._anomalies_path = str(blocked)               # every anomaly append fails
    frames = _moved_device_frames()
    reported = {}
    _feed(engine, frames[:3 * HOSTS + 3])                        # one device moves: one lost row
    capsys.readouterr()                                          # drop setup output
    [line] = _checkpoint_lines(capsys, engine, tmp_path, reported)
    assert line.startswith("[!] 1 row not written to anomalies.csv (first error: [Errno 21] Is a directory")
    assert _checkpoint_lines(capsys, engine, tmp_path, reported) == []       # unchanged: silent
    assert _checkpoint_lines(capsys, engine, tmp_path, reported) == []
    _feed(engine, frames[3 * HOSTS + 3:3 * HOSTS + 30])           # 9 more devices move
    [line] = _checkpoint_lines(capsys, engine, tmp_path, reported)
    assert line.startswith("[!] 10 rows not written to anomalies.csv (first error: [Errno 21] Is a directory")
    assert "Checkpoint failed" not in line
    assert _checkpoint_lines(capsys, engine, tmp_path, reported) == []


def test_checkpoint_reports_a_snapshot_failure_and_stays_silent_once_it_recovers(tmp_path, capsys, monkeypatch):
    engine = _session_engine(tmp_path)
    _feed(engine, _moved_device_frames()[:30])
    original = AssetInventory.export_csv
    monkeypatch.setattr(AssetInventory, "export_csv",
                        lambda self, path: (_ for _ in ()).throw(PermissionError(13, "Permission denied")))
    reported = {}
    capsys.readouterr()                                          # drop setup output
    assert _checkpoint_lines(capsys, engine, tmp_path, reported) == [
        "[!] assets.csv not written (1 failed write) (first error: [Errno 13] Permission denied)"]
    monkeypatch.setattr(AssetInventory, "export_csv", original)
    assert _checkpoint_lines(capsys, engine, tmp_path, reported) == []        # recovered: silent


def test_the_final_export_prints_no_checkpoint_message(tmp_path, capsys):
    engine = _session_engine(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    engine.writer._anomalies_path = str(blocked)
    _feed(engine, _moved_device_frames())
    capsys.readouterr()                                          # drop setup output
    result = _checkpoint_session(engine.inventory, engine, str(tmp_path), threading.Lock(), final=True)
    assert capsys.readouterr().out == "" and result["export_complete"] is False
