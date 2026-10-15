"""
A capture file that ends at a damaged or incomplete record is reported, never cut short silently.

Files are built byte by byte with struct.pack. Two outcomes are distinguished: the last record is
incomplete (the file ends inside it, as when a capture is stopped abruptly; it is skipped), or the
file is damaged before its end (analysis stops and the rest is not read). The damaged record is
never processed. Classic pcap positions are record numbers; pcapng positions are packets read
and a byte offset.
"""

import os
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scrutics.capture.capture_file import DAMAGED, INCOMPLETE, REASON_DAMAGED, REASON_INCOMPLETE
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.ui.tui import ScruticsApp

N = 2000
FRAME_LEN = 42


def _frame(i):
    """Ethernet + IPv4 + UDP 40000 -> 502, one sender per 100 frames (10.0.0.1 .. 10.0.0.20)."""
    host = i // 100 + 1
    eth = bytes([2, 0, 0, 0, 0, 0xfe]) + bytes([2, 0, 0, 0, 0, host]) + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, i & 0xFFFF, 0, 64, 17, 0,
                     bytes([10, 0, 0, host]), bytes([10, 0, 0, 200]))
    return eth + ip + struct.pack("!HHHH", 40000, 502, 8, 0)


def _pcap(n=N, snaplen=65535):
    """Classic pcap bytes and the offset of each record."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1)
    offsets = []
    for i in range(n):
        data = _frame(i)
        offsets.append(len(out))
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(data), len(data)) + data
    return out, offsets


def _block(btype, body):
    pad = (-len(body)) % 4
    length = 12 + len(body) + pad
    return struct.pack("<II", btype, length) + body + b"\0" * pad + struct.pack("<I", length)


def _pcapng(n=N):
    out = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += _block(1, struct.pack("<HHI", 1, 0, 65535))
    offsets = []
    for i in range(n):
        data = _frame(i)
        ts = (1_700_000_000 + i) * 1_000_000
        offsets.append(len(out))
        out += _block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data)
    return out, offsets


def _set_u32(data, offset, value):
    return data[:offset] + struct.pack("<I", value) + data[offset + 4:]


def _run(tmp_path, data, name):
    path = tmp_path / name
    path.write_bytes(data)
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.no_baseline = True
    seen = []
    original = engine._ingest_packet
    engine._ingest_packet = lambda pkt, p="live": (seen.append(pkt), original(pkt, p))
    engine.start_file(str(path))
    return engine, seen


def _messages(engine):
    return [m for _, m, _ in engine.event_log]


# ── clean files ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("build, name", [(_pcap, "clean.pcap"), (_pcapng, "clean.pcapng")])
def test_a_complete_file_has_no_problem(tmp_path, build, name):
    engine, seen = _run(tmp_path, build()[0], name)
    assert len(seen) == N
    assert engine.ingest_stats.capture_file_problem is None
    assert engine.ingest_stats.capture_file_line() == ""
    assert engine.ingest_stats.rejected_total == 0


# ── classic pcap ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("caplen", [0x11170, 0x7FFFFFFF, 0xFFFFFFFF])
def test_a_damaged_record_stops_analysis_and_is_not_processed(tmp_path, caplen):
    data, offsets = _pcap()
    damaged = _set_u32(data, offsets[1000] + 8, caplen)          # record 1001's captured length
    engine, seen = _run(tmp_path, damaged, "damaged.pcap")
    stats = engine.ingest_stats
    assert len(seen) == 1000                                       # record 1001 never processed
    assert stats.capture_file_problem.kind == DAMAGED
    assert stats.rejected_by_reason == {REASON_DAMAGED: 1}
    assert stats.capture_file_line() == (
        f"Analysis stopped at pcap record 1001 (byte offset {offsets[1000]}) of a damaged file; "
        "the rest of the file was not read.")
    assert any(m.startswith(f"Rejected input at pcap record 1001: {REASON_DAMAGED}") for m in _messages(engine))
    assert "Processed 1000 packets" in _messages(engine)
    assert sorted(a.ip for a in engine.inventory.get_all()) == sorted(f"10.0.0.{h}" for h in range(1, 11))


def test_a_last_header_outside_the_format_limits_is_damage(tmp_path):
    data, offsets = _pcap()
    damaged = _set_u32(data, offsets[-1] + 8, 0xFFFF)             # caplen above its own wirelen
    engine, seen = _run(tmp_path, damaged, "damaged_last.pcap")
    assert len(seen) == N - 1
    assert engine.ingest_stats.capture_file_problem.kind == DAMAGED


@pytest.mark.parametrize("cut", [16 + 10, 8], ids=["inside data", "inside header"])
def test_a_file_cut_inside_its_last_record_skips_that_record(tmp_path, cut):
    data, offsets = _pcap()
    engine, seen = _run(tmp_path, data[:offsets[-1] + cut], "cut.pcap")
    stats = engine.ingest_stats
    assert len(seen) == N - 1
    assert stats.capture_file_problem.kind == INCOMPLETE
    assert stats.rejected_by_reason == {REASON_INCOMPLETE: 1}
    assert stats.capture_file_line() == (
        f"The last record (pcap record {N}) is incomplete, typical of a capture stopped abruptly; "
        "it was skipped.")


# ── pcapng ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("length", [0x7FFFFFF0, 8, None], ids=["too long", "too short", "trailer mismatch"])
def test_a_damaged_pcapng_block_stops_analysis(tmp_path, length):
    data, offsets = _pcapng()
    start = offsets[1000]
    if length is None:
        length = struct.unpack("<I", data[start + 4:start + 8])[0] + 4
    engine, seen = _run(tmp_path, _set_u32(data, start + 4, length), "damaged.pcapng")
    stats = engine.ingest_stats
    assert len(seen) == 1000
    assert stats.capture_file_problem.kind == DAMAGED
    assert stats.rejected_by_reason == {REASON_DAMAGED: 1}
    line = stats.capture_file_line()
    assert line == (f"Analysis stopped after 1000 packets, at byte offset {start} of a damaged pcapng "
                    "file; the rest of the file was not read.")
    assert "record" not in line
    assert any(f"Rejected input at pcapng file after 1000 packets, at byte offset {start}" in m
               for m in _messages(engine))


def test_a_pcapng_file_cut_inside_its_last_block_skips_that_block(tmp_path):
    data, offsets = _pcapng()
    engine, seen = _run(tmp_path, data[:offsets[-1] + 30], "cut.pcapng")
    stats = engine.ingest_stats
    assert len(seen) == N - 1
    assert stats.capture_file_problem.kind == INCOMPLETE
    assert stats.capture_file_line() == (
        f"The last pcapng block (after {N - 1} packets, at byte offset {offsets[-1]}) is incomplete, "
        "typical of a capture stopped abruptly; it was skipped.")


def test_a_stopped_run_is_not_reported_as_damage(tmp_path):
    data, _ = _pcap()
    path = tmp_path / "stop.pcap"
    path.write_bytes(data)
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.no_baseline = True
    original = engine._ingest_packet

    def ingest(pkt, p="live"):
        original(pkt, p)
        if engine._ingest_index == 10:
            engine.request_stop()
    engine._ingest_packet = ingest
    engine.start_file(str(path))
    assert engine._ingest_index == 10
    assert engine.ingest_stats.capture_file_problem is None


# ── summaries ─────────────────────────────────────────────────────────────────

def test_cli_summary_states_the_early_stop(tmp_path):
    data, offsets = _pcap()
    path = tmp_path / "damaged.pcap"
    path.write_bytes(_set_u32(data, offsets[1000] + 8, 0x7FFFFFFF))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, HOME=str(tmp_path), PYTHONPATH=root)
    result = subprocess.run(
        [sys.executable, "-m", "scrutics", "--file", str(path), "--headless", "--no-baseline",
         "--output", str(tmp_path / "out")],
        capture_output=True, text=True, cwd=str(tmp_path), env=env, timeout=300)
    assert f"[!] Input: 1 rejected ({REASON_DAMAGED}: 1)" in result.stdout
    assert (f"[!] Analysis stopped at pcap record 1001 (byte offset {offsets[1000]}) of a damaged file; "
            "the rest of the file was not read.") in result.stdout


def test_tui_summary_warns_about_the_early_stop(tmp_path):
    data, offsets = _pcapng()
    engine, _ = _run(tmp_path, data[:offsets[-1] + 30], "cut.pcapng")
    notices = []
    widget = SimpleNamespace(label="", remove_class=lambda *a: None)
    app = SimpleNamespace(
        engine=engine, inventory=engine.inventory, _session_dir=str(tmp_path), _paused=True,
        query_one=lambda *a, **k: widget, _export_session=lambda: None,
        _set_status=lambda text, **k: None,
        notify=lambda message, **kw: notices.append((message, kw)),
    )
    ScruticsApp._on_capture_done(app)
    line = engine.ingest_stats.capture_file_line()
    assert (line, {"severity": "warning", "markup": False}) in notices


def test_a_gzip_compressed_capture_is_checked_the_same_way(tmp_path):
    import gzip
    data, offsets = _pcap()
    damaged = gzip.compress(_set_u32(data, offsets[1000] + 8, 0x7FFFFFFF))
    engine, seen = _run(tmp_path, damaged, "damaged_gz.pcap")
    problem = engine.ingest_stats.capture_file_problem
    assert len(seen) == 1000
    assert (problem.kind, problem.offset) == (DAMAGED, offsets[1000])   # offset in the decompressed data
    clean, _ = _run(tmp_path, gzip.compress(data), "clean_gz.pcap")
    assert clean.ingest_stats.capture_file_problem is None


def _read_sizes_asked(path):
    """Read a capture through CaptureFile; return (packets, problem, sizes asked of the real file)."""
    import scapy.all  # noqa: F401
    from scrutics.capture.capture_file import CaptureFile
    asked = []
    with CaptureFile(str(path)) as capture:
        inner = capture._tracker.inner

        class Spy:
            def read(self, size=-1):
                asked.append(size)
                return inner.read(size)

            def __getattr__(self, name):
                return getattr(inner, name)
        capture._tracker.inner = Spy()
        packets = sum(1 for _ in capture)
    return packets, capture.problem, asked


@pytest.mark.parametrize("caplen", [0x7FFFFFFF, 0xFFFFFFFF])
def test_a_huge_record_length_never_asks_for_more_than_the_file_holds(tmp_path, caplen):
    data, offsets = _pcap()
    path = tmp_path / "huge.pcap"
    path.write_bytes(_set_u32(data, offsets[1000] + 8, caplen))
    packets, problem, asked = _read_sizes_asked(path)
    assert packets == 1000 and problem.kind == DAMAGED
    assert asked and max(asked) <= len(data) and min(asked) >= 0


def test_a_huge_record_length_in_a_gzip_capture_is_read_in_bounded_chunks(tmp_path):
    import gzip
    from scrutics.capture.capture_file import _ReadTracker
    data, offsets = _pcap()
    path = tmp_path / "huge_gz.pcap"
    path.write_bytes(gzip.compress(_set_u32(data, offsets[1000] + 8, 0xFFFFFFFF)))
    packets, problem, asked = _read_sizes_asked(path)
    assert packets == 1000 and problem.kind == DAMAGED
    assert max(asked) <= _ReadTracker._CHUNK
