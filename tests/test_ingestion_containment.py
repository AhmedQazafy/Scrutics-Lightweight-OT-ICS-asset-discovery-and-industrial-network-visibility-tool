"""
An unexpected error while processing one packet or log line skips that item and the run
continues, in every ingestion path. Errors are counted per kind with one event log entry per
kind, and their text is shown as plain text.
"""

import io
import json
from types import SimpleNamespace

import pytest
import scapy.all
from rich.console import Console
from scapy.all import Ether, IP, TCP, wrpcap

from scrutics.capture.engine import CaptureEngine
from scrutics.capture.ingest_stats import CONTAINED_KEY_LIMIT, IngestStats
from scrutics.db.inventory import AssetInventory
from scrutics.ui.tui import ScruticsApp

BAD_IP = "10.0.0.66"
GOOD_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
HOSTILE_TEXT = "[bold]x[/bold] [link=https://example.invalid]y[/link] \x1b[31mred"


def _packets():
    def pkt(ip, i):
        p = Ether(src="02:00:00:00:00:%02x" % i, dst="02:ff:ff:ff:ff:fe") / IP(src=ip, dst="10.0.0.200") / TCP(sport=40000, dport=502)
        p.time = 1_700_000_000.0 + i
        return p
    order = [GOOD_IPS[0], BAD_IP, GOOD_IPS[1], BAD_IP, GOOD_IPS[2], GOOD_IPS[3]]
    return [pkt(ip, i) for i, ip in enumerate(order)]


def _engine_failing_on(monkeypatch, exc_factory=lambda: ValueError(HOSTILE_TEXT)):
    original = CaptureEngine._process_flow_data

    def flaky(self, src_ip, *args, **kwargs):
        if src_ip == BAD_IP:
            raise exc_factory()
        return original(self, src_ip, *args, **kwargs)

    monkeypatch.setattr(CaptureEngine, "_process_flow_data", flaky)
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    return engine


def _assert_contained_and_continued(engine, path):
    for ip in GOOD_IPS:
        assert engine.inventory.get(ip) is not None, f"{ip} not processed after the error"
    stats = engine.ingest_stats
    assert stats.contained_total == 2
    assert len(stats.contained) == 1
    [entry] = stats.contained.values()
    assert entry.exception_type == "ValueError"
    assert entry.first_item.startswith(path)
    contained_log = [m for _, m, _ in engine.event_log if m.startswith("Contained error")]
    assert len(contained_log) == 1


def test_error_in_live_capture_is_contained(monkeypatch):
    engine = _engine_failing_on(monkeypatch)
    packets = _packets()

    def fake_sniff(prn=None, **kwargs):
        for p in packets:
            prn(p)
        engine.request_stop()

    monkeypatch.setattr(scapy.all, "sniff", fake_sniff)
    engine.start_live(interface="test0", timeout=5)
    _assert_contained_and_continued(engine, "live packet")


def test_error_in_pcap_file_is_contained(monkeypatch, tmp_path):
    engine = _engine_failing_on(monkeypatch)
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), _packets())
    engine.start_file(str(path))
    _assert_contained_and_continued(engine, "pcap packet")


def test_error_in_zeek_log_is_contained(monkeypatch, tmp_path):
    engine = _engine_failing_on(monkeypatch)
    rows = [GOOD_IPS[0], BAD_IP, GOOD_IPS[1], BAD_IP, GOOD_IPS[2], GOOD_IPS[3]]
    lines = ["#separator \\x09", "#path\tconn",
             "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto"]
    lines += [f"{1_700_000_000 + i}.0\t{ip}\t40000\t10.0.0.200\t502\ttcp" for i, ip in enumerate(rows)]
    path = tmp_path / "conn.log"
    path.write_text("\n".join(lines) + "\n")
    engine.start_file(str(path))
    _assert_contained_and_continued(engine, "zeek line")


def test_error_in_suricata_eve_is_contained(monkeypatch, tmp_path):
    engine = _engine_failing_on(monkeypatch)
    rows = [GOOD_IPS[0], BAD_IP, GOOD_IPS[1], BAD_IP, GOOD_IPS[2], GOOD_IPS[3]]
    events = [{"timestamp": "2024-01-01T00:00:00.000000+0000", "event_type": "flow", "src_ip": ip,
               "dest_ip": "10.0.0.200", "dest_port": 502, "proto": "TCP"} for ip in rows]
    path = tmp_path / "eve.json"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    engine.start_file(str(path))
    _assert_contained_and_continued(engine, "suricata line")


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
def test_interrupts_are_not_contained(monkeypatch, tmp_path, exc_type):
    engine = _engine_failing_on(monkeypatch, exc_factory=exc_type)
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), _packets())
    with pytest.raises(exc_type):
        engine.start_file(str(path))
    assert engine.ingest_stats.contained_total == 0


def test_distinct_error_kinds_are_bounded():
    logged = []
    stats = IngestStats(log=logged.append)
    for i in range(CONTAINED_KEY_LIMIT + 6):
        exc_type = type(f"Kind{i}Error", (Exception,), {})
        try:
            raise exc_type("detail")
        except Exception as exc:
            stats.contain(exc, "pcap", i + 1)
    assert len(stats.contained) == CONTAINED_KEY_LIMIT
    assert stats.contained_overflow == 6
    assert stats.contained_total == CONTAINED_KEY_LIMIT + 6
    assert len(logged) == CONTAINED_KEY_LIMIT + 1


def test_error_text_is_shown_literally(monkeypatch, tmp_path):
    engine = _engine_failing_on(monkeypatch)
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), _packets())
    engine.start_file(str(path))

    [entry] = engine.ingest_stats.contained.values()
    shown = "[bold]x[/bold] [link=https://example.invalid]y[/link] \\x1b[31mred"
    assert entry.first_message == shown
    [log_line] = [m for _, m, _ in engine.event_log if m.startswith("Contained error")]
    assert shown in log_line and "\x1b" not in log_line
    summary = engine.ingest_stats.summary_line()
    assert shown in summary and "\x1b" not in summary

    # The TUI shows the summary in a notification with markup parsing off
    notices, statuses = [], []
    widget = SimpleNamespace(label="", remove_class=lambda *a: None)
    app = SimpleNamespace(
        engine=engine, _session_dir=str(tmp_path), _paused=True,
        query_one=lambda *a, **k: widget, _export_session=lambda: None,
        _set_status=lambda text, **k: statuses.append(text),
        notify=lambda message, **kw: notices.append((message, kw)),
    )
    ScruticsApp._on_capture_done(app)
    [(message, kwargs)] = [n for n in notices if n[1].get("severity") == "warning"]
    assert kwargs.get("markup") is False
    assert message == summary
    rendered = io.StringIO()
    Console(file=rendered, width=10_000, color_system=None).print(message, markup=False)
    assert rendered.getvalue().rstrip("\n") == summary
    assert "input: 0 rejected, 2 contained errors" in statuses[-1]


def test_reader_error_on_one_suricata_line_skips_only_that_line(monkeypatch, tmp_path):
    import scrutics.parsers.suricata as suricata
    original = suricata._flow_from_event

    def flaky(event):
        if event.get("src_ip") == BAD_IP:
            raise RuntimeError("reader failure")
        return original(event)

    monkeypatch.setattr(suricata, "_flow_from_event", flaky)
    rows = [GOOD_IPS[0], BAD_IP, GOOD_IPS[1]]
    events = [{"event_type": "flow", "src_ip": ip, "dest_ip": "10.0.0.200", "dest_port": 502, "proto": "TCP"}
              for ip in rows]
    path = tmp_path / "eve.json"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine.start_file(str(path))
    assert engine.inventory.get(GOOD_IPS[0]) and engine.inventory.get(GOOD_IPS[1])
    [entry] = engine.ingest_stats.contained.values()
    assert (entry.count, entry.first_item) == (1, "suricata line 2")


def test_reader_error_on_one_zeek_line_skips_only_that_line(monkeypatch, tmp_path):
    import scrutics.parsers.zeek as zeek
    original = zeek._flow_from_record

    def flaky(record):
        if record.get("id.orig_h") == BAD_IP:
            raise RuntimeError("reader failure")
        return original(record)

    monkeypatch.setattr(zeek, "_flow_from_record", flaky)
    lines = ["#separator \\x09", "#path\tconn", "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto"]
    lines += [f"1700000000.{i}\t{ip}\t10.0.0.200\t502\ttcp" for i, ip in enumerate([GOOD_IPS[0], BAD_IP, GOOD_IPS[1]])]
    path = tmp_path / "conn.log"
    path.write_text("\n".join(lines) + "\n")
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine.start_file(str(path))
    assert engine.inventory.get(GOOD_IPS[0]) and engine.inventory.get(GOOD_IPS[1])
    [entry] = engine.ingest_stats.contained.values()
    assert (entry.count, entry.first_item) == (1, "zeek line 5")
