"""
Captured frames that cannot produce an asset are counted by kind, and a capture that produced no
assets says which of four conditions it met: the capture is empty; the file stopped early (its own
line); no frame was of a supported kind; or supported frames were present but none produced an
asset. The lines state observed counts only. Frames are struct.pack bytes.
"""

import os
import random
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP
from scapy.layers.l2 import CookedLinux, CookedLinuxV2, Ether
from scapy.packet import Raw

from scrutics.capture import frame_kinds as fk
from scrutics.capture.engine import CaptureEngine
from scrutics.capture.ingest_stats import FILTERED_MAC, FILTERED_SCOPE
from scrutics.db.inventory import AssetInventory
from scrutics.ui.tui import ScruticsApp

SRC_MAC = bytes([2, 0, 0, 0, 0, 5])
DST_MAC = bytes([2, 0, 0, 0, 0, 9])


def _ipv4_udp(i=0, src="10.0.0.5", dst="10.0.0.9"):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, i, 0, 64, 17, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return ip + struct.pack("!HHHH", 40000, 502, 8, 0)


def _ipv6_udp():
    return (struct.pack("!IHBB", 6 << 28, 8, 17, 64) + b"\xfe\x80" + b"\0" * 13 + b"\x05"
            + b"\xfe\x80" + b"\0" * 13 + b"\x09" + struct.pack("!HHHH", 40000, 502, 8, 0))


def _ether(ethertype, payload, src=SRC_MAC):
    return DST_MAC + src + struct.pack("!H", ethertype) + payload


def _vlan(ethertype, payload):
    return DST_MAC + SRC_MAC + struct.pack("!HHH", 0x8100, 5, ethertype) + payload


def _sll(payload, proto=0x0800):
    return struct.pack("!HHH8sH", 4, 1, 6, SRC_MAC + b"\0\0", proto) + payload


def _sll2(payload, proto=0x0800):
    return struct.pack("!HHIHBB8s", proto, 0, 2, 1, 4, 6, SRC_MAC + b"\0\0") + payload


def _pcap(linktype, frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, data in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(data), len(data)) + data
    return out


def _run(tmp_path, data, name="capture.pcap"):
    path = tmp_path / name
    path.write_bytes(data)
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.no_baseline = True
    engine.start_file(str(path))
    return engine


PAYLOAD = b"\0" * 30
LLDP = _ether(0x88CC, PAYLOAD)
GOOSE = _ether(0x88B8, PAYLOAD)


# ── frame kinds ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pkt, expected", [
    (CookedLinux(_sll(_ipv4_udp())), fk.SLL),
    (CookedLinuxV2(_sll2(_ipv4_udp())), fk.SLL2),
    (IP(_ipv4_udp()), fk.RAW_IP),
    (Ether(_ether(0x86DD, _ipv6_udp())), fk.IPV6),
    (Ether(_ether(0x8892, PAYLOAD)), "PROFINET (0x8892)"),
    (Ether(_vlan(0x8892, PAYLOAD)), "PROFINET (0x8892)"),          # the tagged payload's type
    (Ether(GOOSE), "IEC 61850 GOOSE (0x88b8)"),
    (Ether(_ether(0x88BA, PAYLOAD)), "IEC 61850 Sampled Values (0x88ba)"),
    (Ether(LLDP), "LLDP (0x88cc)"),
    (Ether(DST_MAC + SRC_MAC + struct.pack("!H", 38) + b"\x42\x42\x03" + PAYLOAD), fk.LLC),
    (Ether(_ether(0x1234, PAYLOAD)), fk.OTHER_ETHERTYPE),
    (Raw(b"\x01\x02\x03"), fk.OTHER_LINK),
], ids=["sll", "sll2", "raw ip", "ipv6", "profinet", "vlan profinet", "goose", "sv", "lldp", "llc",
        "other ethertype", "other link"])
def test_frame_kind(pkt, expected):
    assert fk.frame_kind(pkt) == expected
    assert expected in fk.KINDS


def test_the_kind_counter_stays_bounded():
    engine = CaptureEngine(inventory=AssetInventory({}))
    rng = random.Random(7)
    for i in range(2000):
        pkt = Ether(_ether(rng.randrange(0x0600, 0x10000), PAYLOAD))
        pkt.time = 1_700_000_000 + i
        engine._ingest_packet(pkt, "pcap")
    kinds = engine.ingest_stats.unsupported_by_kind
    assert set(kinds) <= set(fk.KINDS) and sum(kinds.values()) == 2000


# ── the four conditions ───────────────────────────────────────────────────────

def test_an_empty_capture(tmp_path):
    engine = _run(tmp_path, _pcap(1, []))
    assert engine.ingest_stats.frame_lines(0) == [("warning", "No assets: the capture contains no frames.")]


@pytest.mark.parametrize("linktype, frames, kind", [
    (113, [_sll(_ipv4_udp(i)) for i in range(30)], fk.SLL),
    (276, [_sll2(_ipv4_udp(i)) for i in range(30)], fk.SLL2),
    (101, [_ipv4_udp(i) for i in range(30)], fk.RAW_IP),
    (1, [_ether(0x86DD, _ipv6_udp())] * 20 + [LLDP] * 10, None),
], ids=["sll", "sll2", "raw ip", "ipv6 and lldp"])
def test_no_frame_of_a_supported_kind(tmp_path, linktype, frames, kind):
    engine = _run(tmp_path, _pcap(linktype, frames))
    stats = engine.ingest_stats
    assert engine.inventory.count() == 0
    assert (stats.frames_read, stats.frames_supported, stats.unsupported_total) == (30, 0, 30)
    seen = f"{kind}: 30" if kind else "IPv6: 20, LLDP (0x88cc): 10"
    assert stats.frame_lines(0) == [("warning",
        "No assets: 30 frames read, none of a kind Scrutics builds assets from "
        f"(Ethernet with an IPv4 or ARP source address). Frames seen: {seen}.")]
    assert stats.rejected_total == 0                       # unsupported frames are not malformed


def test_supported_frames_but_no_asset(tmp_path):
    frames = ([_ether(0x0800, _ipv4_udp(i, src="8.8.8.8")) for i in range(5)]
              + [_ether(0x0800, _ipv4_udp(i), src=b"\xff" * 6) for i in range(3)] + [GOOSE])
    engine = _run(tmp_path, _pcap(1, frames))
    stats = engine.ingest_stats
    assert engine.inventory.count() == 0
    assert stats.filtered_by_reason == {FILTERED_SCOPE: 5, FILTERED_MAC: 3}
    assert stats.frame_lines(0) == [
        ("warning", "No assets: 9 frames read, 8 of a supported kind (Ethernet with an IPv4 or ARP "
                    f"source address); none produced an asset ({FILTERED_MAC}: 3, {FILTERED_SCOPE}: 5)."),
        ("information", "Frames of kinds Scrutics does not build assets from: 1 (IEC 61850 GOOSE (0x88b8): 1)."),
    ]


def test_a_damaged_file_is_explained_by_its_own_line_only(tmp_path):
    data = _pcap(1, [_ether(0x0800, _ipv4_udp(i)) for i in range(5)])
    damaged = data[:24 + 8] + struct.pack("<I", 0x7FFFFFFF) + data[24 + 12:]
    stats = _run(tmp_path, damaged).ingest_stats
    assert stats.capture_file_line().startswith("Analysis stopped at pcap record 1")
    assert stats.frame_lines(0) == []


def test_the_four_conditions_give_distinct_lines(tmp_path):
    lines = []
    for name, data in [("empty", _pcap(1, [])), ("sll", _pcap(113, [_sll(_ipv4_udp())])),
                       ("raw", _pcap(101, [_ipv4_udp()]))]:
        lines.append(" ".join(text for _, text in _run(tmp_path, data, name + ".pcap").ingest_stats.frame_lines(0)))
    data = _pcap(1, [_ether(0x0800, _ipv4_udp())])
    lines.append(_run(tmp_path, data[:24 + 8] + struct.pack("<I", 0x7FFFFFFF) + data[24 + 12:],
                      "damaged.pcap").ingest_stats.capture_file_line())
    assert all(lines) and len(set(lines)) == 4


# ── with assets, and other inputs ─────────────────────────────────────────────

def test_kind_counts_are_listed_when_assets_exist(tmp_path):
    frames = [_ether(0x0800, _ipv4_udp(i)) for i in range(4)] + [LLDP, LLDP, _ether(0x86DD, _ipv6_udp())]
    engine = _run(tmp_path, _pcap(1, frames))
    stats = engine.ingest_stats
    assert engine.inventory.count() >= 1
    assert (stats.frames_read, stats.frames_supported) == (7, 4)
    assert stats.frame_lines(engine.inventory.count()) == [
        ("information", "Frames of kinds Scrutics does not build assets from: 3 (IPv6: 1, LLDP (0x88cc): 2).")]


def test_a_supported_only_capture_prints_nothing(tmp_path):
    engine = _run(tmp_path, _pcap(1, [_ether(0x0800, _ipv4_udp(i)) for i in range(4)]))
    assert engine.ingest_stats.frame_lines(engine.inventory.count()) == []


def test_live_capture_frames_are_counted_the_same_way():
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.ingest_stats.frame_source = "live"           # set by start_live
    for i in range(3):
        pkt = CookedLinux(_sll(_ipv4_udp(i)))
        pkt.time = 1_700_000_000 + i
        engine._ingest_packet(pkt, "live")
    assert engine.ingest_stats.frame_lines(0)[0][1].startswith(
        "No assets: 3 frames read, none of a kind Scrutics builds assets from")


def test_log_input_has_no_frame_lines(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("#separator \\x09\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n",
                    encoding="utf-8")
    engine = CaptureEngine(inventory=AssetInventory({}))
    engine.start_file(str(path))
    assert engine.ingest_stats.frame_source is None and engine.ingest_stats.frame_lines(0) == []


# ── summaries ─────────────────────────────────────────────────────────────────

def test_cli_summary_explains_an_sll_capture(tmp_path):
    path = tmp_path / "sll.pcap"
    path.write_bytes(_pcap(113, [_sll(_ipv4_udp(i)) for i in range(12)]))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "-m", "scrutics", "--file", str(path), "--headless", "--no-baseline",
         "--output", str(tmp_path / "out")],
        capture_output=True, text=True, cwd=str(tmp_path), env=dict(os.environ, HOME=str(tmp_path), PYTHONPATH=root),
        timeout=300)
    assert ("[!] No assets: 12 frames read, none of a kind Scrutics builds assets from (Ethernet with "
            f"an IPv4 or ARP source address). Frames seen: {fk.SLL}: 12.") in result.stdout


def test_tui_summary_shows_the_frame_lines(tmp_path):
    frames = [_ether(0x0800, _ipv4_udp(i)) for i in range(2)] + [LLDP]
    engine = _run(tmp_path, _pcap(1, frames))
    notices = []
    widget = SimpleNamespace(label="", remove_class=lambda *a: None)
    app = SimpleNamespace(
        engine=engine, inventory=engine.inventory, _session_dir=str(tmp_path), _paused=True,
        query_one=lambda *a, **k: widget, _export_session=lambda: None,
        _set_status=lambda text, **k: None,
        notify=lambda message, **kw: notices.append((message, kw)),
    )
    ScruticsApp._on_capture_done(app)
    assert ("Frames of kinds Scrutics does not build assets from: 1 (LLDP (0x88cc): 1).",
            {"severity": "information", "markup": False}) in notices
