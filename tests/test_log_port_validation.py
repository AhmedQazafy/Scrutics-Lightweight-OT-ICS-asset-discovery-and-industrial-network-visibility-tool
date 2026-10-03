"""
Ports read from Zeek and Suricata logs must be port numbers.

A destination port that is not an integer in 0..65535 rejects its line as malformed input, so
per-device port sets stay within the port number space. In Zeek logs "-" means unset and is
kept as no port.
"""

import json

import pytest

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory

ZEEK_HEADER = ("#separator \\x09\n#path\tconn\n"
               "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n")
ZEEK_REASON = "Zeek field id.resp_p is not a port number (0-65535)"


def _run(tmp_path, name, text):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine.start_file(str(f))
    return engine


def _zeek(tmp_path, ports):
    lines = "".join(f"{1700000000 + i}\tC{i}\t10.0.0.{10 + i}\t40000\t10.0.1.1\t{port}\ttcp\n"
                    for i, port in enumerate(ports))
    return _run(tmp_path, "conn.log", ZEEK_HEADER + lines)


@pytest.mark.parametrize("port", ["65536", "70000", "1000000000", "-5", "T", "F", "True", "False",
                                  "502.0", "1e3", "+502", "abc", "", "\u0665\u0660\u0662"])
def test_zeek_line_with_a_port_that_is_not_a_port_number_is_rejected(tmp_path, port):
    engine = _zeek(tmp_path, ["502", port, "102"])
    assert engine.ingest_stats.rejected_by_reason == {ZEEK_REASON: 1}
    assert engine.ingest_stats.contained_total == 0
    assert engine.inventory.get("10.0.0.11") is None
    assert engine.inventory.get("10.0.0.10") and engine.inventory.get("10.0.0.12")


def test_zeek_ports_in_range_and_unset_are_accepted(tmp_path):
    engine = _zeek(tmp_path, ["0", "65535", "-", "502"])
    assert engine.ingest_stats.rejected_total == 0
    assert engine.inventory.get("10.0.0.10").contacted_ports == set()      # port 0 is not recorded
    assert engine.inventory.get("10.0.0.11").contacted_ports == {65535}
    assert engine.inventory.get("10.0.0.12").contacted_ports == set()      # unset
    assert engine.inventory.get("10.0.0.13").contacted_ports == {502}
    assert engine.inventory.get("10.0.1.1").ports_seen == {65535, 502}


def _eve(tmp_path, ports):
    lines = [json.dumps({"event_type": "flow", "src_ip": f"10.0.0.{10 + i}", "dest_ip": "10.0.1.1",
                         "dest_port": port, "proto": "TCP"}) for i, port in enumerate(ports)]
    return _run(tmp_path, "eve.json", "\n".join(lines) + "\n")


def test_suricata_out_of_range_and_boolean_ports_are_rejected(tmp_path):
    engine = _eve(tmp_path, [502, 65536, -1, 10**9, True, False, 102])
    assert engine.ingest_stats.rejected_by_reason == {
        "EVE field dest_port is out of range (0-65535)": 3,
        "EVE field dest_port is not an integer": 2,
    }
    assert engine.ingest_stats.contained_total == 0
    assert [ip for ip in (f"10.0.0.{10 + i}" for i in range(7)) if engine.inventory.get(ip)] == ["10.0.0.10", "10.0.0.16"]


def test_suricata_ports_at_both_ends_of_the_range_are_accepted(tmp_path):
    engine = _eve(tmp_path, [0, 65535])
    assert engine.ingest_stats.rejected_total == 0
    assert engine.inventory.get("10.0.0.10").contacted_ports == set()
    assert engine.inventory.get("10.0.0.11").contacted_ports == {65535}
