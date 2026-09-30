"""Tests for parsers and baseline modules.

Covers file-type detection, Zeek conn.log parsing, Suricata EVE JSON
parsing, baseline engine anomaly detection, confidence scorer, and
PCAP timestamp handling.
"""

import os
import json
import time
import tempfile
import pytest
from scapy.all import Ether, IP, TCP

from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory
from scrutics.parsers.detector import detect_file_type
from scrutics.parsers.zeek import extract_flows_from_zeek
from scrutics.parsers.suricata import extract_flows_from_eve
from scrutics.baseline.baselineengine import BaselineEngine, DeviceBaseline
from scrutics.baseline.scorer import (
    oui_score, protocol_score, confidence_pct, confidence_color
)


# ── File Type Detection ───────────────────────────────────────────────────────

class TestFileTypeDetection:

    def test_pcap_extension_detected(self, tmp_path):
        f = tmp_path / "capture.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        assert detect_file_type(str(f)) == "pcap"

    def test_pcapng_extension_detected(self, tmp_path):
        f = tmp_path / "capture.pcapng"
        f.write_bytes(b"\x00" * 4)
        assert detect_file_type(str(f)) == "pcapng"

    def test_zeek_log_detected(self, tmp_path):
        f = tmp_path / "conn.log"
        f.write_text("#separator \\t\n#fields\tts\tid.orig_h\tid.resp_h\n")
        assert detect_file_type(str(f)) == "zeek"

    def test_suricata_eve_detected(self, tmp_path):
        f = tmp_path / "eve.json"
        line = json.dumps({"event_type": "flow", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"})
        f.write_text(line + "\n")
        assert detect_file_type(str(f)) == "suricata"

    def test_unknown_file_returns_unknown(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert detect_file_type(str(f)) == "unknown"


# ── Zeek Parser ───────────────────────────────────────────────────────────────

class TestZeekParser:

    def _write_conn_log(self, path: str):
        content = (
            "#separator \\t\n"
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "#path\tconn\n"
            "1700000000.0\t192.168.1.10\t54321\t192.168.1.20\t502\ttcp\n"
            "1700000001.0\t192.168.1.10\t54322\t192.168.1.21\t44818\ttcp\n"
        )
        with open(path, "w") as f:
            f.write(content)

    def test_conn_log_parses_flows(self, tmp_path):
        log = str(tmp_path / "conn.log")
        self._write_conn_log(log)
        flows = extract_flows_from_zeek(log)
        assert len(flows) == 2

    def test_conn_log_extracts_correct_ips(self, tmp_path):
        log = str(tmp_path / "conn.log")
        self._write_conn_log(log)
        flows = extract_flows_from_zeek(log)
        assert flows[0]["src_ip"] == "192.168.1.10"
        assert flows[0]["dst_ip"] == "192.168.1.20"

    def test_conn_log_extracts_port(self, tmp_path):
        log = str(tmp_path / "conn.log")
        self._write_conn_log(log)
        flows = extract_flows_from_zeek(log)
        assert flows[0]["dst_port"] == 502

    def test_modbus_log_forces_port_502(self, tmp_path):
        content = (
            "#separator \\t\n"
            "#fields\tts\tid.orig_h\tid.resp_h\n"
            "#path\tmodbus\n"
            "1700000000.0\t192.168.1.10\t192.168.1.20\n"
        )
        log = str(tmp_path / "modbus.log")
        with open(log, "w") as f:
            f.write(content)
        flows = extract_flows_from_zeek(log)
        assert len(flows) == 1
        assert flows[0]["dst_port"] == 502
        assert flows[0]["source"] == "zeek_modbus"

    def test_empty_log_returns_no_flows(self, tmp_path):
        log = str(tmp_path / "empty.log")
        with open(log, "w") as f:
            f.write("#separator \\t\n#fields\tts\n#path\tconn\n")
        flows = extract_flows_from_zeek(log)
        assert flows == []


# ── Suricata Parser ───────────────────────────────────────────────────────────

class TestSuricataParser:

    def _write_eve(self, path: str):
        events = [
            {"event_type": "flow",  "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dest_port": 502,   "proto": "TCP", "timestamp": "2024-01-01T00:00:00+00:00"},
            {"event_type": "alert", "src_ip": "10.0.0.3", "dest_ip": "10.0.0.4", "dest_port": 44818, "proto": "TCP", "timestamp": "2024-01-01T00:00:01+00:00",
             "alert": {"signature": "ET ICS Modbus write", "category": "ICS", "severity": 1, "action": "allowed"}},
            {"event_type": "flow",  "src_ip": "10.0.0.5", "dest_ip": "10.0.0.6", "dest_port": 20000, "proto": "TCP", "timestamp": "2024-01-01T00:00:02+00:00"},
        ]
        with open(path, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

    def test_eve_parses_all_events(self, tmp_path):
        eve = str(tmp_path / "eve.json")
        self._write_eve(eve)
        flows = extract_flows_from_eve(eve)
        assert len(flows) == 3

    def test_alert_has_alert_field(self, tmp_path):
        eve = str(tmp_path / "eve.json")
        self._write_eve(eve)
        flows = extract_flows_from_eve(eve)
        alerts = [f for f in flows if "alert" in f]
        assert len(alerts) == 1
        assert alerts[0]["alert"]["signature"] == "ET ICS Modbus write"

    def test_flow_has_correct_ips(self, tmp_path):
        eve = str(tmp_path / "eve.json")
        self._write_eve(eve)
        flows = extract_flows_from_eve(eve)
        assert flows[0]["src_ip"] == "10.0.0.1"
        assert flows[0]["dst_ip"] == "10.0.0.2"

    def test_malformed_lines_skipped(self, tmp_path):
        eve = str(tmp_path / "bad.json")
        with open(eve, "w") as f:
            f.write("not json\n")
            f.write(json.dumps({"event_type": "flow", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80, "proto": "TCP"}) + "\n")
        flows = extract_flows_from_eve(eve)
        assert len(flows) == 1


# ── Baseline Engine ───────────────────────────────────────────────────────────

class TestBaselineEngine:

    def test_observe_returns_none_before_lock(self):
        engine = BaselineEngine(observation_window=999)
        result = engine.observe("10.0.0.1", time.time(), True, {"10.0.0.2"})
        assert result is None

    def test_behavioral_score_zero_with_no_data(self):
        engine = BaselineEngine(observation_window=999)
        assert engine.get_behavioral_score("10.0.0.1") == 0

    def test_behavioral_score_increases_with_observations(self):
        engine = BaselineEngine(observation_window=999)
        ts = time.time()
        for i in range(10):
            engine.observe("10.0.0.1", ts + i, True, {"10.0.0.2"})
        score = engine.get_behavioral_score("10.0.0.1")
        assert score > 0

    def test_directionality_score_high_when_consistent(self):
        engine = BaselineEngine(observation_window=999)
        ts = time.time()
        for i in range(20):
            engine.observe("10.0.0.1", ts + i, True, {"10.0.0.2"})
        assert engine.get_directionality_score("10.0.0.1") >= 7

    def test_directionality_score_low_when_mixed(self):
        engine = BaselineEngine(observation_window=999)
        ts = time.time()
        for i in range(10):
            engine.observe("10.0.0.1", ts + i, i % 2 == 0, {"10.0.0.2"})
        assert engine.get_directionality_score("10.0.0.1") <= 4

    def test_status_no_data_initially(self):
        engine = BaselineEngine(observation_window=999)
        assert engine.get_status("10.0.0.1") == "no_data"

    def test_status_building_after_first_observation(self):
        engine = BaselineEngine(observation_window=999)
        engine.observe("10.0.0.1", time.time(), True, set())
        assert "building" in engine.get_status("10.0.0.1")

    def test_observation_window_uses_packet_timestamps(self):
        engine = BaselineEngine(observation_window=10)
        engine.observe("10.0.0.1", 1000.0, True, {"10.0.0.2"})
        assert "building" in engine.get_status("10.0.0.1")
        engine.observe("10.0.0.1", 1011.0, True, {"10.0.0.2"})
        assert engine.get_status("10.0.0.1") == "active"

    def test_anomaly_new_peer_after_lock(self):
        engine = BaselineEngine(observation_window=0)  # instant lock
        ts = time.time()
        # Feed enough data to lock
        for i in range(15):
            engine.observe("10.0.0.1", ts + i * 0.1, True, {"10.0.0.2"})
        # Force lock by directly setting
        engine._devices["10.0.0.1"]._lock()
        # Now introduce new peer
        result = engine.observe("10.0.0.1", ts + 5, True, {"10.0.0.99"})
        assert result is not None
        assert result["type"] == "NEW_PEER"

    def test_process_packet_uses_packet_timestamp(self):
        engine = CaptureEngine(inventory=AssetInventory())
        seen = {}
        engine._process_flow_data = lambda **kwargs: seen.update(kwargs)
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(dport=502)
        )
        pkt.time = 1234.5
        engine._process_packet(pkt)
        assert seen["ts"] == 1234.5

    def test_raw_packet_does_not_credit_unknown_destination_port_as_listener(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=40000, dport=55556)
        )
        engine._process_packet(pkt)
        assert 55556 in inventory.get("192.168.1.10").contacted_ports
        assert inventory.get("192.168.1.20") is None

    def test_raw_packet_credits_known_destination_port_as_listener(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=40000, dport=502)
        )
        engine._process_packet(pkt)
        assert 502 in inventory.get("192.168.1.20").ports_seen

    def test_raw_packet_credits_known_source_port_as_listener(self):
        inventory = AssetInventory()
        engine = CaptureEngine(inventory=inventory)
        pkt = (
            Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
            / IP(src="192.168.1.20", dst="192.168.1.10")
            / TCP(sport=502, dport=40000)
        )
        engine._process_packet(pkt)
        assert 502 in inventory.get("192.168.1.20").ports_seen


# ── Confidence Scorer ─────────────────────────────────────────────────────────

class TestConfidenceScorer:

    def test_oui_score_ot_vendor(self):
        assert oui_score(True) == 30

    def test_oui_score_unknown_vendor(self):
        assert oui_score(False) == 0

    def test_protocol_score_ics_match(self):
        assert protocol_score(matched_ics=True, matched_it=False) == 40

    def test_protocol_score_it_only(self):
        s = protocol_score(matched_ics=False, matched_it=True)
        assert 0 < s < 40

    def test_protocol_score_unknown(self):
        assert protocol_score(matched_ics=False, matched_it=False) == 0

    def test_confidence_pct_full_score(self):
        pct = confidence_pct(oui_s=30, protocol_s=40, behavioral_s=20, directional_s=10)
        assert pct == 100

    def test_confidence_pct_capped_at_100(self):
        pct = confidence_pct(oui_s=30, protocol_s=40, behavioral_s=20, directional_s=15)
        assert pct == 100

    def test_confidence_pct_partial(self):
        pct = confidence_pct(oui_s=30, protocol_s=40, behavioral_s=0, directional_s=0)
        assert pct == 70

    def test_confidence_color_green_high(self):
        assert "green" in confidence_color(80)

    def test_confidence_color_yellow_medium(self):
        assert "yellow" in confidence_color(55)

    def test_confidence_color_red_low(self):
        assert "red" in confidence_color(20)
