"""
Per-device retention limits.

Every per-asset collection that observed traffic can grow keeps a bounded number of entries. Keep-first
collections keep the first entries seen and never evict or replace them; a refused addition is
counted on the asset, so truncation is never silent. Under the limits nothing changes.
"""

import re
import struct

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import scrutics.db.inventory as inventory
from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import (
    Asset, AssetInventory, Evidence, MAX_DNS_NAMES, MAX_EVIDENCE_VALUES_PER_TYPE, MAX_IP_HISTORY,
)

T0 = 1_700_000_000.0
MAC = "02:00:00:00:00:a1"


def _asset():
    return Asset(ip="10.0.0.1", mac=MAC)


# ── Evidence: distinct values per type ────────────────────────────────────────

def test_evidence_limit_is_64_distinct_values_per_type():
    assert MAX_EVIDENCE_VALUES_PER_TYPE == 64


@pytest.mark.parametrize("added, kept, refused", [(64, 64, 0), (65, 64, 1), (1000, 64, 936)])
def test_evidence_keeps_the_first_values_of_a_type_and_counts_the_rest(added, kept, refused):
    asset = _asset()
    results = [asset.add_evidence("hostname", f"h{i}", 5, "DHCP") for i in range(added)]
    assert [e.value for e in asset.evidence] == [f"h{i}" for i in range(kept)]
    assert results == [True] * kept + [False] * refused
    assert asset.evidence_overflow == ({"hostname": refused} if refused else {})


def test_a_refused_value_is_counted_every_time_it_is_offered():
    asset = _asset()
    for i in range(64):
        asset.add_evidence("discovery", f"n{i}.local.", 15, "mDNS")
    for _ in range(3):
        assert asset.add_evidence("discovery", "late.local.", 15, "mDNS") is False
    assert asset.evidence_overflow == {"discovery": 3}
    assert not asset.has_evidence("discovery", "late.local.")


def test_each_type_has_its_own_limit_and_count():
    asset = _asset()
    for i in range(70):
        asset.add_evidence("hostname", f"h{i}", 5, "DHCP")
    for i in range(66):
        asset.add_evidence("dns", f"f{i}.example", 5, "DHCP")
    asset.add_evidence("port", "502", 20, "traffic")
    assert asset.evidence_overflow == {"hostname": 6, "dns": 2}
    assert sum(1 for e in asset.evidence if e.type == "port") == 1


def test_a_kept_value_from_another_source_is_stored_at_the_limit():
    # The limit counts distinct (type, value) identities, not records: a second source of a kept
    # value adds a record without adding a value
    asset = _asset()
    for i in range(64):
        asset.add_evidence("os_hint", f"v{i}", 5, "traffic")
    for i in range(64):
        assert asset.add_evidence("os_hint", f"v{i}", 10, "DHCP") is True
    assert sum(1 for e in asset.evidence if e.type == "os_hint") == 128
    assert asset.evidence_overflow == {}
    assert asset.add_evidence("os_hint", "v64", 10, "DHCP") is False
    assert asset.evidence_overflow == {"os_hint": 1}


def test_a_duplicate_record_is_neither_stored_nor_counted():
    asset = _asset()
    for i in range(64):
        asset.add_evidence("vendor", f"v{i}", 5, "DHCP")
    assert asset.add_evidence("vendor", "v3", 5, "DHCP") is False
    assert asset.evidence_overflow == {}


def test_refused_evidence_leaves_classification_confidence_unchanged():
    asset = _asset()
    for i in range(64):
        asset.add_evidence("hostname", f"h{i}", 1, "DHCP")
    assert asset.classification_confidence_pct == 64
    asset.add_evidence("hostname", "extra", 30, "DHCP")
    assert asset.classification_confidence_pct == 64


# ── OS hints follow their evidence ────────────────────────────────────────────

def test_os_hints_stop_growing_when_os_hint_evidence_is_refused():
    asset = _asset()
    for i in range(80):
        asset.add_os_hint(f"hint {i}")
    assert asset.os_hints == [f"hint {i}" for i in range(64)]
    assert [e.value for e in asset.evidence if e.type == "os_hint"] == asset.os_hints
    assert asset.evidence_overflow == {"os_hint": 16}
    asset.add_os_hint("hint 70")                      # refused again: no duplicate in os_hints
    assert len(asset.os_hints) == 64 and asset.evidence_overflow == {"os_hint": 17}


def test_os_hints_do_not_grow_when_other_sources_filled_the_type():
    asset = _asset()
    for i in range(64):
        asset.add_evidence("os_hint", f"dhcp {i}", 10, "DHCP")
    asset.add_os_hint("Linux/Unix-like (observed TTL: 64, inferred initial: 64)")
    assert asset.os_hints == []
    assert asset.evidence_overflow == {"os_hint": 1}


# ── DNS names ─────────────────────────────────────────────────────────────────

def test_dns_name_limit_is_64():
    assert MAX_DNS_NAMES == 64


@pytest.mark.parametrize("added, kept, refused", [(64, 64, 0), (65, 64, 1), (1000, 64, 936)])
def test_dns_names_keep_the_first_names_and_count_the_rest(added, kept, refused):
    asset = _asset()
    for i in range(added):
        asset.add_dns_name(f"f{i}.example")
    assert asset.dns_names == [f"f{i}.example" for i in range(kept)]
    assert asset.dns_names_overflow == refused


def test_a_known_dns_name_is_not_counted_at_the_limit():
    asset = _asset()
    for i in range(64):
        asset.add_dns_name(f"f{i}.example")
    asset.add_dns_name("f0.example")
    assert asset.dns_names_overflow == 0
    asset.add_dns_name("new.example")
    asset.add_dns_name("new.example")
    assert asset.dns_names_overflow == 2


# ── Session load ──────────────────────────────────────────────────────────────

def _record(type_, value, source="mDNS"):
    return Evidence(type=type_, value=value, weight=15, source=source, confidence="HIGH")


def test_session_load_keeps_records_as_saved_under_the_limit():
    asset = _asset()
    saved = [_record("discovery", "a"), _record("discovery", "a"), _record("port", "502", "traffic")]
    for ev in saved:
        assert asset.load_evidence(ev) is True
    assert asset.evidence == saved                    # duplicates kept, order kept
    assert asset.classification_confidence_pct == 0   # not recomputed on load
    assert asset.evidence_overflow == {}


def test_session_load_respects_the_limit_and_counts_refused_records():
    asset = _asset()
    for i in range(70):
        asset.load_evidence(_record("discovery", f"n{i}"))
    asset.load_evidence(_record("discovery", "n3", "WS-Discovery"))   # a kept value: stored
    assert [e.value for e in asset.evidence] == [f"n{i}" for i in range(64)] + ["n3"]
    assert asset.evidence_overflow == {"discovery": 6}
    # Traffic after the load is refused the same way
    asset.add_evidence("discovery", "after.local.", 15, "mDNS")
    assert asset.evidence_overflow == {"discovery": 7}


def test_session_load_accepts_unhashable_values_and_counts_them_once():
    asset = _asset()
    for i in range(63):
        asset.load_evidence(_record("discovery", f"n{i}"))
    assert asset.load_evidence(_record("discovery", ["odd"])) is True
    assert asset.load_evidence(_record("discovery", ["odd"], "other")) is True   # same value
    assert asset.load_evidence(_record("discovery", ["other"])) is False
    assert asset.evidence_overflow == {"discovery": 1}


# ── Through the capture engine ────────────────────────────────────────────────

def _dhcp_request(option: bytes, t: float):
    """DHCPREQUEST from MAC with one extra option; BOOTP fields per RFC 2131 section 2."""
    chaddr = bytes.fromhex(MAC.replace(":", "")) + b"\x00" * 10
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, 0x1234, 0, 0,
                        b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, chaddr, b"", b"")
    options = b"\x63\x82\x53\x63" + b"\x35\x01\x03" + option + b"\xff"
    pkt = Ether(src=MAC, dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="255.255.255.255") \
        / UDP(sport=68, dport=67) / Raw(bootp + options)
    pkt = Ether(bytes(pkt))
    pkt.time = T0 + t
    return pkt


def _fqdn_option(name: bytes):
    # Option 81 (RFC 4702 section 2): flags, two RCODE bytes, then the name
    return bytes([81, 3 + len(name), 0, 0, 0]) + name


def test_dhcp_fqdn_flood_is_bounded_in_evidence_and_dns_names():
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    seed = Ether(src=MAC, dst="02:00:00:00:00:fe") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000, dport=80)
    seed.time = T0
    engine._process_packet(seed)
    for i in range(100):
        engine._process_packet(_dhcp_request(_fqdn_option(b"f%03d.example" % i), 1 + i))
    asset = engine.inventory.get("10.0.0.1")
    assert asset.dns_names == ["f%03d.example" % i for i in range(64)]
    assert [e.value for e in asset.evidence if e.type == "dns"] == asset.dns_names
    assert asset.dns_names_overflow == 36
    assert asset.evidence_overflow == {"dns": 36}


# ── IP history and baseline cursors ───────────────────────────────────────────

def test_ip_history_limit_is_256_episodes():
    assert MAX_IP_HISTORY == 256


def _hop_ip(i):
    return f"10.1.{i // 250}.{i % 250 + 1}"


@pytest.mark.parametrize("episodes, kept", [(256, 256), (257, 256), (5000, 256)])
def test_ip_history_keeps_the_most_recent_episodes_and_counts_dropped_ones(episodes, kept):
    asset = _asset()
    for i in range(episodes):
        asset.record_ip(_hop_ip(i), T0 + i)
        asset.record_ip(_hop_ip(i), T0 + i + 0.5)         # same episode: last_seen moves
    expected = [{"ip": _hop_ip(i), "first_seen": T0 + i, "last_seen": T0 + i + 0.5}
                for i in range(episodes - kept, episodes)]
    assert asset.ip_history == expected
    assert asset.ip_history_dropped == episodes - kept
    assert asset.ip == _hop_ip(episodes - 1)


def test_ip_history_counts_episodes_not_distinct_ips():
    asset = _asset()
    for i in range(300):
        asset.record_ip(("10.0.0.1", "10.0.0.2")[i % 2], T0 + i)
    assert len(asset.ip_history) == 256 and asset.ip_history_dropped == 44
    assert [e["ip"] for e in asset.ip_history[:2]] == ["10.0.0.1", "10.0.0.2"]


def test_a_cursor_is_dropped_only_when_its_ip_has_no_episode_left():
    asset = _asset()
    baselines = BaselineEngine()
    asset.record_ip("10.0.0.1", T0)
    asset.add_peer("10.0.9.1")
    asset.peers_not_given_to(baselines.device("10.0.0.1"))
    for i in range(255):                                  # 256 episodes: 10.0.0.1 still kept
        asset.record_ip(_hop_ip(i), T0 + 1 + i)
        asset.peers_not_given_to(baselines.device(_hop_ip(i)))
    assert "10.0.0.1" in asset._baseline_peer_cursors
    asset.record_ip("10.0.0.2", T0 + 1000)
    assert "10.0.0.1" not in asset._baseline_peer_cursors
    assert set(asset._baseline_peer_cursors) <= {e["ip"] for e in asset.ip_history}
    # Returning to the forgotten IP gives its baseline every peer again
    asset.record_ip("10.0.0.1", T0 + 2000)
    assert asset.peers_not_given_to(baselines.device("10.0.0.1")) == ["10.0.9.1"]


def test_cursor_map_stays_within_the_ip_history_while_hopping():
    asset = _asset()
    baselines = BaselineEngine()
    for i in range(2000):
        asset.record_ip(_hop_ip(i % 700), T0 + i)
        asset.add_peer(f"10.0.9.{i % 200 + 1}")
        asset.peers_not_given_to(baselines.device(asset.ip))
        assert len(asset._baseline_peer_cursors) <= MAX_IP_HISTORY
    assert set(asset._baseline_peer_cursors) <= {e["ip"] for e in asset.ip_history}


def _hopping_run():
    """One MAC learns peers at A, hops through 300 IPs learning more, then returns to A."""
    engine = CaptureEngine(inventory=AssetInventory(), baseline_window=60)
    engine.no_baseline = False
    packets = [("10.0.0.70", f"10.0.9.{i % 5 + 1}", i * 5) for i in range(15)]        # A locks
    packets += [(_hop_ip(i), f"10.0.8.{i % 40 + 1}", 100 + i) for i in range(300)]
    packets += [("10.0.0.70", "10.0.9.1", 1000), ("10.0.0.70", "10.0.7.1", 1001)]
    for src, dst, t in packets:
        pkt = Ether(src=MAC, dst="02:00:00:00:00:fe") / IP(src=src, dst=dst) / TCP(sport=40000, dport=502, flags="PA")
        pkt.time = T0 + t
        engine._process_packet(pkt)
    return engine


def _normalized_anomalies(engine):
    found = []
    for a in engine.baseline.anomaly_log:
        detail = a["detail"]
        m = re.search(r"New peer\(s\): (.*)$", detail)
        if m:
            detail = ", ".join(sorted(m.group(1).split(", ")))
        found.append((a["type"], a["ip"], detail))
    return found


def test_dropping_cursors_does_not_change_anomalies(monkeypatch):
    bounded = _hopping_run()
    asset = bounded.inventory.get_by_mac(MAC)
    assert asset.ip_history_dropped == 302 - 256
    assert "10.0.0.70" in asset._baseline_peer_cursors   # recreated on return
    monkeypatch.setattr(inventory, "MAX_IP_HISTORY", 10**9)
    unbounded = _hopping_run()
    assert _normalized_anomalies(bounded) == _normalized_anomalies(unbounded)
    new_peer = [a for a in _normalized_anomalies(bounded) if a[0] == "NEW_PEER" and a[1] == "10.0.0.70"]
    assert new_peer and "10.0.8.1" in new_peer[0][2] and "10.0.7.1" in new_peer[-1][2]
