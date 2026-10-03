"""
Peer retention limits and what saturation changes.

An asset keeps its first MAX_PEERS peer IPs. Once full, a new peer is not kept, so it is not in
peer_ips, the peer log or what device baselines receive, and a locked baseline does not report it
as a new peer. Every refused addition is counted, repeats included. Topology edges come from the
engine's own edge table and are not affected. peer_first_seen has its own limit of the same size,
filled independently.
"""

import re

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

import scrutics.classifier.protocol as protocol
from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import Asset, AssetInventory, MAX_PEERS

T0 = 1_700_000_000.0
MAC = "02:00:00:00:00:a1"
SRC = "10.0.0.70"


def _peer(i):
    return f"10.9.{i // 250}.{i % 250 + 1}"


def test_peer_limit_is_4096():
    assert MAX_PEERS == 4096


# ── Asset level ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("added, kept", [(4096, 4096), (4097, 4096), (10_000, 4096)])
def test_peers_keep_the_first_and_count_every_refused_addition(added, kept):
    asset = Asset(ip=SRC, mac=MAC)
    for i in range(added):
        asset.add_peer(_peer(i))
    assert asset.peer_ips == {_peer(i) for i in range(kept)}
    assert asset._synced_peer_log() == [_peer(i) for i in range(kept)]
    assert asset.peer_additions_rejected == added - kept
    assert asset.to_dict()["peer_count"] == kept


def test_repeats_of_a_refused_peer_are_counted_each_time():
    asset = Asset(ip=SRC, mac=MAC)
    for i in range(MAX_PEERS):
        asset.add_peer(_peer(i))
    for _ in range(5):
        asset.add_peer("10.8.0.1")
    asset.add_peer(_peer(7))                              # a kept peer is not counted
    assert asset.peer_additions_rejected == 5
    assert len(asset.peer_ips) == MAX_PEERS


def test_a_full_peer_set_gives_baselines_nothing_new():
    asset = Asset(ip=SRC, mac=MAC)
    baseline = BaselineEngine().device(SRC)
    for i in range(MAX_PEERS):
        asset.add_peer(_peer(i))
    assert len(asset.peers_not_given_to(baseline)) == MAX_PEERS
    asset.add_peer("10.8.0.1")
    assert asset.peers_not_given_to(baseline) == []


@pytest.mark.parametrize("added, kept", [(4096, 4096), (4097, 4096), (10_000, 4096)])
def test_first_seen_times_keep_the_first_peers_and_count_the_rest(added, kept):
    asset = Asset(ip=SRC, mac=MAC)
    for i in range(added):
        asset.record_peer_first_seen(_peer(i), float(i))
    assert list(asset.peer_first_seen) == [_peer(i) for i in range(kept)]
    assert asset.peer_first_seen_overflow == added - kept
    assert asset.peers_first_seen_since(0) == kept
    asset.record_peer_first_seen(_peer(0), 1e9)           # a kept peer keeps its first time
    assert asset.peer_first_seen[_peer(0)] == 0.0


def test_first_seen_limit_is_independent_of_the_peer_set():
    # Late start: first-seen recording begins after peer_ips is full, so it keeps peers that
    # peer_ips refused
    asset = Asset(ip=SRC, mac=MAC)
    for i in range(MAX_PEERS):
        asset.add_peer(_peer(i))
    for i in range(MAX_PEERS, MAX_PEERS + 10):
        asset.add_peer(_peer(i))
        asset.record_peer_first_seen(_peer(i), float(i))
    assert asset.peer_additions_rejected == 10
    assert list(asset.peer_first_seen) == [_peer(i) for i in range(MAX_PEERS, MAX_PEERS + 10)]
    assert asset.peer_first_seen_overflow == 0


# ── Through the capture engine ────────────────────────────────────────────────

@pytest.fixture
def rules(monkeypatch):
    def use(user_rules):
        monkeypatch.setattr(protocol, "_USER_RULES", list(user_rules))
        monkeypatch.setattr(protocol, "_BUILTIN_RULES", [])
    return use


def _send(engine, dst, t):
    pkt = Ether(src=MAC, dst="02:00:00:00:00:fe") / IP(src=SRC, dst=dst) / TCP(sport=40000, dport=502, flags="PA")
    pkt.time = T0 + t
    engine._process_packet(pkt)


def _new_peer_sets(engine):
    return [set(re.search(r"New peer\(s\): (.*)$", a["detail"]).group(1).split(", "))
            for a in engine.baseline.anomaly_log if a["type"] == "NEW_PEER" and a["ip"] == SRC]


def test_saturated_asset_does_not_report_unretained_peers_but_topology_keeps_them(rules):
    rules([{"name": "rate", "mac_prefix": MAC, "classify_as": "X", "role": "X", "is_ot": True,
            "max_new_peers_per_hour": 100_000}])
    engine = CaptureEngine(inventory=AssetInventory(), baseline_window=60)
    engine.no_baseline = False
    for i in range(MAX_PEERS):                            # all within the 60 s learning window
        _send(engine, _peer(i), i * 0.01)
    _send(engine, _peer(0), 100)                          # locks the baseline
    _send(engine, _peer(MAX_PEERS - 1), 101)
    assert _new_peer_sets(engine) == []
    late = "10.8.0.1"
    for k in range(3):
        _send(engine, late, 102 + k)
    asset = engine.inventory.get(SRC)
    assert late not in asset.peer_ips and len(asset.peer_ips) == MAX_PEERS
    assert asset.peer_additions_rejected == 3
    assert _new_peer_sets(engine) == []                   # before the limit this would be {late}
    # The rule applied from the first packet, so first-seen times filled with the same peers
    assert set(asset.peer_first_seen) == asset.peer_ips
    assert asset.peer_first_seen_overflow == 3
    assert asset.peers_first_seen_since(T0) == MAX_PEERS
    # Topology is built from the engine's edges, which do not depend on peer_ips
    late_asset = engine.inventory.get(late)
    assert late_asset is not None
    assert (asset.primary_key, late_asset.primary_key) in engine.topology_edges


def test_an_unsaturated_asset_still_reports_a_new_peer(rules):
    rules([])
    engine = CaptureEngine(inventory=AssetInventory(), baseline_window=60)
    engine.no_baseline = False
    for i in range(10):
        _send(engine, _peer(i), i)
    _send(engine, _peer(0), 100)
    _send(engine, "10.8.0.1", 101)
    assert _new_peer_sets(engine) == [{"10.8.0.1"}]
