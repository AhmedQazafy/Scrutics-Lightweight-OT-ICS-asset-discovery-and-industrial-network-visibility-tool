"""
Each device baseline receives only the peers it has not been given yet.

A baseline is kept per IP and an asset per MAC. An asset that changes IP and returns still
passes the peers it learned elsewhere to the baseline of the IP it returns to, so a locked
baseline reports them as new peers. The anomalies and baseline state must equal those produced
by passing the asset's whole peer set on every packet.
"""

import random
import re

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from scrutics.baseline.baselineengine import BaselineEngine
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import Asset, AssetInventory

T0 = 1_700_000_000.0
MAC_A = "02:00:00:00:00:a1"
MAC_B = "02:00:00:00:00:b1"


def _packet(src_mac, src_ip, dst_ip, t, dport=502):
    pkt = Ether(src=src_mac, dst="02:00:00:00:00:fe") / IP(src=src_ip, dst=dst_ip) / TCP(sport=40000, dport=dport, flags="PA")
    pkt.time = T0 + t
    return pkt


def _engine():
    engine = CaptureEngine(inventory=AssetInventory(), baseline_window=60)
    engine.no_baseline = False
    return engine


def _new_peer_sets(engine, ip):
    found = []
    for anomaly in engine.baseline.anomaly_log:
        if anomaly["type"] == "NEW_PEER" and anomaly["ip"] == ip:
            found.append(set(re.search(r"New peer\(s\): (.*)$", anomaly["detail"]).group(1).split(", ")))
    return found


def test_peers_learned_at_another_ip_reach_the_locked_baseline_on_return():
    engine = _engine()
    for i in range(15):                                   # baseline of 10.0.0.70 locks after 60 s
        engine._process_packet(_packet(MAC_A, "10.0.0.70", f"10.0.0.{80 + i % 2}", i * 5))
    engine._process_packet(_packet(MAC_A, "10.0.0.71", "10.0.0.82", 80))
    engine._process_packet(_packet(MAC_A, "10.0.0.71", "10.0.0.83", 85))
    engine._process_packet(_packet(MAC_A, "10.0.0.70", "10.0.0.80", 90))
    assert _new_peer_sets(engine, "10.0.0.70") == [{"10.0.0.82", "10.0.0.83"}]


def test_a_known_peer_is_not_reported_again():
    engine = _engine()
    for i in range(15):
        engine._process_packet(_packet(MAC_A, "10.0.0.70", "10.0.0.80", i * 5))
    engine._process_packet(_packet(MAC_A, "10.0.0.70", "10.0.0.81", 80))
    engine._process_packet(_packet(MAC_A, "10.0.0.70", "10.0.0.81", 85))
    engine._process_packet(_packet(MAC_A, "10.0.0.70", "10.0.0.80", 90))
    assert _new_peer_sets(engine, "10.0.0.70") == [{"10.0.0.81"}]


def test_a_new_baseline_engine_receives_every_peer_of_an_existing_asset():
    asset = Asset(ip="10.0.0.70", mac=MAC_A)
    for peer in ("10.0.0.80", "10.0.0.81"):
        asset.add_peer(peer)
    first = BaselineEngine()
    assert set(asset.peers_not_given_to(first.device("10.0.0.70"))) == {"10.0.0.80", "10.0.0.81"}
    assert asset.peers_not_given_to(first.device("10.0.0.70")) == []
    second = BaselineEngine()
    assert set(asset.peers_not_given_to(second.device("10.0.0.70"))) == {"10.0.0.80", "10.0.0.81"}


def test_each_baseline_ip_keeps_its_own_position():
    asset = Asset(ip="10.0.0.70", mac=MAC_A)
    baselines = BaselineEngine()
    asset.add_peer("10.0.0.80")
    assert asset.peers_not_given_to(baselines.device("10.0.0.70")) == ["10.0.0.80"]
    asset.add_peer("10.0.0.81")
    assert asset.peers_not_given_to(baselines.device("10.0.0.71")) == ["10.0.0.80", "10.0.0.81"]
    asset.add_peer("10.0.0.82")
    assert asset.peers_not_given_to(baselines.device("10.0.0.70")) == ["10.0.0.81", "10.0.0.82"]
    assert asset.peers_not_given_to(baselines.device("10.0.0.71")) == ["10.0.0.82"]


def _random_traffic(seed):
    rng = random.Random(seed)
    macs = [MAC_A, MAC_B, "02:00:00:00:00:c1"]
    ips = [f"10.0.0.{70 + i}" for i in range(4)]
    peers = [f"10.0.1.{i}" for i in range(1, 30)]
    t = 0.0
    packets = []
    for _ in range(400):
        t += rng.choice((0.5, 1, 2, 5, 20))
        packets.append(_packet(rng.choice(macs), rng.choice(ips), rng.choice(peers), t))
    return packets


def _observable_state(engine):
    anomalies = []
    for a in engine.baseline.anomaly_log:
        detail = a["detail"]
        m = re.search(r"New peer\(s\): (.*)$", detail)
        if m:
            detail = sorted(m.group(1).split(", "))
        anomalies.append((a["type"], a["ip"], a["timestamp"], str(detail)))
    devices = {
        ip: (d.locked, set(d.known_peers), set(d._peers_observed), d._initiate_count, d._respond_count)
        for ip, d in engine.baseline._devices.items()
    }
    assets = sorted(
        (a.ip, a.mac, a.baseline_status, a.behavioral_score, a.directionality_score, a.confidence_pct)
        for a in engine.inventory.get_all()
    )
    return anomalies, devices, assets


@pytest.mark.parametrize("seed", range(6))
def test_delivery_equals_passing_the_whole_peer_set_every_packet(seed, monkeypatch):
    packets = _random_traffic(seed)
    with monkeypatch.context() as patch:
        patch.setattr(Asset, "peers_not_given_to", lambda self, baseline: list(self.peer_ips))
        reference = _engine()
        for pkt in packets:
            reference._process_packet(pkt)
    engine = _engine()
    for pkt in packets:
        engine._process_packet(pkt)
    assert _observable_state(engine) == _observable_state(reference)
