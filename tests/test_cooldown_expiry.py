"""
Anomaly cooldown keys age out.

A packet is late when it is more than one cooldown behind the newest packet time the cooldown table
has seen (its watermark). For input without late packets, decisions equal those of a table that
keeps every key forever. Late packets may alert where a kept key would have suppressed them, but
each key alerts at most floor((W1 - W0) / cooldown) + 2 times while the watermark moves from W0 to
W1. The alert_on_new_port port set shares the per-asset table and is never removed.
"""

import math
import random
from types import SimpleNamespace

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

import scrutics.classifier.protocol as protocol
from scrutics.capture.cooldown import Cooldowns
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory

T0 = 1_700_000_000.0


class _Forever:
    """The decision rule before keys aged out: every key is kept."""

    def __init__(self):
        self.times = {}

    def allow(self, key, timestamp, cooldown):
        last = self.times.get(key)
        if last is not None and (timestamp - last) < cooldown:
            return False
        self.times[key] = timestamp
        return True


COOLDOWNS = {"NEVER_INITIATES": 60, "PEER_RATE": 300}


def _cooldown(key):
    return COOLDOWNS.get(key, 300)


def _random_key(rng):
    return rng.choice(["NEVER_INITIATES", "PEER_RATE", f"PEER_10.0.0.{rng.randint(1, 30)}", f"PORT_{rng.randint(1, 30)}"])


# ── Decisions ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("seed", range(30))
def test_decisions_without_late_packets_equal_keeping_every_key(seed):
    rng = random.Random(seed)
    aging, forever = Cooldowns({}), _Forever()
    watermark = 0.0
    for _ in range(3000):
        key = _random_key(rng)
        cooldown = _cooldown(key)
        # Never more than one cooldown behind the newest time: forward steps and small reorderings
        ts = max(0.0, watermark + rng.choice((0, 0, 1, 5, 30, 200, 900)) - rng.random() * cooldown)
        watermark = max(watermark, ts)
        assert aging.allow(key, ts, cooldown) == forever.allow(key, ts, cooldown)
    assert len(aging.times) < len(forever.times)


def test_keys_age_out_under_a_long_flood_of_distinct_keys():
    times = {}
    cooldowns = Cooldowns(times)
    largest = 0
    for i in range(20_000):
        assert cooldowns.allow(f"PEER_10.{i // 65536}.{i // 256 % 256}.{i % 256}", T0 + i, 300)
        largest = max(largest, len(times))
    # A key lives until the watermark is two cooldowns past it: about 600 keys at one per second
    assert largest <= 601
    assert len(times) <= 601


def test_entries_not_stored_through_allow_are_never_removed():
    times = {"_known_ports": {502}}
    cooldowns = Cooldowns(times)
    for i in range(2000):
        cooldowns.allow(f"PORT_{i}", T0 + i * 10, 300)
    assert times["_known_ports"] == {502}


# ── Late packets ──────────────────────────────────────────────────────────────

def test_a_late_packet_after_its_key_aged_out_alerts_and_is_rate_limited():
    cooldowns, forever = Cooldowns({}), _Forever()
    for c in (cooldowns, forever):
        assert c.allow("PEER_10.0.0.5", T0, 300)
        assert c.allow("PORT_1", T0 + 700, 300)             # watermark two cooldowns past T0
    assert "PEER_10.0.0.5" not in cooldowns.times
    # Late (more than one cooldown behind the watermark): a kept key would suppress it
    assert forever.allow("PEER_10.0.0.5", T0 + 10, 300) is False
    assert cooldowns.allow("PEER_10.0.0.5", T0 + 10, 300) is True
    assert cooldowns.times["PEER_10.0.0.5"] == T0 + 700 - 300   # watermark - cooldown, not T0 + 10
    # Further late packets for that key, however many, stay suppressed at this watermark
    for k in range(1000):
        assert cooldowns.allow("PEER_10.0.0.5", T0 + 10 + k * 0.1, 300) is False
    # A packet at the watermark is suppressed too, until one cooldown after the stored time
    assert cooldowns.allow("PEER_10.0.0.5", T0 + 699, 300) is False
    assert cooldowns.allow("PEER_10.0.0.5", T0 + 700, 300) is True


@pytest.mark.parametrize("seed", range(30))
def test_each_key_alerts_at_most_once_per_cooldown_of_watermark_advance_plus_two(seed):
    rng = random.Random(seed)
    cooldowns = Cooldowns({})
    alerts = {}                                          # key -> watermarks at which it alerted
    watermark = 0.0
    for _ in range(5000):
        key = _random_key(rng)
        cooldown = _cooldown(key)
        if rng.random() < 0.5:                           # adversarial late packets, any distance back
            ts = rng.random() * watermark
        else:
            ts = watermark + rng.choice((0, 1, 10, 100, 400))
        watermark = max(watermark, ts)
        if cooldowns.allow(key, ts, cooldown):
            alerts.setdefault(key, []).append(watermark)
    for key, marks in alerts.items():
        bound = math.floor((marks[-1] - marks[0]) / _cooldown(key)) + 2
        assert len(marks) <= bound, (key, len(marks), bound)


def test_many_late_keys_each_alert_at_most_twice_at_a_fixed_watermark():
    cooldowns = Cooldowns({})
    cooldowns.allow("PORT_0", T0 + 10_000, 300)
    counts = {}
    rng = random.Random(1)
    for _ in range(20_000):
        key = f"PEER_10.0.{rng.randint(0, 3)}.{rng.randint(1, 250)}"
        if cooldowns.allow(key, T0 + rng.random() * 9_000, 300):
            counts[key] = counts.get(key, 0) + 1
    assert counts and max(counts.values()) <= 2


# ── Through the capture engine ────────────────────────────────────────────────

MAC = "02:00:00:00:00:a1"
SRC = "10.0.0.70"


@pytest.fixture
def rules(monkeypatch):
    def use(user_rules):
        monkeypatch.setattr(protocol, "_USER_RULES", list(user_rules))
        monkeypatch.setattr(protocol, "_BUILTIN_RULES", [])
    return use


def _packet(src_mac, src_ip, dst_ip, dport, t):
    pkt = Ether(src=src_mac, dst="02:00:00:00:00:fe") / IP(src=src_ip, dst=dst_ip) / TCP(sport=40000, dport=dport, flags="PA")
    pkt.time = T0 + t
    return pkt


def _engine():
    """An engine that records every anomaly it emits (its anomaly_log keeps only the last 100)."""
    engine = CaptureEngine(inventory=AssetInventory())
    engine.no_baseline = True
    engine.emitted = []
    engine.sink_manager = SimpleNamespace(emit_anomaly=engine.emitted.append)
    return engine


def _violations(engine):
    return [(a["type"], a["ip"], a["detail"], a["timestamp"]) for a in engine.emitted]


CONSTRAINT_RULE = {"name": "strict", "mac_prefix": MAC, "classify_as": "X", "role": "X", "is_ot": True,
                   "allowed_peers": ["10.0.1.1"], "allowed_ports": [502], "never_initiates": True,
                   "alert_on_new_port": True}


def _constraint_traffic(engine, rng, hours=3):
    t = 0.0
    while t < hours * 3600:
        engine._process_packet(_packet(MAC, SRC, f"10.0.2.{rng.randint(1, 40)}", rng.choice((502, 102, 80, 20000)), t))
        t += rng.choice((1, 5, 30, 120))


def test_engine_constraint_alerts_are_unchanged_for_in_order_traffic(rules, monkeypatch):
    rules([CONSTRAINT_RULE])
    aging = _engine()
    _constraint_traffic(aging, random.Random(5))
    monkeypatch.setattr(Cooldowns, "_expire", lambda self: None)     # keep every key
    forever = _engine()
    _constraint_traffic(forever, random.Random(5))
    assert _violations(aging) == _violations(forever)
    assert [m for _, m, _ in aging.event_log] == [m for _, m, _ in forever.event_log]
    aged = aging.inventory.get(SRC)._constraint_anomaly_ts
    kept = forever.inventory.get(SRC)._constraint_anomaly_ts
    assert len(aged) < len(kept)
    # The new-port set is not cooldown state: kept whole, and no port is reported new twice
    assert aged["_known_ports"] == kept["_known_ports"] == {502, 102, 80, 20000}
    new_ports = [d for t, _, d, _ in _violations(aging) if "[NEW_PORT]" in d]
    assert len(new_ports) == len(set(new_ports)) == 3


def _mac_traffic(engine):
    # Two MACs alternately claim one IP while a third moves among IPs that change every 10
    # minutes, for an hour, so earlier keys stop being used
    for i in range(720):
        t = i * 5.0
        engine._process_packet(_packet(("02:00:00:00:00:b1", "02:00:00:00:00:b2")[i % 2], "10.0.0.80", "10.0.0.1", 502, t))
        engine._process_packet(_packet("02:00:00:00:00:c1", f"10.0.{1 + i // 120}.{90 + i % 7}", "10.0.0.1", 502, t))


def test_engine_mac_alerts_are_unchanged_for_in_order_traffic(monkeypatch):
    aging = _engine()
    _mac_traffic(aging)
    monkeypatch.setattr(Cooldowns, "_expire", lambda self: None)
    forever = _engine()
    _mac_traffic(forever)
    assert _violations(aging) == _violations(forever)
    assert any(v[0] == "MAC_CHANGED" for v in _violations(aging))
    assert any(v[0] == "DEVICE_MOVED" for v in _violations(aging))
    assert len(aging._mac_anomaly_ts) < len(forever._mac_anomaly_ts)


def test_engine_mac_keys_stay_bounded_when_many_macs_claim_one_ip():
    engine = CaptureEngine(inventory=AssetInventory()); engine.no_baseline = True
    largest = 0
    for i in range(3000):
        mac = "02:00:00:%02x:%02x:%02x" % (i >> 16 & 0xff, i >> 8 & 0xff, i & 0xff)
        engine._process_packet(_packet(mac, "10.0.0.80", "10.0.0.1", 502, i * 2.0))
        largest = max(largest, len(engine._mac_anomaly_ts))
    # One key per packet at most, each living until the watermark is 600 s past it
    assert largest <= 301
